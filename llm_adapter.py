import json
import time
import random
import os
from typing import Optional, List, Dict
from openai import OpenAI

client = OpenAI()          # needs OPENAI_API_KEY
MODEL = "gpt-4o-mini"

# Production settings
MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "300"))
MAX_RETRIES = int(os.getenv("LLM_MAX_RETRIES", "3"))

SYSTEM = (
    "You are an Incident Response assistant. "
    "Return JSON only with keys: "
    "{label: one of [xss, sql_injection, bruteforce, ssrf, rce, other], "
    " score: 0..1, evidence: [], rationale: string, "
    " missing: subset of [app, endpoint, ip, url, user]}. "
    "Keep responses concise for token efficiency."
)

class LLMUnavailable(Exception): ...

def _retry_with_backoff(func, max_retries=MAX_RETRIES):
    """Retry with exponential backoff for rate limits."""
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            error_str = str(e).lower()
            if "rate limit" in error_str or "429" in error_str:
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) + random.uniform(0, 1)
                    time.sleep(wait_time)
                    continue
            raise e
    raise Exception(f"Max retries ({max_retries}) exceeded")

def _truncate_for_tokens(text: str, max_chars: int = 2000) -> str:
    """Simple token approximation: ~4 chars per token."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "...[truncated]"

def classify_and_slots(text: str,
                       kb_context: Optional[str] = None,
                       history: Optional[List[Dict]] = None) -> dict:
    
    # Token optimization
    text = _truncate_for_tokens(text, 1500)
    kb_context = _truncate_for_tokens(kb_context, 800) if kb_context else None
    
    msgs = [{"role":"system","content": SYSTEM}]
    if kb_context:
        msgs.append({"role":"system","content": f"Context:\n{kb_context}"})
    if history:
        # Limit history for token efficiency
        msgs.extend(history[-4:])
    msgs.append({"role":"user","content": f"Incident text:\n{text}\nReturn JSON only."})

    def _make_request():
        try:
            r = client.chat.completions.create(
                model=MODEL,
                messages=msgs,
                temperature=0.1,
                max_tokens=MAX_TOKENS,
                response_format={"type":"json_object"},
                timeout=25
            )
            m = r.choices[0].message
            return getattr(m, "parsed", json.loads(m.content))
        except Exception as e:
            error_str = str(e).lower()
            if any(term in error_str for term in ["insufficient_quota", "error code: 429", "rate limit", "quota"]):
                raise LLMUnavailable("OpenAI quota/rate-limit") from e
            raise
    
    return _retry_with_backoff(_make_request)