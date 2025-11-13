import time, json, io, os
from pathlib import Path
import streamlit as st
from extractor import extract_entities, extract_IOCs, detect_symptoms
from llm_adapter import classify_and_slots
from nvd import fetch_cve, mitre_url
from lc_retriever import build_inmemory_kb, format_retrieval_snippets

# Load environment variables from .env file
def load_env_file():
    env_file = Path(__file__).parent / ".env"
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key] = value

# Load environment at startup
load_env_file()

# Thresholds mandated by the paper/algorithms
THRESH_LOW = float(os.getenv("THRESH_LOW", 0.6))  # ask one clarification
THRESH_GO  = float(os.getenv("THRESH_GO", 0.7))   # ready to hand off

REPORT_CATEGORY_MAP = {
    "sql_injection": "Injection Attack",
    "xss": "Injection Attack",
    "ssrf": "Injection Attack",
    "rce": "Injection Attack",
    "bruteforce": "Denial of Service",
    "dos": "Denial of Service",
    "misconfig": "Misconfiguration",
    "phishing": "Phishing",
    "other": "Other"
}

st.set_page_config(page_title="IR ChatOps — Phase 1", layout="wide")
st.title("Incident Response ChatOps — Phase 1")

# Show current system status
provider = os.getenv("LLM_PROVIDER", "openai")
api_status = "✓" if os.getenv("GOOGLE_API_KEY" if provider == "gemini" else "OPENAI_API_KEY") else "✗"
st.caption(f"Input → IOCs/Entities → NVD context → Classification → Phase-2 Ready JSON ({api_status} online)")

if "history" not in st.session_state:
    greetings = [
        "Hey there. What's the security situation you're dealing with?",
        "Hi. Tell me about the incident you need help with.",
        "What's going on? Describe the security issue you've encountered.",
        "Hey. What kind of security incident are we looking at?"
    ]
    import random
    
    st.session_state.history = [
        {"role":"assistant","content": random.choice(greetings)}
    ]
if "phase1_output" not in st.session_state:
    st.session_state.phase1_output = None
if "last_input_cache" not in st.session_state:
    st.session_state.last_input_cache = {}
if "asked_slots" not in st.session_state:
    st.session_state.asked_slots = set()
if "asked_slots" not in st.session_state:
    st.session_state.asked_slots = set()
if "last_input_cache" not in st.session_state:
    st.session_state.last_input_cache = {}

def templated_reply(user_text: str, label: str, score: float, iocs: dict, rationale: str, kb_present: bool, followup: str|None):
    sig = []
    if iocs.get("ip"):  sig.append(f"ip={', '.join(iocs['ip'][:2])}")
    if iocs.get("url"): sig.append(f"url={', '.join(iocs['url'][:1])}")
    if iocs.get("cve"): sig.append(f"cve={', '.join(iocs['cve'][:2])}")
    signals = " · ".join(sig) if sig else "no indicators yet"

    # Natural response variations
    import random
    
    # Different responses based on confidence
    if score >= 0.8:
        # High confidence responses
        openings = [
            "Alright, got a clear read on this.",
            "Right, this looks straightforward.", 
            "Okay, pretty clear what we're dealing with here.",
            "Got it. Analysis came back definitive."
        ]
        classification_intros = [
            "This is definitely",
            "Clear case of", 
            "We're looking at",
            "Identified as"
        ]
        confidence_phrase = "high confidence"
        
    elif score >= 0.6:
        # Medium confidence responses  
        openings = [
            "Alright, I've looked at this incident.",
            "Okay, processed what you described.",
            "Got it. Here's my assessment.",
            "Right, analyzed the details."
        ]
        classification_intros = [
            "This appears to be",
            "Looking like", 
            "Seems we're dealing with",
            "Assessment shows"
        ]
        confidence_phrase = "fairly confident"
        
    else:
        # Low confidence responses
        openings = [
            "Hmm, taking a look at this.",
            "Okay, trying to piece this together.",
            "Right, let me work through this.",
            "Got it, though need a bit more to go on."
        ]
        classification_intros = [
            "Best guess is",
            "Might be looking at",
            "Could be dealing with",
            "Initial assessment suggests"
        ]
        confidence_phrase = "not entirely sure yet"
    
    parts = []
    parts.append(random.choice(openings))
    
    if label == "other" and score < 0.6:
        parts.append(f"**{random.choice(classification_intros)} something unclear** - {confidence_phrase} ({score:.2f})")
    else:
        parts.append(f"**{random.choice(classification_intros)} {label.replace('_', ' ')}** - {confidence_phrase} ({score:.2f})")
    
    if rationale:
        if "need more details" in rationale.lower() or "more specific" in rationale.lower():
            parts.append(f"**Issue:** {rationale}")
        else:
            parts.append(f"**Analysis:** {rationale}")
        
    parts.append(f"**Indicators:** {signals}")
    
    if kb_present:
        parts.append("**Plus:** vulnerability data enrichment applied")
        
    if followup:
        if "can you be more specific" in followup.lower() or "what type of" in followup.lower():
            parts.append(f"**Need help:** {followup}")
        else:
            followup_intros = [
                "Quick question -",
                "One thing -", 
                "Need to know -",
                "Just checking -"
            ]
            parts.append(f"**{random.choice(followup_intros)}** {followup}")
    else:
        if score >= 0.7:
            endings = [
                "Should be good to escalate this.",
                "Ready to pass this along.",
                "Think we've got enough to move forward.",
                "Confident enough to proceed."
            ]
        else:
            endings = [
                "That's what I can determine so far.",
                "Best assessment with current info.",
                "Working with what we have here."
            ]
        parts.append(f"**Status:** {random.choice(endings)}")
            
    return "\n\n".join(parts)

# Render prior messages
for m in st.session_state.history:
    with st.chat_message(m["role"]):
        st.markdown(m["content"])

user_text = st.chat_input("Describe the incident…")
if user_text:
    st.session_state.history.append({"role":"user","content":user_text})
    with st.chat_message("user"): st.markdown(user_text)

    with st.chat_message("assistant"):
        with st.spinner("Analyzing…"):
            t0 = time.perf_counter()

            # 1) Extraction
            ents = extract_entities(user_text)
            iocs = extract_IOCs(user_text)

            # 2) NVD CVE context (free; optional NVD key improves rate limit)
            kb_context = ""
            if ents.cves:
                docs = [fetch_cve(c) for c in ents.cves]
                ret = build_inmemory_kb(docs)
                if ret:
                    # small k to reduce tokens
                    kb_context = format_retrieval_snippets(ret.get_relevant_documents(user_text))

            # 3) Classification (LLM → JSON) with retry/backoff inside; graceful degradation if quota out
            rationale = ""
            cache_key = user_text.strip()
            out = None
            if cache_key in st.session_state.last_input_cache:
                out = st.session_state.last_input_cache[cache_key]
            if out is None:
                try:
                    # Convert entities and IOCs to the expected format
                    entities_dict = {
                        "ip": iocs.get("ip", []),
                        "url": iocs.get("url", []), 
                        "cve": ents.cves
                    }
                    
                    # Use new Gemini-powered classification
                    st.write("🔍 Analyzing with Gemini AI...")
                    gemini_result = classify_and_slots(user_text, entities_dict, {"kb_context": kb_context})
                    
                    # Convert to expected format
                    out = {
                        "label": gemini_result.get("classification", "other").lower().replace(" ", "_").replace("-", "_"),
                        "score": gemini_result.get("confidence", 0.0),
                        "rationale": gemini_result.get("reasoning", ""),
                        "evidence": entities_dict.get("ip", []) + entities_dict.get("url", []) + entities_dict.get("cve", []),
                        "missing": []
                    }
                    st.session_state.last_input_cache[cache_key] = out
                    st.success("✅ Gemini AI analysis complete!")
                    
                except RuntimeError as e:
                    st.error(f"🚨 API Error: {str(e)}")
                    if "API_KEY" in str(e):
                        provider = os.getenv("LLM_PROVIDER", "openai")
                        st.warning(f"Degraded mode: {provider.title()} API key unavailable. Using local analysis for now.")
                    else:
                        st.warning("Degraded mode: LLM API unavailable. Using local analysis for now.")
                except Exception as e:
                    st.error(f"🚨 Classification Error: {str(e)}")
                    st.warning("Falling back to local analysis...")
                    pass

            missing = set(); evidence = []
            if out:
                label     = out.get("label","other")
                score     = float(out.get("score",0.0))
                evidence  = out.get("evidence",[])
                rationale = out.get("rationale","")
                missing   = set(out.get("missing",[]))
            else:
                # Local heuristic fallback
                symptoms = detect_symptoms(user_text)
                if symptoms:
                    s = symptoms[0]  # Take the first/best symptom
                    label, score, evidence = s.label, s.score, list(s.evidence)
                else:
                    label, score, evidence = "other", 0.5, []
                rationale = "Local heuristic based on keywords/patterns."

            # 4) Enhanced follow-up logic with better guidance
            followup = None
            if score < THRESH_LOW:
                if label == "other":
                    # Provide specific guidance for unclear incidents
                    guidance_options = [
                        "Can you be more specific? For example: 'SQL injection attack', 'malware detected', 'phishing email', or 'brute force login attempts'?",
                        "What type of security issue is this? Try describing it with terms like: attack, malware, vulnerability, breach, or suspicious activity.",
                        "I need more technical details. What system was affected and what exactly happened? Include any error messages, IP addresses, or file names.",
                        "Help me understand the incident better. Describe what you observed: unusual network traffic, suspicious files, failed logins, or application errors?"
                    ]
                    import random
                    followup = random.choice(guidance_options)
                else:
                    followup = "Which application/service and endpoint is affected?"
            elif not iocs.get("ip") and not iocs.get("url"):
                followup = "Do you have an affected IP or URL?"
            else:
                qmap = {
                    "app":"Which application/service is affected?",
                    "endpoint":"Which endpoint/route is affected?", 
                    "ip":"Which source IP is involved?",
                    "url":"Which URL is involved?",
                    "user":"Which user/account is impacted?"
                }
                for k in ("app","endpoint","ip","url","user"):
                    if k in missing:
                        followup = qmap[k]; break

            # don't repeat the same follow-up
            if followup and followup in st.session_state.asked_slots:
                followup = None
            elif followup:
                st.session_state.asked_slots.add(followup)

            sig = []
            if iocs.get("ip"):  sig.append(f"ip={', '.join(iocs['ip'][:2])}")
            if iocs.get("url"): sig.append(f"url={', '.join(iocs['url'][:1])}")
            if ents.cves:       sig.append(f"cve={', '.join(ents.cves[:2])}")
            signals = " · ".join(sig) if sig else "no indicators yet"

            # 5) Chatty response (works both full/degenerate modes)
            msg = templated_reply(
                user_text=user_text,
                label=label,
                score=score,
                iocs=iocs,
                rationale=rationale,
                kb_present=bool(kb_context),
                followup=followup if (followup and score < THRESH_GO) else None
            )
            st.markdown(msg)

            # 5) Phase-2 handoff JSON
            report_category = REPORT_CATEGORY_MAP.get(label, "Other")
            st.session_state.phase1_output = {
                "incident_type": report_category,
                "fine_label": label,
                "confidence": score,
                "rationale": rationale,
                "entities": ents.__dict__,
                "iocs": iocs,
                "related_CVEs": ents.cves,
                "kb_excerpt": kb_context[:600],
                "timestamp_ms": round((time.perf_counter()-t0)*1000,1)
            }

            with st.expander("Advanced details (Phase-2 input)"):
                st.json(st.session_state.phase1_output)
                if ents.cves:
                    st.markdown("**MITRE CVE Links:**")
                    for c in ents.cves[:5]:
                        st.markdown(f"- [{c}]({mitre_url(c)})")

            # 6) download JSON
            if st.session_state.phase1_output:
                import io
                buf = io.BytesIO(json.dumps(st.session_state.phase1_output, indent=2).encode("utf-8"))
                st.download_button(
                    "Download Phase-1 Output (JSON)",
                    data=buf,
                    file_name="phase1_output.json",
                    mime="application/json"
                )

    st.session_state.history.append({"role":"assistant","content":msg})