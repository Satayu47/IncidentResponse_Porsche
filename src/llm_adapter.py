import os
import json
import time
import random
import requests
from typing import Dict, Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configuration from environment
PROVIDER = os.getenv("LLM_PROVIDER", "openai").lower()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
NVD_API_KEY = os.getenv("NVD_API_KEY")

# Import providers based on configuration
if PROVIDER == "gemini":
    try:
        import google.generativeai as genai
        api_key = os.getenv("GOOGLE_API_KEY")
        genai.configure(api_key=api_key)
    except ImportError:
        print("Warning: google.generativeai not available, falling back to OpenAI")
        PROVIDER = "openai"
    except Exception as e:
        print(f"Warning: Gemini configuration failed: {e}")
        PROVIDER = "openai"

if PROVIDER == "openai":
    try:
        from openai import OpenAI
    except ImportError:
        print("Warning: openai not available")

def _exp_backoff(attempt: int) -> float:
    base = 0.4
    jitter = random.random() * 0.1
    return base * (2 ** attempt) + jitter

def _lookup_cve_data(cve_id: str) -> Optional[Dict]:
    """Look up CVE data from National Vulnerability Database"""
    if not NVD_API_KEY:
        return None
    
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        headers = {"apiKey": NVD_API_KEY}
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("vulnerabilities"):
                vuln = data["vulnerabilities"][0]
                cve_data = vuln.get("cve", {})
                
                return {
                    "cvss_score": _extract_cvss_score(cve_data),
                    "severity": _extract_severity(cve_data),
                    "description": _extract_description(cve_data),
                    "published": cve_data.get("published", "Unknown"),
                    "modified": cve_data.get("lastModified", "Unknown")
                }
    except Exception as e:
        print(f"NVD API lookup failed for {cve_id}: {e}")
    
    return None

def _extract_cvss_score(cve_data: Dict) -> Optional[float]:
    """Extract CVSS score from CVE data"""
    try:
        metrics = cve_data.get("metrics", {})
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV3" in metrics and metrics["cvssMetricV3"]:
            return metrics["cvssMetricV3"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            return metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
    except:
        pass
    return None

def _extract_severity(cve_data: Dict) -> str:
    """Extract severity from CVE data"""
    try:
        metrics = cve_data.get("metrics", {})
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            return metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        elif "cvssMetricV3" in metrics and metrics["cvssMetricV3"]:
            return metrics["cvssMetricV3"][0]["cvssData"]["baseSeverity"]
    except:
        pass
    return "UNKNOWN"

def _extract_description(cve_data: Dict) -> str:
    """Extract description from CVE data"""
    try:
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "No description available")
    except:
        pass
    return "No description available"

def classify_incident(cleaned_input: str, entities: dict, context_data: dict, max_attempts: int = 5) -> dict:
    """
    Legacy wrapper for backward compatibility. Uses new classify_and_slots internally.
    """
    # Enrich with CVE data if available
    enriched_context = context_data.copy()
    cve_enrichment = {}
    
    # Look up CVE data for any CVE mentions in entities
    if entities.get('cve'):
        for cve_id in entities['cve'][:2]:  # Limit to first 2 CVEs
            cve_data = _lookup_cve_data(cve_id)
            if cve_data:
                cve_enrichment[cve_id] = cve_data
    
    if cve_enrichment:
        enriched_context['cve_details'] = cve_enrichment
    
    # Build context for new function
    kb_context = ""
    if enriched_context.get('cve_details'):
        kb_context += f"CVE Details: {enriched_context['cve_details']}\n"
    if enriched_context.get('conversation_history'):
        kb_context += f"Conversation History: {enriched_context['conversation_history']}\n"
    
    context = {"kb_context": kb_context}
    
    try:
        # Use new enhanced function
        result = classify_and_slots(cleaned_input, entities, context)
        return result
    except Exception as e:
        # Fallback to basic analysis
        return {
            "classification": "other",
            "confidence": 0.3,
            "reasoning": f"Analysis failed: {str(e)[:100]}",
            "candidates": [{"label": "other", "score": 0.3}],
            "missing_slots": ["technical_details"],
            "user_level": "novice"
        }

def _classify_with_gemini(incident: str, entities: dict, context: dict, max_attempts: int) -> dict:
    try:
        import google.generativeai as genai
    except ImportError:
        return {
            "classification": "other",
            "confidence": 0.3,
            "candidates": [{"label": "other", "score": 0.3}],
            "reasoning": "Analysis library unavailable - please provide more specific security details",
            "missing_slots": ["technical_details", "system_type"],
            "indicators": [],
            "severity": "low",
            "recommendations": ["Install required dependencies", "Provide more incident details"]
        }
    
    genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
    model = genai.GenerativeModel('gemini-2.5-flash')
    
    # Build conversation context
    conversation_history = context.get('conversation_history', '')
    previous_incidents = context.get('previous_incidents', [])
    enhanced_context = context.get('enhanced_context', {})
    
    context_str = ""
    if conversation_history:
        context_str += f"Previous discussion: {conversation_history}\n"
    if previous_incidents:
        recent = [f"- {inc.get('classification', 'Unknown')} ({inc.get('confidence', 0):.2f})" 
                 for inc in previous_incidents[-3:]]
        context_str += f"Recent incidents: {', '.join(recent)}\n"
    if enhanced_context:
        if enhanced_context.get('cve_details'):
            context_str += f"CVE context: {enhanced_context['cve_details']}\n"

    for attempt in range(max_attempts):
        try:
            prompt = f"""
Analyze this security incident report and provide MULTIPLE hypotheses following OWASP Top 10 framework.
Do NOT jump to attack conclusions without clear malicious indicators.

SECURITY CATEGORIES (OWASP-based):
1. injection - SQL injection, XSS, command injection (ONLY with clear malicious payloads)
2. broken_authentication - Login/session issues, credential problems
3. broken_access_control - Users accessing unauthorized functions/data
4. security_misconfiguration - Wrong settings, exposed services, deployment issues
5. vulnerable_component - Outdated libraries, known CVEs
6. sensitive_data_exposure - Unencrypted data, information leakage
7. logging_monitoring_issue - Missing logs, detection failures
8. ssrf - Server-side request forgery
9. phishing - Deceptive emails/websites
10. malware - Malicious software
11. dos - Denial of service attacks
12. other - Unclear or insufficient information

CLASSIFICATION RULES - BE CAUTIOUS:
• If only "missing table/column/config" → prefer "security_misconfiguration", NOT injection
• If "can't login" but no brute force evidence → "broken_authentication", NOT attack
• If "permission denied" for normal user → could be "broken_access_control" OR normal behavior
• Only use "injection" when clear payloads: quotes, OR 1=1, UNION SELECT, <script>, etc.
• When unclear → use "other" with LOW confidence and fill missing_slots

CONVERSATION CONTEXT:
{context_str}

INCIDENT DESCRIPTION: {incident}
ENTITIES FOUND: {entities}

Provide analysis in this exact JSON format:
{{
    "classification": "primary category from above list",
    "confidence": 0.XX,
    "candidates": [
        {{"label": "primary_category", "score": 0.XX}},
        {{"label": "alternative_category", "score": 0.XX}},
        {{"label": "third_possibility", "score": 0.XX}}
    ],
    "reasoning": "why these candidates, what evidence supports each",
    "missing_slots": ["app_name", "endpoint", "user_role", "timeline", "etc"],
    "indicators": ["specific", "evidence", "found"],
    "severity": "low|medium|high|critical",
    "recommendations": ["immediate", "actions"]
}}

Return 2-3 candidates ranked by likelihood. Be conversational and consider full context."""

            response = model.generate_content(prompt)
            
            if response.text:
                try:
                    # Try to parse JSON response
                    import json
                    import re
                    
                    # Extract JSON from response
                    json_match = re.search(r'\{.*\}', response.text, re.DOTALL)
                    if json_match:
                        result = json.loads(json_match.group())
                        
                        # Validate required fields
                        if all(key in result for key in ["classification", "confidence", "candidates"]):
                            # Ensure candidates is properly formatted
                            candidates = result.get("candidates", [])
                            if not candidates:
                                candidates = [{"label": result["classification"], "score": result["confidence"]}]
                            result["candidates"] = candidates
                            
                            return result
                
                except (json.JSONDecodeError, KeyError):
                    # Fallback to pattern matching if JSON parsing fails
                    pass
                
                # Fallback pattern matching for non-JSON responses
                text = response.text.lower()
                
                # Enhanced OWASP pattern matching
                candidates = []
                
                # Injection patterns
                injection_score = 0.0
                if any(x in text for x in ["sql injection", "sqli", "union select", "or 1=1", "xss", "cross-site scripting", "<script", "javascript injection", "command injection"]):
                    injection_score = 0.75 if any(x in text for x in ["union select", "or 1=1", "<script"]) else 0.60
                
                # Misconfiguration patterns  
                misconfig_score = 0.0
                if any(x in text for x in ["misconfiguration", "configuration", "exposed", "default", "missing table", "column", "deployment"]):
                    misconfig_score = 0.70
                
                # Authentication patterns
                auth_score = 0.0
                if any(x in text for x in ["authentication", "login", "credential", "session", "password"]):
                    auth_score = 0.65
                
                # Access control patterns
                access_score = 0.0
                if any(x in text for x in ["access", "authorization", "permission", "privilege"]):
                    access_score = 0.60
                
                # Build candidates list
                all_scores = [
                    ("injection", injection_score),
                    ("security_misconfiguration", misconfig_score),
                    ("broken_authentication", auth_score),
                    ("broken_access_control", access_score)
                ]
                
                # Add other patterns
                if any(x in text for x in ["phishing", "fake", "deceptive"]):
                    all_scores.append(("phishing", 0.70))
                if any(x in text for x in ["malware", "virus", "trojan"]):
                    all_scores.append(("malware", 0.70))
                if any(x in text for x in ["dos", "denial", "flood"]):
                    all_scores.append(("dos", 0.70))
                
                # Sort and take top 3
                all_scores.sort(key=lambda x: x[1], reverse=True)
                top_scores = [s for s in all_scores if s[1] > 0.0][:3]
                
                if not top_scores:
                    top_scores = [("other", 0.30)]
                
                candidates = [{"label": label, "score": score} for label, score in top_scores]
                primary = candidates[0]
                
                return {
                    "classification": primary["label"],
                    "confidence": primary["score"],
                    "candidates": candidates,
                    "reasoning": response.text[:200] + "..." if len(response.text) > 200 else response.text,
                    "missing_slots": ["more_details", "timeline", "system_type"],
                    "indicators": list(entities.get('ip', [])) + list(entities.get('url', [])) + list(entities.get('cve', [])),
                    "severity": "medium" if primary["score"] > 0.6 else "low",
                    "recommendations": ["Gather more details", "Monitor for patterns"]
                }
            
        except Exception as e:
            if attempt < max_attempts - 1:
                time.sleep(_exp_backoff(attempt))
                continue
            else:
                return {
                    "classification": "other",
                    "confidence": 0.3,
                    "candidates": [{"label": "other", "score": 0.3}],
                    "reasoning": f"Analysis failed after {max_attempts} attempts: {str(e)[:100]}",
                    "missing_slots": ["technical_details", "error_messages", "system_context"],
                    "indicators": [],
                    "severity": "low",
                    "recommendations": ["Provide clearer incident description", "Include technical details"]
                }
    
    return {
        "classification": "other",
        "confidence": 0.25,
        "candidates": [{"label": "other", "score": 0.25}],
        "reasoning": "Unable to analyze incident - need more specific security details",
        "missing_slots": ["incident_details", "system_info", "timeline"],
        "indicators": [],
        "severity": "low",
        "recommendations": ["Describe what happened specifically", "Include any error messages or technical indicators"]
    }

def _classify_with_openai(incident: str, entities: dict, context: dict, max_attempts: int) -> dict:
    try:
        from openai import OpenAI
        client = OpenAI()
        
        prompt = f"""Classify this cybersecurity incident:

Incident: {incident}
Entities: {entities}
Context: {context}

Respond with JSON: {{"incident_type": "category", "confidence": 0.0, "reason": "explanation"}}

Categories: SQL Injection, XSS, CSRF, Phishing, Denial of Service, Misconfiguration, Malware, Brute Force, Other"""
        
        for attempt in range(max_attempts):
            try:
                response = client.chat.completions.create(
                    model=OPENAI_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=300,
                    temperature=0.15,
                    timeout=15,
                )
                
                content = response.choices[0].message.content
                if content:
                    try:
                        result = json.loads(content)
                        if "incident_type" in result:
                            return result
                    except:
                        pass
                        
            except Exception as e:
                if attempt == max_attempts - 1:
                    return {
                        "incident_type": "Other",
                        "confidence": 0.3,
                        "reason": f"OpenAI failed: {str(e)[:50]}"
                    }
                time.sleep(_exp_backoff(attempt))
    except ImportError:
        return {
            "incident_type": "Other",
            "confidence": 0.3,
            "reason": "OpenAI library not installed"
        }

def classify_and_slots(user_text: str, entities: dict, context: dict) -> dict:
    """
    Enhanced incident classification with OWASP hypotheses approach and multi-turn support.
    
    Args:
        user_text: raw incident description from user
        entities: {"ip": [...], "url": [...], "cve": [...]} extracted IOCs
        context: {
            "kb_context": "...",                    # optional knowledge base / NVD snippet
            "conversation_context": "...",          # previous messages for multi-turn reasoning
            "user_confused": bool                   # flag for confused users
        }
    
    Returns:
        {
            "classification": str,          # main OWASP label, lower_snake_case
            "confidence": float,            # 0.0 - 1.0
            "reasoning": str,               # short explanation for analysts
            "candidates": [                 # ordered best → worst
                {"label": str, "score": float},
                ...
            ],
            "missing_slots": [str],         # e.g. ["app", "endpoint", "user"]
            "user_level": str               # "novice" | "intermediate" | "expert"
        }
    """
    kb_context = context.get("kb_context", "")
    conversation_context = context.get("conversation_context", "")
    user_confused = context.get("user_confused", False)
    
    prompt = _build_phase1_prompt(user_text, entities, kb_context, conversation_context, user_confused)
    
    try:
        if PROVIDER == "gemini":
            result = _call_gemini(prompt)
        else:
            result = _call_openai(prompt)
        
        return _normalize_slots_output(result)
        
    except Exception as e:
        # Fallback with basic heuristics
        return {
            "classification": "other",
            "confidence": 0.3,
            "reasoning": f"Classification failed: {str(e)[:100]}. Using basic heuristics.",
            "candidates": [{"label": "other", "score": 0.3}],
            "missing_slots": ["technical_details", "system_info", "timeline"],
            "user_level": "novice"
        }

def _build_phase1_prompt(user_text: str, entities: dict, kb_context: str, conversation_context: str = "", user_confused: bool = False) -> str:
    """
    Build comprehensive prompt for OWASP hypothesis classification with multi-turn context.
    """
    
    # Build conversation awareness section
    conversation_section = ""
    if conversation_context:
        conversation_section = f"""
PREVIOUS CONVERSATION:
{conversation_context}

IMPORTANT: Use the conversation history above to MAINTAIN YOUR CLASSIFICATION across turns unless NEW contradictory evidence appears.
If the user is adding details about the SAME incident, REFINE your confidence but KEEP the same classification.
Only CHANGE classification if the new message clearly describes a DIFFERENT type of incident.

CRITICAL: If the user explicitly says "this is [attack type]" or "it's [attack type]", RESPECT their statement and classify accordingly.
Examples of explicit statements you MUST respect:
- "this is sql injection" → classify as injection
- "i already said it's brute force" → classify as broken_authentication  
- "yes it's xss" → classify as injection
- "definitely misconfiguration" → classify as security_misconfiguration
DO NOT ignore or contradict explicit user statements about attack types.
"""
    
    # Build confusion awareness section
    confusion_section = ""
    if user_confused:
        confusion_section = """
USER STATUS: This user seems confused or uncertain. Be patient and ask ONE simple, clear question at a time.
"""
    
    prompt = f"""You are an expert cybersecurity incident responder. Analyze this security incident and provide a detailed assessment with actionable insights.
{conversation_section}{confusion_section}
CURRENT MESSAGE:
{user_text}

EXTRACTED INDICATORS:
IPs: {entities.get('ip', [])}
URLs: {entities.get('url', [])}
CVEs: {entities.get('cve', [])}

KNOWLEDGE BASE CONTEXT:
{kb_context if kb_context else "No additional context available"}

Your task is to:
1. Classify the incident using OWASP categories as HYPOTHESES (not final truth)
2. Provide specific, actionable reasoning
3. Identify exactly what information is missing
4. Ask targeted questions that will help resolve the incident

OWASP CATEGORIES:
- injection: SQL injection, XSS, command injection (ONLY with clear malicious payloads like OR 1=1, <script>, etc.)
- broken_authentication: Login/session/credential issues
- broken_access_control: Unauthorized access to functions/data
- security_misconfiguration: Wrong settings, missing tables, deployment issues
- vulnerable_component: Outdated software with known CVEs
- sensitive_data_exposure: Data leaks, unencrypted information
- logging_monitoring_issue: Missing/inadequate security logs
- ssrf: Server making unintended external requests
- phishing: Deceptive emails/websites
- malware: Malicious software
- dos: Service overload/unavailability
- other: Unclear/insufficient information

CLASSIFICATION RULES:
• For VAGUE symptoms like "table missing", "can't login", "error", "problem":
  - If confidence would be < 0.7, classify as "other" with LOW confidence (0.3-0.5)
  - List ALL possible causes in candidates (misconfiguration, injection, access control, human error, malware)
  - DO NOT pick one classification without evidence
  - Ask specific questions to determine root cause
  
• Only classify with confidence > 0.6 when you have EVIDENCE:
  - injection: Clear malicious payloads (OR 1=1, <script>, UNION SELECT, command injection syntax)
  - broken_authentication: Multiple failed logins, session hijacking, credential stuffing
  - broken_access_control: User accessing unauthorized resources, IDOR with proof
  - security_misconfiguration: Configuration files shown, deployment errors, wrong permissions
  
• ALWAYS acknowledge multiple possibilities for ambiguous symptoms
• Ask questions that distinguish between: attack vs. human error vs. system failure vs. configuration issue

USER LEVEL DETECTION:
• novice: Simple language, basic descriptions
• intermediate: Some technical terms, mentions specific errors
• expert: Technical jargon, logs, stack traces, CVE numbers, payload analysis

Provide ONLY valid JSON with this schema:
{{
    "classification": "primary_category",
    "confidence": 0.XX,
    "reasoning": "Specific explanation of why this classification fits and what evidence supports it",
    "candidates": [
        {{"label": "primary_category", "score": 0.XX}},
        {{"label": "alternative_category", "score": 0.XX}}
    ],
    "missing_slots": ["specific", "information", "needed"],
    "user_level": "novice|intermediate|expert",
    "next_questions": [
        "For VAGUE symptoms (table missing, error, problem): Ask to distinguish between attack/human error/system failure",
        "Did you or your team intentionally modify this? Any suspicious activity in logs? When did this happen - during deployment/update?",
        "For ATTACK scenarios: Which IP/user was involved? What endpoint was affected? Do you have logs?"
    ],
    "immediate_actions": [
        "What they should do right now",
        "How to gather more evidence"
    ]
}}

Be specific and actionable. Avoid generic responses."""
    
    return prompt

def _call_gemini(prompt: str, max_attempts: int = 4) -> dict:
    """
    Call Gemini API with JSON response format and retry logic.
    """
    model = genai.GenerativeModel(
        model_name=GEMINI_MODEL,
        generation_config={
            "response_mime_type": "application/json",
            "temperature": 0.1
        }
    )
    
    for attempt in range(max_attempts):
        try:
            response = model.generate_content(prompt)
            if response.text:
                # Parse JSON response
                result = json.loads(response.text)
                return result
        except json.JSONDecodeError as e:
            if attempt < max_attempts - 1:
                time.sleep(_exp_backoff(attempt))
                continue
            raise RuntimeError(f"Gemini returned invalid JSON after {max_attempts} attempts: {e}")
        except Exception as e:
            if attempt < max_attempts - 1:
                time.sleep(_exp_backoff(attempt))
                continue
            raise RuntimeError(f"Gemini API error after {max_attempts} attempts: {e}")
    
    raise RuntimeError(f"Gemini classification failed after {max_attempts} attempts")

def _call_openai(prompt: str, max_attempts: int = 4) -> dict:
    """
    Call OpenAI API with JSON response format and retry logic.
    """
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    
    for attempt in range(max_attempts):
        try:
            response = client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "You are an expert cybersecurity incident classifier. Respond only with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=1000
            )
            
            result = json.loads(response.choices[0].message.content)
            return result
            
        except json.JSONDecodeError as e:
            if attempt < max_attempts - 1:
                time.sleep(_exp_backoff(attempt))
                continue
            raise RuntimeError(f"OpenAI returned invalid JSON after {max_attempts} attempts: {e}")
        except Exception as e:
            if attempt < max_attempts - 1:
                time.sleep(_exp_backoff(attempt))
                continue
            raise RuntimeError(f"OpenAI API error after {max_attempts} attempts: {e}")
    
    raise RuntimeError(f"OpenAI classification failed after {max_attempts} attempts")

def _exp_backoff(attempt: int) -> float:
    """
    Exponential backoff for retries.
    """
    return min(2 ** attempt + random.uniform(0, 1), 30)

def _normalize_slots_output(raw: dict) -> dict:
    """
    Normalize and validate the LLM output to ensure consistent schema.
    """
    # Ensure required fields exist with defaults
    classification = raw.get("classification", "other").lower().replace(" ", "_").replace("-", "_")
    confidence = float(raw.get("confidence", 0.0))
    confidence = max(0.0, min(1.0, confidence))  # Clamp to [0, 1]
    
    reasoning = raw.get("reasoning", "No reasoning provided")
    if len(reasoning) > 500:
        reasoning = reasoning[:500] + "..."
    
    candidates = raw.get("candidates", [])
    if not candidates:
        # Build from classification + confidence if missing
        candidates = [{"label": classification, "score": confidence}]
    
    # Ensure candidates have proper format
    normalized_candidates = []
    for candidate in candidates[:3]:  # Limit to top 3
        label = candidate.get("label", "other").lower().replace(" ", "_").replace("-", "_")
        score = float(candidate.get("score", 0.0))
        score = max(0.0, min(1.0, score))
        normalized_candidates.append({"label": label, "score": score})
    
    missing_slots = raw.get("missing_slots", [])
    if not isinstance(missing_slots, list):
        missing_slots = []
    
    user_level = raw.get("user_level", "novice")
    if user_level not in ["novice", "intermediate", "expert"]:
        user_level = "novice"
    
    # Handle new fields
    next_questions = raw.get("next_questions", [])
    if not isinstance(next_questions, list):
        next_questions = []
    
    immediate_actions = raw.get("immediate_actions", [])
    if not isinstance(immediate_actions, list):
        immediate_actions = []
    
    return {
        "classification": classification,
        "confidence": confidence,
        "reasoning": reasoning,
        "candidates": normalized_candidates,
        "missing_slots": missing_slots,
        "user_level": user_level,
        "next_questions": next_questions,
        "immediate_actions": immediate_actions
    }

def classify(cleaned_input: str, entities: dict, context_data: dict) -> str:
    """Legacy wrapper returning just the classification"""
    result = classify_incident(cleaned_input, entities, context_data)
    return result.get("classification", "other")