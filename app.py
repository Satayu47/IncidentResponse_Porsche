"""
Incident Response ChatOps - Phase 1 + Phase 2 (FULLY CONNECTED)
================================================================

This application provides:
✅ AI-powered incident classification using OWASP Top 10:2025
✅ Multi-hypothesis analysis with confidence scoring
✅ User-level adaptation (novice/intermediate/expert)
✅ Entity extraction (IPs, URLs, CVEs) + NVD enrichment
✅ Phase-1 → Phase-2 handoff via structured JSON
✅ Automated response playbook execution (Phase-2 engine)
✅ Complete SOAR pipeline (Incident → Classification → Response)

Phase-2 Integration:
- Connected to friend's IR-SANDBOX playbook engine
- 10 OWASP playbooks (A01-A10) covering all attack categories
- Dry-run simulation mode for safe execution
- Real-time response plan display with incident response phases

Architecture:
Phase 1 (This file) → JSON handoff → Phase 2 (phase2_engine/) → Automated Response
"""

import time, json, io, os
from pathlib import Path
import streamlit as st
from src.extractor import extract_entities, extract_IOCs, detect_symptoms
from src.llm_adapter import classify_and_slots
from src.nvd import fetch_cve, mitre_url
from src.lc_retriever import build_inmemory_kb, format_retrieval_snippets
from src.explicit_detector import force_classification_if_explicit, detect_explicit_attack
from src.dialogue_state import DialogueContext, DialogueState, update_context

# ✅ Phase 2 integration - FROM FRIEND'S IR-SANDBOX REPO (NOW FULLY CONNECTED)
from phase2_engine.core.runner import run_phase2_from_incident

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


def build_conversation_context(max_turns: int = 6) -> str:
    """
    Build a short conversation window (last N user/assistant messages).
    This is passed into classify_and_slots so the LLM sees multi-turn context.
    """
    if "history" not in st.session_state:
        return ""
    turns = [m for m in st.session_state.history if m["role"] in ("user", "assistant")]
    if not turns:
        return ""
    window = turns[-max_turns:]
    return "\n".join(f"{m['role']}: {m['content']}" for m in window)


def detect_user_confusion(text: str) -> bool:
    """
    Lightweight confusion detector for messy human chat:
    detects 'i don't know', '??', 'what is that', etc.
    """
    t = text.lower()
    patterns = [
        "i dont know", "i don't know", "idk",
        "dont know", "don't know",
        "what is that", "what is this",
        "what is endpoint", "what is an endpoint",
        "อะไรคือ", "คืออะไร", "งง", "ไม่เข้าใจ",
        "huh?", "???", "??", "wtf"
    ]
    return any(p in t for p in patterns)


def answer_general_security_question(user_text: str) -> str | None:
    """
    Handle general security questions directly without running incident classification.
    Returns a best-practice answer for prevention/explanation questions, or None.
    """
    text_lower = user_text.lower()
    
    # Detect general "how to prevent" or "what is" questions
    prevention_keywords = ["how to prevent", "how can i prevent", "how do i prevent", 
                          "prevent", "protection", "how to protect", "how to secure"]
    what_is_keywords = ["what is", "what are", "explain", "tell me about"]
    
    is_prevention = any(kw in text_lower for kw in prevention_keywords)
    is_what_is = any(kw in text_lower for kw in what_is_keywords)
    
    if not (is_prevention or is_what_is):
        return None
    
    # Brute force / authentication attacks
    if "brute" in text_lower or "brute force" in text_lower or "bruteforce" in text_lower:
        return """## 🛡️ Preventing Brute Force Attacks

**Best Practices:**

1. **Account Lockout Policy**
   - Lock account after 5-10 failed login attempts
   - Temporary lockout (15-30 minutes) or require admin unlock

2. **Rate Limiting**
   - Limit login attempts per IP address
   - Use CAPTCHA after 3 failed attempts

3. **Multi-Factor Authentication (MFA)**
   - Require second authentication factor
   - Google Authenticator, SMS codes, hardware tokens

4. **Strong Password Policy**
   - Minimum 12+ characters
   - Require mix of uppercase, lowercase, numbers, symbols
   - Check against common password lists

5. **Monitoring & Alerts**
   - Log all failed login attempts with IP addresses
   - Alert security team on suspicious patterns
   - Monitor for distributed attacks from multiple IPs

6. **Delay Responses**
   - Add progressive delays after failed attempts
   - Makes automated attacks impractical

**Example (Python/Flask):**
```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit: 5 attempts/minute
def login():
    # Login logic here
    pass
```"""
    
    # DDoS prevention
    if "ddos" in text_lower or "dos" in text_lower or "denial of service" in text_lower:
        return """## 🛡️ Preventing DDoS (Denial of Service) Attacks

**Best Practices:**

1. **Use CDN & DDoS Protection Services**
   - Cloudflare, AWS Shield, Akamai
   - Absorb traffic spikes and filter malicious requests

2. **Rate Limiting**
   - Limit requests per IP/user
   - Implement at application and network layers

3. **Network Architecture**
   - Load balancers to distribute traffic
   - Auto-scaling to handle legitimate traffic spikes
   - Anycast network routing

4. **Firewall Rules**
   - Block suspicious traffic patterns
   - Geo-blocking if appropriate
   - IP blacklisting for known attackers

5. **Monitoring & Alerting**
   - Real-time traffic monitoring
   - Anomaly detection for unusual patterns
   - Automatic traffic rerouting

6. **Infrastructure Redundancy**
   - Multiple servers across different locations
   - Failover capabilities"""
    
    # SQL Injection prevention
    if "sql injection" in text_lower or "sqli" in text_lower:
        return """## 🛡️ Preventing SQL Injection

**Best Practices:**

1. **Use Parameterized Queries (Prepared Statements)**
   - Never concatenate user input directly into SQL queries
   - Use placeholders: `SELECT * FROM users WHERE id = ?`

2. **Input Validation**
   - Whitelist allowed characters
   - Validate data types (numbers should be numbers)
   - Limit input length

3. **Least Privilege**
   - Database users should have minimal necessary permissions
   - Never use admin accounts for application queries

4. **Use ORM Frameworks**
   - Frameworks like SQLAlchemy, Hibernate, Entity Framework handle escaping

5. **Web Application Firewall (WAF)**
   - Can block common SQL injection patterns

**Example (Python):**
```python
# ❌ BAD - Vulnerable
query = f"SELECT * FROM users WHERE name = '{user_input}'"

# ✅ GOOD - Safe
query = "SELECT * FROM users WHERE name = ?"
cursor.execute(query, (user_input,))
```"""

    # XSS prevention
    elif "xss" in text_lower or "cross-site scripting" in text_lower or "cross site scripting" in text_lower:
        return """## 🛡️ Preventing Cross-Site Scripting (XSS)

**Best Practices:**

1. **Output Encoding**
   - Encode all user data before displaying in HTML
   - Use proper encoding for context (HTML, JavaScript, URL)

2. **Content Security Policy (CSP)**
   - HTTP header that restricts where scripts can load from
   - `Content-Security-Policy: default-src 'self'`

3. **Input Validation**
   - Reject inputs with `<script>`, `javascript:`, `on*=` patterns
   - Whitelist safe characters

4. **Use Security Libraries**
   - DOMPurify for JavaScript
   - Bleach for Python
   - OWASP Java Encoder

5. **HTTPOnly Cookies**
   - Prevents JavaScript from accessing session cookies

**Example:**
```javascript
// ❌ BAD - Vulnerable
div.innerHTML = userInput;

// ✅ GOOD - Safe
div.textContent = userInput;
```"""

    # Phishing prevention
    elif "phishing" in text_lower:
        return """## 🛡️ Preventing Phishing Attacks

**For Users:**

1. **Check Email Sender**
   - Verify sender email address carefully
   - Look for typos or strange domains

2. **Hover Before Clicking**
   - Hover over links to see real URL
   - Look for suspicious domains

3. **Never Share Credentials**
   - Legitimate companies won't ask for passwords via email
   - Go directly to website, don't click email links

4. **Enable MFA**
   - Multi-Factor Authentication protects even if password is stolen

5. **Report Suspicious Emails**
   - Forward to IT/security team

**For Organizations:**

1. **Email Authentication** (SPF, DKIM, DMARC)
2. **Security Awareness Training**
3. **Email Filtering** and anti-phishing tools
4. **Regular Phishing Simulations**
5. **Report Button** in email clients"""

    # Malware prevention
    elif "malware" in text_lower or "virus" in text_lower:
        return """## 🛡️ Preventing Malware Infections

**Best Practices:**

1. **Keep Software Updated**
   - Enable automatic updates for OS and applications
   - Patch vulnerabilities promptly

2. **Use Antivirus/EDR**
   - Keep antivirus software updated
   - Enterprise: Use Endpoint Detection & Response (EDR)

3. **Email Security**
   - Don't open attachments from unknown senders
   - Be suspicious of .exe, .zip, .scr files

4. **Download Safety**
   - Only download from official sources
   - Verify checksums for important files

5. **Network Security**
   - Use firewall
   - Segment networks
   - Monitor outbound connections

6. **Backup Regularly**
   - Offline backups protect against ransomware
   - Test restore procedures"""

    # DDoS prevention
    elif "ddos" in text_lower or "dos attack" in text_lower or "denial of service" in text_lower:
        return """## 🛡️ Preventing DDoS Attacks

**Best Practices:**

1. **Use CDN/DDoS Protection**
   - Cloudflare, Akamai, AWS Shield
   - Absorb and filter malicious traffic

2. **Rate Limiting**
   - Limit requests per IP address
   - Throttle suspicious traffic

3. **Network Architecture**
   - Distribute servers geographically
   - Use load balancers
   - Overprovision bandwidth

4. **Monitoring & Alerts**
   - Detect traffic anomalies early
   - Automated response playbooks

5. **Blackhole Routing**
   - Drop traffic from attacking IPs
   - Use BGP blackholing for large attacks"""

    # Authentication best practices
    elif "authentication" in text_lower or "password" in text_lower or "login" in text_lower:
        return """## 🛡️ Authentication Security Best Practices

**Best Practices:**

1. **Multi-Factor Authentication (MFA)**
   - Require 2FA/MFA for all accounts
   - Use authenticator apps, not SMS when possible

2. **Strong Password Policy**
   - Minimum 12+ characters
   - Complexity requirements
   - Password managers encouraged

3. **Account Lockout**
   - Lock after 5-10 failed attempts
   - Implement CAPTCHA

4. **Session Management**
   - Secure, HTTPOnly, SameSite cookies
   - Session timeout after inactivity
   - Regenerate session ID after login

5. **Password Storage**
   - Use bcrypt, Argon2, or scrypt
   - Never store plaintext passwords
   - Salt all passwords

6. **Monitoring**
   - Log failed login attempts
   - Alert on suspicious patterns (brute force)"""

    return None  # Not a general security question

REPORT_CATEGORY_MAP = {
    "sql_injection": "Injection Attack",
    "xss": "Injection Attack",
    "ssrf": "Injection Attack",
    "rce": "Injection Attack",
    "injection": "Injection Attack",
    "bruteforce": "Denial of Service",
    "dos": "Denial of Service",
    "broken_authentication": "Denial of Service",
    "broken_access_control": "Broken Access Control",
    "sensitive_data_exposure": "Cryptographic Failures",
    "security_misconfiguration": "Misconfiguration",
    "misconfig": "Misconfiguration",
    "vulnerable_component": "Vulnerable Components",
    "malware": "Malware",
    "phishing": "Phishing",
    "other": "Other"
}

st.set_page_config(
    page_title="Incident Response Assistant", 
    layout="wide", 
    page_icon="🛡️"
)

st.title("🛡️ Incident Response Assistant")
st.caption("OWASP Top 10:2025 Classification • Phase-1 & Phase-2 Integration")

if "history" not in st.session_state:
    greetings = [
        "Hi! Describe the security incident you're investigating.",
        "Hello. What incident are you looking into?",
        "What security issue can I help you classify?"
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
if "dialogue_ctx" not in st.session_state:
    st.session_state.dialogue_ctx = DialogueContext()

def templated_reply(
    user_text: str,
    label: str,
    score: float,
    iocs: dict,
    rationale: str,
    kb_present: bool,
    followup: str | None,
    user_level: str = "intermediate",
    candidates: list = None,
    user_confused: bool = False
):
    """
    Generate balanced Phase-1 analysis response.
    
    Adapts tone to user level while keeping responses:
    - Not too long (3-5 paragraphs max)
    - Not too short (still informative)
    - Easy to read in chat history
    """
    parts = []

    # ---- 1) Short, user-level-friendly opening ----
    nice_label = label.replace("_", " ")

    if user_confused:
        opening = "Let's work through this step by step."
    elif user_level == "novice":
        opening = "Analysis result:"
    elif user_level == "expert":
        opening = "Classification:"
    else:
        opening = "Assessment:"

    parts.append(opening)

    # ---- 2) Classification + confidence ----
    nice_label_formatted = nice_label.title()
    
    if score >= 0.8:
        conf_text = "High confidence"
    elif score >= 0.6:
        conf_text = "Medium confidence"
    else:
        conf_text = "Low confidence"

    parts.append(f"**Type:** {nice_label_formatted} ({conf_text}, {int(score*100)}%)")

    # ---- 3) Why ----
    max_len = 380
    clean_rationale = rationale.strip() if rationale else ""
    if len(clean_rationale) > max_len:
        clean_rationale = clean_rationale[:max_len].rsplit(" ", 1)[0] + "…"

    if clean_rationale:
        parts.append(f"**Why:** {clean_rationale}")
    else:
        parts.append("**Why:** Based on the patterns and keywords in your description.")

    # ---- 4) Indicators ----
    sig_bits = []
    if iocs.get("ip"):
        sig_bits.append(f"{len(iocs['ip'])} IP(s)")
    if iocs.get("url"):
        sig_bits.append(f"{len(iocs['url'])} URL(s)")
    if iocs.get("cve"):
        sig_bits.append(f"{len(iocs['cve'])} CVE(s)")

    if sig_bits:
        parts.append("**Found:** " + ", ".join(sig_bits))

    # ---- 5) Optional follow-up when needed ----
    if followup:
        parts.append(f"**Need to know:** {followup}")

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
        # Show spinner while processing
        with st.spinner("Processing..."):
            t0 = time.perf_counter()
            
            # Detect conversation type
            text_lower = user_text.lower()
            
            # Detect if this is a general security question
            is_general_question = any(p in text_lower for p in [
                "how to prevent", "how can i prevent", "what is", "explain", "tell me about"
            ])
            
            # Detect explicit override (user names the attack)
            explicit_attack, explicit_conf = detect_explicit_attack(user_text)
            explicit_override = explicit_attack is not None

            # 0) Check if this is a general security question (bypass incident pipeline)
            general_answer = answer_general_security_question(user_text)
            if general_answer:
                st.markdown(general_answer)
                st.session_state.history.append({"role":"assistant","content":general_answer})
                # Update dialogue state for general question
                ctx = st.session_state.dialogue_ctx
                ctx.state = DialogueState.GENERAL_QUESTION
                ctx.turns += 1
                st.stop()  # Don't proceed to incident classification

            # Track if the user seems confused (for tone adaptation)
            user_confused = detect_user_confusion(user_text)

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

            # 2.5) Multi-turn conversation context (last few messages)
            conversation_context = build_conversation_context(max_turns=6)

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
                    
                    # Pass multi-turn context into LLM
                    extra_ctx = {
                        "kb_context": kb_context,
                        "conversation_context": conversation_context,
                        "user_confused": user_confused,
                    }
                    gemini_result = classify_and_slots(user_text, entities_dict, extra_ctx)
                    
                    # ✅ FORCE CLASSIFICATION if user explicitly names an attack
                    gemini_result = force_classification_if_explicit(user_text, gemini_result)
                    
                    # Store full Gemini response in session
                    st.session_state.gemini_full_response = gemini_result
                    
                    # Convert to expected format
                    out = {
                        "label": gemini_result.get("classification", "other").lower().replace(" ", "_").replace("-", "_"),
                        "score": gemini_result.get("confidence", 0.0),
                        "rationale": gemini_result.get("reasoning", ""),
                        "evidence": entities_dict.get("ip", []) + entities_dict.get("url", []) + entities_dict.get("cve", []),
                        "missing": gemini_result.get("missing_slots", []),
                        "user_level": gemini_result.get("user_level", "novice"),
                        "next_questions": gemini_result.get("next_questions", []),
                        "immediate_actions": gemini_result.get("immediate_actions", []),
                        "candidates": gemini_result.get("candidates", [])
                    }
                    st.session_state.last_input_cache[cache_key] = out
                    st.success("✅ Analysis complete")
                    
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

            # Extract user level and candidates
            user_level = out.get("user_level", "novice") if out else "novice"
            candidates_list = out.get("candidates", []) if out else []

            # 5) Update dialogue context
            asked_followup = followup is not None
            
            ctx = update_context(
                ctx=st.session_state.dialogue_ctx,
                user_text=user_text,
                label=label,
                confidence=score,
                user_level=user_level,
                candidates=candidates_list,
                asked_followup=asked_followup,
                is_general_question=is_general_question,
                explicit_override=explicit_override,
                thresh_low=THRESH_LOW,
                thresh_go=THRESH_GO,
            )
            st.session_state.dialogue_ctx = ctx
            
            # 6) Conditional response based on dialogue state
            # If state is CONFIRMED or READY_FOR_PHASE2, don't spam with more questions
            if ctx.state in {DialogueState.INCIDENT_CONFIRMED, DialogueState.READY_FOR_PHASE2}:
                followup_for_reply = None
            else:
                followup_for_reply = followup
            
            # Check dialogue state to determine what to show
            # GATHERING_INFO or CLARIFYING → Only ask questions
            # INCIDENT_SUSPECTED → Show tentative classification + ask for confirmation
            # INCIDENT_CONFIRMED/READY_FOR_PHASE2 → Full classification
            
            from src.dialogue_state import DialogueState
            
            if ctx.state == DialogueState.GATHERING_INFO or score < THRESH_LOW:
                # First turn: ask for more info
                clarification_msgs = []
                
                # Simple acknowledgment
                clarification_msgs.append("Understood. Need additional details to classify this.")
                
                if user_confused:
                    clarification_msgs.append("Let's break it down.")
                elif user_level == "novice":
                    clarification_msgs.append("Please provide more information about what happened.")
                elif user_level == "expert":
                    clarification_msgs.append("Need technical details for accurate classification.")
                else:
                    clarification_msgs.append("More context needed.")
                
                if followup_for_reply:
                    clarification_msgs.append(f"**Question:** {followup_for_reply}")
                else:
                    # Generic request
                    if label == "other":
                        clarification_msgs.append("**Question:** What kind of security issue is this?")
                    else:
                        clarification_msgs.append("**Question:** Which system was affected and what happened?")
                
                # Show technical clues if found
                sig_bits = []
                if iocs.get("ip"): sig_bits.append("IP found")
                if iocs.get("url"): sig_bits.append("URL found")
                if iocs.get("cve"): sig_bits.append("CVE found")
                if sig_bits:
                    clarification_msgs.append("(" + ", ".join(sig_bits) + ")")
                
                msg = "\n\n".join(clarification_msgs)
                
            elif ctx.state == DialogueState.INCIDENT_SUSPECTED:
                # Second turn: tentative classification
                msg = f"""Based on the information provided:

**Likely classification:** {label.replace('_', ' ').title()} (preliminary)

**Reasoning:** {rationale}
"""
                if followup_for_reply:
                    msg += f"\n\n**Additional information needed:** {followup_for_reply}"
                
            else:
                # INCIDENT_CONFIRMED or READY_FOR_PHASE2: Full classification response
                msg = templated_reply(
                    user_text=user_text,
                    label=label,
                    score=score,
                    iocs=iocs,
                    rationale=rationale,
                    kb_present=bool(kb_context),
                    followup=followup_for_reply,
                    user_level=user_level,
                    candidates=candidates_list,
                    user_confused=user_confused
                )
            
            # This is the "chat" part that appears in the conversation history
            st.markdown(msg)

    st.session_state.history.append({"role":"assistant","content":msg})

    # Prepare Phase-1 handoff JSON and category mapping
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
        "timestamp_ms": round((time.perf_counter() - t0) * 1000, 1),
    }

# ===============================
# Always-visible Phase-1 summary + Phase-2
# (Outside the 'if user_text:' block so it persists across reruns)
# ===============================
if st.session_state.get("phase1_output"):
    p1 = st.session_state.phase1_output
    
    # ---------------- SUMMARY CARD ----------------
    st.markdown("---")
    st.subheader("Current Assessment")
    
    nice_label = p1['incident_type'].replace('_', ' ').title()
    conf_pct = int(p1['confidence'] * 100)
    
    col1, col2 = st.columns([2, 1])
    with col1:
        st.write(f"**Type:** {nice_label}")
    with col2:
        if conf_pct >= 70:
            st.write(f"**Confidence:** High ({conf_pct}%)")
        elif conf_pct >= 60:
            st.write(f"**Confidence:** Medium ({conf_pct}%)")
        else:
            st.write(f"**Confidence:** Low ({conf_pct}%)")
    
    # Indicators
    indicators = []
    if p1['iocs'].get("ip"):
        indicators.append(f"{len(p1['iocs']['ip'])} IP(s)")
    if p1['iocs'].get("url"):
        indicators.append(f"{len(p1['iocs']['url'])} URL(s)")
    if p1.get('related_CVEs'):
        indicators.append(f"{len(p1['related_CVEs'])} CVE(s)")
    
    if indicators:
        st.write("**Indicators:** " + ", ".join(indicators))
    
    # ---------------- PHASE-2 BUTTON ----------------
    ctx = st.session_state.dialogue_ctx
    
    if ctx.is_ready_for_phase2(thresh=THRESH_GO):
        st.markdown("---")
        st.subheader("Automated Response")
        
        if st.button("Generate Response Plan", type="primary", key="phase2_trigger"):
            with st.spinner("Generating response plan..."):
                try:
                    phase2_result = run_phase2_from_incident(p1, dry_run=True)
                    
                    if phase2_result["status"] == "success":
                        st.success("✅ Response plan generated successfully")
                        
                        playbook_name = phase2_result.get('playbook', 'Unknown').replace('_', ' ').title()
                        st.info(f"**Playbook:** {playbook_name}")
                        st.caption(phase2_result.get('description', ''))
                        
                        # Group steps by phase
                        steps_by_phase = {}
                        for step in phase2_result["steps"]:
                            phase = step.get("phase", "unknown")
                            if phase not in steps_by_phase:
                                steps_by_phase[phase] = []
                            steps_by_phase[phase].append(step)
                        
                        # Phase order and friendly names with emojis
                        phase_names = {
                            "preparation": "🛡️ Preparation",
                            "detection_analysis": "🔍 Detection & Analysis",
                            "containment": "⚠️ Containment",
                            "eradication": "🧹 Eradication",
                            "recovery": "♻️ Recovery",
                            "post_incident": "📋 Post-Incident Review"
                        }
                        
                        # Display steps grouped by phase
                        for phase_key in ["preparation", "detection_analysis", "containment", "eradication", "recovery", "post_incident"]:
                            if phase_key in steps_by_phase:
                                phase_steps = steps_by_phase[phase_key]
                                st.markdown(f"### {phase_names.get(phase_key, phase_key.title())}")
                                
                                for step in phase_steps:
                                    with st.container():
                                        col_num, col_info = st.columns([1, 11])
                                        with col_num:
                                            st.markdown(f"**Step {step['step']}**")
                                        with col_info:
                                            st.markdown(f"**{step['name']}**")
                                            if step.get('ui_description'):
                                                st.caption(step['ui_description'])
                                            else:
                                                st.caption(step['message'])
                                st.markdown("")
                    else:
                        st.warning(f"⚠️ Response plan could not be generated: {phase2_result.get('message', 'Unknown error')}")
                
                except Exception as e:
                    st.error("❌ Failed to generate response plan")
                    st.exception(e)
    
    # ---------------- JSON EXPANDER (always show for audit) ----------------
    st.markdown("---")
    with st.expander("⚙️ Technical Details (for audit & review)"):
        st.json(p1)
        
        if p1.get('related_CVEs'):
            st.markdown("**CVE Links:**")
            for c in p1['related_CVEs'][:5]:
                st.markdown(f"- [{c}]({mitre_url(c)})")
        
        # Download button
        buf = io.BytesIO(json.dumps(p1, indent=2).encode("utf-8"))
        st.download_button(
            "Download JSON",
            data=buf,
            file_name="incident_report.json",
            mime="application/json",
        )