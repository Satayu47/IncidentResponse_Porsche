import time, json, io, os
from pathlib import Path
import streamlit as st
from src.extractor import extract_entities, extract_IOCs, detect_symptoms
from src.llm_adapter import classify_and_slots
from src.nvd import fetch_cve, mitre_url
from src.lc_retriever import build_inmemory_kb, format_retrieval_snippets

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

def templated_reply(user_text: str, label: str, score: float, iocs: dict, rationale: str, kb_present: bool, followup: str|None, user_level: str = "novice"):
    """
    Adapt tone and level of detail based on user_level.
    
    user_level can be:
      - "novice": user is non-technical, confused, no logs/payloads.
      - "intermediate": some technical terms, but not deep.
      - "expert": provides payloads, logs, CVEs, knows tools.
    
    Behavior:
    - For "novice":
        * Use friendly, reassuring language.
        * Explain things in simple terms.
        * Longer explanations are OK.
    - For "intermediate":
        * Balanced: clear but not too verbose.
    - For "expert":
        * Short, direct, technical.
    """
    sig = []
    if iocs.get("ip"):  sig.append(f"ip={', '.join(iocs['ip'][:2])}")
    if iocs.get("url"): sig.append(f"url={', '.join(iocs['url'][:1])}")
    if iocs.get("cve"): sig.append(f"cve={', '.join(iocs['cve'][:2])}")
    signals = " · ".join(sig) if sig else "no indicators yet"

    # Natural response variations
    import random
    
    # Different responses based on confidence AND user level
    if score >= 0.8:
        # High confidence responses - adapt by user_level
        if user_level == "expert":
            openings = [
                "Clear classification.",
                "Definitive read.",
                "High confidence assessment.",
                "Analysis complete."
            ]
            classification_intros = [
                "Classified as",
                "Identified:",
                "Category:",
                "Type:"
            ]
        elif user_level == "intermediate":
            openings = [
                "Got a clear read on this.",
                "Analysis shows high confidence.",
                "Pretty straightforward case.",
                "Clear classification here."
            ]
            classification_intros = [
                "This is",
                "Identified as",
                "We're looking at",
                "Classification:"
            ]
        else:  # novice
            openings = [
                "Alright, I've analyzed your report and I'm quite confident about what's happening here.",
                "Good news - I have a clear understanding of this incident.",
                "Okay, I've looked at everything you described and I'm pretty sure I know what this is.",
                "Got it. After reviewing the details, I can tell you what's going on."
            ]
            classification_intros = [
                "This is definitely",
                "I'm confident this is",
                "What you're dealing with is",
                "This appears to be"
            ]
        confidence_phrase = "high confidence"
        
    elif score >= 0.6:
        # Medium confidence responses - adapt by user_level
        if user_level == "expert":
            openings = [
                "Likely scenario identified.",
                "Working hypothesis:",
                "Probable classification.",
                "Best match based on indicators."
            ]
            classification_intros = [
                "Probably",
                "Likely",
                "Appears to be",
                "Most consistent with"
            ]
        elif user_level == "intermediate":
            openings = [
                "I have a working theory here.",
                "Based on the evidence, likely scenario is:",
                "Pretty good read, though want to confirm a few things.",
                "Got a probable classification."
            ]
            classification_intros = [
                "This is probably",
                "Most likely",
                "Looks like",
                "Appears to be"
            ]
        else:  # novice
            openings = [
                "Okay, I have a pretty good idea of what this is, but I'd like to confirm a few things first.",
                "I think I know what's happening here, but let me ask a couple questions to be sure.",
                "Got a good lead on this, but want to double-check some details.",
                "I have a working theory - just need to verify a few points."
            ]
            classification_intros = [
                "I believe this is",
                "This is probably",
                "My assessment is that this is",
                "Most likely we're dealing with"
            ]
        confidence_phrase = "medium confidence"
        
    elif score >= 0.5:
        # Fair confidence responses - adapt by user_level
        if user_level == "expert":
            openings = [
                "Tentative classification.",
                "Preliminary assessment.",
                "Initial read (low confidence).",
                "Working theory, needs validation."
            ]
            classification_intros = [
                "Possibly",
                "May be",
                "Could be",
                "Tentatively"
            ]
        elif user_level == "intermediate":
            openings = [
                "Got a tentative read on this.",
                "Here's my preliminary assessment.",
                "I have an idea, but low confidence.",
                "Initial analysis suggests this, though uncertain."
            ]
            classification_intros = [
                "This may be",
                "Could be looking at",
                "Possibly",
                "Tentatively classified as"
            ]
        else:  # novice
            openings = [
                "I'm not entirely sure about this one yet, but here's my best guess.",
                "This is a bit tricky to pin down, but I have a theory.",
                "I need more information to be confident, but here's what I'm thinking.",
                "Got it. Here's my assessment, though I'm not fully certain."
            ]
            classification_intros = [
                "This appears to be",
                "Looking like", 
                "Seems we're dealing with",
                "My initial assessment shows"
            ]
        confidence_phrase = "fairly confident"
        
    else:
        # Low confidence responses - adapt by user_level
        if user_level == "expert":
            openings = [
                "Insufficient data.",
                "Classification unclear.",
                "Low confidence read.",
                "Need more context."
            ]
            classification_intros = [
                "Unclear -",
                "Uncertain -",
                "Cannot classify:",
                "Ambiguous:"
            ]
        elif user_level == "intermediate":
            openings = [
                "Having trouble classifying this one.",
                "Not enough to work with here.",
                "This one's unclear to me.",
                "Need more details to classify this properly."
            ]
            classification_intros = [
                "Best guess is",
                "Might be looking at",
                "Could be",
                "Initial assessment suggests"
            ]
        else:  # novice
            openings = [
                "I'm having a hard time understanding what's going on here. Let me ask you some questions to get more clarity.",
                "This one's a bit unclear to me - I need more information to help you properly.",
                "Hmm, I'm not quite sure what we're dealing with yet. Can you provide more details?",
                "I'm struggling to classify this one - let's work together to figure it out."
            ]
            classification_intros = [
                "My best guess is",
                "I think this might be",
                "This could be",
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
            if user_level == "expert":
                followup_intros = ["Q:", "Clarify:", "Need:", "Confirm:"]
            elif user_level == "intermediate":
                followup_intros = ["Quick question -", "One thing -", "Need to know -", "Just checking -"]
            else:  # novice
                followup_intros = [
                    "I need to ask you something -",
                    "Can you help me understand -",
                    "One quick question -",
                    "I'd like to know -"
                ]
            parts.append(f"**{random.choice(followup_intros)}** {followup}")
    else:
        if score >= 0.7:
            if user_level == "expert":
                endings = ["Ready for escalation.", "Actionable.", "Proceed with response.", "Clear to escalate."]
            elif user_level == "intermediate":
                endings = [
                    "Should be good to escalate this.",
                    "Ready to pass this along.",
                    "Think we've got enough to move forward.",
                    "Confident enough to proceed."
                ]
            else:  # novice
                endings = [
                    "This looks clear enough that we can take action on it.",
                    "I'm confident enough in this assessment that you can proceed with the response steps.",
                    "We have a good understanding here - ready to move forward.",
                    "This is solid - you're good to escalate this to your security team."
                ]
        else:
            if user_level == "expert":
                endings = ["Current assessment.", "Working with available data.", "Need more context."]
            elif user_level == "intermediate":
                endings = [
                    "That's what I can determine so far.",
                    "Best assessment with current info.",
                    "Working with what we have here."
                ]
            else:  # novice
                endings = [
                    "This is the best I can figure out with what you've told me so far.",
                    "That's my assessment based on the information I have right now.",
                    "This is what I'm seeing, but I might need more details to be more certain."
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

            # 0) Check if this is a general security question (bypass incident pipeline)
            general_answer = answer_general_security_question(user_text)
            if general_answer:
                st.markdown(general_answer)
                st.session_state.history.append({"role":"assistant","content":general_answer})
                st.stop()  # Don't proceed to incident classification

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
            user_level = out.get("user_level", "novice") if out else "novice"
            msg = templated_reply(
                user_text=user_text,
                label=label,
                score=score,
                iocs=iocs,
                rationale=rationale,
                kb_present=bool(kb_context),
                followup=followup if (followup and score < THRESH_GO) else None,
                user_level=user_level
            )
            st.markdown(msg)
            
            # Display enhanced Gemini features
            if out:
                # Show multiple candidates if available
                candidates = out.get("candidates", [])
                if len(candidates) > 1 and score < 0.85:
                    st.markdown("### 🤔 Other Possibilities")
                    st.write("The system also considered these scenarios:")
                    for cand in candidates[1:3]:  # Show top 2 alternatives
                        cand_label = cand.get("label", "unknown")
                        cand_score = cand.get("score", 0)
                        if cand_score >= 0.3:
                            st.write(f"- **{cand_label.replace('_', ' ').title()}**: {cand_score:.0%} confidence")
                
                # Show immediate actions for high confidence
                immediate_actions = out.get("immediate_actions", [])
                if immediate_actions and score >= THRESH_GO:
                    st.markdown("### ⚡ Immediate Actions")
                    for idx, action in enumerate(immediate_actions[:4], 1):
                        st.write(f"{idx}. {action}")
                
                # Show next questions for medium/low confidence
                next_questions = out.get("next_questions", [])
                if next_questions and score < THRESH_GO:
                    st.markdown("### 🔍 Need More Info")
                    st.write("To better assess this incident, please answer:")
                    for idx, question in enumerate(next_questions[:3], 1):
                        st.write(f"{idx}. {question}")
                
                # Show user level detection
                user_level = out.get("user_level", "novice")
                if user_level == "expert":
                    st.info("💡 **Expert mode detected** - Providing technical details")
                elif user_level == "novice":
                    st.info("💡 **Beginner-friendly mode** - Providing step-by-step guidance")

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

            # 6) download JSON - only when confidence is high enough and not "other"
            if st.session_state.phase1_output and score >= THRESH_GO and label != "other":
                import io
                buf = io.BytesIO(json.dumps(st.session_state.phase1_output, indent=2).encode("utf-8"))
                st.download_button(
                    "📥 Download Phase-1 Output (JSON)",
                    data=buf,
                    file_name="phase1_output.json",
                    mime="application/json"
                )

    st.session_state.history.append({"role":"assistant","content":msg})