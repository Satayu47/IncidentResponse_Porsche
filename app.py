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

# Copilot: Make the chatbot responses more useful and action-oriented.
#
# Current problems:
# - Too much meta text like "Other possibilities", "Beginner-friendly mode".
# - Not enough concrete "What you should do now".
#
# New behavior for templated_reply:
#
# 1) For every response with score >= THRESH_LOW:
#    - ALWAYS include a section:
#          **What you should do now (simple steps):**
#          - ...
#          - ...
#    - The steps must be SAFE, high-level triage, not destructive.
#
# 2) Remove or simplify noisy sections:
#    - Remove "🤔 Other Possibilities" and "🔍 Need More Info" headings.
#    - Instead, use one short line for alternatives if needed.
#
# 3) Keep this structure in the reply:
#    - Opening sentence (adapted to user_level).
#    - **Likely issue:** <label> with confidence.
#    - **What you should do now (simple steps):** bullet list (2–4 items).
#    - **Why I think this:** short rationale.
#    - Optionally: one line about other possibilities if candidates exist.
#    - Follow-up question (if score < THRESH_GO).
#
# 4) Do NOT change logic for:
#    - label, score, kb_present, followup calculation.
#    - Only change how the message text is composed.

def templated_reply(user_text: str, label: str, score: float, iocs: dict, rationale: str, kb_present: bool, followup: str|None, user_level: str = "novice", candidates: list = None):
    """
    Generate actionable, user-friendly incident response with concrete next steps.
    
    Focus on:
    - Clear likely issue
    - Concrete action steps (safe triage)
    - Brief explanation
    - Follow-up questions if needed
    """
    sig = []
    if iocs.get("ip"):  sig.append(f"ip={', '.join(iocs['ip'][:2])}")
    if iocs.get("url"): sig.append(f"url={', '.join(iocs['url'][:1])}")
    if iocs.get("cve"): sig.append(f"cve={', '.join(iocs['cve'][:2])}")
    signals = " · ".join(sig) if sig else "no indicators yet"

    import random
    parts = []
    
    # 1) Opening adapted to user level and confidence
    if score >= 0.7:
        if user_level == "expert":
            parts.append(random.choice(["Clear classification.", "High confidence read.", "Analysis complete."]))
        elif user_level == "intermediate":
            parts.append(random.choice(["Got a clear read on this.", "Pretty straightforward case.", "Clear classification here."]))
        else:  # novice
            parts.append(random.choice([
                "I've looked at what you described.",
                "Okay, I've analyzed your report.",
                "Alright, I've reviewed the details."
            ]))
    elif score >= 0.6:
        if user_level == "expert":
            parts.append(random.choice(["Working hypothesis.", "Probable classification.", "Likely scenario."]))
        elif user_level == "intermediate":
            parts.append(random.choice(["I have a working theory here.", "Got a probable classification."]))
        else:  # novice
            parts.append(random.choice([
                "I've looked at what you described.",
                "Okay, I have a pretty good idea of what's happening.",
                "I think I know what's going on here."
            ]))
    else:
        if user_level == "expert":
            parts.append(random.choice(["Low confidence.", "Insufficient data.", "Classification unclear."]))
        elif user_level == "intermediate":
            parts.append(random.choice(["This one's unclear to me.", "Not enough to work with here."]))
        else:  # novice
            parts.append(random.choice([
                "I'm having a bit of trouble understanding this one.",
                "This is a bit unclear to me right now.",
                "I need more information to help you properly."
            ]))
    
    # 2) Likely issue with confidence
    label_display = label.replace('_', ' ')
    if label == "other" and score < 0.6:
        parts.append(f"**Likely issue:** Unclear / needs more details (confidence ~{score:.2f})")
    else:
        parts.append(f"**Likely issue:** {label_display} (confidence ~{score:.2f})")
    
    # 3) Action steps - concrete, safe triage steps
    actions = []
    if score >= THRESH_LOW:
        if label in ("security_misconfiguration", "misconfig", "misconfiguration", "other"):
            actions = [
                "Ask your developer or IT team if there was a recent deployment, migration, or maintenance operation.",
                "Check if there's a backup or migration script that can recreate the missing table/resource.",
                "Avoid making manual database or configuration changes until someone reviews the situation.",
                "Check server logs around the time the issue appeared for any errors or warnings."
            ]
        elif label in ("injection", "sql_injection", "xss", "command_injection"):
            actions = [
                "Temporarily reduce exposure of the affected page or form if possible (disable or restrict access).",
                "Capture any suspicious input or payloads you saw - save screenshots or copy the exact text.",
                "Notify your security or development team immediately to review logs around the time of the incident.",
                "Do not attempt to 'fix' the input manually - preserve evidence for investigation."
            ]
        elif label in ("broken_authentication", "authentication_failures", "bruteforce"):
            actions = [
                "Force logout the affected user account and reset their password.",
                "Check if MFA is enabled for the account - if not, enable it now.",
                "Review login logs for the affected account and any unusual IP addresses or locations.",
                "Notify the security team if you see continued failed login attempts or unusual patterns."
            ]
        elif label in ("broken_access_control", "authorization_bypass", "idor"):
            actions = [
                "Temporarily disable or restrict access to the affected functionality if possible.",
                "Document exactly what the user was able to access that they shouldn't have.",
                "Notify your development team to review authorization checks for this resource.",
                "Check logs to see if other users may have exploited the same issue."
            ]
        elif label in ("sensitive_data_exposure", "crypto", "cryptographic_failures"):
            actions = [
                "Identify what sensitive data may have been exposed (passwords, credit cards, personal info, etc.).",
                "If credentials were exposed, force password resets for affected users immediately.",
                "Notify your security team and consider whether breach notification is required.",
                "Disable the insecure endpoint or communication channel until it can be properly secured."
            ]
        elif label in ("vulnerable_component", "cve"):
            actions = [
                "Identify the exact version of the vulnerable software component mentioned.",
                "Check if a security patch or updated version is available from the vendor.",
                "If a patch exists, prioritize applying it - especially if this CVE is actively exploited.",
                "If no patch exists yet, consider workarounds like disabling the feature or restricting access."
            ]
        elif label in ("malware", "ransomware"):
            actions = [
                "Immediately disconnect the affected system from the network to prevent spread.",
                "Do not attempt to clean or fix it yourself - preserve it for forensics.",
                "Notify your IT/security team immediately - this may require incident response procedures.",
                "If you have backups, verify they are clean before considering restoration."
            ]
        elif label in ("phishing", "social_engineering"):
            actions = [
                "Do not click any links or download any attachments from the suspicious message.",
                "Forward the phishing email to your IT/security team for analysis.",
                "If you already clicked a link or entered credentials, change your password immediately.",
                "Report this to your security team so they can warn other users and block the sender."
            ]
        else:
            # Generic safe actions for unknown scenarios
            actions = [
                "Document exactly what happened, including any error messages or unusual behavior.",
                "If possible, take screenshots or save logs showing the issue.",
                "Avoid making changes that might destroy evidence or make the problem worse.",
                "Contact your IT or security team for guidance on next steps."
            ]
        
        parts.append("\n**What you should do now (simple steps):**")
        for action in actions[:4]:  # Show top 4 actions
            parts.append(f"- {action}")
    
    # 4) Why I think this - brief rationale
    if rationale and score >= THRESH_LOW:
        # Clean up rationale to be more user-friendly
        why_text = rationale
        if len(why_text) > 200:
            why_text = why_text[:200] + "..."
        parts.append(f"\n**Why I think this:** {why_text}")
    
    # 5) Indicators if present
    if signals != "no indicators yet":
        parts.append(f"\n**Indicators found:** {signals}")
    
    if kb_present:
        parts.append("_(Plus: CVE vulnerability data was used to enrich this analysis)_")
    
    # 6) Other possibilities - compact single line
    if candidates and len(candidates) > 1:
        alt = [c for c in candidates if c.get("label", "").lower().replace(" ", "_") != label][:1]
        if alt:
            alt_label = alt[0].get("label", "unknown").replace("_", " ")
            alt_score = alt[0].get("score", 0.0)
            parts.append(f"\n_I'm also considering: **{alt_label}** (~{alt_score:.2f}), but I'd need more evidence to be sure._")
    
    # 7) Follow-up question if needed
    if followup and score < THRESH_GO:
        if user_level == "expert":
            parts.append(f"\n**Q:** {followup}")
        elif user_level == "intermediate":
            parts.append(f"\n**Quick question:** {followup}")
        else:  # novice
            parts.append(f"\n**To help me understand better:** {followup}")
            
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
            candidates_list = out.get("candidates", []) if out else []
            msg = templated_reply(
                user_text=user_text,
                label=label,
                score=score,
                iocs=iocs,
                rationale=rationale,
                kb_present=bool(kb_context),
                followup=followup if (followup and score < THRESH_GO) else None,
                user_level=user_level,
                candidates=candidates_list
            )
            st.markdown(msg)
            
            # Display enhanced Gemini features
            if out:
                # Show multiple candidates if available
                candidates = out.get("candidates", [])
                if len(candidates) > 1 and score < 0.85:
                    st.markdown("### Alternative Scenarios")
                    st.write("Also considered:")
                    for cand in candidates[1:3]:  # Show top 2 alternatives
                        cand_label = cand.get("label", "unknown")
                        cand_score = cand.get("score", 0)
                        if cand_score >= 0.3:
                            st.write(f"- **{cand_label.replace('_', ' ').title()}**: {cand_score:.0%} confidence")
                
                # Show immediate actions for high confidence
                immediate_actions = out.get("immediate_actions", [])
                if immediate_actions and score >= THRESH_GO:
                    st.markdown("### Immediate Actions")
                    for idx, action in enumerate(immediate_actions[:4], 1):
                        st.write(f"{idx}. {action}")
                
                # Show next questions for medium/low confidence
                next_questions = out.get("next_questions", [])
                if next_questions and score < THRESH_GO:
                    st.markdown("### Additional Information Needed")
                    st.write("To better assess this incident, please answer:")
                    for idx, question in enumerate(next_questions[:3], 1):
                        st.write(f"{idx}. {question}")

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

            # 6) Download and Phase 2 Response
            # Show if confidence is high enough, regardless of mapped category
            if st.session_state.phase1_output and score >= THRESH_GO:
                st.markdown("---")
                st.markdown("### Next Steps")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    import io
                    buf = io.BytesIO(json.dumps(st.session_state.phase1_output, indent=2).encode("utf-8"))
                    st.download_button(
                        "📄 Download Report",
                        data=buf,
                        file_name="incident_report.json",
                        mime="application/json",
                        help="Download incident classification report as JSON"
                    )
                
                with col2:
                    if st.button("▶️ View Response Plan", type="primary", help="See recommended response actions"):
                        st.session_state.show_phase2 = True
                
                # Show Phase 2 results if button was clicked
                if st.session_state.get("show_phase2", False):
                    from phase2_engine.core.runner import run_phase2_from_incident
                    
                    with st.spinner("Loading response playbook..."):
                        phase2_result = run_phase2_from_incident(
                            st.session_state.phase1_output,
                            dry_run=True  # Safe simulation mode
                        )
                        
                        if phase2_result["status"] == "success":
                            st.markdown("---")
                            st.markdown("### 📋 Recommended Response Actions")
                            st.info(f"**Playbook:** {phase2_result.get('playbook', 'Unknown')} - {phase2_result.get('description', '')}")
                            
                            # Group steps by phase
                            steps_by_phase = {}
                            for step in phase2_result["steps"]:
                                phase = step.get("phase", "unknown")
                                if phase not in steps_by_phase:
                                    steps_by_phase[phase] = []
                                steps_by_phase[phase].append(step)
                            
                            # Phase order and friendly names
                            phase_names = {
                                "preparation": "🔧 Preparation",
                                "detection_analysis": "🔍 Detection & Analysis",
                                "containment": "🛡️ Containment",
                                "eradication": "⚔️ Eradication",
                                "recovery": "🔄 Recovery",
                                "post_incident": "📊 Post-Incident"
                            }
                            
                            # Display steps grouped by phase
                            for phase_key in ["preparation", "detection_analysis", "containment", "eradication", "recovery", "post_incident"]:
                                if phase_key in steps_by_phase:
                                    phase_steps = steps_by_phase[phase_key]
                                    st.markdown(f"#### {phase_names.get(phase_key, phase_key.title())}")
                                    
                                    for step in phase_steps:
                                        with st.container():
                                            col_num, col_info = st.columns([1, 11])
                                            with col_num:
                                                st.markdown(f"**{step['step']}**")
                                            with col_info:
                                                st.markdown(f"**{step['name']}**")
                                                if step.get('ui_description'):
                                                    st.caption(step['ui_description'])
                                                else:
                                                    st.caption(step['message'])
                                    st.markdown("")
                            
                            # Reset button
                            if st.button("✕ Close Response Plan"):
                                st.session_state.show_phase2 = False
                                st.rerun()
                        else:
                            st.warning(f"⚠️ {phase2_result['message']}")
                            st.session_state.show_phase2 = False

    st.session_state.history.append({"role":"assistant","content":msg})