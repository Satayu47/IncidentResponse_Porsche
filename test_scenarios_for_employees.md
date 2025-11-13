# Employee Test Scenarios - Incident Response System
*Real-world situations any company employee might encounter*

## 🔍 **SCENARIO 1: Suspicious Login Activity**
**What happened:** "I got an email saying someone tried to log into my account from Russia 15 times last night. My password is the same one I've used for 3 years."

**Expected AI Result:** Brute Force Attack (High Confidence)
**Tests:** Entity extraction (geographic indicators), pattern recognition, security education

---

## 📧 **SCENARIO 2: Suspicious Email** 
**What happened:** "I received an email from 'IT Support' asking me to click a link to update my password. The email looks official but the sender address is weird: it-support@companyy.com (notice the extra 'y')"

**Expected AI Result:** Phishing Attack (High Confidence)  
**Tests:** Social engineering detection, domain spoofing, user education

---

## 💻 **SCENARIO 3: Weird Computer Behavior**
**What happened:** "My computer is running super slow today. There are pop-ups saying I won a prize and need to download something. Also, my antivirus keeps showing warnings about a file called 'invoice.exe' that I don't remember downloading."

**Expected AI Result:** Malware Infection (High Confidence)
**Tests:** Malware indicators, file analysis, system behavior

---

## 🌐 **SCENARIO 4: Website Problems** 
**What happened:** "I was trying to submit a form on our company website and it gave me a weird error message. Now when I go to the page, it shows a bunch of code and says something like 'script src=' with lots of symbols."

**Expected AI Result:** XSS Attack (Cross-Site Scripting) (High Confidence)
**Tests:** Web application security, code injection detection

---

## 💳 **SCENARIO 5: Database Error**
**What happened:** "I was searching for a customer in our system and typed their name, but instead of showing results, the screen showed a long list of ALL customers with their credit card numbers visible. This has never happened before."

**Expected AI Result:** SQL Injection Attack (High Confidence)  
**Tests:** Database security, data exposure, input validation

---

## 📱 **SCENARIO 6: Social Media Issue**
**What happened:** "Someone created a fake LinkedIn profile using my name and photo. They're messaging my coworkers asking for sensitive company information and claiming they're starting a new project."

**Expected AI Result:** Social Engineering/Impersonation Attack (High Confidence)
**Tests:** Identity theft, social engineering, insider threats

---

## 🔒 **SCENARIO 7: System Access Problem**
**What happened:** "I can't access any of our internal systems today. Other people in my department are having the same issue. We keep getting timeout errors and the pages won't load at all."

**Expected AI Result:** Denial of Service Attack (Medium-High Confidence)
**Tests:** Service availability, network attacks, business impact

---

## ⚙️ **SCENARIO 8: Configuration Issue**
**What happened:** "I accidentally found that I can access the HR database even though I work in Marketing. I can see everyone's salary information and personal details. This seems wrong - I shouldn't be able to see this."

**Expected AI Result:** Misconfiguration/Access Control Issue (High Confidence)
**Tests:** Access control, privilege escalation, system configuration

---

## 💔 **SCENARIO 9: Unclear/Vague Report**
**What happened:** "Something weird is happening with my computer. It's not working right. Can you help?"

**Expected AI Result:** Request for More Information (Smart Guidance System)
**Tests:** Natural language guidance, user education, clarification requests

---

## 🔄 **HOW TO TEST:**

1. **Copy and paste each scenario** into your incident response chat
2. **Watch for these indicators:**
   - 🔍 "Analyzing with Gemini AI..." message appears
   - ✅ "Gemini AI analysis complete!" confirmation  
   - High confidence scores (0.80+) for clear scenarios
   - Natural, helpful responses (not obviously AI-generated)
   - Professional Phase-2 JSON output with proper classification

3. **What makes a good result:**
   - **Fast response** (2-3 seconds)
   - **Accurate classification** of the security threat
   - **Helpful explanation** in plain English
   - **Professional handoff data** for security team
   - **CVE enrichment** when relevant vulnerabilities exist

4. **Test the smart guidance with:**
   - Scenario 9 (vague report) should trigger helpful questions
   - Misspelled words should still work (tests retry logic)
   - Very brief descriptions should get clarification requests

Your system should handle all of these like a professional security analyst who can explain complex threats in simple terms! 🎯