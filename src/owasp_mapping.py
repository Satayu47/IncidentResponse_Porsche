# OWASP Top 10 Follow-up Question Mapping
# Used to differentiate between similar OWASP categories when confidence scores are close

FOLLOWUP_OWASP = {
    "injection_vs_security_misconfiguration": 
        "Did this start after someone changed configuration or deployed a new version, "
        "or only when certain strange input is sent to the application?",

    "injection_vs_broken_authentication":
        "Does the error only appear when someone tries weird/invalid input, "
        "or does it happen even with normal, correct credentials?",

    "broken_authentication_vs_broken_access_control":
        "Is the problem about logging in (username/password/session), "
        "or about accessing functions/data that the user should not see?",

    "security_misconfiguration_vs_vulnerable_component":
        "Did anything change in configuration recently, or is it about using an outdated library/software version?",

    "broken_access_control_vs_security_misconfiguration":
        "Can normal users access things they shouldn't, or is it about wrong system settings/exposed services?",

    "vulnerable_component_vs_injection":
        "Is this about outdated software with known vulnerabilities (CVEs), "
        "or about malicious input being processed by the application?",

    "sensitive_data_exposure_vs_security_misconfiguration":
        "Is sensitive information being leaked/exposed, or are system settings configured incorrectly?",

    "logging_monitoring_issue_vs_security_misconfiguration":
        "Are logs missing/inadequate for detecting issues, or are security settings configured wrong?",

    "ssrf_vs_injection":
        "Is the server making requests to unintended external resources, "
        "or is malicious input being processed internally?",

    "phishing_vs_broken_authentication":
        "Are users being tricked by fake emails/websites, or are there legitimate login/session problems?",

    "malware_vs_vulnerable_component":
        "Is malicious software detected, or is this about outdated components with security flaws?",

    "dos_vs_security_misconfiguration":
        "Is someone intentionally overwhelming the system, or is it slow due to wrong settings?",

    "other_vs_any": 
        "Could you provide more specific details about what happened? "
        "For example: error messages, which system/application, what the user was trying to do, "
        "and any suspicious IP addresses or unusual behavior you noticed?"
}

def get_followup_question(primary_label: str, alternative_label: str) -> str:
    """Get appropriate follow-up question for OWASP category disambiguation."""
    
    # Sort labels to ensure consistent mapping
    labels = sorted([primary_label, alternative_label])
    key = f"{labels[0]}_vs_{labels[1]}"
    
    # Try exact match first
    if key in FOLLOWUP_OWASP:
        return FOLLOWUP_OWASP[key]
    
    # Try with 'other' if one of them is 'other'
    if 'other' in labels:
        return FOLLOWUP_OWASP["other_vs_any"]
    
    # Fallback to generic clarification
    return (f"I see this could be either {primary_label.replace('_', ' ')} or {alternative_label.replace('_', ' ')}. "
            f"Could you provide more details to help distinguish between these possibilities?")

def get_incident_specific_questions(label: str) -> list:
    """Get specific follow-up questions based on incident type."""
    
    questions = {
        "injection": [
            "What specific input or data caused this issue?",
            "Are there any error messages mentioning SQL, database, or scripts?",
            "Which application endpoint or form was being used?"
        ],
        "broken_authentication": [
            "Who is experiencing login problems?", 
            "Are users being locked out or seeing strange session behavior?",
            "When did these authentication issues start?"
        ],
        "broken_access_control": [
            "What specific data or functions can users access that they shouldn't?",
            "Which user roles are affected?",
            "Is this happening for all users or specific accounts?"
        ],
        "security_misconfiguration": [
            "What system or application is affected?",
            "Were there any recent configuration changes or deployments?",
            "Are there any exposed services or unusual system behavior?"
        ],
        "vulnerable_component": [
            "Which software or library version is involved?",
            "Are there any CVE numbers or security advisories mentioned?",
            "When was the component last updated?"
        ],
        "sensitive_data_exposure": [
            "What type of sensitive information is involved?",
            "How was the data exposure discovered?",
            "Are there any logs showing unauthorized access?"
        ],
        "phishing": [
            "What email addresses or websites are involved?",
            "How many users have been targeted?",
            "Are there any suspicious attachments or links?"
        ],
        "malware": [
            "Which systems or files are affected?",
            "What antivirus or security tools detected this?",
            "Are there any suspicious file names or processes?"
        ],
        "dos": [
            "Which services are unavailable or slow?",
            "Are there any suspicious IP addresses or traffic patterns?",
            "When did the performance issues start?"
        ]
    }
    
    return questions.get(label, [
        "Could you provide more specific technical details?",
        "What system or application is involved?", 
        "Are there any error messages or unusual behavior?"
    ])