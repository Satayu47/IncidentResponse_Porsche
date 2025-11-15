"""
Explicit Attack Name Detection
--------------------------------
When users explicitly name an attack type, force that classification.
This prevents the system from ignoring obvious user statements.
"""

import re

# Attack patterns with common variations and typos
ATTACK_PATTERNS = {
    "injection": [
        r'\bsql\s*inj',  # sql injection, sql inj, sqlinj
        r'\bsqli\b',      # sqli
        r'\bxss\b',       # xss
        r'\bcross[\s-]?site[\s-]?script',  # cross-site scripting
        r'\bcommand\s+inj',  # command injection
        r'\bunion\s+select',  # union select (payload indicator)
        r'\bor\s+1\s*=\s*1',  # or 1=1 (payload indicator)
        r'\b<script>',    # script tag (xss indicator)
        r"'\s*or\s+",     # ' or (sql injection pattern)
    ],
    "broken_authentication": [
        r'\bbrute[\s-]?force',  # brute force, bruteforce
        r'\bcredential\s+stuff',  # credential stuffing
        r'\bsession\s+hijack',   # session hijacking
        r'\bpassword\s+attack',  # password attack
        r'\bauth\w*\s+bypass',   # authentication bypass, auth bypass
        r'\bmultiple\s+login\s+fail',  # multiple login failures
        r'\blogin\s+attack',
    ],
    "broken_access_control": [
        r'\bidor\b',  # idor
        r'\baccess\s+control',  # access control
        r'\bunauth\w*\s+access',  # unauthorized access
        r'\bprivilege\s+escal',  # privilege escalation
        r'\bpath\s+travers',    # path traversal
        r'\b\.\./',             # ../ (path traversal indicator)
        r'\burl\s+manip',       # url manipulation
        r'\bchanged?\s+id\s+in\s+url',  # changed id in url
    ],
    "cryptographic_failures": [
        r'\bcrypt\w+\s+fail',  # cryptographic failure
        r'\bweak\s+encrypt',   # weak encryption
        r'\bmd5\b',            # md5
        r'\bsha1\b',           # sha1
        r'\bplain\s*text\s+pass',  # plaintext password
        r'\bhttp\s+not\s+https',   # http not https
        r'\bno\s+encrypt',     # no encryption
    ],
    "security_misconfiguration": [
        r'\bmisconfig',        # misconfiguration, misconfig
        r'\bdefault\s+cred',   # default credentials
        r'\bwrong\s+setting',  # wrong settings
        r'\bconfig\w*\s+error',  # configuration error
        r'\bmissing\s+table',  # missing table (could be misconfig)
        r'\bdeployment\s+fail',  # deployment failure
    ],
    "vulnerable_component": [
        r'\bvuln\w*\s+comp',   # vulnerable component
        r'\boutdated\s+soft',  # outdated software
        r'\bold\s+version',    # old version
        r'\bcve[-\s]?\d',      # CVE-2024, CVE 2024
        r'\bunpatched',        # unpatched
    ],
    "malware": [
        r'\bmalware\b',
        r'\bvirus\b',
        r'\btrojan\b',
        r'\bransom\w*',  # ransomware
        r'\bworm\b',
        r'\bbackdoor\b',
    ],
    "dos": [
        r'\bd+dos\b',  # ddos, dos
        r'\bdenial[\s-]of[\s-]service',
        r'\bservice\s+unavail',  # service unavailable
        r'\boverload',
        r'\bflood',
    ],
    "phishing": [
        r'\bphish',  # phishing
        r'\bspoof',  # spoofing
        r'\bfake\s+email',
        r'\bsocial\s+eng',  # social engineering
    ],
}


def detect_explicit_attack(text: str) -> tuple[str | None, float]:
    """
    Detect if user explicitly names an attack type.
    
    Returns:
        (attack_type, confidence) or (None, 0.0) if no explicit mention
        
    Examples:
        "this is sql injection" → ("injection", 0.95)
        "maybe brute force?" → ("broken_authentication", 0.90)
        "i think it's xss" → ("injection", 0.95)
        "definitely misconfig" → ("security_misconfiguration", 0.90)
    """
    text_lower = text.lower()
    
    # Check for explicit confirmation words that boost confidence
    confirmation_words = [
        r'\bthis\s+is\b',
        r'\bit\s*\'?s\b',
        r'\bdefinitely\b',
        r'\bobviously\b',
        r'\bclearly\b',
        r'\bconfirmed?\b',
        r'\byes\s+it\s*\'?s\b',
        r'\bok\s+yes\b',
    ]
    
    has_confirmation = any(re.search(pattern, text_lower) for pattern in confirmation_words)
    
    # Check for thinking/uncertainty words that lower confidence
    uncertainty_words = [
        r'\bmaybe\b',
        r'\bprobably\b',
        r'\bmight\s+be\b',
        r'\bcould\s+be\b',
        r'\bpossibly\b',
        r'\bi\s+think\b',
        r'\bseems?\s+like\b',
        r'\blooks?\s+like\b',
    ]
    
    has_uncertainty = any(re.search(pattern, text_lower) for pattern in uncertainty_words)
    
    # Scan for attack patterns
    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                # Calculate confidence based on context
                if has_confirmation:
                    confidence = 0.95
                elif has_uncertainty:
                    confidence = 0.75
                else:
                    confidence = 0.85
                
                return attack_type, confidence
    
    return None, 0.0


def force_classification_if_explicit(user_text: str, llm_result: dict) -> dict:
    """
    Override LLM classification if user explicitly names an attack.
    
    This prevents the system from ignoring obvious user statements like:
    - "this is sql injection"
    - "i already told you it's brute force"
    - "yes it's xss"
    
    Args:
        user_text: Current user message
        llm_result: Classification result from LLM
        
    Returns:
        Modified result with forced classification if applicable
    """
    explicit_type, explicit_confidence = detect_explicit_attack(user_text)
    
    if explicit_type:
        # User explicitly named an attack - override LLM
        original_classification = llm_result.get("classification", "other")
        original_confidence = llm_result.get("confidence", 0.0)
        
        # Only override if different or lower confidence
        if explicit_type != original_classification or explicit_confidence > original_confidence:
            llm_result["classification"] = explicit_type
            llm_result["confidence"] = explicit_confidence
            llm_result["reasoning"] = (
                f"User explicitly identified this as {explicit_type.replace('_', ' ')}. "
                f"{llm_result.get('reasoning', '')}"
            )
            
            # Update candidates
            llm_result["candidates"] = [
                {"label": explicit_type, "score": explicit_confidence}
            ]
    
    return llm_result
