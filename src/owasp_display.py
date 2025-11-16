"""
OWASP Top 10:2025 Official Name Mapping
Maps internal system labels to official OWASP names for user display
"""

OWASP_DISPLAY_NAMES = {
    # Internal label -> (OWASP ID, Official Name, Specific Type)
    # Format: "internal_label": ("OWASP_ID", "Official OWASP Name", "Specific Detection")
    
    "broken_access_control": ("A01:2025", "Broken Access Control", None),
    
    # A04:2025 - Cryptographic Failures (parent category)
    "cryptographic_failures": ("A04:2025", "Cryptographic Failures", None),
    "sensitive_data_exposure": ("A04:2025", "Cryptographic Failures", "Sensitive Data Exposure"),
    
    # A05:2025 - Injection
    "injection": ("A05:2025", "Injection", None),
    
    "insecure_design": ("A06:2025", "Insecure Design", None),
    "security_misconfiguration": ("A02:2025", "Security Misconfiguration", None),
    "vulnerable_component": ("A03:2025", "Software Supply Chain Failures", None),
    
    # A07:2025 - Authentication Failures (parent category)
    "broken_authentication": ("A07:2025", "Authentication Failures", "Broken Authentication"),
    "authentication_failures": ("A07:2025", "Authentication Failures", None),
    
    "software_data_integrity": ("A08:2025", "Software or Data Integrity Failures", None),
    "logging_monitoring_issue": ("A09:2025", "Logging and Alerting Failures", None),
    "ssrf": ("A10:2025", "Server-Side Request Forgery", None),
    
    # Additional attack types (not in OWASP Top 10 but system supports)
    "phishing": ("Social Engineering", "Phishing Attack", None),
    "malware": ("Malware", "Malicious Software", None),
    "dos": ("DoS/DDoS", "Denial of Service", None),
    "other": ("Other", "Other/Insufficient Information", None),
}


def get_owasp_display_name(internal_label: str, show_specific: bool = True) -> str:
    """
    Convert internal label to official OWASP display name.
    
    Args:
        internal_label: System's internal classification label
        show_specific: If True, shows specific detection + OWASP category (recommended)
        
    Returns:
        Formatted string with OWASP category and specific type
        
    Example:
        >>> get_owasp_display_name("broken_authentication", show_specific=True)
        "Broken Authentication (OWASP A07:2025 - Authentication Failures)"
        
        >>> get_owasp_display_name("broken_authentication", show_specific=False)
        "A07:2025 - Authentication Failures"
    """
    if internal_label in OWASP_DISPLAY_NAMES:
        owasp_id, official_name, specific_type = OWASP_DISPLAY_NAMES[internal_label]
        
        if show_specific and specific_type:
            # Show specific detection + parent OWASP category
            return f"{specific_type} (OWASP {owasp_id} - {official_name})"
        else:
            # Show only OWASP official name
            return f"{owasp_id} - {official_name}"
    
    # Fallback: return cleaned internal label
    return internal_label.replace("_", " ").title()


def get_short_display_name(internal_label: str) -> str:
    """
    Get just the official OWASP name without ID.
    
    Example:
        >>> get_short_display_name("broken_authentication")
        "Authentication Failures"
    """
    if internal_label in OWASP_DISPLAY_NAMES:
        _, official_name, _ = OWASP_DISPLAY_NAMES[internal_label]
        return official_name
    
    return internal_label.replace("_", " ").title()


def get_owasp_id(internal_label: str) -> str:
    """
    Get just the OWASP ID.
    
    Example:
        >>> get_owasp_id("broken_authentication")
        "A07:2025"
    """
    if internal_label in OWASP_DISPLAY_NAMES:
        owasp_id, _, _ = OWASP_DISPLAY_NAMES[internal_label]
        return owasp_id
    
    return "Other"


def get_specific_type(internal_label: str) -> str:
    """
    Get the specific detection type if available.
    
    Example:
        >>> get_specific_type("broken_authentication")
        "Broken Authentication"
        
        >>> get_specific_type("injection")
        "Injection"  # No specific subtype
    """
    if internal_label in OWASP_DISPLAY_NAMES:
        _, official_name, specific_type = OWASP_DISPLAY_NAMES[internal_label]
        return specific_type if specific_type else official_name
    
    return internal_label.replace("_", " ").title()
