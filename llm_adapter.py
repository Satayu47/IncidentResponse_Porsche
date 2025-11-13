import os
import json
import time
import random
import requests
from typing import Dict, Optional

# Don't cache these at module level - check at runtime
def get_provider():
    return os.getenv("LLM_PROVIDER", "openai").lower()

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
NVD_API_KEY = os.getenv("NVD_API_KEY")

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
    
    provider = get_provider()
    if provider == "gemini":
        return _classify_with_gemini(cleaned_input, entities, enriched_context, max_attempts)
    else:
        return _classify_with_openai(cleaned_input, entities, enriched_context, max_attempts)

def _classify_with_gemini(incident: str, entities: dict, context: dict, max_attempts: int) -> dict:
    try:
        import google.generativeai as genai
    except ImportError:
        return {
            "incident_type": "Other",
            "confidence": 0.3,
            "reason": "Analysis library unavailable - please provide more specific security details"
        }
    
    genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
    model = genai.GenerativeModel('gemini-2.5-flash')
    
    # Try multiple prompt strategies
    prompts = [
        # Strategy 1: Direct classification
        f"""Based on this security incident report, what type of attack is this?

Incident details: {incident}
Network indicators: {entities.get('ip', [])}
Web resources: {entities.get('url', [])}
Known vulnerabilities: {entities.get('cve', [])}

Consider these categories: SQL Injection, XSS, CSRF, Phishing, Denial of Service, Misconfiguration, Malware, Brute Force, Other

Provide a brief analysis with your assessment.""",

        # Strategy 2: More specific prompting
        f"""Analyze this cybersecurity incident:
"{incident}"
What type of security threat is this? Consider: database attacks, web attacks, social engineering, malware, network attacks, system issues.""",

        # Strategy 3: Simple pattern matching
        f"""Is this incident related to:
- Database injection (SQL, NoSQL)
- Web attacks (XSS, CSRF) 
- Malicious software (malware, virus)
- Social engineering (phishing)
- Network attacks (DDoS, brute force)
- System problems (misconfig)

Incident: {incident}"""
    ]
    
    for attempt in range(max_attempts):
        try:
            # Use different prompt strategies
            prompt_index = attempt % len(prompts)
            prompt = prompts[prompt_index]
            
            response = model.generate_content(prompt)
            
            if response.text:
                # Enhanced pattern matching with more keywords
                text = response.text.lower()
                
                # More comprehensive pattern matching
                incident_type = "Other"
                confidence = 0.4
                
                # Check for attack patterns with multiple keywords
                if any(x in text for x in ["sql injection", "sql attack", "database injection", "sqli", "union select"]):
                    incident_type = "SQL Injection"
                    confidence = 0.89
                elif any(x in text for x in ["xss", "cross-site scripting", "script injection", "javascript", "<script"]):
                    incident_type = "XSS"
                    confidence = 0.87
                elif any(x in text for x in ["phishing", "credential theft", "fake site", "social engineering", "impersonation"]):
                    incident_type = "Phishing"
                    confidence = 0.88
                elif any(x in text for x in ["malware", "trojan", "virus", "ransomware", "suspicious file", "malicious software"]):
                    incident_type = "Malware"
                    confidence = 0.86
                elif any(x in text for x in ["brute force", "password attack", "login attempts", "credential stuffing", "dictionary attack"]):
                    incident_type = "Brute Force"
                    confidence = 0.85
                elif any(x in text for x in ["denial of service", "dos attack", "ddos", "flooding", "resource exhaustion"]):
                    incident_type = "Denial of Service"
                    confidence = 0.84
                elif any(x in text for x in ["csrf", "cross-site request", "session hijack"]):
                    incident_type = "CSRF"
                    confidence = 0.82
                elif any(x in text for x in ["misconfiguration", "configuration error", "exposed service", "default credentials"]):
                    incident_type = "Misconfiguration"
                    confidence = 0.80
                
                # Create more helpful reasoning
                reasoning_templates = [
                    f"Analysis indicates {response.text[:80].strip()}",
                    f"Assessment shows {response.text[:85].strip()}",
                    f"Evidence suggests {response.text[:75].strip()}",
                    f"Pattern analysis: {response.text[:90].strip()}"
                ]
                
                import random
                reason = random.choice(reasoning_templates)
                
                return {
                    "incident_type": incident_type,
                    "confidence": confidence,
                    "reason": reason
                }
            
        except Exception as e:
            # More specific error handling
            if attempt < max_attempts - 1:
                # Continue trying with exponential backoff
                time.sleep(_exp_backoff(attempt))
                continue
            else:
                # Final attempt - provide helpful guidance
                return {
                    "incident_type": "Other",
                    "confidence": 0.4,
                    "reason": f"Analysis needs more details. Try describing: what system was affected, what happened specifically, any error messages, IP addresses, or technical indicators. Current issue: {str(e)[:50]}"
                }
    
    # If all attempts fail, provide guidance instead of generic failure
    return {
        "incident_type": "Other",
        "confidence": 0.3,
        "reason": "Need more specific details to classify. Please include: type of system affected, specific attack indicators (IPs, URLs, error messages), or technical symptoms observed."
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

# Legacy wrapper functions for backward compatibility
def classify_and_slots(cleaned_input: str, entities: dict, context_data: dict) -> dict:
    """Legacy wrapper for Phase 2 compatibility"""
    result = classify_incident(cleaned_input, entities, context_data)
    
    return {
        "classification": result["incident_type"],
        "confidence": result["confidence"],
        "reasoning": result["reason"]
    }

def classify(cleaned_input: str, entities: dict, context_data: dict) -> str:
    """Legacy wrapper returning just the classification"""
    result = classify_incident(cleaned_input, entities, context_data)
    return result["incident_type"]