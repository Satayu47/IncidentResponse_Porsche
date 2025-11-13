import re, spacy
from dataclasses import dataclass, field
from typing import List, Dict

try:
    nlp = spacy.load("en_core_web_md")
except Exception:
    nlp = spacy.blank("en")

RE_IP   = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
RE_URL  = re.compile(r"\bhttps?://[^\s<>'\"]+\b", re.I)
RE_MAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
RE_HASH = re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
RE_CVE  = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
RE_CWE  = re.compile(r"\bCWE-\d{1,5}\b", re.I)

@dataclass
class Entities:
    persons: List[str] = field(default_factory=list)
    orgs:    List[str] = field(default_factory=list)
    cves:    List[str] = field(default_factory=list)
    cwes:    List[str] = field(default_factory=list)
    
    def __len__(self) -> int:
        """Return total number of entities found"""
        return len(self.persons) + len(self.orgs) + len(self.cves) + len(self.cwes)
    
    def to_list(self) -> List[str]:
        """Convert all entities to a flat list"""
        return self.persons + self.orgs + self.cves + self.cwes
    
    def to_dict(self) -> Dict[str, List[str]]:
        """Convert to dictionary for JSON serialization"""
        return {
            "persons": self.persons,
            "orgs": self.orgs,
            "cves": self.cves,
            "cwes": self.cwes
        }

def extract_entities(text: str) -> Entities:
    doc = nlp(text)
    persons = list({e.text for e in doc.ents if e.label_=="PERSON"})
    orgs    = list({e.text for e in doc.ents if e.label_ in ("ORG","PRODUCT")})
    cves    = list({m.group(0).upper() for m in RE_CVE.finditer(text)})
    cwes    = list({m.group(0).upper() for m in RE_CWE.finditer(text)})
    return Entities(persons, orgs, cves, cwes)

def extract_IOCs(text: str) -> Dict[str, List[str]]:
    return {
        "ip":   list({m.group(0) for m in RE_IP.finditer(text)}),
        "url":  list({m.group(0) for m in RE_URL.finditer(text)}),
        "email":list({m.group(0) for m in RE_MAIL.finditer(text)}),
        "hash": list({m.group(0) for m in RE_HASH.finditer(text)}),
        "cve":  list({m.group(0).upper() for m in RE_CVE.finditer(text)}),
        "cwe":  list({m.group(0).upper() for m in RE_CWE.finditer(text)}),
    }

# heuristic fallback if LLM unavailable
@dataclass
class Symptom:
    label: str
    score: float
    evidence: List[str]
    
    def __len__(self) -> int:
        """Return 1 for compatibility - this is a single symptom"""
        return 1
    
    def to_dict(self) -> Dict[str, any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "label": self.label,
            "score": self.score,
            "evidence": self.evidence
        }

def detect_symptoms(text: str) -> List[Symptom]:
    """Detect security symptoms in text - returns list for consistency"""
    t = text.lower()
    rules = [
        ("sql_injection", [" or 1=1", "union select", "sql syntax", "sqli"]),
        ("xss", ["<script>", "alert(", "xss"]),
        ("ssrf", ["169.254.169.254", "metadata service", "ssrf"]),
        ("bruteforce", ["too many failed", "multiple failed login", "brute"]),
        ("rce", ["remote code execution", "deserialization", "rce"]),
        ("malware", ["trojan", "virus", "malware", "suspicious file"]),
        ("phishing", ["phishing", "fake", "credential harvesting", "suspicious email"]),
        ("intrusion", ["unauthorized access", "network intrusion", "scan", "probe"])
    ]
    
    symptoms = []
    for label, keys in rules:
        hits = [k for k in keys if k in t]
        if hits:
            score = min(0.9, 0.55 + 0.1*len(hits))
            symptoms.append(Symptom(label, score, hits))
    
    # If no specific symptoms found, add a generic one
    if not symptoms:
        symptoms.append(Symptom("other", 0.45, ["general_incident"]))
    
    return symptoms