#!/usr/bin/env python3
"""Test the new action-oriented responses."""

import sys
sys.path.insert(0, '.')

# Silence Streamlit warnings
import warnings
warnings.filterwarnings("ignore")

# Mock Streamlit to avoid errors
class MockStreamlit:
    def __getattr__(self, name):
        return lambda *args, **kwargs: None

sys.modules['streamlit'] = MockStreamlit()

from app import templated_reply, THRESH_LOW, THRESH_GO

print("=" * 80)
print("TESTING ACTION-ORIENTED RESPONSES")
print("=" * 80)
print()

# Test case 1: Missing table (misconfiguration) - low-medium confidence
print("[TEST 1] Missing table scenario (misconfiguration, confidence 0.60)")
print("-" * 80)
msg = templated_reply(
    user_text="table is missing from my database",
    label="security_misconfiguration",
    score=0.60,
    iocs={},
    rationale="A missing table is usually caused by a failed migration, accidental DROP TABLE, or a deployment script issue. No clear signs of an attack yet.",
    kb_present=False,
    followup="Did you see any strange inputs or error messages (for example with quotes ' or OR 1=1)?",
    user_level="novice",
    candidates=[
        {"label": "security_misconfiguration", "score": 0.60},
        {"label": "injection", "score": 0.30}
    ]
)
print(msg)
print("\n" + "=" * 80 + "\n")

# Test case 2: SQL injection - high confidence, expert user
print("[TEST 2] SQL injection (expert user, high confidence 0.95)")
print("-" * 80)
msg = templated_reply(
    user_text="Detected UNION-based SQLi with payload: ' UNION SELECT null",
    label="injection",
    score=0.95,
    iocs={"ip": ["192.168.1.100"], "url": ["https://example.com/search"]},
    rationale="Clear SQL injection pattern detected with UNION-based payload attempting to extract data.",
    kb_present=False,
    followup=None,
    user_level="expert",
    candidates=[
        {"label": "injection", "score": 0.95},
        {"label": "broken_access_control", "score": 0.15}
    ]
)
print(msg)
print("\n" + "=" * 80 + "\n")

# Test case 3: Brute force - medium confidence, novice user
print("[TEST 3] Brute force attack (novice user, confidence 0.75)")
print("-" * 80)
msg = templated_reply(
    user_text="Someone tried logging into my account 20 times",
    label="broken_authentication",
    score=0.75,
    iocs={"ip": ["203.0.113.45"]},
    rationale="Multiple failed login attempts from the same IP address suggests a brute force attack.",
    kb_present=False,
    followup=None,
    user_level="novice",
    candidates=[
        {"label": "broken_authentication", "score": 0.75},
        {"label": "dos", "score": 0.20}
    ]
)
print(msg)
print("\n" + "=" * 80 + "\n")

print("✅ All tests completed! Check if responses are action-oriented.")
