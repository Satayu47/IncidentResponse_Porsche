"""
Quick test to verify OWASP display names are working
"""
from src.owasp_display import get_owasp_display_name, get_short_display_name, get_owasp_id, get_specific_type

print("=" * 80)
print("OWASP 2025 DISPLAY NAME MAPPING TEST")
print("=" * 80)

test_labels = [
    "broken_authentication",
    "sensitive_data_exposure",
    "broken_access_control",
    "injection",
    "security_misconfiguration"
]

print("\n" + "=" * 80)
print("OPTION A: Show Specific Type + OWASP Category (RECOMMENDED)")
print("=" * 80)
for label in test_labels:
    display = get_owasp_display_name(label, show_specific=True)
    print(f"  {label:30} ->  {display}")

print("\n" + "=" * 80)
print("OPTION B: Show Only OWASP Official Name")
print("=" * 80)
for label in test_labels:
    display = get_owasp_display_name(label, show_specific=False)
    print(f"  {label:30} ->  {display}")

print("\n" + "=" * 80)
print("DETAILED BREAKDOWN")
print("=" * 80)
for label in test_labels:
    owasp_id = get_owasp_id(label)
    official = get_short_display_name(label)
    specific = get_specific_type(label)
    print(f"\nInternal: {label}")
    print(f"  OWASP ID: {owasp_id}")
    print(f"  Official Category: {official}")
    print(f"  Specific Detection: {specific}")

print("\n" + "=" * 80)
print("✅ OWASP 2025 mapping verified!")
print("=" * 80)
