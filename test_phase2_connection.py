"""Quick test to verify Phase 2 connection"""
from phase2_engine.core.runner import run_phase2_from_incident

# Test incident
test_incident = {
    'incident_type': 'Injection Attack',
    'fine_label': 'injection',
    'confidence': 0.95
}

print("Testing Phase 2 connection...")
result = run_phase2_from_incident(test_incident, dry_run=True)

print(f"Status: {result['status']}")
print(f"Playbook: {result.get('playbook', 'N/A')}")
print(f"Description: {result.get('description', 'N/A')}")
print(f"Steps: {len(result.get('steps', []))}")

if result['status'] == 'success':
    print("\n✓ Phase 2 connection working correctly")
    for i, step in enumerate(result['steps'][:3], 1):
        print(f"  Step {i}: {step.get('name', 'Unknown')}")
else:
    print(f"\n✗ Error: {result.get('message', 'Unknown')}")
