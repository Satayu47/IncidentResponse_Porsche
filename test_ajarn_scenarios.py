"""
Test the 4 OWASP scenarios requested by Ajarn for presentation
Tests multi-turn conversation flow with realistic dialogue
"""
import sys
from src.extractor import extract_entities, extract_IOCs
from src.llm_adapter import classify_and_slots
from src.dialogue_state import DialogueContext, update_context, DialogueState

def test_conversation(name, turns, expected_final_classification):
    """Run a multi-turn conversation test"""
    print("\n" + "=" * 100)
    print(f"TEST: {name}")
    print("=" * 100)
    
    conversation_history = []
    ctx = DialogueContext()
    
    for turn_num, user_msg in enumerate(turns, 1):
        print(f"\n{'-' * 100}")
        print(f"TURN {turn_num}/{len(turns)}")
        print(f"{'-' * 100}")
        print(f"User: {user_msg}")
        print()
        
        # Extract entities
        ents = extract_entities(user_msg)
        iocs = extract_IOCs(user_msg)
        
        entities_dict = {
            "ip": iocs.get("ip", []),
            "url": iocs.get("url", []),
            "cve": ents.cves
        }
        
        # Build conversation context (last 6 messages)
        recent_history = conversation_history[-6:] if len(conversation_history) > 6 else conversation_history
        conv_context_str = "\n".join([f"{msg['role']}: {msg['content']}" for msg in recent_history])
        
        # Check for explicit attack naming
        from src.explicit_detector import detect_explicit_attack
        explicit_type, explicit_confidence = detect_explicit_attack(user_msg)
        
        # Classify with context
        extra_ctx = {
            "kb_context": "",
            "conversation_context": conv_context_str,
            "user_confused": any(phrase in user_msg.lower() for phrase in ["i don't know", "not sure", "???", "confused"])
        }
        
        result = classify_and_slots(user_msg, entities_dict, extra_ctx)
        
        # Handle explicit detection override
        if explicit_type:
            result["classification"] = explicit_type
            result["confidence"] = explicit_confidence
            print(f"[EXPLICIT] User explicitly named attack type")
            print(f"   Override confidence to {explicit_confidence:.2f}")
            print()
        
        classification = result.get("classification", "unknown")
        confidence = result.get("confidence", 0.0)
        user_level = result.get("user_level", "intermediate")
        reasoning = result.get("reasoning", "")
        followup = result.get("followup_question", "")
        candidates = result.get("candidates", [{"label": classification, "confidence": confidence}])
        
        # Update dialogue context
        ctx = update_context(
            ctx=ctx,
            user_text=user_msg,
            label=classification,
            confidence=confidence,
            user_level=user_level,
            candidates=candidates,
            asked_followup=bool(followup),
            is_general_question=False,
            explicit_override=bool(explicit_type),
            thresh_low=0.6,
            thresh_go=0.7
        )
        
        # Display results
        print(f"Bot Response:")
        print(f"   State: {ctx.state.name}")
        print(f"   Classification: {classification}")
        print(f"   Confidence: {confidence:.2%}")
        print(f"   User Level: {user_level}")
        print()
        
        # State-specific response format
        if ctx.state == DialogueState.GATHERING_INFO:
            print(f"   System: \"Understood. Need additional details to classify this.\"")
            if followup:
                print(f"   Follow-up: {followup}")
        
        elif ctx.state == DialogueState.INCIDENT_SUSPECTED:
            print(f"   System: \"Based on the information provided:\"")
            print(f"   Likely classification: {classification} (preliminary)")
            print(f"   Reasoning: {reasoning[:200]}...")
            if followup:
                print(f"   Additional information needed: {followup}")
        
        elif ctx.state in [DialogueState.INCIDENT_CONFIRMED, DialogueState.READY_FOR_PHASE2]:
            print(f"   System: \"Assessment:\"")
            print(f"   Type: {classification} ({confidence:.0%} confidence)")
            print(f"   Why: {reasoning[:200]}...")
            if ctx.is_ready_for_phase2(thresh=0.70):
                print(f"   STATUS: READY FOR PHASE-2")
        
        # Update conversation history
        conversation_history.append({"role": "user", "content": user_msg})
        conversation_history.append({"role": "assistant", "content": f"[classified as {classification}]"})
    
    # Final summary
    print(f"\n{'=' * 100}")
    print(f"FINAL RESULTS")
    print(f"{'=' * 100}")
    print(f"Expected: {expected_final_classification}")
    actual_label = ctx.hypotheses[0]['label'] if ctx.hypotheses and isinstance(ctx.hypotheses[0], dict) else str(ctx.hypotheses[0]) if ctx.hypotheses else 'unknown'
    print(f"Actual:   {actual_label}")
    print(f"Confidence: {ctx.last_confidence:.2%}")
    print(f"Final State: {ctx.state.name}")
    print(f"Phase-2 Ready: {'YES' if ctx.is_ready_for_phase2(thresh=0.70) else 'NO'}")
    print(f"Total Turns: {ctx.turns}")
    
    # Validation
    match = expected_final_classification.lower() in actual_label.lower()
    phase2_ready = ctx.is_ready_for_phase2(thresh=0.70)
    
    if match and phase2_ready:
        print(f"\n[PASS] Classification correct and Phase-2 ready")
        return True
    elif match:
        print(f"\n[PARTIAL] Classification correct but confidence < 70%")
        return True
    else:
        print(f"\n[FAIL] Expected '{expected_final_classification}' but got '{actual_label}'")
        return False


def main():
    """Run all 4 Ajarn scenarios"""
    print("\n" + "=" * 100)
    print("AJARN'S 4 OWASP SCENARIOS - PRESENTATION TEST SUITE")
    print("=" * 100)
    
    results = []
    
    # Test 1: A01 - Broken Access Control
    results.append(test_conversation(
        name="A01 - Broken Access Control (Admin Panel Access)",
        turns=[
            "normal users can access the /admin page",
            "they don't have permission but still can enter",
            "they can also edit settings"
        ],
        expected_final_classification="broken_access_control"
    ))
    
    # Test 2: A04 - Sensitive Data Exposure (Cryptographic Failure)
    results.append(test_conversation(
        name="A04 - Sensitive Data Exposure (Plaintext Passwords)",
        turns=[
            "I found user passwords in plain text in the log file",
            "login api",
            "it was uploaded to the s3 bucket by mistake"
        ],
        expected_final_classification="sensitive_data_exposure"  # System's internal label
    ))
    
    # Test 3: A05 - Security Misconfiguration → Injection (Hypothesis Switch)
    results.append(test_conversation(
        name="A05/A03 - Misconfiguration to Injection Switch (Missing Table)",
        turns=[
            "my table is missing from the database",
            "some weird query appeared in the search bar",
            "something like 1=1"
        ],
        expected_final_classification="injection"
    ))
    
    # Test 4: A07 - Broken Authentication
    results.append(test_conversation(
        name="A07 - Identification & Authentication Failures (Login Bypass)",
        turns=[
            "users can log in without password",
            "all accounts",
            "login api returned status 200 even with empty fields"
        ],
        expected_final_classification="broken_authentication"  # System's internal label
    ))
    
    # Summary
    print("\n" + "=" * 100)
    print("TEST SUITE SUMMARY")
    print("=" * 100)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    print(f"Success Rate: {passed/total:.0%}")
    
    if passed == total:
        print("\n[SUCCESS] ALL TESTS PASSED - Ready for presentation!")
    else:
        print(f"\n[WARNING] {total - passed} test(s) failed - Review results above")
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
