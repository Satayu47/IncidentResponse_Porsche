#!/usr/bin/env python3
"""Test the general security Q&A feature."""

import sys
sys.path.insert(0, '.')

from app import answer_general_security_question

test_questions = [
    "How to prevent SQL injection?",
    "how can i prevent xss attacks?",
    "What is phishing and how to stop it?",
    "Tell me how to prevent malware",
    "How do I prevent brute force attacks?",
    "What is SQL injection?",  # What-is question
    "I have a SQL injection incident",  # Should return None (incident, not general Q)
    "The database is showing errors"  # Should return None (incident description)
]

print("=" * 60)
print("TESTING GENERAL SECURITY Q&A HANDLER")
print("=" * 60)
print()

for i, question in enumerate(test_questions, 1):
    print(f"[TEST {i}] {question}")
    answer = answer_general_security_question(question)
    
    if answer:
        print(f"✓ Got answer ({len(answer)} chars)")
        # Show first 100 chars of answer
        preview = answer[:100].replace('\n', ' ')
        print(f"  Preview: {preview}...")
    else:
        print(f"✗ No answer (proceeds to incident classification)")
    print()

print("=" * 60)
print("Testing complete!")
print("=" * 60)
