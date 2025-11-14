# Incident Response Phase-1

My capstone project for analyzing security incidents automatically. Helps security teams classify incidents faster using OWASP Top 10 categories.

## What it does

Takes incident reports and:
- Classifies the attack type (OWASP Top 10 categories)
- Extracts IPs, emails, CVE numbers
- Looks up vulnerability info from databases
- Outputs structured JSON data

Phase-2 will handle automated responses. This phase focuses on analysis.

## How it works

Uses Google Gemini API for classification and spaCy for entity extraction. Has a simple Streamlit chatbot interface where you describe an incident and it tells you what's going on.

Added confidence scoring so it shows when it's uncertain instead of guessing.

## Setup

Install dependencies:
```bash
pip install -r requirements.txt
```

Add API key to `.env` file:
```
LLM_PROVIDER=gemini
GOOGLE_API_KEY=your_key_here
NVD_API_KEY=optional
```

Run:
```bash
streamlit run app.py
```

Opens at localhost:8501.

## Testing

Test with examples like:
- "Got suspicious emails asking for password"
- "Multiple failed login attempts from Russia"
- "Database showing credit card numbers"

Test cases in `tests/` folder cover OWASP categories A01, A04, A05, A07.

## Project structure

```
├── app.py              # Streamlit interface
├── src/                # Core modules
│   ├── llm_adapter.py  # Gemini integration
│   ├── extractor.py    # Entity extraction
│   ├── nvd.py         # CVE lookups
│   └── owasp_mapping.py
├── tests/             # Test scenarios
└── docs/              # Documentation
```

## Key features

- Shows multiple possibilities when confidence is low
- Detects user expertise level and adjusts response
- Conversation memory for follow-up questions
- Playbook with action steps when confidence is high

## Tech stack

- Google Gemini 2.5 Pro (classification)
- spaCy (entity extraction)
- Streamlit (web interface)
- FAISS (knowledge base)
- NVD API (CVE data)

## Status

Working well for most incident types. Ready for demo. Some edge cases still need testing.

## Future work

Phase-2 will add automated response actions like blocking IPs and quarantining systems.

## License

MIT License