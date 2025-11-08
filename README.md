# Incident Response Bot - Phase 1

My senior project for automating security incident response. This part handles the initial analysis - takes incident reports through a web interface and classifies them so the next part can take appropriate action.

## Features
- Streamlit web interface for submitting incidents
- Extracts IPs, URLs, CVE numbers from text using spaCy and regex
- Queries NIST vulnerability database for context
- GPT-based classification with confidence scoring
- Basic conversation flow with clarification questions
- Fallback to pattern matching when API quota runs out
- Structured JSON output for downstream processing

## Setup
```powershell
# Create virtual environment
py -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_md

# Set environment variables (don't commit these)
$env:OPENAI_API_KEY="sk-your-openai-key"
$env:NVD_API_KEY="optional-nvd-key"

# Run the app
streamlit run app.py
```

## Notes
- Needs OpenAI API credits (separate from ChatGPT subscription)
- NVD API key is optional but recommended for higher rate limits
- App degrades gracefully when APIs are unavailable