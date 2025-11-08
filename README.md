# Incident Response Bot - Phase 1

Built the classification part of an incident response system. Takes in security reports and figures out what kind of attack it is, extracts IPs and stuff, then hands off clean data to whatever automation comes next.

## What it does
- Chat interface for submitting incidents
- Finds IPs, URLs, CVEs in the text
- Looks up vulnerability info from NVD
- Classifies the incident type with confidence scores
- Asks follow-up questions when it's not sure
- Runs offline mode if APIs are unavailable  
- Outputs JSON for the next phase

## How to run it
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m spacy download en_core_web_md
# set your API key for this session
$env:OPENAI_API_KEY="sk-your-actual-key"
# this one's optional but helps
$env:NVD_API_KEY="your-nvd-key"
streamlit run app.py
```

## Setup notes
- You need actual OpenAI API credits, not ChatGPT Plus (different thing)
- Don't accidentally push your .env file with the real API keys 
- If the OpenAI API is down, it falls back to basic keyword matching