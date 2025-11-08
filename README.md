# Incident Response Bot

Classifies security incidents and extracts useful data. Built this for my capstone project.

## What it does
- Web interface for reporting incidents
- Finds IPs, URLs, CVE numbers in text
- Looks up vulnerability info
- Classifies incident types
- Outputs JSON for automation

## Setup
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m spacy download en_core_web_md
$env:OPENAI_API_KEY="your-key"
streamlit run app.py
```

Need OpenAI API access (not ChatGPT Plus).