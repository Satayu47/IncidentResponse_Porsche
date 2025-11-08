# Incident Response Bot

Takes incident reports and figures out what type of attack it is. Made this for my senior project.

## What it does
- Chat interface for incident reports
- Finds IPs, URLs, CVE numbers in the text
- Gets vulnerability details from databases
- Classifies different attack types
- Spits out JSON data

## Running it
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m spacy download en_core_web_md
$env:OPENAI_API_KEY="your-key"
streamlit run app.py
```

You need an OpenAI API key (the paid one, not ChatGPT Plus).