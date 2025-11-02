# Incident Response ChatOps - Phase 1

This is the first part of our incident response bot that handles input classification and analysis. When security incidents come in, it figures out what type they are and extracts useful info for automated response.

## What it does
- Web chat interface for incident reports
- Pulls out IPs, URLs, CVEs, and other indicators
- Gets vulnerability details from the NVD database  
- Uses OpenAI to classify incident types with confidence scores
- Asks one follow-up question if needed for clarity
- Works offline with basic pattern matching if API is down
- Exports structured data for Phase 2 automation

## Getting it running
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m spacy download en_core_web_md
# add your API key (don't commit this!)
$env:OPENAI_API_KEY="sk-your-key-here"
# optional - helps with rate limits
$env:NVD_API_KEY="your-nvd-key"
streamlit run app.py
```

## Important stuff
- You need OpenAI API credits (ChatGPT Plus doesn't count)
- Never commit your `.env` file with real keys
- The app still works without API access, just less smart