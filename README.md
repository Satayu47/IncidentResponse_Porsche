# Incident Response ChatOps — Phase 1 (Input & Classification)
AI-driven Phase-1 for "Incident Response ChatOps Bot with Automated Dynamic Playbooks for Real-Time Threat Mitigation".

## Features
- Streamlit chat UI
- Entity & IOC extraction (spaCy + regex)
- NVD CVE context (free) + MITRE links
- OpenAI classification with confidence + rationale
- Thresholds: 0.6 (clarify) / 0.7 (handoff)
- One-question clarification loop
- Degraded mode (heuristic) when OpenAI quota is out
- Downloadable `phase1_output.json` for Phase-2

## Setup (Windows PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m spacy download en_core_web_md
# set your secrets for this session (do NOT commit them)
$env:OPENAI_API_KEY="sk-..."
# optional, free
$env:NVD_API_KEY="..."
streamlit run app.py
```

## Notes

* ChatGPT Plus ≠ API credits. Fund your **OpenAI API**.
* Do not commit `.env` or any real keys.
* If quota is out, app still runs in degraded mode.