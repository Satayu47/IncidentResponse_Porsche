# Incident Response ChatOps — Phase 1 (Input & Classification)

## 1) Setup (Windows, no Docker)
```

py -m venv .venv
..venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m spacy download en_core_web_md

```

## 2) OpenAI API key (your paper uses OpenAI)
Set the key in the SAME terminal you’ll run Streamlit:
```

$env:OPENAI_API_KEY="sk-REPLACE_WITH_YOUR_API_KEY"

```
> Note: ChatGPT Plus ≠ API credits. Your API key’s project/account must have billing/credits.

## 3) Run
```

streamlit run app.py

```

## 4) Try these inputs
- `SQL syntax error near 'OR 1=1' on /auth; source 198.51.100.23`
- `Blocked <script>alert(1)</script> from 203.0.113.10 on /login; CVE-2021-44228 suspected.`
- `Users report too many failed logins from multiple IPs on /login`
- `App fetched 169.254.169.254 via /proxy?url= — possible SSRF`

You’ll see a classification with confidence, a short “signals” line, and (only if needed) one clarifying question.  
Open the **Advanced details** expander to view the Phase-2 handoff JSON; click **Download Phase-1 Output (JSON)** to send to your teammate.


## Run it in VS Code (quick)

1. Open the `IncidentResponse_Phase1` folder in VS Code.
2. Open a terminal inside VS Code:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   python -m spacy download en_core_web_md
   $env:OPENAI_API_KEY="sk-...YOUR_API_KEY_WITH_API_CREDITS..."
   streamlit run app.py
   ```
3. Paste a test incident; download `phase1_output.json` and send it to your Phase-2 friend.

If anything doesn’t run in your environment, paste the exact error (without sharing secrets) and I’ll give you a line-by-line fix.
