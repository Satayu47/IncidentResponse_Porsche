#  Incident Response System - Complete Solution

**AI-Powered Security Incident Classification & Automated Response**

Combined Phase 1 (Intelligent Classification) + Phase 2 (Automated Playbooks) = Complete IR System

##  What It Does

User Reports Incident  AI Classifies (OWASP)  Automated Response  Result

### Phase 1: AI Classification
- Google Gemini 2.5 Pro analyzes incidents using OWASP Top 10:2025
- Extracts IPs, URLs, CVEs automatically
- Adapts tone to user expertise (novice/intermediate/expert)
- 0.6-1.0 confidence scoring

### Phase 2: Automated Response
- 10 YAML playbooks for each OWASP category
- Safe dry-run simulation mode
- Step-by-step execution tracking

##  Quick Start

pip install -r requirements.txt
streamlit run app.py --server.port 8504

##  Status

11/11 tests passing | Production ready | Demo Nov 18, 2025

GitHub: https://github.com/Satayu47/IncidentResponse_Porsche
