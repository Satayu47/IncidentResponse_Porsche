# Project Organization Guide

This doc explains how I've organized the IncidentResponse_Phase1 project and where to find everything.

## What this project actually does

I built an incident response system that can automatically analyze security incidents and classify them. The goal was to create something that security teams could actually use in real life, not just a demo that looks good but doesn't work.

Basically, you describe an incident (like "user clicked suspicious email attachment") and the system:
1. Figures out what type of attack it is
2. Extracts important information like IPs, emails, file names
3. Looks up relevant CVE information
4. Packages everything into structured data for automated systems

## File organization

I organized everything into logical folders because the project got pretty big:

### Main code files (in root folder):
- `app.py` - The web interface built with Streamlit
- `llm_adapter.py` - Handles OpenAI API calls with retry logic
- `extractor.py` - Uses spaCy to extract entities and IOCs from text
- `nvd.py` - Connects to NIST vulnerability database
- `lc_retriever.py` - Knowledge base search using LangChain

### tests/ folder:
I spent a lot of time building a proper testing framework:
- `baseline_test.py` - Quick test to make sure everything works
- `experimental_framework.py` - Comprehensive testing suite
- `analyze_results.py` - Statistical analysis of test results
- `summary.py` - Quick status check

### docs/ folder:
All the documentation and academic writeups:
- `PROJECT_SUMMARY.md` - Complete project overview
- `research_journal.md` - My research methodology and findings
- `testing_guide.md` - How to run tests and what they check

### results/ folder:
- `experimental_data/` - All test results and performance data
- Sample outputs showing what the system produces

## How to actually use this

### If you just want to see it work:
1. Install requirements: `pip install -r requirements.txt`
2. Download spaCy model: `python -m spacy download en_core_web_md`
3. Run quick test: `cd tests && python baseline_test.py`
4. Start web interface: `streamlit run app.py`

### If you want to test everything properly:
You'll need an OpenAI API key (costs a few dollars for testing). Put it in a `.env` file, then run the full experimental framework.

### If you're grading this or want to understand the research:
Start with `docs/PROJECT_SUMMARY.md` which has the complete academic writeup.

## Design decisions I made

**Why I used these specific technologies:**
- Streamlit: Easy to build a clean web interface quickly
- OpenAI GPT: Best available model for text classification
- spaCy: Reliable, fast NLP library with good entity recognition
- LangChain: Standard framework for combining LLMs with external data

**Why I built the testing framework:**
Academic projects need proper validation. I wanted to show that this actually works reliably, not just cherry-pick a few examples that look good.

**Why I included fallback modes:**
Real systems need to work even when APIs are down or you hit rate limits. The system gracefully degrades to rule-based classification when the AI isn't available.

## Current status

Everything works. I've tested it pretty thoroughly:
- Entity extraction finds the right IOCs about 90% of the time
- CVE database integration is reliable
- Web interface is responsive and handles errors well
- Test framework runs clean on fresh installs

The main limitation is that you need an OpenAI API key for the full classification features. But even without that, it still extracts entities and provides useful analysis.

## What I learned building this

This was way more complex than I expected when I started. Some things I figured out:
- API integration is harder than it looks (rate limits, timeouts, authentication)
- Building reliable systems requires a lot of error handling
- Testing is crucial but time-consuming
- Documentation matters more than I thought

The hardest part was probably getting all the different APIs to work together reliably, especially handling failures gracefully.

## Future work (Phase-2)

The next phase will add actual automated response capabilities. This Phase-1 system will feed structured data to Phase-2, which will handle:
- Blocking malicious IPs at firewalls
- Quarantining infected systems
- Creating support tickets
- Running incident response playbooks

I'm planning to work on that with a friend after graduation.