# Incident Response Phase-1

My capstone project for automating security incident analysis. Built this to help security teams quickly understand and categorize incidents without having to manually read through everything.

## What this does

Basically takes messy incident reports and automatically:
- Figures out what type of attack it is (phishing, malware, network intrusion, etc.)
- Pulls out important stuff like IP addresses, email addresses, CVE numbers
- Looks up vulnerability details from public databases
- Gives you structured data that can feed into automated response systems

The idea is that Phase-2 (which I'll work on with a friend after graduation) will actually do the response actions, but this Phase-1 handles all the analysis and decision-making.

## How it works

I'm using OpenAI's GPT model for the smart classification part, combined with some traditional NLP techniques for extracting specific information. When the AI isn't available, it falls back to rule-based classification so the system stays reliable.

The web interface is pretty straightforward - you type in an incident description and it spits out a JSON structure with all the analysis results.

## Running it locally

You'll need Python 3.11+ and these packages:

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_md
```

For the AI features, you need an OpenAI API key (the paid one). Create a `.env` file:
```
OPENAI_API_KEY=your_key_here
NVD_API_KEY=optional_nvd_key
```

Then just run:
```bash
streamlit run app.py
```

## Testing the system

I built a pretty comprehensive testing framework for this. You can run basic tests without any API keys:

```bash
cd tests
python baseline_test.py
```

For full testing with all the AI features:
```bash
python experimental_framework.py
```

## Project structure

```
├── app.py              # Main web interface
├── llm_adapter.py      # OpenAI integration + fallbacks
├── extractor.py        # Entity extraction using spaCy
├── nvd.py             # CVE database lookups
├── lc_retriever.py    # Knowledge base search
├── docs/              # All the documentation
├── tests/             # Testing framework
└── results/           # Test results and data
```

## Status

Everything's working well. I've tested it with various types of incidents and the classification is pretty accurate. The entity extraction finds most of the important IOCs, and the fallback system works when APIs are down.

Still need to do some more testing with edge cases and weird input formats, but it's definitely ready for demo and grading.

## What's next (Phase-2)

After I graduate, I'm planning to work with a friend to build the actual automated response part. This system will feed structured incident data to Phase-2, which will handle things like:
- Automatically blocking malicious IPs
- Quarantining infected systems  
- Creating tickets and notifications
- Running response playbooks

## Academic stuff

This project demonstrates several concepts I learned:
- Practical application of NLP in cybersecurity
- Building resilient systems with multiple failure modes
- Integrating multiple APIs and data sources
- Creating confidence-aware automation (not just blindly automating everything)

All the testing methodology and results are documented in the `docs/` folder if you want to see the academic analysis.

## License

MIT License - feel free to use this for your own projects or research.