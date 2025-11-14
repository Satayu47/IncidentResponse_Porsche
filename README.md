# Incident Response Phase-1

This is my capstone project - I've been working on it for months trying to solve a real problem I saw during my internship. Security teams get swamped with incident reports and spend way too much time just figuring out what they're looking at.

## What this does

So basically, you dump an incident report into this thing and it:
- Tells you what kind of attack you're dealing with - uses OWASP Top 10 categories which my advisor recommended
- Digs out the important bits like IP addresses, suspicious emails, CVE numbers
- Cross-references vulnerability databases to get more context  
- Spits out clean JSON that other tools can actually use

I'm planning to build Phase-2 with a classmate after we graduate - that'll handle the actual response workflows. This Phase-1 is all about the analysis and decision making part, which honestly took way longer than I expected.

## How it works

After trying a bunch of different approaches (and wasting like 2 weeks on regex patterns that didn't work), I ended up using Google's Gemini API for the classification logic. It's way more reliable than the rule-based stuff I started with. I also added some traditional NLP using spaCy for pulling out specific data points, plus fallback logic so it doesn't completely break if the API is down.

The chatbot interface uses Streamlit because it's super easy to set up. You type in what happened and it analyzes everything and shows you what it thinks is going on. I added this confidence scoring system too, so it tells you when it's not really sure about something instead of just guessing.

## Running it locally

You'll need Python 3.11+ and the usual packages:

```bash
pip install -r requirements.txt
```

I switched to Google's Gemini API after my initial OpenAI experiments burned through my free credits too fast. You'll need an API key in your `.env` file:
```
LLM_PROVIDER=gemini
GOOGLE_API_KEY=your_key_here
NVD_API_KEY=optional_for_cve_lookups
```

Then just:
```bash
streamlit run app.py
```

It'll open in your browser at localhost:8501. Pretty simple.

## Testing it out

I wrote some realistic scenarios to test with - stuff that actual employees might report:
- "I got suspicious emails asking for my password"
- "Someone tried logging into my account 20 times from Russia" 
- "Database error showing everyone's credit card numbers"

The system should classify each one correctly and extract any important details. There's also a bunch of test cases in the `tests/` folder that cover different OWASP categories - my advisor wanted me to make sure I tested A01, A04, A05, and A07 thoroughly for the demo.

## Project structure

```
├── app.py              # Main chatbot interface (Streamlit)
├── src/                # Core modules I built
│   ├── llm_adapter.py  # Gemini API integration
│   ├── extractor.py    # Entity extraction (uses spaCy)
│   ├── nvd.py         # CVE database lookups
│   ├── lc_retriever.py # Knowledge base search
│   └── owasp_mapping.py # OWASP category helpers
├── tests/             # Test scenarios
├── docs/              # Documentation
└── .env               # API keys (don't commit this!)
```

## What I learned / Challenges

The biggest challenge was honestly getting the AI to not be overconfident. Early versions would just pick one category and run with it, even when the incident was ambiguous. I had to rework the whole prompt engineering part to make it show multiple possibilities when it's not sure.

Also spent forever debugging the conversation memory feature - turns out Streamlit session state is kinda weird. But now it can handle follow-up questions like "isn't it SQL injection?" without losing context.

The user-level detection was actually a fun addition. The system now figures out if someone's a beginner (they say "the website is acting weird") vs an expert (they paste actual SQL injection payloads) and adjusts how technical the response is.

## Current Status

Everything's working pretty well now. I've tested it with different types of incidents and the OWASP classification is accurate most of the time. The entity extraction catches most IP addresses and email addresses, though it sometimes misses weirdly formatted ones.

The confidence-gated playbook system is probably my favorite feature - when the system is really confident (like 70%+), it gives you immediate action steps. When it's less sure, it just asks clarifying questions instead of giving bad advice.

Still need to test some edge cases more thoroughly, but it's definitely ready for the demo next week. My advisor seems happy with it.

## What's next (Phase-2)

After graduation, me and a friend are planning to extend this into a full automated response system. This Phase-1 will feed structured incident data to Phase-2, which will actually do stuff like:
- Blocking malicious IPs automatically
- Quarantining infected machines  
- Creating tickets in the ticketing system
- Running response playbooks

That's gonna be way more complex though since it involves actually touching production systems. This phase is just the analysis part.

## Technologies I used

- **Google Gemini 2.5 Pro** - for the main classification (switched from GPT-4 because of cost)
- **spaCy** - for entity extraction, worked better than my initial regex attempts
- **Streamlit** - for the web interface, super easy to prototype with
- **FAISS** - for the knowledge base retrieval stuff
- **National Vulnerability Database API** - for CVE lookups

The whole multi-provider setup with Gemini as primary and OpenAI as backup took forever to get right, but now it gracefully falls back if one API is down.

## Academic stuff

This project covers several concepts from my coursework:
- OWASP Top 10:2025 taxonomy for real-world security classification
- Confidence-aware AI systems (not just blindly automating everything)
- Natural language processing in cybersecurity context
- Multi-source data integration (NVD, MITRE, etc.)
- User experience design for different expertise levels

I documented all the methodology and testing results in the `docs/` folder for the academic analysis part of the report.

## Contributing

If you want to extend this or use it for your own project, feel free! Just follow the usual stuff - make sure your code works, add tests if you can, and keep the documentation updated.

See CONTRIBUTING.md for more details.

## License

MIT License - use it however you want for your projects or research.