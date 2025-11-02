import time, json, io, os
import streamlit as st
from extractor import extract_entities, extract_IOCs, detect_symptoms
from llm_adapter import classify_and_slots, LLMUnavailable
from nvd import fetch_cve, mitre_url
from lc_retriever import build_inmemory_kb, format_retrieval_snippets

# Thresholds mandated by the paper/algorithms
THRESH_LOW = float(os.getenv("THRESH_LOW", 0.6))  # ask one clarification
THRESH_GO  = float(os.getenv("THRESH_GO", 0.7))   # ready to hand off

REPORT_CATEGORY_MAP = {
    "sql_injection": "Injection Attack",
    "xss": "Injection Attack",
    "ssrf": "Injection Attack",
    "rce": "Injection Attack",
    "bruteforce": "Denial of Service",
    "dos": "Denial of Service",
    "misconfig": "Misconfiguration",
    "phishing": "Phishing",
    "other": "Other"
}

st.set_page_config(page_title="IR ChatOps — Phase 1", layout="wide")
st.title("Incident Response ChatOps — Phase 1")
st.caption("Input → IOCs/Entities → NVD context → OpenAI classification → Clarify if needed")

if "history" not in st.session_state:
    st.session_state.history = [
        {"role":"assistant","content":"Hi! Tell me what happened—I'll analyze it and only ask one quick follow-up if needed."}
    ]
if "phase1_output" not in st.session_state:
    st.session_state.phase1_output = None
if "asked_slots" not in st.session_state:
    st.session_state.asked_slots = set()
if "last_input_cache" not in st.session_state:
    st.session_state.last_input_cache = {}

def templated_reply(user_text: str, label: str, score: float, iocs: dict, rationale: str, kb_present: bool, followup: str|None):
    sig = []
    if iocs.get("ip"):  sig.append(f"ip={', '.join(iocs['ip'][:2])}")
    if iocs.get("url"): sig.append(f"url={', '.join(iocs['url'][:1])}")
    if iocs.get("cve"): sig.append(f"cve={', '.join(iocs['cve'][:2])}")
    signals = " · ".join(sig) if sig else "no indicators yet"

    parts = []
    parts.append("Understood. I analyzed that incident:")
    parts.append(f"**Classification:** {label} (conf {score:.2f})")
    if rationale:
        parts.append(f"**Rationale:** {rationale}")
    parts.append(f"**Signals:** {signals}")
    if kb_present:
        parts.append("**CVE context available.**")
    if followup:
        parts.append(f"**Quick question:** {followup}")
    else:
        parts.append("Ready to hand this to Phase 2.")
    return "\n\n".join(parts)

# Render prior messages
for m in st.session_state.history:
    with st.chat_message(m["role"]):
        st.markdown(m["content"])

user_text = st.chat_input("Describe the incident…")
if user_text:
    st.session_state.history.append({"role":"user","content":user_text})
    with st.chat_message("user"): st.markdown(user_text)

    with st.chat_message("assistant"):
        with st.spinner("Analyzing…"):
            t0 = time.perf_counter()

            # 1) Extraction
            ents = extract_entities(user_text)
            iocs = extract_IOCs(user_text)

            # 2) NVD CVE context (free; optional NVD key improves rate limit)
            kb_context = ""
            if ents.cves:
                docs = [fetch_cve(c) for c in ents.cves]
                ret = build_inmemory_kb(docs)
                if ret:
                    # small k to reduce tokens
                    kb_context = format_retrieval_snippets(ret.get_relevant_documents(user_text))

            # 3) Classification (OpenAI → JSON) with retry/backoff inside; graceful degradation if quota out
            rationale = ""
            cache_key = user_text.strip()
            out = None
            if cache_key in st.session_state.last_input_cache:
                out = st.session_state.last_input_cache[cache_key]
            if out is None:
                try:
                    out = classify_and_slots(
                        text=user_text,
                        kb_context=kb_context,
                        history=st.session_state.history[-4:]
                    )
                    st.session_state.last_input_cache[cache_key] = out
                except LLMUnavailable:
                    st.warning("Degraded mode: OpenAI API quota unavailable. Using local analysis for now.")
                except Exception:
                    pass

            missing = set(); evidence = []
            if out:
                label     = out.get("label","other")
                score     = float(out.get("score",0.0))
                evidence  = out.get("evidence",[])
                rationale = out.get("rationale","")
                missing   = set(out.get("missing",[]))
            else:
                # Local heuristic fallback
                s = detect_symptoms(user_text)
                label, score, evidence = s.label, s.score, s.evidence
                rationale = "Local heuristic based on keywords/patterns."

            # 4) One follow-up max, no repeats
            followup = None
            if score < THRESH_LOW:
                followup = "Which application/service and endpoint is affected?"
            elif not iocs.get("ip") and not iocs.get("url"):
                followup = "Do you have an affected IP or URL?"
            else:
                qmap = {
                    "app":"Which application/service is affected?",
                    "endpoint":"Which endpoint/route is affected?",
                    "ip":"Which source IP is involved?",
                    "url":"Which URL is involved?",
                    "user":"Which user/account is impacted?"
                }
                for k in ("app","endpoint","ip","url","user"):
                    if k in missing:
                        followup = qmap[k]; break

            # don't repeat the same follow-up
            if followup and followup in st.session_state.asked_slots:
                followup = None
            elif followup:
                st.session_state.asked_slots.add(followup)

            sig = []
            if iocs.get("ip"):  sig.append(f"ip={', '.join(iocs['ip'][:2])}")
            if iocs.get("url"): sig.append(f"url={', '.join(iocs['url'][:1])}")
            if ents.cves:       sig.append(f"cve={', '.join(ents.cves[:2])}")
            signals = " · ".join(sig) if sig else "no indicators yet"

            # 5) Chatty response (works both full/degenerate modes)
            msg = templated_reply(
                user_text=user_text,
                label=label,
                score=score,
                iocs=iocs,
                rationale=rationale,
                kb_present=bool(kb_context),
                followup=followup if (followup and score < THRESH_GO) else None
            )
            st.markdown(msg)

            # 5) Phase-2 handoff JSON
            report_category = REPORT_CATEGORY_MAP.get(label, "Other")
            st.session_state.phase1_output = {
                "incident_type": report_category,
                "fine_label": label,
                "confidence": score,
                "rationale": rationale,
                "entities": ents.__dict__,
                "iocs": iocs,
                "related_CVEs": ents.cves,
                "kb_excerpt": kb_context[:600],
                "timestamp_ms": round((time.perf_counter()-t0)*1000,1)
            }

            with st.expander("Advanced details (Phase-2 input)"):
                st.json(st.session_state.phase1_output)
                if ents.cves:
                    st.markdown("**MITRE CVE Links:**")
                    for c in ents.cves[:5]:
                        st.markdown(f"- [{c}]({mitre_url(c)})")

            # 6) download JSON
            if st.session_state.phase1_output:
                import io
                buf = io.BytesIO(json.dumps(st.session_state.phase1_output, indent=2).encode("utf-8"))
                st.download_button(
                    "Download Phase-1 Output (JSON)",
                    data=buf,
                    file_name="phase1_output.json",
                    mime="application/json"
                )

    st.session_state.history.append({"role":"assistant","content":msg})