from __future__ import annotations

import json
from io import StringIO

import pandas as pd
import plotly.express as px
import streamlit as st

from threatintel.engine import configured_keys, enrich_and_save, enrich_indicator
from threatintel.normalizer import IndicatorError
from threatintel.storage import clear_history, get_latest, get_recent

st.set_page_config(
    page_title="Threat Intel Enrichment Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .stApp { background: #0b1020; color: #e6edf7; }
      [data-testid="stSidebar"] { background: #10182b; border-right: 1px solid #26334d; }
      [data-testid="stMetric"] { background: #121c31; padding: 16px 18px; border: 1px solid #26334d; border-radius: 12px; }
      div[data-testid="stDataFrame"] { border: 1px solid #26334d; border-radius: 8px; }
      .hero { padding: 18px 0 10px 0; }
      .eyebrow { color: #69d5c4; font-size: .78rem; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; }
      .subtle { color: #a7b6cf; }
      .source-pill { border: 1px solid #33425e; padding: 3px 8px; border-radius: 20px; margin-right: 6px; color: #bac9df; font-size: .8rem; }
      hr { border-color: #26334d; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.sidebar.markdown("# 🛡️ TI Enrichment")
st.sidebar.caption("Threat intelligence workbench")
page = st.sidebar.radio("Workspace", ["Overview", "Enrich indicators", "History", "Scoring & methodology"], index=0, key="workspace")
st.sidebar.divider()

keys = configured_keys()
allow_external = st.sidebar.toggle("Enable external reputation lookups", value=False)
if allow_external:
    st.sidebar.warning("Submitted indicators may be sent to VirusTotal and/or AbuseIPDB. Do not submit confidential internal indicators unless approved.")
else:
    st.sidebar.caption("Local-only mode · no indicator is sent to a provider")

st.sidebar.markdown("**Provider configuration**")
st.sidebar.write(("🟢" if keys["virustotal"] else "⚪") + " VirusTotal API key " + ("configured" if keys["virustotal"] else "not configured"))
st.sidebar.write(("🟢" if keys["abuseipdb"] else "⚪") + " AbuseIPDB API key " + ("configured" if keys["abuseipdb"] else "not configured"))
st.sidebar.caption("Keys are read from your local .env file; never commit that file.")


def _display_frame(records: list[dict], columns: list[str] | None = None) -> None:
    if not records:
        st.info("No indicators have been enriched yet. Add an IOC in the Enrich indicators workspace, or load the safe sample set.")
        return
    frame = pd.DataFrame(records)
    if columns:
        columns = [column for column in columns if column in frame.columns]
        frame = frame[columns]
    st.dataframe(frame, use_container_width=True, hide_index=True)


def _parse_uploaded_csv(upload) -> list[str]:
    if upload is None:
        return []
    try:
        upload.seek(0)
        frame = pd.read_csv(upload, dtype=str, keep_default_na=False)
    except Exception as exc:
        raise ValueError(f"Could not read CSV: {exc}") from exc
    if frame.empty or len(frame.columns) == 0:
        return []
    candidates = {"indicator", "ioc", "value", "observable", "ip", "domain", "url", "hash"}
    selected = next((col for col in frame.columns if col.strip().lower() in candidates), frame.columns[0])
    return [str(value).strip() for value in frame[selected].tolist() if str(value).strip()]


DEMO_VALUES = [
    "login-verification.example",
    "hxxps://account-verify.example/login?reset=password",
    "http://192.0.2.44/login/verify",
    "192.0.2.10",
    "0000000000000000000000000000000000000000000000000000000000000000",
]

def _load_demo_and_navigate() -> None:
    st.session_state["ioc_text"] = "\n".join(DEMO_VALUES)
    st.session_state["load_demo_notice"] = True
    st.session_state["workspace"] = "Enrich indicators"

def _insert_demo_values() -> None:
    st.session_state["ioc_text"] = "\n".join(DEMO_VALUES)


def _render_result(result: dict) -> None:
    color = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Unknown": "⚪"}.get(result["verdict"], "⚪")
    st.subheader(f"{color} {result['verdict']} · {result['risk_score']}/100")
    st.progress(result["risk_score"] / 100)
    st.write(result["summary"])
    left, right = st.columns([1, 1])
    with left:
        st.markdown("**Indicator details**")
        st.json({"original": result["indicator"], "normalized": result["normalized"], "type": result["ioc_type"]})
        st.markdown("**Evidence & reasoning**")
        if result.get("evidence"):
            for item in result["evidence"]:
                st.markdown(f"- {item}")
        else:
            st.caption("No evidence available.")
    with right:
        st.markdown("**Provider results**")
        st.json(result.get("sources", {}))
        st.caption("The score is an investigation-priority aid, not proof that an indicator is malicious or benign.")


if page == "Overview":
    st.markdown('<div class="hero"><div class="eyebrow">Security operations · threat intelligence</div><h1>Threat Intelligence Enrichment Engine</h1><div class="subtle">Normalize indicators, enrich with reputation context, and prioritize investigation from one analyst workbench.</div></div>', unsafe_allow_html=True)
    records = get_latest()
    if not records:
        st.info("Your workspace is ready. Start in **Enrich indicators** or use this safe local-only demo set.")
        st.button("Load safe demo indicators", type="primary", on_click=_load_demo_and_navigate)
    scores = [int(row["risk_score"]) for row in records]
    high_count = sum(score >= 50 for score in scores)
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Unique indicators", len(records))
    c2.metric("High / critical", high_count)
    c3.metric("Average risk score", f"{avg_score}/100")
    c4.metric("External lookups", "Opt-in", help="External queries remain disabled until you enable them in the sidebar.")
    st.divider()
    chart_col, type_col = st.columns(2)
    with chart_col:
        st.markdown("#### Risk distribution")
        if records:
            risk_order = ["Critical", "High", "Medium", "Low", "Unknown"]
            risk_counts = pd.Series([row["verdict"] for row in records]).value_counts().reindex(risk_order, fill_value=0).rename_axis("Verdict").reset_index(name="Indicators")
            fig = px.bar(risk_counts, x="Verdict", y="Indicators", text="Indicators", category_orders={"Verdict": risk_order}, color="Verdict")
            fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", showlegend=False, margin=dict(l=10, r=10, t=20, b=10))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.caption("Risk charts appear after the first enrichment.")
    with type_col:
        st.markdown("#### Indicators by type")
        if records:
            type_counts = pd.Series([row["ioc_type"] for row in records]).value_counts().rename_axis("IOC type").reset_index(name="Indicators")
            fig = px.pie(type_counts, names="IOC type", values="Indicators", hole=.55)
            fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", margin=dict(l=10, r=10, t=20, b=10), legend_title_text="")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.caption("IOC type chart appears after the first enrichment.")
    st.markdown("#### Latest findings")
    _display_frame(records, ["created_at", "normalized", "ioc_type", "risk_score", "verdict", "summary"])

elif page == "Enrich indicators":
    st.title("Enrich indicators")
    st.caption("Paste one IOC per line or upload a CSV. Supported: IPv4/IPv6, domains, HTTP(S) URLs, MD5, SHA-1, and SHA-256.")
    if st.session_state.pop("load_demo_notice", False):
        st.success("Safe demo indicators loaded. They use reserved example data and are intended for local-only testing.")
    demo_button_col, _ = st.columns([1, 3])
    with demo_button_col:
        st.button("Insert sample indicators", on_click=_insert_demo_values)
    st.text_area("Indicators", key="ioc_text", height=150, placeholder="8.8.8.8\nexample.com\nhxxps://login[.]example/path\n<sha256 hash>")
    upload = st.file_uploader("Optional CSV upload", type=["csv"], help="Uses a column named indicator, ioc, value, observable, ip, domain, url, or hash; otherwise uses the first column.")
    if allow_external and keys["virustotal"]:
        st.warning("VirusTotal's public API has a low request quota. For a public-key workflow, this run is capped at four indicators to reduce rate-limit errors.")
    if st.button("Run enrichment", type="primary", use_container_width=True):
        raw_values = [line.strip() for line in st.session_state.get("ioc_text", "").splitlines() if line.strip()]
        try:
            raw_values.extend(_parse_uploaded_csv(upload))
        except ValueError as exc:
            st.error(str(exc))
            # Continue with pasted indicators even if the optional upload is invalid.
        # Keep first occurrence while preserving input order.
        unique_values = list(dict.fromkeys(raw_values))
        if not unique_values:
            st.error("Add an indicator or upload a CSV first.")
        else:
            maximum = 4 if allow_external and keys["virustotal"] else 100
            if len(unique_values) > maximum:
                st.warning(f"This run will process the first {maximum} indicators. The remaining {len(unique_values) - maximum} were not processed.")
                unique_values = unique_values[:maximum]
            results = []
            progress = st.progress(0)
            status = st.empty()
            for index, raw in enumerate(unique_values, start=1):
                status.write(f"Enriching {index}/{len(unique_values)}…")
                try:
                    result = enrich_and_save(raw, allow_external=allow_external)
                    results.append(result)
                except IndicatorError as exc:
                    st.error(f"Skipped `{raw}`: {exc}")
                except Exception as exc:
                    st.error(f"Unexpected error while processing `{raw}`: {type(exc).__name__}: {exc}")
                progress.progress(index / len(unique_values))
            status.empty()
            if results:
                st.success(f"Processed and saved {len(results)} indicator(s) to local SQLite history.")
                for result in results:
                    with st.expander(f"{result['verdict']} · {result['risk_score']}/100 · {result['normalized']}", expanded=len(results) == 1):
                        _render_result(result)
                csv_frame = pd.DataFrame([{
                    "indicator": r["indicator"], "normalized": r["normalized"], "ioc_type": r["ioc_type"],
                    "risk_score": r["risk_score"], "verdict": r["verdict"], "summary": r["summary"],
                    "evidence": " | ".join(r["evidence"]), "sources": json.dumps(r["sources"]),
                } for r in results])
                st.download_button("Download results as CSV", csv_frame.to_csv(index=False).encode("utf-8"), "enrichment-results.csv", "text/csv")

elif page == "History":
    st.title("Enrichment history")
    st.caption("Every successful enrichment is saved locally in SQLite. The table below shows each run; repeated indicators remain in history.")
    history = get_recent(limit=500)
    if history:
        frame = pd.DataFrame([{
            "ID": r["id"], "Time (UTC)": r["created_at"], "Indicator": r["normalized"], "Type": r["ioc_type"],
            "Risk score": r["risk_score"], "Verdict": r["verdict"], "Summary": r["summary"],
        } for r in history])
        filter_col, type_col = st.columns(2)
        with filter_col:
            verdict_filter = st.multiselect("Filter by verdict", ["Critical", "High", "Medium", "Low", "Unknown"])
        with type_col:
            available_types = sorted(frame["Type"].dropna().unique().tolist())
            type_filter = st.multiselect("Filter by indicator type", available_types)
        filtered = frame
        if verdict_filter:
            filtered = filtered[filtered["Verdict"].isin(verdict_filter)]
        if type_filter:
            filtered = filtered[filtered["Type"].isin(type_filter)]
        st.dataframe(filtered, use_container_width=True, hide_index=True)
        selected_id = st.selectbox("Inspect a saved result", frame["ID"].tolist())
        selected = next((r for r in history if r["id"] == selected_id), None)
        if selected:
            with st.expander("Saved evidence", expanded=False):
                st.markdown(f"**{selected['normalized']}** · {selected['verdict']} ({selected['risk_score']}/100)")
                st.write(selected["summary"])
                for item in selected["evidence"]:
                    st.markdown(f"- {item}")
                st.json(selected["sources"])
        with st.expander("Danger zone: clear local history"):
            st.warning("This permanently deletes the enrichment history from this local app database.")
            confirm_clear = st.checkbox("I understand this cannot be undone.")
            if st.button("Clear history", disabled=not confirm_clear):
                clear_history()
                st.success("Local history cleared.")
                st.rerun()
    else:
        st.info("No saved enrichment history yet.")

else:
    st.title("Scoring & methodology")
    st.markdown("""
    ### Supported workflow
    1. **Normalize** common defanged formats, classify the IOC, and validate basic syntax.
    2. **Analyze locally** using transparent, intentionally weak heuristics.
    3. **Enrich optionally** with VirusTotal and AbuseIPDB when the sidebar setting is enabled and API keys are configured.
    4. **Score and preserve evidence** in local SQLite so analysts can investigate and export results.

    ### Risk score interpretation
    | Score | Label | Suggested handling |
    |---:|---|---|
    | 0 | Unknown | Insufficient positive risk evidence; not proof of safety |
    | 1–24 | Low | Review context if relevant |
    | 25–49 | Medium | Investigate supporting evidence |
    | 50–74 | High | Prioritize analyst review |
    | 75–100 | Critical | Urgent review, while validating source confidence |

    ### Important limitations
    - Local heuristics are explainable signals, not a malware classifier. Heuristics alone are capped below the High threshold.
    - Provider reputation can be stale, incomplete, or wrong. Detection counts are not interchangeable across providers.
    - A score of zero or an empty provider report does not mean an IOC is safe.
    - The app does not download files, visit submitted URLs, scan hosts, or execute samples.
    - Non-global IP addresses are not submitted to external providers. URL/domain/hash indicators may still be sensitive: external lookups stay disabled by default.
    - This is a portfolio project, not a production security control or automated blocking system.

    ### Provider references
    - [VirusTotal API v3 overview](https://docs.virustotal.com/reference/overview)
    - [AbuseIPDB API v2 documentation](https://docs.abuseipdb.com/)
    - [Streamlit installation guide](https://docs.streamlit.io/get-started/installation)
    """)

st.sidebar.divider()
st.sidebar.caption("Portfolio build · Python + Streamlit + SQLite")
