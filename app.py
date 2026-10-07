# python"""
# app.py
# -------
# Streamlit frontend + orchestration for the AI-Powered Email Threat
# Detection, Geolocation and Forensic Intelligence Platform.

# Run with:
#     streamlit run app.py
# """
"""
app.py

-------

Streamlit frontend + orchestration for the AI-Powered Email Threat

Detection, Geolocation and Forensic Intelligence Platform.

Run with:

    streamlit run app.py

"""

from __future__ import annotations

import io
from datetime import datetime

import streamlit as st

from analyzer import get_classifier, run_full_analysis
from utils import attachment_analyzer, forensic_parser, geoip_analyzer
from utils.pdf_report import build_pdf_report

st.set_page_config(
    page_title="Threat Lens",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
if "history" not in st.session_state:
    st.session_state.history = []       # list of full analysis result dicts
if "current_result" not in st.session_state:
    st.session_state.current_result = None

RISK_COLOR = {"Low": "🟢", "Medium": "🟡", "High": "🔴"}
BAND_COLOR = {"LOW RISK": "🟢", "MEDIUM RISK": "🟡", "HIGH RISK": "🔴"}


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
def render_sidebar() -> str:
    with st.sidebar:
        st.markdown("## 🛡️ Threat Lens")
        st.caption("AI-Powered Email Threat Detection")
        st.divider()

        page = st.radio(
            "Navigation",
            ["Dashboard", "Email Analyzer", "Investigation / Forensics", "Help & About"],
            label_visibility="collapsed",
        )

        st.divider()
        st.markdown("**System Status**")

        classifier = get_classifier()
        st.markdown(f"{'🟢' if classifier.available else '🔴'} ML Model: "
                     f"{'Active' if classifier.available else 'Not loaded'}")
        st.markdown("🟢 URL Intelligence: Active")

        geo_status = geoip_analyzer.geoip_status()
        st.markdown(f"{'🟢' if geo_status['available'] else '🟡'} GeoIP: "
                     f"{'Local DB active' if geo_status['available'] else 'Best-effort live lookup'}")

        vt_status = attachment_analyzer.virustotal_status()
        st.markdown(f"{'🟢' if vt_status['configured'] else '⚪'} VirusTotal: "
                     f"{'Configured' if vt_status['configured'] else 'Not configured (optional)'}")

        st.markdown("🟢 Forensic Engine: Active")

        if not classifier.available:
            st.warning(classifier.load_error, icon="⚠️")

        st.divider()
        st.caption("AI-assisted hybrid email threat analysis platform.")
    return page


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
def render_dashboard():
    st.title("AI-Powered Email Threat Detection")
    st.caption("Unified Email Security & Forensic Intelligence")

    history = st.session_state.history
    total = len(history)
    high = sum(1 for r in history if r["threat"]["risk_level"] == "HIGH RISK")
    medium = sum(1 for r in history if r["threat"]["risk_level"] == "MEDIUM RISK")
    low = sum(1 for r in history if r["threat"]["risk_level"] == "LOW RISK")
    total_urls = sum(len(r["url_results"]) for r in history)
    suspicious_urls = sum(
        len([u for u in r["url_results"] if u["risk"] in ("Medium", "High")]) for r in history
    )
    total_attachments = sum(len(r["attachment_results"]) for r in history)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Emails Analyzed", total)
    c2.metric("High Risk", high)
    c3.metric("Medium Risk", medium)
    c4.metric("Low Risk", low)

    c5, c6, c7 = st.columns(3)
    c5.metric("URLs Detected", total_urls)
    c6.metric("Suspicious URLs", suspicious_urls)
    c7.metric("Attachments Detected", total_attachments)

    st.divider()
    st.info(
        "Our platform combines machine learning, security rules, authentication "
        "analysis, threat intelligence and forensic parsing to investigate "
        "suspicious emails."
    )

    st.subheader("Recent Analysis")
    if not history:
        st.warning("No email analyzed yet. Upload an .eml file or paste email content to begin investigation.")
        return

    for r in reversed(history[-8:]):
        rec = r["record"]
        band = r["threat"]["risk_level"]
        with st.expander(
            f"{BAND_COLOR.get(band, '⚪')} {rec.get('subject', '(no subject)') or '(no subject)'} "
            f"— {band} ({r['threat']['score']}/100)"
        ):
            st.write(f"**From:** {rec.get('from', 'unknown')}")
            st.write(f"**AI Classification:** {r['ml_result']['prediction']} "
                      f"({r['ml_result']['confidence']}%)")
            st.write(f"**Analyzed at:** {r.get('analyzed_at', '')}")


# ---------------------------------------------------------------------------
# Email Analyzer
# ---------------------------------------------------------------------------
def render_email_analyzer():
    st.title("Email Analyzer")
    st.caption("Upload a raw .eml file or paste email content to run a full investigation.")

    tab1, tab2 = st.tabs(["📁 Upload .EML", "✍️ Paste Email"])

    record_to_analyze = None

    with tab1:
        uploaded = st.file_uploader("Upload Email File", type=["eml"])
        if uploaded is not None:
            st.success(f"Loaded: {uploaded.name}")
            if st.button("🔍 Analyze Email", key="analyze_upload"):
                raw_bytes = uploaded.getvalue()
                record_to_analyze = forensic_parser.parse_eml_bytes(raw_bytes)

    with tab2:
        col1, col2 = st.columns(2)
        with col1:
            from_addr = st.text_input("From", placeholder="sender@example.com")
            subject = st.text_input("Subject", placeholder="Email subject line")
        with col2:
            to_addr = st.text_input("To", placeholder="recipient@example.com")
        headers_text = st.text_area(
            "Additional Headers (optional)",
            placeholder=(
                "Reply-To: someone@example.com\n"
                "Return-Path: bounce@example.com\n"
                "Authentication-Results: mx.example.com; spf=fail; dkim=pass; dmarc=fail\n"
                "Received: from mail1.example.com (mail1.example.com [203.0.113.5]) ..."
            ),
            height=120,
        )
        body_text = st.text_area("Email Body", height=220, placeholder="Paste the full email body here...")

        if st.button("🔍 Analyze Email", key="analyze_paste"):
            record_to_analyze = forensic_parser.parse_pasted_email(
                from_addr, to_addr, subject, headers_text, body_text
            )

    if record_to_analyze is not None:
        with st.spinner("Running hybrid analysis: ML classification, URL, sender, "
                          "authentication, GeoIP and attachment checks..."):
            result = run_full_analysis(record_to_analyze)
            result["analyzed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.session_state.current_result = result
        st.session_state.history.append(result)
        st.success("Analysis complete. See results below, or open 'Investigation / Forensics' for full detail.")

    if st.session_state.current_result is not None:
        _render_result_summary(st.session_state.current_result)


def _render_result_summary(result):
    rec = result["record"]
    ml = result["ml_result"]
    threat = result["threat"]

    st.divider()
    st.subheader("Email Overview")
    c1, c2 = st.columns(2)
    with c1:
        st.write(f"**Subject:** {rec.get('subject', '') or '-'}")
        st.write(f"**Sender:** {rec.get('from', '') or '-'}")
        st.write(f"**Recipient:** {rec.get('to', '') or '-'}")
    with c2:
        st.write(f"**Date:** {rec.get('date', '') or '-'}")
        st.write(f"**Reply-To:** {rec.get('reply_to', '') or '-'}")
        st.write(f"**Return-Path:** {rec.get('return_path', '') or '-'}")

    st.divider()
    band = threat["risk_level"]
    score_col, class_col = st.columns(2)
    with score_col:
        st.metric("THREAT SCORE", f"{threat['score']} / 100", label_visibility="visible")
        st.progress(threat["score"] / 100)
        st.markdown(f"### {BAND_COLOR.get(band, '⚪')} {band}")
    with class_col:
        st.subheader("AI Email Classification")
        st.write(f"**Prediction:** {ml['prediction']}")
        st.progress(min(max(ml["confidence"] / 100, 0.0), 1.0))
        st.write(f"**Confidence:** {ml['confidence']}%")
        st.caption(
            "The ML model analyzes textual patterns in the email using TF-IDF "
            "features and a Multinomial Naive Bayes classifier."
        )
        if ml.get("note"):
            st.info(ml["note"])

    st.subheader("Why?")
    for reason in threat["reasons"]:
        st.markdown(f"✓ {reason}")
    if threat["investigate_further"]:
        st.markdown("**Recommended investigation:**")
        for item in threat["investigate_further"]:
            st.markdown(f"🔎 {item}")

    st.divider()
    if st.button("📄 Generate Forensic Report"):
        pdf_bytes = build_pdf_report(result)
        st.download_button(
            "⬇️ Download Forensic Report (PDF)",
            data=pdf_bytes,
            file_name=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mime="application/pdf",
        )


# ---------------------------------------------------------------------------
# Investigation / Forensics
# ---------------------------------------------------------------------------
def render_investigation():
    st.title("Investigation / Forensics")

    result = st.session_state.current_result
    if result is None:
        st.warning("No email analyzed yet. Go to 'Email Analyzer' to investigate an email first.")
        return

    rec = result["record"]

    st.subheader("Email Metadata")
    st.json({
        "subject": rec.get("subject", ""),
        "from": rec.get("from", ""),
        "display_name": rec.get("from_display_name", ""),
        "to": rec.get("to", ""),
        "date": rec.get("date", ""),
        "reply_to": rec.get("reply_to", ""),
        "return_path": rec.get("return_path", ""),
    }, expanded=False)

    with st.expander("Header Analysis (raw headers)"):
        if rec.get("headers"):
            for k, v in rec["headers"].items():
                st.text(f"{k}: {v}")
        else:
            st.info("No raw headers were available for this email.")

    st.subheader("Observable Email Transmission Timeline")
    received = rec.get("received_headers", [])
    if received:
        hop_labels = ["Email Received"] + [f"Mail Server {i}" for i in range(1, len(received))] + \
            (["Destination Server"] if len(received) > 1 else [])
        # Build a simple readable hop list (Received headers are usually newest-first)
        for i, hop in enumerate(reversed(received)):
            st.markdown(f"**Hop {i + 1}**")
            st.code(hop.strip(), language="text")
            if i < len(received) - 1:
                st.markdown("↓")
        st.caption(
            "This timeline reflects the mail-hop order recorded in the email's own "
            "Received headers. It is not always the attacker's complete route."
        )
    else:
        st.info("No Received headers were found to reconstruct a transmission timeline.")

        st.subheader("Extracted IP Addresses & GeoIP Intelligence")
    if result["geo_results"]:
        st.dataframe(
            [{
                "IP Address": g["ip"], "Country": g["country"], "Region": g["region"],
                "City": g["city"], "ISP": g["isp"], "Organization": g["organization"],
                "ASN": g["asn"], "Source": g["source"],
            } for g in result["geo_results"]],
            use_container_width=True,
        )

        # The Received-header chain lists the most recent mail hop first and
        # the original sending server last, so the LAST public IP found is
        # the closest approximation of the scammer's originating network.
        originating = result["geo_results"][-1]
        st.markdown(
            f"**🔎 Likely originating IP (closest hop to the sender):** "
            f"`{originating['ip']}` — {originating['city']}, {originating['region']}, "
            f"{originating['country']} (ISP: {originating['isp']})"
        )

        mappable = [g for g in result["geo_results"]
                    if g.get("latitude") not in (None, "Unavailable")
                    and g.get("longitude") not in (None, "Unavailable")]
        if mappable:
            import pandas as pd
            map_df = pd.DataFrame([{"lat": g["latitude"], "lon": g["longitude"]} for g in mappable])
            st.map(map_df, zoom=1)
        else:
            st.caption("Map view unavailable — coordinates were not returned by the GeoIP source.")

        st.caption(
            "IP geolocation provides approximate network/location information and "
            "does not identify the attacker's exact physical location."
        )
    else:
        st.info("No public IP addresses were found in the Received headers.")

    st.subheader("URL Analysis")
    if result["url_results"]:
        st.dataframe(
            [{
                "URL": u["url"], "Domain": u["domain"], "HTTPS": u["https"],
                "IP-based": u["ip_based"], "Length": u["length"],
                "Suspicious Indicators": "; ".join(u["indicators"]) or "None",
                "Threat Intel": u.get("threat_intel", "N/A"),
                "Risk": u["risk"],
            } for u in result["url_results"]],
            use_container_width=True,
        )
    else:
        st.info("No URLs were detected in this email.")

    st.subheader("Sender Analysis")
    sender = result["sender_result"]
    st.markdown(f"**Sender Risk:** {RISK_COLOR.get(sender['risk'], '⚪')} {sender['risk']}")
    if sender["reasons"]:
        for r in sender["reasons"]:
            st.markdown(f"⚠️ {r}")
    else:
        st.success("No sender mismatch indicators detected.")

    st.subheader("Authentication Results (SPF / DKIM / DMARC)")
    auth = result["auth_result"]
    a1, a2, a3 = st.columns(3)
    for col, label, key in [(a1, "SPF", "spf"), (a2, "DKIM", "dkim"), (a3, "DMARC", "dmarc")]:
        value = auth[key]
        icon = "✅" if value == "PASS" else ("❌" if value == "FAIL" else "⚪")
        col.metric(label, f"{icon} {value}")
        col.caption(auth["explanations"][label])
    if auth.get("note"):
        st.info(auth["note"])

    st.subheader("Attachments")
    if result["attachment_results"]:
        for a in result["attachment_results"]:
            with st.expander(f"{RISK_COLOR.get(a['risk'], '⚪')} {a['filename']} ({a['risk']} risk)"):
                st.write(f"**MIME type:** {a['content_type']}")
                st.write(f"**Size:** {a['size_human']}")
                st.write(f"**Extension:** .{a['extension']}" if a["extension"] else "**Extension:** none")
                st.code(a["sha256"] or "N/A", language="text")
                if a["indicators"]:
                    for ind in a["indicators"]:
                        st.markdown(f"⚠️ {ind}")
                else:
                    st.success("No suspicious filename/MIME patterns detected.")
                st.write(f"**VirusTotal:** {a['virustotal']['verdict']}")
    else:
        st.info("No attachments were found in this email.")

    st.subheader("Forensic Indicators")
    indicators_summary = []
    if result["ml_result"]["prediction"] == "SPAM":
        indicators_summary.append("Email content classified as SPAM by the ML model.")
    indicators_summary += [f"URL risk: {u['url']} → {u['risk']}" for u in result["url_results"] if u["risk"] != "Low"]
    indicators_summary += sender["reasons"]
    if auth["spf"] == "FAIL":
        indicators_summary.append("SPF authentication failed.")
    if auth["dkim"] == "FAIL":
        indicators_summary.append("DKIM authentication failed.")
    if auth["dmarc"] == "FAIL":
        indicators_summary.append("DMARC authentication failed.")
    indicators_summary += [f"Attachment risk: {a['filename']} → {a['risk']}"
                            for a in result["attachment_results"] if a["risk"] != "Low"]

    if indicators_summary:
        for item in indicators_summary:
            st.markdown(f"🔸 {item}")
    else:
        st.success("No notable forensic indicators were identified.")

    st.divider()
    if st.button("📄 Generate Forensic Report", key="forensic_pdf_btn"):
        pdf_bytes = build_pdf_report(result)
        st.download_button(
            "⬇️ Download Forensic Report (PDF)",
            data=pdf_bytes,
            file_name=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mime="application/pdf",
            key="forensic_pdf_dl",
        )


# ---------------------------------------------------------------------------
# Help & About
# ---------------------------------------------------------------------------
def render_help():
    st.title("Help & About")

    st.header("What is this platform?")
    st.write(
        "An AI-assisted hybrid email threat analysis platform for investigating "
        "suspicious emails. It goes beyond simple spam detection by combining "
        "machine learning with security rules, protocol checks and forensic "
        "parsing into one explainable investigation workflow."
    )

    st.header("How does it work?")
    st.write(
        "An uploaded or pasted email is forensically parsed into headers, body "
        "text, URLs, IP addresses and attachments. Each piece of evidence is then "
        "analyzed by a dedicated module, and the results are combined into a "
        "single, explainable threat score."
    )

    st.header("Why machine learning?")
    st.write(
        "Spam and unwanted email often share recurring textual patterns. A "
        "TF-IDF + Multinomial Naive Bayes classifier, trained on the "
        "SpamAssassin Public Corpus, captures those patterns to flag likely "
        "spam content."
    )

    st.header("Why are other features not trained?")
    st.write(
        "URL structure, sender header mismatches, authentication protocols and "
        "attachment types are governed by well-defined technical rules and "
        "internet standards. Encoding these as explicit, auditable rules is "
        "more reliable and transparent than training a model to guess them."
    )

    st.header("What is SPF?")
    st.write("Checks whether the sending mail server is authorized to send on behalf of the domain.")

    st.header("What is DKIM?")
    st.write("Checks the cryptographic signature attached to the email to verify it was not altered in transit.")

    st.header("What is DMARC?")
    st.write("Checks alignment between SPF/DKIM results and the visible From domain, applying the domain owner's policy.")

    st.header("What is GeoIP?")
    st.write(
        "GeoIP maps a public IP address to an approximate network location "
        "(country, region, city, ISP) using a geolocation database or service. "
        "It reflects the network's registered location, not a person's precise location."
    )

    st.header("What is forensic analysis?")
    st.write(
        "The systematic extraction and review of email evidence — headers, "
        "the mail-hop chain, URLs, IPs and attachments — to support a "
        "security investigation."
    )

    st.header("Limitations")
    st.markdown(
        "- The ML component only evaluates textual spam-like patterns; it is not a phishing-specific model.\n"
        "- URL and sender checks are heuristic; matches require human review, not automatic action.\n"
        "- GeoIP data is approximate and reflects network registration, not physical location.\n"
        "- Threat intelligence coverage (PhishTank/VirusTotal) depends on optional external services.\n"
        "- \"Not found in available intelligence\" never means a URL or file is confirmed safe."
    )

    st.header("Hybrid Architecture")
    st.markdown(
        "**ML:** Email content classification (TF-IDF + Multinomial Naive Bayes)\n\n"
        "**Rules:** URL, sender, attachment analysis\n\n"
        "**Protocols:** SPF / DKIM / DMARC parsing\n\n"
        "**Database/API:** GeoIP / optional threat intelligence (PhishTank, VirusTotal)\n\n"
        "**Correlation:** Final explainable 0-100 risk score"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    page = render_sidebar()
    if page == "Dashboard":
        render_dashboard()
    elif page == "Email Analyzer":
        render_email_analyzer()
    elif page == "Investigation / Forensics":
        render_investigation()
    else:
        render_help()


if __name__ == "__main__":
    main()




