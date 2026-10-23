"""PhishGuard AI: Streamlit web interface.

Run from the project folder:
    python -m streamlit run app.py

The app only analyses the text you paste. It never opens links, never
calls external services and does not store or log your messages.
"""

import html
import json

import pandas as pd
import streamlit as st

from src.analysis import CHANNEL_EMAIL, CHANNEL_SMS, AnalysisResult, analyse_message
from src import config
from src.phishing_detector import ModelNotFoundError, PhishingDetector
from src.risk_assessment import (
    HIGH,
    MEDIUM,
    REASON_BORDERLINE,
    REASON_INDICATORS,
    REASON_MEDIUM_BAND,
    format_score,
    format_threshold,
)

MAX_EMAIL_CHARS = 20000
MAX_SMS_CHARS = 2000
EMAIL_OPTION = "Email Analysis"
SMS_OPTION = "SMS Analysis"

st.set_page_config(page_title="PhishGuard AI", page_icon="🛡️", layout="centered")

# ---------------------------------------------------------------- styling
st.markdown("""
<style>
.pg-header {background: #0F2A5C; color: #FFFFFF; padding: 1.4rem 1.6rem; border-radius: 12px; margin-bottom: 1.2rem;}
.pg-header h1 {color: #FFFFFF; font-size: 2rem; margin: 0; padding: 0;}
.pg-header .pg-subtitle {color: #C9D8F5; font-size: 1.05rem; margin: 0.2rem 0 0.6rem 0;}
.pg-header p {color: #E6ECF7; margin: 0; font-size: 0.95rem;}
.pg-card {border: 1px solid #D5DDEA; border-left-width: 6px; border-radius: 10px; padding: 0.9rem 1rem;
          background: #FFFFFF; min-height: 185px; margin-bottom: 0.6rem;}
.pg-card-title {font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; color: #4A5B7A;}
.pg-card-value {font-size: 1.35rem; font-weight: 700; margin: 0.25rem 0;}
.pg-card-caption {font-size: 0.82rem; color: #4A5B7A;}
.pg-danger  {border-left-color: #B42318; background: #FEF3F2;} .pg-danger  .pg-card-value {color: #B42318;}
.pg-warning {border-left-color: #B54708; background: #FFFAEB;} .pg-warning .pg-card-value {color: #93370D;}
.pg-safe    {border-left-color: #067647; background: #ECFDF3;} .pg-safe    .pg-card-value {color: #067647;}
.pg-neutral {border-left-color: #1E4FA3; background: #EFF4FF;} .pg-neutral .pg-card-value {color: #1E3A8A;}
.pg-message {border: 1px solid #D5DDEA; border-radius: 10px; padding: 0.9rem 1rem; background: #F8FAFD;
             white-space: pre-wrap; word-break: break-word; max-height: 320px; overflow-y: auto;
             font-size: 0.92rem; line-height: 1.5;}
.pg-message mark {background: #FDE68A; color: #0F1E3D; padding: 0 2px; border-radius: 3px;}
.pg-table {width: 100%; border-collapse: collapse; font-size: 0.88rem; margin-bottom: 0.4rem;}
.pg-table th {background: #EFF4FF; color: #0F2A5C; text-align: left; padding: 0.5rem; border: 1px solid #D5DDEA;}
.pg-table td {padding: 0.5rem; border: 1px solid #D5DDEA; vertical-align: top; word-break: break-all;}
.pg-table td.pg-warn {word-break: normal; color: #93370D;}
.pg-table td.pg-ok {word-break: normal; color: #067647;}
.pg-footer {font-size: 0.82rem; color: #4A5B7A; border-top: 1px solid #D5DDEA; padding-top: 0.8rem; margin-top: 2rem;}
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------- model loading
@st.cache_resource(show_spinner="Loading the trained model...")
def load_detector() -> PhishingDetector:
    """Loaded once per app session and then reused for every analysis."""
    return PhishingDetector(config.MODEL_PATH, config.THRESHOLDS_PATH)


@st.cache_data
def load_test_results() -> dict | None:
    """Actual test-set results written by evaluate_model.py (None if not run yet)."""
    if not config.EVALUATION_REPORT_PATH.exists():
        return None
    with open(config.EVALUATION_REPORT_PATH, encoding="utf-8") as file:
        return json.load(file)["splits"]["test"]


# ---------------------------------------------------------------- helpers
def card(title: str, value: str, caption: str, tone: str) -> str:
    return (f'<div class="pg-card pg-{tone}"><div class="pg-card-title">{title}</div>'
            f'<div class="pg-card-value">{value}</div><div class="pg-card-caption">{caption}</div></div>')


def clear_inputs():
    for key in ("subject", "email_body", "sms_body"):
        st.session_state[key] = ""
    st.session_state.pop("result", None)


def forget_result():
    st.session_state.pop("result", None)


def show_header():
    st.markdown("""
    <div class="pg-header">
      <h1>🛡️ PhishGuard AI</h1>
      <div class="pg-subtitle">NLP-Powered Email and SMS Phishing Detection</div>
      <p>Paste an email or SMS message. A machine learning model trained on labelled phishing and
      legitimate messages estimates whether it is phishing, and extra checks look for suspicious
      phrases and risky-looking links. Links are never opened.</p>
    </div>
    """, unsafe_allow_html=True)


def show_summary_cards(result: AnalysisResult, thresholds: dict):
    prediction, risk = result.prediction, result.risk
    col1, col2, col3 = st.columns(3)

    if prediction.is_phishing:
        pred_html = card("Model prediction", "⚠ Potential phishing",
                         "The classifier labelled this message as phishing.", "danger")
    elif risk.uncertainty_reason == REASON_BORDERLINE:
        pred_html = card("Model prediction", "◐ Legitimate (borderline)",
                         "Classified as legitimate, but the score is just below the phishing threshold.",
                         "warning")
    elif risk.uncertainty_reason == REASON_MEDIUM_BAND:
        pred_html = card("Model prediction", "◐ Legitimate (use caution)",
                         "Not classified as phishing, but the score is in the Medium-risk range.",
                         "warning")
    elif risk.uncertainty_reason == REASON_INDICATORS:
        pred_html = card("Model prediction", "✔ Legitimate",
                         "The model found little evidence of phishing, but link or phrase warnings "
                         "raised the risk level.", "safe")
    else:
        pred_html = card("Model prediction", "✔ Likely legitimate",
                         "The classifier did not find enough evidence of phishing.", "safe")

    # The score card separates the ONE classification threshold from the risk-band thresholds
    score_html = card(
        "Model score", format_score(prediction.phishing_score),
        f"Phishing if ≥ {format_threshold(prediction.classification_threshold)}.<br>"
        f"Risk: Medium ≥ {format_threshold(thresholds['medium_threshold'])}, "
        f"High ≥ {format_threshold(thresholds['high_threshold'])}.<br>"
        "An estimated score (0–1), not a guaranteed probability.", "neutral")

    tone = {HIGH: "danger", MEDIUM: "warning"}.get(risk.level, "safe")
    symbol = {HIGH: "▲", MEDIUM: "■"}.get(risk.level, "●")
    risk_caption = ("Raised one level by the extra indicators."
                    if risk.raised_by_indicators else "Based on the model score.")
    risk_html = card("Overall risk", f"{symbol} {risk.level} risk", risk_caption, tone)

    col1.markdown(pred_html, unsafe_allow_html=True)
    col2.markdown(score_html, unsafe_allow_html=True)
    col3.markdown(risk_html, unsafe_allow_html=True)


def show_phrases(result: AnalysisResult):
    st.subheader("Message analysis")
    st.caption("Your message, with suspicious phrases highlighted. It is shown as plain text: "
               "nothing in it is executed or opened.")
    # highlighted_html is already HTML-escaped by highlight_phrases()
    st.markdown(f'<div class="pg-message">{result.highlighted_html}</div>', unsafe_allow_html=True)

    st.markdown("**Suspicious phrases detected**")
    if result.phrase_matches:
        for match in result.phrase_matches:
            st.markdown(f"- “{match.matched_text}” – {match.description}")
        st.caption("Legitimate messages can also contain these phrases, so they are indicators, not proof.")
    else:
        st.write("No phrases from the suspicious-phrase list were found.")


def show_urls(result: AnalysisResult):
    st.subheader("URL analysis")
    if not result.url_reports:
        st.write("No URL detected.")
        return
    # A plain HTML table: every value is escaped, and URLs are shown as text, never as clickable links
    rows = []
    for report in result.url_reports:
        if report.warnings:
            warnings = "<br>".join("⚠ " + html.escape(w) for w in report.warnings)
            warning_cell = f'<td class="pg-warn">{warnings}</td>'
        else:
            warning_cell = '<td class="pg-ok">None found</td>'
        rows.append(f"<tr><td>{html.escape(report.url)}</td>"
                    f"<td>{html.escape(report.hostname or '(could not be read)')}</td>{warning_cell}</tr>")
    st.markdown('<table class="pg-table"><tr><th>URL (not opened)</th><th>Domain</th>'
                '<th>Structural warning signs</th></tr>' + "".join(rows) + "</table>",
                unsafe_allow_html=True)
    st.caption("Links were NOT opened or checked online. These warnings describe the link's structure "
               "only; a warning does not confirm that a link is malicious, and no warning does not "
               "make it safe.")


def show_explanation(result: AnalysisResult):
    st.subheader("Explanation")
    st.write(result.risk.explanation)

    st.subheader("Recommended next steps")
    for tip in result.risk.recommendations:
        st.markdown(f"- {tip}")

    st.info("This result is an automated estimate. It is not a guarantee that the message is safe "
            "or malicious.", icon="ℹ️")


def show_how_it_works(detector: PhishingDetector | None):
    with st.expander("How it works"):
        st.markdown("""
**1. Text preprocessing.** The message is lower-cased, HTML and extra spaces are removed, and
useful clues such as links, numbers and currency symbols are kept. Exactly the same steps are
used when training the model and when analysing your message.

**2. TF-IDF (turning text into numbers).** TF-IDF gives every word and two-word phrase a weight.
A phrase scores highly when it appears in this message but is uncommon across all messages,
so words like "verify your" or "claim" stand out more than "the" or "and".

**3. Logistic Regression (the classifier).** The model learned a weight for each word or phrase
from thousands of labelled phishing and legitimate messages. It adds up the weights for your
message and turns the total into a **score between 0 and 1**. Scores at or above the threshold
are labelled *potential phishing*. The score is the model's estimate, not a guaranteed probability.

**4. Suspicious phrase detection.** A separate, editable list of phrases (such as "verify your
account" or "click here") is searched for and highlighted. These are hints for you, not the
main decision.

**5. URL analysis.** Links are checked *only by their structure*: IP addresses instead of names,
URL shorteners, very long links, a hidden "@", many subdomains, look-alike characters and
official-sounding words. Links are never visited.

**6. Risk level.** The model score sets the starting level. A URL warning or two or more
suspicious phrases can raise it by one level, but the extra checks never lower the risk and
cannot turn a model "legitimate" result into High risk.
""")
        if detector is not None:
            t = detector.thresholds
            source = ("risk bands chosen on validation data"
                      if detector.thresholds_source == "validation" else "default values")
            st.markdown(
                f"**Current thresholds** ({source}):\n"
                f"- **Prediction:** phishing if the score is ≥ {format_threshold(t['classification_threshold'])}, "
                "otherwise legitimate.\n"
                f"- **Risk level:** Low below {format_threshold(t['medium_threshold'])}, "
                f"Medium from {format_threshold(t['medium_threshold'])}, "
                f"High from {format_threshold(t['high_threshold'])}.\n\n"
                "The two are separate: a message can be classified as legitimate and still be "
                "Medium risk if its score is in the Medium range or link/phrase warnings raise it."
            )

        results = load_test_results()
        if results:
            st.markdown("**Measured results on the held-out test set** (from `reports/evaluation.json`):")
            st.dataframe(pd.DataFrame([{
                "Group": group.upper() if group == "sms" else group.capitalize(),
                "Messages": m["messages"],
                "Precision": f"{m['precision']:.3f}",
                "Recall": f"{m['recall']:.3f}",
                "F1": f"{m['f1']:.3f}",
            } for group, m in results.items()]), hide_index=True, use_container_width=True)
        else:
            st.markdown("_Test results are not available yet. Run `python evaluate_model.py`._")

        st.markdown("""
**Main limitations**
- The model only knows patterns from its training data: public datasets of older emails and SMS
  messages. New scam styles may be missed.
- The legitimate emails (2002) and phishing emails (2016–2022) come from different sources and
  years, so test scores are likely more optimistic than real-world performance.
- Genuine messages that look like scams (for example, real bank OTP messages) can be flagged.
- Sender details, email headers and attachments are not analysed, and links are not checked online.
""")


def show_footer():
    st.markdown(
        '<div class="pg-footer">PhishGuard AI is an educational phishing-detection tool. Predictions are '
        'automated estimates and should not be treated as proof that a message is safe or malicious.</div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------- page
def main():
    show_header()

    try:
        detector = load_detector()
    except ModelNotFoundError as error:
        st.error("The trained model was not found, so messages cannot be analysed yet.")
        st.code(str(error), language=None)
        st.markdown("After training, refresh this page.")
        show_how_it_works(None)
        show_footer()
        st.stop()
    except Exception:  # e.g. a model saved with a different scikit-learn version
        st.error("The model file exists but could not be loaded. Re-create it with "
                 "`python train_model.py` using the versions in requirements.txt.")
        show_footer()
        st.stop()

    if detector.thresholds_source == "defaults":
        st.warning("models/thresholds.json was not found, so default risk thresholds are used. "
                   "Re-run `python train_model.py` to create it.")

    # ----- input
    option = st.radio("What do you want to analyse?", [EMAIL_OPTION, SMS_OPTION],
                      horizontal=True, key="channel_option", on_change=forget_result)
    if option == EMAIL_OPTION:
        channel = CHANNEL_EMAIL
        subject = st.text_input("Email subject (optional)", key="subject", max_chars=500)
        message = st.text_area("Email body", key="email_body", height=220, max_chars=MAX_EMAIL_CHARS,
                               placeholder="Paste the email text here...")
    else:
        channel = CHANNEL_SMS
        subject = None
        message = st.text_area("SMS message", key="sms_body", height=140, max_chars=MAX_SMS_CHARS,
                               placeholder="Paste the SMS text here...")

    analyse_col, clear_col, _ = st.columns([1.3, 1, 3])
    analyse_clicked = analyse_col.button("Analyse Message", type="primary", use_container_width=True)
    clear_col.button("Clear Input", on_click=clear_inputs, use_container_width=True)

    if analyse_clicked:
        full_text = f"{subject or ''} {message or ''}"
        if not full_text.strip():
            forget_result()
            st.warning("Please paste a message to analyse. The text box is empty.")
        elif not any(char.isalpha() for char in full_text):
            forget_result()
            st.warning("The message contains no words. Please paste the actual text of the email or SMS.")
        else:
            try:
                with st.spinner("Analysing..."):
                    st.session_state["result"] = analyse_message(detector, channel, message, subject)
            except ValueError as error:
                forget_result()
                st.warning(str(error))

    # ----- results
    result = st.session_state.get("result")
    if result is not None:
        st.divider()
        st.header("Results")
        show_summary_cards(result, detector.thresholds)
        show_phrases(result)
        show_urls(result)
        show_explanation(result)

    st.divider()
    show_how_it_works(detector)
    show_footer()


main()
