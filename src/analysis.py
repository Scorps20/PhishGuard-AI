"""Run every check on one message. This is the single function the app calls."""

from dataclasses import dataclass

from src.phishing_detector import PhishingDetector, Prediction
from src.preprocessing import combine_email_text
from src.risk_assessment import RiskAssessment, assess_risk
from src.suspicious_phrases import PhraseMatch, find_suspicious_phrases, highlight_phrases, split_by_phrases
from src.url_analyzer import UrlReport, analyse_message_urls

CHANNEL_EMAIL = "email"
CHANNEL_SMS = "sms"


@dataclass
class AnalysisResult:
    channel: str
    prediction: Prediction          # from the trained model
    risk: RiskAssessment            # model score + indicators
    phrase_matches: list[PhraseMatch]
    url_reports: list[UrlReport]
    highlighted_html: str           # original message, HTML-escaped, phrases in <mark>
    segments: list[dict]            # original message as plain-text pieces, suspicious ones flagged


def analyse_message(detector: PhishingDetector, channel: str, message: str,
                    subject: str | None = None) -> AnalysisResult:
    """Analyse an email (subject + body) or an SMS (message only).

    Raises ValueError for an unknown channel or an empty message.
    """
    if channel not in (CHANNEL_EMAIL, CHANNEL_SMS):
        raise ValueError(f"Unknown channel '{channel}'. Use 'email' or 'sms'.")
    if channel == CHANNEL_SMS:
        subject = None  # SMS messages have no subject

    # 1. Trained model (primary classifier)
    prediction = detector.predict(message, subject=subject)

    # 2. Rule-based indicators run on the ORIGINAL text, not the cleaned text
    original = combine_email_text(subject, message)
    phrase_matches = find_suspicious_phrases(original)
    url_reports = analyse_message_urls(original)

    # 3. Combine into a risk level, explanation and advice
    risk = assess_risk(prediction, phrase_matches, url_reports, detector.thresholds)

    return AnalysisResult(
        channel=channel,
        prediction=prediction,
        risk=risk,
        phrase_matches=phrase_matches,
        url_reports=url_reports,
        highlighted_html=highlight_phrases(original, phrase_matches),
        segments=split_by_phrases(original, phrase_matches),
    )
