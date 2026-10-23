"""Turn the model score and extra indicators into a risk level, explanation and advice.

How the risk level is decided (all thresholds come from models/thresholds.json,
chosen on the validation set, or config/settings.json defaults):

  1. Start from the MODEL SCORE:
        score >= high_threshold    -> High
        score >= medium_threshold  -> Medium
        otherwise                  -> Low
     A message the model predicts as phishing is never Low.
  2. Extra indicators (URL structure warnings, or at least N suspicious
     phrases) can raise the level by ONE step:
        Low    -> Medium   (always allowed)
        Medium -> High     (only if the model itself predicted phishing)
     Indicators never lower the risk and never override the model's prediction.

For a message the model classified as LEGITIMATE but whose final risk is
Medium, `uncertainty_reason` says why, so the wording stays accurate:
  "borderline_score"  - score is within `borderline_margin` below the phishing threshold
  "medium_band_score" - score is in the Medium band but not close to the phishing threshold
  "raised_by_indicators" - score was Low; link/phrase warnings raised the risk
All comparisons use the original, unrounded score.
"""

from dataclasses import dataclass
from decimal import ROUND_DOWN, Decimal

from src.config import load_settings
from src.phishing_detector import Prediction
from src.suspicious_phrases import PhraseMatch
from src.url_analyzer import UrlReport

LOW, MEDIUM, HIGH = "Low", "Medium", "High"

# Situations used to pick recommendations
SITUATION_PHISHING = "phishing"
SITUATION_UNCERTAIN = "uncertain"
SITUATION_LEGITIMATE = "legitimate"

# Why a legitimate prediction still has Medium risk (see module docstring)
REASON_BORDERLINE = "borderline_score"
REASON_MEDIUM_BAND = "medium_band_score"
REASON_INDICATORS = "raised_by_indicators"

DEFAULT_BORDERLINE_MARGIN = 0.05

RECOMMENDATIONS = {
    SITUATION_PHISHING: [
        "Do not click links or call numbers in this message.",
        "Never share passwords, PINs or one-time passwords (OTPs).",
        "Verify the request using official contact details you find yourself, not those in the message.",
        "Do not open unexpected attachments.",
        "Report the message to the organisation it claims to come from, then delete it.",
    ],
    SITUATION_UNCERTAIN: [
        "Treat this message with caution until you have verified it.",
        "Verify the sender and the request through an official channel before acting.",
        "Avoid clicking links or sharing personal details until you have verified it.",
    ],
    SITUATION_LEGITIMATE: [
        "The model did not find enough evidence of phishing in this message.",
        "Automated detection can make mistakes. If the message asks for money, "
        "passwords or OTPs, verify it independently first.",
    ],
}


@dataclass
class RiskAssessment:
    level: str                  # final level shown to the user
    model_level: str            # level from the model score alone
    raised_by_indicators: bool  # True if indicators raised the level by one step
    situation: str              # phishing / uncertain / legitimate
    explanation: str
    recommendations: list[str]
    uncertainty_reason: str | None = None  # only set for legitimate + Medium (see docstring)


def model_risk_level(prediction: Prediction, thresholds: dict) -> str:
    score = prediction.phishing_score
    if score >= thresholds["high_threshold"]:
        level = HIGH
    elif score >= thresholds["medium_threshold"]:
        level = MEDIUM
    else:
        level = LOW
    # Safety rule: a phishing prediction is never shown as Low risk
    if prediction.is_phishing and level == LOW:
        level = MEDIUM
    return level


def indicators_present(phrase_matches: list[PhraseMatch], url_reports: list[UrlReport],
                       risk_settings: dict) -> bool:
    """True if the extra indicators are strong enough to raise the risk level."""
    url_warning = risk_settings["url_warning_raises_risk"] and any(r.has_warnings for r in url_reports)
    enough_phrases = len(phrase_matches) >= risk_settings["min_phrase_matches_to_raise"]
    return url_warning or enough_phrases


def _join(items: list[str]) -> str:
    """['a'] -> 'a';  ['a', 'b', 'c'] -> 'a, b and c'"""
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def format_score(score: float) -> str:
    """Show the score with 4 decimals, for display only.

    The score is cut off (truncated) instead of rounded, so the displayed value
    never crosses a threshold: 0.49996 shows as "0.4999", not "0.5000".
    Values that would show as 0.0000 or 1.0000 are shown as "below 0.0001" /
    "above 0.9999", because a score of exactly 0 or 1 would suggest certainty.
    """
    shown = Decimal(repr(float(score))).quantize(Decimal("0.0001"), rounding=ROUND_DOWN)
    if shown >= 1:
        return "above 0.9999"
    if shown <= 0:
        return "below 0.0001"
    return f"{shown:.4f}"


def format_threshold(value: float) -> str:
    """Thresholds are stored with at most 4 decimals, so this shows them exactly."""
    return f"{value:.4f}"


def legitimate_uncertainty_reason(prediction: Prediction, model_level: str, final_level: str,
                                  borderline_margin: float) -> str | None:
    """Why a LEGITIMATE prediction ended up Medium risk (None otherwise)."""
    if prediction.is_phishing or final_level != MEDIUM:
        return None
    if model_level == LOW:
        return REASON_INDICATORS
    distance = prediction.classification_threshold - prediction.phishing_score
    return REASON_BORDERLINE if distance <= borderline_margin else REASON_MEDIUM_BAND


def build_explanation(prediction: Prediction, model_level: str, final_level: str,
                      phrase_matches: list[PhraseMatch], url_reports: list[UrlReport],
                      thresholds: dict, uncertainty_reason: str | None = None,
                      max_quoted_phrases: int = 4) -> str:
    """Describe ONLY what was actually found. Nothing is invented."""
    score = format_score(prediction.phishing_score)
    cutoff = format_threshold(prediction.classification_threshold)
    if prediction.is_phishing:
        sentences = [f"The model classified this message as potentially phishing (model score {score})."]
    elif uncertainty_reason == REASON_BORDERLINE:
        sentences = [f"The model classified this message as legitimate, but its score ({score}) is just "
                     f"below the phishing threshold ({cutoff}), so the result is borderline."]
    elif model_level == MEDIUM:
        sentences = [f"The model classified this message as legitimate (model score {score}, below the "
                     f"phishing threshold of {cutoff}). The score is above the Medium-risk threshold "
                     f"({format_threshold(thresholds['medium_threshold'])}), so the message deserves "
                     "caution even though it is not classified as phishing."]
    else:
        sentences = [f"The model did not find enough evidence of phishing (model score {score})."]

    if phrase_matches:
        descriptions = list(dict.fromkeys(m.description for m in phrase_matches))
        quoted = ", ".join(f"\"{m.matched_text}\"" for m in phrase_matches[:max_quoted_phrases])
        if len(phrase_matches) > max_quoted_phrases:
            quoted += f" and {len(phrase_matches) - max_quoted_phrases} more"
        sentences.append(f"It contains language associated with {_join(descriptions)}: {quoted}.")

    if url_reports:
        flagged = sum(r.has_warnings for r in url_reports)
        url_word = "URL was" if len(url_reports) == 1 else "URLs were"
        if flagged:
            sentences.append(f"{len(url_reports)} {url_word} detected, and {flagged} "
                             "showed structural warning signs (see the URL analysis).")
        else:
            sentences.append(f"{len(url_reports)} {url_word} detected with no structural warnings.")

    if final_level != model_level:
        sentences.append(f"The risk was raised from {model_level} to {final_level} "
                         "because of these additional indicators.")

    if not phrase_matches and not any(r.has_warnings for r in url_reports):
        sentences.append("No suspicious phrases or URL warnings were detected by these checks. "
                         "This does not guarantee that the message is safe.")
    return " ".join(sentences)


def assess_risk(prediction: Prediction, phrase_matches: list[PhraseMatch],
                url_reports: list[UrlReport], thresholds: dict,
                risk_settings: dict | None = None) -> RiskAssessment:
    risk_settings = risk_settings or load_settings()["risk"]
    model_level = model_risk_level(prediction, thresholds)

    final_level = model_level
    if indicators_present(phrase_matches, url_reports, risk_settings):
        if model_level == LOW:
            final_level = MEDIUM
        elif model_level == MEDIUM and prediction.is_phishing:
            final_level = HIGH

    if prediction.is_phishing:
        situation = SITUATION_PHISHING
    elif final_level == MEDIUM:
        situation = SITUATION_UNCERTAIN
    else:
        situation = SITUATION_LEGITIMATE

    reason = legitimate_uncertainty_reason(
        prediction, model_level, final_level,
        risk_settings.get("borderline_margin", DEFAULT_BORDERLINE_MARGIN),
    )
    return RiskAssessment(
        level=final_level,
        model_level=model_level,
        raised_by_indicators=final_level != model_level,
        situation=situation,
        explanation=build_explanation(prediction, model_level, final_level, phrase_matches,
                                      url_reports, thresholds, reason),
        recommendations=RECOMMENDATIONS[situation],
        uncertainty_reason=reason,
    )
