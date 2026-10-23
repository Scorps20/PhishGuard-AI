"""Tests for the deterministic risk rules.

Predictions are built by hand here, so these tests check the RULES only,
separately from the machine learning model.
"""

import pytest

from src.phishing_detector import Prediction
from src.risk_assessment import HIGH, LOW, MEDIUM, assess_risk
from src.suspicious_phrases import PhraseMatch
from src.url_analyzer import UrlReport

THRESHOLDS = {"classification_threshold": 0.5, "medium_threshold": 0.3, "high_threshold": 0.6}
RISK_SETTINGS = {"min_phrase_matches_to_raise": 2, "url_warning_raises_risk": True}

CLEAN_URL = UrlReport("https://example.com", "example.com", [])
BAD_URL = UrlReport("bit.ly/x", "bit.ly", ["Uses a URL shortener, which hides the real destination."])


def phrase(text, description="urgency or pressure to act quickly"):
    return PhraseMatch(phrase=text.lower(), category="test", description=description,
                       matched_text=text, spans=[(0, len(text))])


def prediction(score, threshold=0.5):
    label = "phishing" if score >= threshold else "legitimate"
    return Prediction(label=label, phishing_score=score, classification_threshold=threshold)


def assess(score, phrases=(), urls=(), thresholds=THRESHOLDS):
    return assess_risk(prediction(score, thresholds["classification_threshold"]),
                       list(phrases), list(urls), thresholds, RISK_SETTINGS)


def test_low_score_no_indicators_is_low():
    risk = assess(0.1)
    assert risk.level == LOW and not risk.raised_by_indicators
    assert risk.situation == "legitimate"


def test_score_bands():
    assert assess(0.35).level == MEDIUM
    assert assess(0.55).level == MEDIUM
    assert assess(0.9).level == HIGH


def test_url_warning_raises_low_to_medium():
    risk = assess(0.1, urls=[BAD_URL])
    assert risk.model_level == LOW and risk.level == MEDIUM and risk.raised_by_indicators
    assert risk.situation == "uncertain"


def test_clean_url_does_not_raise_risk():
    assert assess(0.1, urls=[CLEAN_URL]).level == LOW


def test_one_phrase_is_not_enough_two_are():
    assert assess(0.1, phrases=[phrase("act now")]).level == LOW
    assert assess(0.1, phrases=[phrase("act now"), phrase("click here")]).level == MEDIUM


def test_indicators_cannot_make_a_legitimate_prediction_high():
    risk = assess(0.4, phrases=[phrase("a"), phrase("b")], urls=[BAD_URL])
    assert risk.level == MEDIUM


def test_indicators_raise_phishing_medium_to_high():
    risk = assess(0.55, urls=[BAD_URL])
    assert risk.model_level == MEDIUM and risk.level == HIGH


def test_indicators_raise_at_most_one_level_and_never_lower():
    assert assess(0.9, urls=[BAD_URL]).level == HIGH
    assert assess(0.9).level == HIGH


@pytest.mark.parametrize("score", [0.5, 0.55, 0.65, 0.8, 0.99])
def test_phishing_prediction_is_never_low_even_with_odd_thresholds(score):
    odd = {"classification_threshold": 0.5, "medium_threshold": 0.85, "high_threshold": 0.95}
    risk = assess(score, thresholds=odd)
    assert risk.level != LOW
    assert risk.situation == "phishing"


@pytest.mark.parametrize("score", [0.0, 0.2, 0.3, 0.49, 0.5, 0.7, 1.0])
def test_level_is_always_valid(score):
    assert assess(score).level in {LOW, MEDIUM, HIGH}


def test_explanation_reflects_actual_findings():
    risk = assess(0.9, phrases=[phrase("Verify your account", "requests for login details")], urls=[BAD_URL])
    assert "potentially phishing" in risk.explanation
    assert "0.9000" in risk.explanation
    assert "\"Verify your account\"" in risk.explanation
    assert "requests for login details" in risk.explanation
    assert "1 URL was detected" in risk.explanation


def test_explanation_without_indicators_does_not_promise_safety():
    risk = assess(0.1)
    assert "did not find enough evidence" in risk.explanation
    assert "does not guarantee" in risk.explanation
    assert "URL" not in risk.explanation.split("No suspicious")[0]  # no invented URL claims


def test_explanation_mentions_raised_risk():
    assert "raised from Low to Medium" in assess(0.1, urls=[BAD_URL]).explanation


def test_recommendations_match_situation():
    assert any("OTP" in r for r in assess(0.9).recommendations)
    assert any("caution" in r for r in assess(0.35).recommendations)
    assert any("can make mistakes" in r for r in assess(0.1).recommendations)


def test_extreme_scores_are_not_shown_as_certain():
    assert "above 0.9999" in assess(1.0).explanation
    assert "below 0.0001" in assess(0.0).explanation
    assert "1.0000" not in assess(0.99999).explanation
    assert "0.0000" not in assess(0.00004).explanation


def test_long_phrase_lists_are_shortened():
    many = [phrase(f"p{i}") for i in range(6)]
    assert "and 2 more" in assess(0.9, phrases=many).explanation


# ---------- regression tests for the threshold audit (2026-10-23) ----------
# These use the real stored thresholds from models/thresholds.json.
from decimal import Decimal  # noqa: E402

from src.risk_assessment import (  # noqa: E402
    REASON_BORDERLINE,
    REASON_INDICATORS,
    REASON_MEDIUM_BAND,
    format_score,
    format_threshold,
)

REAL = {"classification_threshold": 0.5, "medium_threshold": 0.2886, "high_threshold": 0.6006}
REAL_SETTINGS = {**RISK_SETTINGS, "borderline_margin": 0.05}


def assess_real(score, phrases=(), urls=()):
    return assess_risk(prediction(score, REAL["classification_threshold"]),
                       list(phrases), list(urls), REAL, REAL_SETTINGS)


@pytest.mark.parametrize("score, expected", [
    (0.49999, "0.4999"), (0.5, "0.5000"), (0.50001, "0.5000"),
    (0.28859, "0.2885"), (0.2886, "0.2886"),
    (0.60059, "0.6005"), (0.6006, "0.6006"),
    (0.123456, "0.1234"),
])
def test_score_shown_with_four_decimals_truncated(score, expected):
    assert format_score(score) == expected


def test_thresholds_shown_exactly():
    assert [format_threshold(REAL[k]) for k in ("classification_threshold", "medium_threshold",
                                                "high_threshold")] == ["0.5000", "0.2886", "0.6006"]


@pytest.mark.parametrize("score, label, level", [
    (0.28859, "legitimate", LOW),     # just below Medium
    (0.2886, "legitimate", MEDIUM),   # exactly Medium
    (0.49999, "legitimate", MEDIUM),  # just below phishing
    (0.5, "phishing", MEDIUM),        # exactly phishing
    (0.60059, "phishing", MEDIUM),    # just below High
    (0.6006, "phishing", HIGH),       # exactly High
])
def test_threshold_edges_and_display_agree(score, label, level):
    risk = assess_real(score)
    assert prediction(score).label == label
    assert risk.level == level
    # The DISPLAYED score must fall on the same side of each DISPLAYED threshold
    shown = Decimal(format_score(score))
    assert (shown >= Decimal(format_threshold(REAL["classification_threshold"]))) == (label == "phishing")
    assert (shown >= Decimal(format_threshold(REAL["medium_threshold"]))) == (level != LOW)
    assert (shown >= Decimal(format_threshold(REAL["high_threshold"]))) == (level == HIGH)


def test_medium_band_score_far_from_threshold_is_not_called_borderline():
    risk = assess_real(0.29)  # the audit's example
    assert risk.level == MEDIUM and risk.uncertainty_reason == REASON_MEDIUM_BAND
    assert "borderline" not in risk.explanation and "close to" not in risk.explanation
    assert "Medium-risk threshold (0.2886)" in risk.explanation
    assert "phishing threshold of 0.5000" in risk.explanation
    assert not any("borderline" in r for r in risk.recommendations)


@pytest.mark.parametrize("score", [0.45, 0.48, 0.49999])
def test_score_just_below_phishing_threshold_is_borderline(score):
    risk = assess_real(score)
    assert risk.uncertainty_reason == REASON_BORDERLINE
    assert "just below the phishing threshold (0.5000)" in risk.explanation


def test_borderline_margin_edge():
    assert assess_real(0.4499).uncertainty_reason == REASON_MEDIUM_BAND


def test_legitimate_raised_by_url_is_not_called_borderline():
    risk = assess_real(0.05, urls=[BAD_URL])
    assert risk.model_level == LOW and risk.level == MEDIUM
    assert risk.uncertainty_reason == REASON_INDICATORS
    assert "borderline" not in risk.explanation
    assert "did not find enough evidence" in risk.explanation
    assert "raised from Low to Medium" in risk.explanation


def test_legitimate_raised_by_phrases_is_not_called_borderline():
    risk = assess_real(0.05, phrases=[phrase("act now"), phrase("click here")])
    assert risk.uncertainty_reason == REASON_INDICATORS
    assert "borderline" not in risk.explanation


def test_no_uncertainty_reason_for_phishing_or_low():
    assert assess_real(0.9).uncertainty_reason is None
    assert assess_real(0.55).uncertainty_reason is None
    assert assess_real(0.1).uncertainty_reason is None


def test_missing_borderline_margin_setting_uses_default():
    risk = assess_risk(prediction(0.48), [], [], REAL, RISK_SETTINGS)  # no borderline_margin key
    assert risk.uncertainty_reason == REASON_BORDERLINE
