"""End-to-end analysis of email and SMS inputs (uses the toy model from conftest.py)."""

import pytest

from src.analysis import analyse_message


def test_email_analysis(toy_detector):
    result = analyse_message(
        toy_detector, "email",
        message="Please verify your account at http://192.168.1.10/login",
        subject="Account notice",
    )
    assert result.channel == "email"
    assert result.prediction.label in {"phishing", "legitimate"}
    assert result.risk.level in {"Low", "Medium", "High"}
    assert [m.phrase for m in result.phrase_matches] == ["verify your account"]
    assert len(result.url_reports) == 1 and result.url_reports[0].has_warnings
    assert result.highlighted_html.startswith("Account notice\n")
    assert "<mark>verify your account</mark>" in result.highlighted_html


def test_sms_analysis_without_url(toy_detector):
    result = analyse_message(toy_detector, "sms", message="see you at lunch tomorrow")
    assert result.channel == "sms"
    assert result.url_reports == []
    assert result.phrase_matches == []
    assert result.risk.level in {"Low", "Medium", "High"}


def test_sms_ignores_subject(toy_detector):
    result = analyse_message(toy_detector, "sms", message="see you", subject="click here")
    assert result.phrase_matches == []


def test_empty_message_rejected(toy_detector):
    with pytest.raises(ValueError):
        analyse_message(toy_detector, "sms", message="   ")


def test_unknown_channel_rejected(toy_detector):
    with pytest.raises(ValueError):
        analyse_message(toy_detector, "fax", message="hello")
