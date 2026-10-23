"""User-interface tests using Streamlit's built-in AppTest (no browser needed).

These run the real app.py with the real trained model, so they are skipped
until train_model.py has been run. They check that the interface works,
not that particular messages get particular predictions.
"""

from pathlib import Path

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from src import config

APP_PATH = str(Path(__file__).resolve().parent.parent / "app.py")
needs_model = pytest.mark.skipif(not config.MODEL_PATH.exists(), reason="run train_model.py first")


def start_app() -> AppTest:
    st.cache_resource.clear()
    st.cache_data.clear()
    app = AppTest.from_file(APP_PATH, default_timeout=60)
    app.run()
    return app


def all_markdown(app: AppTest) -> str:
    return "\n".join(m.value for m in app.markdown)


@needs_model
def test_app_starts_without_errors():
    app = start_app()
    assert not app.exception
    assert "PhishGuard AI" in all_markdown(app)
    assert "educational phishing-detection tool" in all_markdown(app)


@needs_model
def test_empty_input_shows_warning():
    app = start_app()
    app.button[0].click().run()  # "Analyse Message"
    assert any("text box is empty" in w.value for w in app.warning)
    assert "Overall risk" not in all_markdown(app)


@needs_model
def test_input_without_words_shows_warning():
    app = start_app()
    app.text_area(key="email_body").input("12345 !!! 678").run()
    app.button[0].click().run()
    assert any("contains no words" in w.value for w in app.warning)


@needs_model
def test_email_analysis_shows_all_result_sections():
    app = start_app()
    app.text_input(key="subject").input("Team update").run()
    app.text_area(key="email_body").input(
        "Please click here to verify your account: http://192.168.0.1/login").run()
    app.button[0].click().run()
    assert not app.exception
    text = all_markdown(app)
    for section in ["Model prediction", "Model score", "Overall risk", "pg-message", "pg-table"]:
        assert section in text
    assert "<mark>click here</mark>" in text
    assert [h.value for h in app.subheader][:4] == [
        "Message analysis", "URL analysis", "Explanation", "Recommended next steps"]


@needs_model
def test_sms_analysis_without_url():
    app = start_app()
    app.radio(key="channel_option").set_value("SMS Analysis").run()
    app.text_area(key="sms_body").input("Running late, see you at 7").run()
    app.button[0].click().run()
    assert not app.exception
    assert "Overall risk" in all_markdown(app)
    assert "No URL detected." in all_markdown(app)


@needs_model
def test_clear_button_resets_inputs_and_results():
    app = start_app()
    app.text_area(key="email_body").input("verify your account now").run()
    app.button[0].click().run()
    assert "Overall risk" in all_markdown(app)
    app.button[1].click().run()  # "Clear Input"
    assert app.text_area(key="email_body").value == ""
    assert "Overall risk" not in all_markdown(app)


def test_missing_model_shows_instructions(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MODEL_PATH", tmp_path / "missing.joblib")
    app = start_app()
    assert not app.exception
    assert any("trained model was not found" in e.value for e in app.error)
    assert any("train_model.py" in c.value for c in app.code)
    st.cache_resource.clear()  # do not leave the failed load cached for other tests


# ---------- prediction/score card wording (regression tests for the threshold audit) ----------
# A toy model (tests/conftest.py) plus a thresholds file built around the toy
# model's actual score makes each case deterministic.
import json  # noqa: E402

from src.phishing_detector import PhishingDetector  # noqa: E402

CARD_MESSAGE = "see you at lunch tomorrow http://192.168.0.1/notes"


def start_app_with_thresholds(monkeypatch, tmp_path, model_path, thresholds):
    thresholds_path = tmp_path / "card_thresholds.json"
    thresholds_path.write_text(json.dumps(thresholds))
    monkeypatch.setattr(config, "MODEL_PATH", model_path)
    monkeypatch.setattr(config, "THRESHOLDS_PATH", thresholds_path)
    app = start_app()
    app.radio(key="channel_option").set_value("SMS Analysis").run()
    app.text_area(key="sms_body").input(CARD_MESSAGE).run()
    app.button[0].click().run()
    assert not app.exception
    return all_markdown(app)


def toy_score(toy_model_files, tmp_path):
    model_path, thresholds_path = toy_model_files
    return PhishingDetector(model_path, thresholds_path).predict(CARD_MESSAGE).phishing_score


def test_card_when_indicators_raise_a_legitimate_result(toy_model_files, tmp_path, monkeypatch):
    score = toy_score(toy_model_files, tmp_path)
    # Score is Low and legitimate; the IP-address URL raises the risk to Medium
    text = start_app_with_thresholds(monkeypatch, tmp_path, toy_model_files[0], {
        "classification_threshold": score + 0.2, "medium_threshold": score + 0.1, "high_threshold": 0.999})
    assert "link or phrase warnings raised the risk level" in text
    assert "borderline" not in text.split("Overall risk")[0]
    assert "Medium risk" in text
    st.cache_resource.clear()


def test_card_when_score_is_just_below_phishing_threshold(toy_model_files, tmp_path, monkeypatch):
    score = toy_score(toy_model_files, tmp_path)
    text = start_app_with_thresholds(monkeypatch, tmp_path, toy_model_files[0], {
        "classification_threshold": score + 0.01, "medium_threshold": score - 0.1, "high_threshold": 0.999})
    assert "Legitimate (borderline)" in text
    st.cache_resource.clear()


def test_card_when_score_is_in_medium_band_far_from_threshold(toy_model_files, tmp_path, monkeypatch):
    score = toy_score(toy_model_files, tmp_path)
    text = start_app_with_thresholds(monkeypatch, tmp_path, toy_model_files[0], {
        "classification_threshold": score + 0.2, "medium_threshold": score - 0.01, "high_threshold": 0.999})
    assert "Legitimate (use caution)" in text
    assert "Legitimate (borderline)" not in text
    st.cache_resource.clear()


@needs_model
def test_score_card_shows_four_decimals_and_separate_thresholds():
    app = start_app()
    app.text_area(key="email_body").input("Please verify your account today").run()
    app.button[0].click().run()
    text = all_markdown(app)
    thresholds = json.loads(config.THRESHOLDS_PATH.read_text())
    assert f"Phishing if ≥ {thresholds['classification_threshold']:.4f}" in text
    assert f"Medium ≥ {thresholds['medium_threshold']:.4f}" in text
    assert f"High ≥ {thresholds['high_threshold']:.4f}" in text
    assert "Prediction:** phishing if the score is ≥ 0.5000" in text  # "How it works" section
