"""Tests for the web API in api.py (FastAPI's test client, no browser needed).

Wording and risk tests use the toy model from conftest.py with a thresholds
file built around its actual score, so each case is deterministic. Tests that
need the real trained model are skipped until train_model.py has been run.
"""

import json

import pytest
from fastapi.testclient import TestClient

import api
from src import config
from src.phishing_detector import PhishingDetector

needs_model = pytest.mark.skipif(not config.MODEL_PATH.exists(), reason="run train_model.py first")
CARD_MESSAGE = "see you at lunch tomorrow http://192.168.0.1/notes"


@pytest.fixture
def client():
    api.reset_detector()
    yield TestClient(api.app)
    api.reset_detector()


def use_toy_model(monkeypatch, tmp_path, toy_model_files, thresholds):
    path = tmp_path / "api_thresholds.json"
    path.write_text(json.dumps(thresholds))
    monkeypatch.setattr(config, "MODEL_PATH", toy_model_files[0])
    monkeypatch.setattr(config, "THRESHOLDS_PATH", path)
    api.reset_detector()


def toy_score(toy_model_files):
    return PhishingDetector(*toy_model_files).predict(CARD_MESSAGE).phishing_score


# ---------- real model ----------

@needs_model
def test_meta_lists_thresholds_examples_and_results(client):
    meta = client.get("/api/meta").json()
    stored = json.loads(config.THRESHOLDS_PATH.read_text())
    assert meta["thresholds"]["display"] == {
        "classification": f"{stored['classification_threshold']:.4f}",
        "medium": f"{stored['medium_threshold']:.4f}",
        "high": f"{stored['high_threshold']:.4f}",
    }
    assert meta["thresholds"]["source"] == "validation"
    assert len(meta["examples"]) == 5
    assert {"overall", "email", "sms"} <= set(meta["test_results"])


@needs_model
def test_email_analysis_returns_every_section(client):
    body = client.post("/api/analyse", json={
        "channel": "email", "subject": "Team update",
        "message": "Please click here to verify your account: http://192.168.0.1/login"}).json()
    assert body["channel"] == "email"
    assert body["verdict"]["title"]
    assert 0 <= body["prediction"]["score"] <= 1
    assert len(body["prediction"]["score_display"]) >= 6
    assert body["risk"]["level"] in {"Low", "Medium", "High"}
    assert [p["phrase"] for p in body["phrases"]] == ["click here", "verify your account"]
    assert body["urls"][0]["hostname"] == "192.168.0.1" and body["urls"][0]["warnings"]
    assert body["risk"]["recommendations"]
    # The segments rebuild the original text exactly, subject first
    assert "".join(s["text"] for s in body["segments"]).startswith("Team update\nPlease click here")


@needs_model
def test_sms_analysis_without_url_ignores_subject(client):
    body = client.post("/api/analyse", json={
        "channel": "sms", "subject": "click here", "message": "Running late, see you at 7"}).json()
    assert body["urls"] == [] and body["phrases"] == []
    assert "".join(s["text"] for s in body["segments"]) == "Running late, see you at 7"


@needs_model
def test_html_in_a_message_comes_back_as_plain_text(client):
    body = client.post("/api/analyse", json={"channel": "sms", "message": "<b>click here</b> now"}).json()
    assert {"text": "click here", "flagged": True} in body["segments"]
    assert body["segments"][0] == {"text": "<b>", "flagged": False}  # raw text, never HTML


# ---------- input validation ----------

@pytest.mark.parametrize("payload, words", [
    ({"channel": "email", "message": "   ", "subject": " "}, "text box is empty"),
    ({"channel": "sms", "message": "12345 !!! 678"}, "contains no words"),
    ({"channel": "sms", "message": "a" * 2001}, "too long"),
])
def test_bad_input_gets_a_helpful_422(client, toy_model_files, tmp_path, monkeypatch, payload, words):
    use_toy_model(monkeypatch, tmp_path, toy_model_files,
                  {"classification_threshold": 0.5, "medium_threshold": 0.3, "high_threshold": 0.8})
    response = client.post("/api/analyse", json=payload)
    assert response.status_code == 422
    assert words in response.json()["detail"]["message"]


def test_unknown_channel_is_rejected(client):
    assert client.post("/api/analyse", json={"channel": "fax", "message": "hi"}).status_code == 422


def test_missing_model_returns_instructions(client, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MODEL_PATH", tmp_path / "missing.joblib")
    api.reset_detector()
    response = client.post("/api/analyse", json={"channel": "sms", "message": "hello there"})
    assert response.status_code == 503
    assert "train_model.py" in response.json()["detail"]["instructions"]
    assert client.get("/api/meta").status_code == 503


# ---------- verdict wording (regression tests from the threshold audit) ----------

def analyse_toy(client, monkeypatch, tmp_path, toy_model_files, thresholds):
    use_toy_model(monkeypatch, tmp_path, toy_model_files, thresholds)
    return client.post("/api/analyse", json={"channel": "sms", "message": CARD_MESSAGE}).json()


def test_verdict_when_indicators_raise_a_legitimate_result(client, toy_model_files, tmp_path, monkeypatch):
    score = toy_score(toy_model_files)
    body = analyse_toy(client, monkeypatch, tmp_path, toy_model_files, {
        "classification_threshold": score + 0.2, "medium_threshold": score + 0.1, "high_threshold": 0.999})
    assert body["verdict"]["title"] == "Legitimate"
    assert "link or phrase warnings raised the risk level" in body["verdict"]["caption"]
    assert body["risk"]["level"] == "Medium" and body["risk"]["raised_by_indicators"]
    assert "borderline" not in body["verdict"]["caption"] + body["risk"]["explanation"]


def test_verdict_when_score_is_just_below_phishing_threshold(client, toy_model_files, tmp_path, monkeypatch):
    score = toy_score(toy_model_files)
    body = analyse_toy(client, monkeypatch, tmp_path, toy_model_files, {
        "classification_threshold": score + 0.01, "medium_threshold": score - 0.1, "high_threshold": 0.999})
    assert body["verdict"]["title"] == "Legitimate (borderline)"


def test_verdict_when_score_is_in_medium_band_far_from_threshold(client, toy_model_files, tmp_path, monkeypatch):
    score = toy_score(toy_model_files)
    body = analyse_toy(client, monkeypatch, tmp_path, toy_model_files, {
        "classification_threshold": score + 0.2, "medium_threshold": score - 0.01, "high_threshold": 0.999})
    assert body["verdict"]["title"] == "Legitimate (use caution)"


def test_score_display_uses_four_truncated_decimals(client, toy_model_files, tmp_path, monkeypatch):
    score = toy_score(toy_model_files)
    body = analyse_toy(client, monkeypatch, tmp_path, toy_model_files, {
        "classification_threshold": 0.5, "medium_threshold": 0.3, "high_threshold": 0.8})
    assert body["prediction"]["score_display"] == f"{int(score * 10000) / 10000:.4f}"
