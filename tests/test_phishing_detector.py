"""Tests for loading the model and making predictions.

Most tests use the tiny toy model from conftest.py, so they test the
prediction CODE, not the quality of the real model.
Tests marked "real model" are skipped until train_model.py has been run.
"""

import json

import pytest

from src.config import MODEL_PATH, THRESHOLDS_PATH
from src.phishing_detector import ModelNotFoundError, PhishingDetector, Prediction
from src.preprocessing import clean_text
from train_model import build_pipeline

# toy_model_files and toy_detector fixtures come from tests/conftest.py


def test_missing_model_gives_helpful_error(tmp_path):
    with pytest.raises(ModelNotFoundError) as error:
        PhishingDetector(tmp_path / "does_not_exist.joblib")
    assert "train_model.py" in str(error.value)


def test_missing_thresholds_file_falls_back_to_defaults(toy_model_files, tmp_path):
    model_path, _ = toy_model_files
    detector = PhishingDetector(model_path, tmp_path / "no_thresholds.json")
    assert detector.thresholds_source == "defaults"
    assert 0 < detector.thresholds["classification_threshold"] < 1


@pytest.mark.parametrize("empty", ["", "   ", "\n\t", None])
def test_empty_input_is_rejected(toy_detector, empty):
    with pytest.raises(ValueError):
        toy_detector.predict(empty)


def test_sms_prediction_has_valid_shape(toy_detector):
    result = toy_detector.predict("hello, are we still meeting tomorrow?")
    assert isinstance(result, Prediction)
    assert result.label in {"phishing", "legitimate"}
    assert 0.0 <= result.phishing_score <= 1.0
    # The label must agree with the score and the threshold
    assert result.is_phishing == (result.phishing_score >= result.classification_threshold)


def test_email_prediction_uses_subject_and_body(toy_detector):
    with_subject = toy_detector.predict("please read the message", subject="verify your account")
    without_subject = toy_detector.predict("please read the message")
    assert 0.0 <= with_subject.phishing_score <= 1.0
    # The subject is part of the input, so it must be able to change the score
    assert with_subject.phishing_score != without_subject.phishing_score


def test_email_with_only_subject_is_accepted(toy_detector):
    result = toy_detector.predict("", subject="verify your account")
    assert 0.0 <= result.phishing_score <= 1.0


def test_predictions_are_deterministic(toy_detector):
    text = "claim your reward"
    assert toy_detector.predict(text).phishing_score == toy_detector.predict(text).phishing_score


def test_pipeline_uses_shared_preprocessing():
    # Training and inference must both use src.preprocessing.clean_text
    assert build_pipeline().named_steps["tfidf"].preprocessor is clean_text


# ---------- real model (skipped until train_model.py has been run) ----------

real_model = pytest.mark.skipif(not MODEL_PATH.exists(), reason="run train_model.py first")


@real_model
def test_real_model_loads_and_scores_email_and_sms():
    detector = PhishingDetector()
    assert detector.thresholds_source == "validation"
    email = detector.predict("Please find the agenda for Monday attached.", subject="Team meeting")
    sms = detector.predict("Running 10 mins late, see you soon")
    for result in (email, sms):
        assert 0.0 <= result.phishing_score <= 1.0
        assert result.label in {"phishing", "legitimate"}


@real_model
def test_real_thresholds_are_ordered():
    thresholds = json.loads(THRESHOLDS_PATH.read_text())
    assert (thresholds["medium_threshold"]
            <= thresholds["classification_threshold"]
            <= thresholds["high_threshold"])
