"""Shared test fixtures.

The toy model is trained on a handful of made-up sentences so that tests can
check the prediction CODE without needing the real model. These sentences are
test fixtures only and are never used as training data for the real model.
"""

import json

import joblib
import pytest

from src.phishing_detector import PhishingDetector
from train_model import build_pipeline

TOY_TEXTS = [
    "verify your account now", "your account is suspended verify now",
    "claim your prize now", "claim your reward now verify",
    "see you at lunch tomorrow", "lunch tomorrow at noon see you",
    "meeting notes attached see you", "notes from the meeting tomorrow",
]
TOY_LABELS = [1, 1, 1, 1, 0, 0, 0, 0]
TOY_THRESHOLDS = {"classification_threshold": 0.5, "medium_threshold": 0.3, "high_threshold": 0.8}


@pytest.fixture
def toy_model_files(tmp_path):
    pipeline = build_pipeline(random_seed=0)
    pipeline.fit(TOY_TEXTS, TOY_LABELS)
    model_path = tmp_path / "model.joblib"
    thresholds_path = tmp_path / "thresholds.json"
    joblib.dump(pipeline, model_path)
    thresholds_path.write_text(json.dumps(TOY_THRESHOLDS))
    return model_path, thresholds_path


@pytest.fixture
def toy_detector(toy_model_files):
    model_path, thresholds_path = toy_model_files
    return PhishingDetector(model_path, thresholds_path)
