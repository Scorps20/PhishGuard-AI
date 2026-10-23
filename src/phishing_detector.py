"""Load the trained model and classify a single message.

The saved pipeline already contains clean_text() as its preprocessing step,
so predictions here use exactly the same preprocessing as training.
"""

import json
from dataclasses import dataclass
from pathlib import Path

import joblib

from src.config import (
    LABEL_LEGITIMATE,
    LABEL_PHISHING,
    MODEL_PATH,
    THRESHOLDS_PATH,
    load_settings,
)
from src.preprocessing import combine_email_text, is_valid_message


class ModelNotFoundError(FileNotFoundError):
    """Raised when the trained model file does not exist yet."""


@dataclass
class Prediction:
    label: str                     # "phishing" or "legitimate"
    phishing_score: float          # model score between 0 and 1 (not a calibrated probability)
    classification_threshold: float

    @property
    def is_phishing(self) -> bool:
        return self.label == LABEL_PHISHING


class PhishingDetector:
    """Wraps the saved TF-IDF + Logistic Regression pipeline."""

    def __init__(self, model_path: Path = MODEL_PATH, thresholds_path: Path = THRESHOLDS_PATH):
        model_path = Path(model_path)
        if not model_path.exists():
            raise ModelNotFoundError(
                f"Trained model not found at {model_path}.\n"
                "Train it first by running these commands in the project folder:\n"
                "    python prepare_data.py\n"
                "    python train_model.py"
            )
        self.pipeline = joblib.load(model_path)
        # Column of predict_proba() that belongs to the phishing class (label 1)
        self._phishing_column = list(self.pipeline.classes_).index(1)
        self.thresholds, self.thresholds_source = self._load_thresholds(Path(thresholds_path))

    @staticmethod
    def _load_thresholds(path: Path):
        """Use thresholds chosen on validation data; fall back to config defaults."""
        if path.exists():
            with open(path, encoding="utf-8") as file:
                return json.load(file), "validation"
        settings = load_settings()
        return {
            "classification_threshold": settings["model"]["classification_threshold"],
            "medium_threshold": settings["risk"]["default_medium_threshold"],
            "high_threshold": settings["risk"]["default_high_threshold"],
        }, "defaults"

    def predict(self, message: str, subject: str | None = None) -> Prediction:
        """Classify one SMS (message only) or email (optional subject + body).

        Raises ValueError if there is no usable text.
        """
        text = combine_email_text(subject, message) if subject else message
        if not is_valid_message(text):
            raise ValueError("The message is empty. Please paste the text you want to analyse.")

        score = float(self.pipeline.predict_proba([text])[0, self._phishing_column])
        threshold = self.thresholds["classification_threshold"]
        label = LABEL_PHISHING if score >= threshold else LABEL_LEGITIMATE
        return Prediction(label=label, phishing_score=score, classification_threshold=threshold)
