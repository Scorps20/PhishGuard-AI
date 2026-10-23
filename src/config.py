"""Central place for project paths and settings.

All paths are built from this file's location, so scripts work no matter
which folder the terminal is currently in.
"""

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CONFIG_DIR = PROJECT_ROOT / "config"
DATA_RAW_DIR = PROJECT_ROOT / "data" / "raw"
DATA_PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"

DATASETS_CONFIG_PATH = CONFIG_DIR / "datasets.json"
SETTINGS_PATH = CONFIG_DIR / "settings.json"
PHRASES_PATH = CONFIG_DIR / "suspicious_phrases.json"

# Output of prepare_data.py
ALL_LABELLED_PATH = DATA_PROCESSED_DIR / "all_labelled.csv"   # phishing / legitimate / spam
TRAINING_DATA_PATH = DATA_PROCESSED_DIR / "training_data.csv"  # phishing / legitimate only

# Output of train_model.py
MODEL_PATH = MODELS_DIR / "phishguard_pipeline.joblib"
TRAIN_SET_PATH = DATA_PROCESSED_DIR / "train_set.csv"
TEST_SET_PATH = DATA_PROCESSED_DIR / "test_set.csv"
VALIDATION_SET_PATH = DATA_PROCESSED_DIR / "validation_set.csv"
THRESHOLDS_PATH = MODELS_DIR / "thresholds.json"

# Output of evaluate_model.py
EVALUATION_REPORT_PATH = REPORTS_DIR / "evaluation.json"
EVALUATION_SUMMARY_PATH = REPORTS_DIR / "evaluation_summary.md"
CONFUSION_MATRIX_PATH = REPORTS_DIR / "confusion_matrix_test.png"

# The two classes the model predicts
LABEL_PHISHING = "phishing"
LABEL_LEGITIMATE = "legitimate"
LABEL_SPAM = "spam"  # kept in all_labelled.csv but excluded from training


def load_json(path: Path) -> dict:
    """Read a JSON file and return its contents, with a clear error if it is missing."""
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def load_settings() -> dict:
    return load_json(SETTINGS_PATH)
