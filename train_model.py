"""Stage 3: train the TF-IDF + Logistic Regression phishing classifier.

Usage:
    python train_model.py

Steps:
  1. Load data/processed/training_data.csv (created by prepare_data.py).
  2. Split it into train (70%), validation (15%) and test (15%) sets,
     stratified by label AND channel so each split has the same mix of
     email/SMS and phishing/legitimate messages.
  3. Fit the pipeline on the TRAIN set only (no leakage into validation/test).
  4. Use the VALIDATION set to choose the Medium/High risk thresholds.
  5. Save the pipeline, thresholds and the three splits.
The test set is not used here at all; evaluate_model.py uses it.
"""

import json
import sys
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_curve
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from src.config import (
    LABEL_LEGITIMATE,
    LABEL_PHISHING,
    MODEL_PATH,
    MODELS_DIR,
    THRESHOLDS_PATH,
    TRAIN_SET_PATH,
    TEST_SET_PATH,
    TRAINING_DATA_PATH,
    VALIDATION_SET_PATH,
    load_settings,
)
from src.preprocessing import clean_text

# Keep tokens like "£500", "$100" and "€50" together; otherwise any word of 1+ characters.
TOKEN_PATTERN = r"[£$€₹]?\b\w+\b"


def build_pipeline(random_seed: int = 42) -> Pipeline:
    """Create the (untrained) TF-IDF + Logistic Regression pipeline.

    clean_text is set as the vectorizer's preprocessor, so the saved pipeline
    applies exactly the same preprocessing at prediction time.
    """
    vectorizer = TfidfVectorizer(
        preprocessor=clean_text,
        token_pattern=TOKEN_PATTERN,
        ngram_range=(1, 2),     # single words and two-word phrases ("verify your")
        min_df=2,               # ignore terms seen in only one message
        max_df=0.95,            # ignore terms found in almost every message
        sublinear_tf=True,      # dampen the effect of very long messages
        max_features=50000,
    )
    classifier = LogisticRegression(
        class_weight="balanced",  # phishing is the minority class
        max_iter=2000,
        random_state=random_seed,
    )
    return Pipeline([("tfidf", vectorizer), ("classifier", classifier)])


def to_binary(labels: pd.Series) -> np.ndarray:
    """phishing -> 1, legitimate -> 0"""
    return (labels == LABEL_PHISHING).astype(int).to_numpy()


def split_data(df: pd.DataFrame, settings: dict):
    """Stratified 70/15/15 split on label + channel, with a fixed random seed."""
    seed = settings["random_seed"]
    strata = df["label"] + "_" + df["channel"]

    train_val, test = train_test_split(
        df, test_size=settings["test_size"], stratify=strata, random_state=seed
    )
    # validation_size is a share of the WHOLE dataset, so rescale it
    val_share = settings["validation_size"] / (1 - settings["test_size"])
    train, validation = train_test_split(
        train_val, test_size=val_share,
        stratify=strata.loc[train_val.index], random_state=seed,
    )
    return train, validation, test


def choose_risk_thresholds(y_true, scores, risk_settings: dict, classification_threshold: float) -> dict:
    """Pick Medium/High risk score thresholds using the validation set.

    - Medium threshold: the highest score threshold that still catches at least
      `medium_recall_target` of validation phishing messages.
    - High threshold: the lowest score threshold at which at least
      `high_precision_target` of validation messages flagged are truly phishing.
    The classification threshold always sits between the two, so a message
    predicted as phishing is never shown as Low risk.
    """
    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    precision, recall = precision[:-1], recall[:-1]  # align with thresholds

    meets_recall = thresholds[recall >= risk_settings["medium_recall_target"]]
    medium = float(meets_recall.max()) if len(meets_recall) else risk_settings["default_medium_threshold"]

    meets_precision = thresholds[precision >= risk_settings["high_precision_target"]]
    high = float(meets_precision.min()) if len(meets_precision) else risk_settings["default_high_threshold"]

    medium = min(medium, classification_threshold)
    high = max(high, classification_threshold)
    return {
        "classification_threshold": classification_threshold,
        "medium_threshold": round(medium, 4),
        "high_threshold": round(high, 4),
        "chosen_on": "validation set",
        "medium_recall_target": risk_settings["medium_recall_target"],
        "high_precision_target": risk_settings["high_precision_target"],
    }


def main() -> int:
    if not TRAINING_DATA_PATH.exists():
        print(f"ERROR: {TRAINING_DATA_PATH} not found. Run first:  python prepare_data.py")
        return 1

    settings = load_settings()
    model_settings = settings["model"]
    seed = model_settings["random_seed"]

    df = pd.read_csv(TRAINING_DATA_PATH)
    df = df[df["label"].isin([LABEL_PHISHING, LABEL_LEGITIMATE])].dropna(subset=["text"])
    print(f"Loaded {len(df)} messages")

    train, validation, test = split_data(df, model_settings)
    for name, part in [("train", train), ("validation", validation), ("test", test)]:
        counts = part.groupby(["channel", "label"]).size().to_dict()
        print(f"  {name:<10} {len(part):>5} messages  {counts}")

    print("Training TF-IDF + Logistic Regression on the training set...")
    pipeline = build_pipeline(seed)
    pipeline.fit(train["text"], to_binary(train["label"]))
    vocabulary_size = len(pipeline.named_steps["tfidf"].vocabulary_)
    print(f"  vocabulary size: {vocabulary_size}")

    print("Choosing risk thresholds on the validation set...")
    validation_scores = pipeline.predict_proba(validation["text"])[:, 1]
    thresholds = choose_risk_thresholds(
        to_binary(validation["label"]), validation_scores,
        settings["risk"], model_settings["classification_threshold"],
    )
    thresholds.update({
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scikit_learn_version": sklearn.__version__,
        "random_seed": seed,
        "train_size": len(train),
        "vocabulary_size": vocabulary_size,
    })
    print(f"  medium >= {thresholds['medium_threshold']}, high >= {thresholds['high_threshold']}")

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    with open(THRESHOLDS_PATH, "w", encoding="utf-8") as file:
        json.dump(thresholds, file, indent=2)
    train.to_csv(TRAIN_SET_PATH, index=False)
    validation.to_csv(VALIDATION_SET_PATH, index=False)
    test.to_csv(TEST_SET_PATH, index=False)

    print(f"\nSaved model to       {MODEL_PATH}")
    print(f"Saved thresholds to  {THRESHOLDS_PATH}")
    print(f"Saved data splits to {TRAIN_SET_PATH.parent}")
    print("Next step:  python evaluate_model.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
