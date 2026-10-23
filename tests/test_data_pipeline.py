"""Tests for dataset preparation and the train/validation/test split."""

import pandas as pd
import pytest

from prepare_data import clean_and_deduplicate, load_one_dataset
from src.config import TEST_SET_PATH, TRAIN_SET_PATH, VALIDATION_SET_PATH
from src.preprocessing import near_duplicate_key
from train_model import choose_risk_thresholds, split_data


def make_config(path, **overrides):
    config = {
        "name": "toy", "channel": "sms", "path": str(path),
        "text_column": "msg", "subject_column": None, "label_column": "tag",
        "label_mapping": {"ham": "legitimate", "smishing": "phishing", "spam": "spam"},
    }
    config.update(overrides)
    return config


def test_labels_are_normalised_and_unknown_labels_dropped(tmp_path):
    csv = tmp_path / "toy.csv"
    pd.DataFrame({"msg": ["a", "b", "c", "d"],
                  "tag": ["Smishing", " HAM ", "unknown", "spam"]}).to_csv(csv, index=False)
    df = load_one_dataset(make_config(csv))
    # "unknown" must be dropped, never assumed legitimate
    assert df["label"].tolist() == ["phishing", "legitimate", "spam"]


def test_missing_column_raises_clear_error(tmp_path):
    csv = tmp_path / "toy.csv"
    pd.DataFrame({"wrong": ["a"], "tag": ["ham"]}).to_csv(csv, index=False)
    with pytest.raises(ValueError, match="not found"):
        load_one_dataset(make_config(csv))


def test_remove_patterns_strip_artifacts(tmp_path):
    csv = tmp_path / "toy.csv"
    pd.DataFrame({"msg": ["Dear jose@monkey.org verify"], "tag": ["smishing"]}).to_csv(csv, index=False)
    df = load_one_dataset(make_config(csv, remove_patterns=[r"jose@monkey\.org"]))
    assert "monkey" not in df["text"].iloc[0]


def test_duplicates_and_conflicting_labels_removed():
    df = pd.DataFrame({
        "text": ["Call 0900111 now", "CALL 0900222 now!", "hi there", "hi there", "same text", "same text", " "],
        "label": ["phishing", "phishing", "legitimate", "legitimate", "phishing", "legitimate", "legitimate"],
        "channel": "sms", "source": "toy",
    })
    result = clean_and_deduplicate(df)
    assert sorted(result["text"]) == ["Call 0900111 now", "hi there"]


def test_split_is_stratified_and_reproducible():
    df = pd.DataFrame({
        "text": [f"message number {i}" for i in range(200)],
        "label": ["phishing"] * 40 + ["legitimate"] * 160,
        "channel": ["sms", "email"] * 100,
    })
    settings = {"random_seed": 42, "validation_size": 0.15, "test_size": 0.15}
    train, val, test = split_data(df, settings)
    assert len(train) + len(val) + len(test) == 200
    assert set(train.index).isdisjoint(test.index) and set(train.index).isdisjoint(val.index)
    assert abs((test["label"] == "phishing").mean() - 0.2) < 0.05
    train_again, _, _ = split_data(df, settings)
    assert train.index.equals(train_again.index)


def test_risk_thresholds_are_ordered():
    y_true = [0, 0, 0, 0, 1, 1, 1, 1]
    scores = [0.05, 0.1, 0.4, 0.6, 0.45, 0.7, 0.9, 0.95]
    risk = {"medium_recall_target": 0.99, "high_precision_target": 0.98,
            "default_medium_threshold": 0.3, "default_high_threshold": 0.8}
    t = choose_risk_thresholds(y_true, scores, risk, classification_threshold=0.5)
    assert t["medium_threshold"] <= 0.5 <= t["high_threshold"]


@pytest.mark.skipif(not TEST_SET_PATH.exists(), reason="run train_model.py first")
def test_no_near_duplicates_shared_between_real_splits():
    keys = {name: set(pd.read_csv(path)["text"].map(near_duplicate_key))
            for name, path in [("train", TRAIN_SET_PATH), ("val", VALIDATION_SET_PATH), ("test", TEST_SET_PATH)]}
    assert keys["train"].isdisjoint(keys["test"])
    assert keys["train"].isdisjoint(keys["val"])
    assert keys["val"].isdisjoint(keys["test"])
