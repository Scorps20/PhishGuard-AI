"""Stage 2: load the raw datasets, clean them and save one combined CSV.

Usage:
    python prepare_data.py

Reads the dataset list from config/datasets.json and writes:
    data/processed/all_labelled.csv   - phishing, legitimate AND spam rows (for reference)
    data/processed/training_data.csv  - phishing and legitimate rows only (used for training)
"""

import sys

import pandas as pd

from src.config import (
    ALL_LABELLED_PATH,
    DATA_PROCESSED_DIR,
    DATA_RAW_DIR,
    DATASETS_CONFIG_PATH,
    LABEL_LEGITIMATE,
    LABEL_PHISHING,
    LABEL_SPAM,
    TRAINING_DATA_PATH,
    load_json,
)
from src.preprocessing import clean_text, combine_email_text, near_duplicate_key

ALLOWED_LABELS = {LABEL_PHISHING, LABEL_LEGITIMATE, LABEL_SPAM}

DOWNLOAD_HELP = """
How to get the datasets (see README.md, section 12 "Dataset placement"):
  1. SMS:   https://data.mendeley.com/datasets/f45bkkt8pr/1
            Download Dataset_5971.zip, unzip it and place Dataset_5971.csv in
            data/raw/sms_mendeley/
  2. Email: https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset
            Download Nazario.csv and SpamAssasin.csv and place them in
            data/raw/email/
"""


def load_one_dataset(config: dict) -> pd.DataFrame:
    """Load one raw dataset and return columns: text, label, channel, source."""
    name = config["name"]
    path = DATA_RAW_DIR / config["path"]
    df = pd.read_csv(path, encoding=config.get("encoding", "utf-8"))

    # Check the configured columns really exist in this file
    needed = [config["text_column"], config["label_column"]]
    if config.get("subject_column"):
        needed.append(config["subject_column"])
    missing = [col for col in needed if col not in df.columns]
    if missing:
        raise ValueError(
            f"[{name}] column(s) {missing} not found. "
            f"Available columns: {list(df.columns)}. Fix config/datasets.json."
        )

    # Build the message text (email = subject + body, SMS = text only)
    if config.get("subject_column"):
        text = [
            combine_email_text(subject, body)
            for subject, body in zip(df[config["subject_column"]], df[config["text_column"]])
        ]
    else:
        text = df[config["text_column"]]
    text = pd.Series(text, index=df.index).fillna("").astype(str)

    # Strip collection artifacts (e.g. the corpus owner's address) that would let
    # the model learn WHICH dataset a message came from instead of its content.
    for pattern in config.get("remove_patterns", []):
        text = text.str.replace(pattern, " ", case=False, regex=True)

    # Normalise labels: "Smishing", " smishing " and "SMISHING" all become "smishing"
    raw_labels = df[config["label_column"]].astype(str).str.strip().str.lower()
    mapping = {str(key).strip().lower(): value for key, value in config["label_mapping"].items()}
    bad_targets = set(mapping.values()) - ALLOWED_LABELS
    if bad_targets:
        raise ValueError(f"[{name}] label_mapping uses unknown target labels: {bad_targets}")

    result = pd.DataFrame({
        "text": text,
        "label": raw_labels.map(mapping),
        "channel": config["channel"],
        "source": name,
    })

    unmapped = result["label"].isna()
    if unmapped.any():
        unknown_values = sorted(raw_labels[unmapped].unique().tolist())
        print(f"  [{name}] dropping {unmapped.sum()} rows with unmapped labels: {unknown_values}")
    result = result[~unmapped]

    print(f"  [{name}] loaded {len(result)} rows from {path.name}")
    return result


def remove_duplicates(df: pd.DataFrame, key_column: str, description: str) -> pd.DataFrame:
    """Keep one copy of each message, judged by key_column.

    If the same message appears with two different labels, the label is
    unreliable, so every copy of it is dropped instead of picking one.
    """
    labels_per_key = df.groupby(key_column)["label"].nunique()
    conflicting = labels_per_key[labels_per_key > 1].index
    conflict_rows = df[key_column].isin(conflicting)
    print(f"  removed {conflict_rows.sum()} rows with conflicting labels ({description} match)")
    df = df[~conflict_rows]

    before = len(df)
    df = df.drop_duplicates(subset=key_column, keep="first")
    print(f"  removed {before - len(df)} {description} duplicates")
    return df


def clean_and_deduplicate(df: pd.DataFrame) -> pd.DataFrame:
    """Remove empty messages, exact duplicates and near-duplicates.

    Removing near-duplicates here (before any train/test split) means the
    same message template cannot end up in both the training and test sets.
    """
    df = df.copy()
    df["text"] = df["text"].fillna("").astype(str)
    df["_clean"] = df["text"].map(clean_text)

    empty = df["_clean"] == ""
    print(f"  removed {empty.sum()} empty messages")
    df = df[~empty]

    # 1. Exact duplicates (same text after cleaning)
    df = remove_duplicates(df, "_clean", "exact")

    # 2. Near-duplicates (same text apart from numbers, links and punctuation)
    df = df.assign(_near=df["text"].map(near_duplicate_key))
    df = remove_duplicates(df, "_near", "near")

    return df.drop(columns=["_clean", "_near"]).reset_index(drop=True)


def main() -> int:
    try:
        datasets_config = load_json(DATASETS_CONFIG_PATH)["datasets"]
    except (FileNotFoundError, KeyError) as error:
        print(f"ERROR: could not read dataset configuration: {error}")
        return 1

    enabled = [cfg for cfg in datasets_config if cfg.get("enabled", True)]
    missing_files = [str(DATA_RAW_DIR / cfg["path"]) for cfg in enabled
                     if not (DATA_RAW_DIR / cfg["path"]).exists()]
    if missing_files:
        print("ERROR: these dataset files are missing:")
        for path in missing_files:
            print(f"  - {path}")
        print(DOWNLOAD_HELP)
        return 1

    print("Loading datasets...")
    try:
        frames = [load_one_dataset(cfg) for cfg in enabled]
    except (ValueError, pd.errors.ParserError, UnicodeDecodeError) as error:
        print(f"ERROR: {error}")
        return 1

    print("Cleaning...")
    combined = clean_and_deduplicate(pd.concat(frames, ignore_index=True))

    DATA_PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    combined.to_csv(ALL_LABELLED_PATH, index=False)

    training = combined[combined["label"].isin([LABEL_PHISHING, LABEL_LEGITIMATE])]
    training.to_csv(TRAINING_DATA_PATH, index=False)

    print("\nAll labelled messages (by label):")
    print(combined["label"].value_counts().to_string())
    print("\nTraining data (spam excluded), by channel and label:")
    print(training.groupby(["channel", "label"]).size().to_string())
    print(f"\nSaved {len(combined)} rows to {ALL_LABELLED_PATH}")
    print(f"Saved {len(training)} rows to {TRAINING_DATA_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
