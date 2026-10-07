"""
train_model.py
----------------
Trains the ONLY machine-learning component of this platform: a
TF-IDF + Multinomial Naive Bayes classifier that scores email TEXT
CONTENT as SPAM or LIKELY LEGITIMATE.

This is intentionally separate from the Streamlit app: training happens
once, offline, and the app simply loads the resulting artifacts.

Input : data/raw/spam/*, data/raw/ham/*   (see download_dataset.py)
Output: model/spam_model.pkl
        model/vectorizer.pkl
        model/metrics.json

Usage:
    python train_model.py
"""

import json
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB

BASE_DIR = Path(__file__).parent
RAW_DIR = BASE_DIR / "data" / "raw"
MODEL_DIR = BASE_DIR / "model"
MODEL_DIR.mkdir(exist_ok=True)

WHITESPACE_RE = re.compile(r"\s+")


def _read_email_text(path: Path) -> str:
    """Extract subject + plain-text body from a raw email file on disk."""
    try:
        with open(path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except Exception:
        return ""

    subject = msg.get("Subject", "") or ""
    body_parts = []
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain" and not part.is_multipart():
                    payload = part.get_payload(decode=True) or b""
                    body_parts.append(payload.decode("utf-8", errors="replace"))
        else:
            payload = msg.get_payload(decode=True) or b""
            body_parts.append(payload.decode("utf-8", errors="replace"))
    except Exception:
        pass

    text = subject + " " + " ".join(body_parts)
    return WHITESPACE_RE.sub(" ", text).strip()


def load_corpus() -> pd.DataFrame:
    rows = []
    for label_name, label_value in (("ham", 0), ("spam", 1)):
        folder = RAW_DIR / label_name
        if not folder.exists():
            print(f"[warn] {folder} not found - run download_dataset.py first.")
            continue
        files = [p for p in folder.rglob("*") if p.is_file()]
        print(f"[load] {label_name}: {len(files)} files found under {folder}")
        for path in files:
            text = _read_email_text(path)
            if text:
                rows.append({"text": text, "label": label_value})

    df = pd.DataFrame(rows)
    df = df.drop_duplicates(subset="text").reset_index(drop=True)
    return df


def main() -> None:
    print("Loading SpamAssassin Public Corpus from data/raw/ ...")
    df = load_corpus()

    if df.empty or df["label"].nunique() < 2:
        raise SystemExit(
            "No usable training data found. Run 'python download_dataset.py' first, "
            "or place raw SpamAssassin messages under data/raw/spam and data/raw/ham."
        )

    print(f"Total usable emails: {len(df)} "
          f"(spam={int((df.label == 1).sum())}, ham={int((df.label == 0).sum())})")

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["label"], test_size=0.20, random_state=42, stratify=df["label"]
    )

    vectorizer = TfidfVectorizer(
        stop_words="english",
        ngram_range=(1, 2),
        max_features=100_000,
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)  # NEVER fit_transform on test/new data

    model = MultinomialNB()
    model.fit(X_train_vec, y_train)

    y_pred = model.predict(X_test_vec)

    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1_score": round(f1_score(y_test, y_pred), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "dataset": "SpamAssassin Public Corpus",
    }

    print("\nEvaluation on held-out test set:")
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    joblib.dump(model, MODEL_DIR / "spam_model.pkl")
    joblib.dump(vectorizer, MODEL_DIR / "vectorizer.pkl")
    with open(MODEL_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nSaved model artifacts to {MODEL_DIR}/")


if __name__ == "__main__":
    main()
