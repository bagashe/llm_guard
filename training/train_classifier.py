#!/usr/bin/env python3
"""Train a multi-label logistic classifier and export JSON model for Go runtime."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any, cast

import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.multiclass import OneVsRestClassifier

LABELS = [
    "prompt_injection",
    "exfiltration_intent",
    "host_takeover_or_jailbreak",
]

TOKENIZER_TYPE = "char_ngram_wb"
TOKENIZER_LOWERCASE = True


def tokenize_text_char_ngram_wb(text: str, min_n: int, max_n: int) -> list[str]:
    value = text.lower() if TOKENIZER_LOWERCASE else text
    words = value.split()
    out: list[str] = []
    for word in words:
        if not word:
            continue
        padded = f" {word} "
        for n in range(min_n, max_n + 1):
            if len(padded) < n:
                continue
            for i in range(len(padded) - n + 1):
                out.append(padded[i : i + n])
    return out


def read_jsonl(path: Path):
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            rows.append(json.loads(line))
    return rows


def to_xy(rows):
    texts = []
    y = np.zeros((len(rows), len(LABELS)), dtype=np.int32)
    for i, row in enumerate(rows):
        texts.append(row["text"])
        labels = set(row.get("labels", []))
        for j, label in enumerate(LABELS):
            y[i, j] = 1 if label in labels else 0
    return texts, y


def optimize_thresholds(y_true, y_prob):
    thresholds = {}
    for i, label in enumerate(LABELS):
        best_t = 0.5
        best_f1 = -1.0
        for t in np.linspace(0.25, 0.85, 25):
            pred = (y_prob[:, i] >= t).astype(int)
            tp = int(((pred == 1) & (y_true[:, i] == 1)).sum())
            fp = int(((pred == 1) & (y_true[:, i] == 0)).sum())
            fn = int(((pred == 0) & (y_true[:, i] == 1)).sum())
            precision = tp / (tp + fp + 1e-9)
            recall = tp / (tp + fn + 1e-9)
            f1 = 2 * precision * recall / (precision + recall + 1e-9)
            if f1 > best_f1:
                best_f1 = f1
                best_t = float(t)
        thresholds[label] = round(best_t, 3)
    return thresholds


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", default="training/data/train.jsonl")
    parser.add_argument("--val", default="training/data/val.jsonl")
    parser.add_argument("--out", default="models/classifier_v1.json")
    parser.add_argument("--metrics-out", default="training/artifacts/classifier_v1_metrics.json")
    parser.add_argument("--max-features", type=int, default=50000)
    parser.add_argument("--char-ngram-min", type=int, default=3)
    parser.add_argument("--char-ngram-max", type=int, default=5)
    args = parser.parse_args()

    if args.char_ngram_min < 1:
        raise ValueError("--char-ngram-min must be >= 1")
    if args.char_ngram_max < args.char_ngram_min:
        raise ValueError("--char-ngram-max must be >= --char-ngram-min")

    train_rows = read_jsonl(Path(args.train))
    val_rows = read_jsonl(Path(args.val))
    x_train, y_train = to_xy(train_rows)
    x_val, y_val = to_xy(val_rows)

    vectorizer = CountVectorizer(
        lowercase=False,
        max_features=args.max_features,
        tokenizer=lambda value: tokenize_text_char_ngram_wb(value, args.char_ngram_min, args.char_ngram_max),
        preprocessor=None,
        token_pattern=cast(Any, None),
    )
    x_train_vec = vectorizer.fit_transform(x_train)
    x_val_vec = vectorizer.transform(x_val)

    model = OneVsRestClassifier(LogisticRegression(max_iter=1000, class_weight="balanced"))
    model.fit(x_train_vec, y_train)

    y_prob = model.predict_proba(x_val_vec)
    thresholds = optimize_thresholds(y_val, y_prob)

    y_pred = np.zeros_like(y_prob, dtype=np.int32)
    for i, label in enumerate(LABELS):
        y_pred[:, i] = (y_prob[:, i] >= thresholds[label]).astype(int)

    zero_division_value: Any = 0
    report_text = classification_report(y_val, y_pred, target_names=LABELS, zero_division=zero_division_value)
    report_dict = classification_report(
        y_val,
        y_pred,
        target_names=LABELS,
        zero_division=zero_division_value,
        output_dict=True,
    )
    print(report_text)

    vocab = {k: int(v) for k, v in vectorizer.vocabulary_.items()}
    n_features = len(vocab)
    weights = {}
    bias = {}
    estimators = list(model.estimators_)
    for i, label in enumerate(LABELS):
        est: Any = estimators[i]
        if hasattr(est, "coef_") and hasattr(est, "intercept_"):
            coef = est.coef_[0]
            coef = coef[:n_features]
            weights[label] = coef.tolist()
            bias[label] = float(est.intercept_[0])
            continue

        weights[label] = [0.0] * n_features
        p = float(y_train[:, i].mean())
        p = min(max(p, 1e-6), 1 - 1e-6)
        bias[label] = float(math.log(p / (1 - p)))

    out = {
        "version": "v1",
        "labels": LABELS,
        "tokenizer": {
            "type": TOKENIZER_TYPE,
            "lowercase": TOKENIZER_LOWERCASE,
            "ngram_min": args.char_ngram_min,
            "ngram_max": args.char_ngram_max,
        },
        "vocab": vocab,
        "weights": weights,
        "bias": bias,
        "thresholds": thresholds,
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(out, f)

    metrics_out_path = Path(args.metrics_out)
    metrics_out_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_payload = {
        "train_rows": len(train_rows),
        "val_rows": len(val_rows),
        "labels": LABELS,
        "thresholds": thresholds,
        "classification_report": report_dict,
    }
    with metrics_out_path.open("w", encoding="utf-8") as f:
        json.dump(metrics_payload, f)

    print(f"saved model to {out_path}")
    print(f"saved metrics to {metrics_out_path}")


if __name__ == "__main__":
    main()
