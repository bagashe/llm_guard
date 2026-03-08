#!/usr/bin/env python3
"""Train a multi-label logistic classifier and export JSON model for Go runtime."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

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
    args = parser.parse_args()

    train_rows = read_jsonl(Path(args.train))
    val_rows = read_jsonl(Path(args.val))
    x_train, y_train = to_xy(train_rows)
    x_val, y_val = to_xy(val_rows)

    vectorizer = CountVectorizer(
        lowercase=True,
        max_features=args.max_features,
        token_pattern=r"(?u)\b\w+\b",
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

    report_text = classification_report(y_val, y_pred, target_names=LABELS, zero_division=0)
    report_dict = classification_report(y_val, y_pred, target_names=LABELS, zero_division=0, output_dict=True)
    print(report_text)

    vocab = {k: int(v) for k, v in vectorizer.vocabulary_.items()}
    n_features = len(vocab)
    weights = {}
    bias = {}
    for i, label in enumerate(LABELS):
        est = model.estimators_[i]
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
