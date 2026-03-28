#!/usr/bin/env python3
"""Build training data for the tool_result classifier.

The tool_result classifier is purpose-built for indirect prompt injection
detection inside web_extract results. Training data:

  - Benign: Wikipedia paragraphs (realistic web content, no attack signal)
  - Injected: Wikipedia paragraphs with an attack phrase spliced in at a
    random sentence boundary (indirect prompt injection)
  - Pure attacks: short attack examples from the main train.jsonl

The resulting distribution trains the classifier to distinguish injected
attack phrases from ordinary web text, preventing the false-positive
avalanche seen when the short-prompt classifier is applied to long pages
via sliding window.

Output schema (same as main train.jsonl):
  {"text": "...", "labels": []}                   # benign
  {"text": "...", "labels": ["prompt_injection"]}  # attack
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import textwrap
from pathlib import Path

SEED = 42

# Approximate word counts for paragraph sizing.
_MIN_WORDS = 50
_MAX_WORDS = 200

# Class sizes. Keep injected > pure so the model learns from web context.
_BENIGN_LIMIT = 20_000
_INJECTED_LIMIT = 15_000
_PURE_ATTACK_LIMIT = 5_000

# 90/10 train/val split.
_VAL_FRACTION = 0.10

ATTACK_LABELS = {"prompt_injection", "exfiltration_intent", "host_takeover_or_jailbreak"}


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _split_paragraphs(text: str, min_words: int, max_words: int) -> list[str]:
    """Split article text into paragraphs of min_words..max_words words."""
    # Normalize whitespace; split on double newlines first, then re-chunk.
    text = re.sub(r"\n{2,}", "\n\n", text.strip())
    raw_paras = [p.strip() for p in re.split(r"\n\n+", text) if p.strip()]

    out: list[str] = []
    for para in raw_paras:
        words = para.split()
        if len(words) < min_words:
            continue
        # Chunk long paragraphs into windows of up to max_words.
        start = 0
        while start < len(words):
            end = min(start + max_words, len(words))
            chunk = " ".join(words[start:end])
            if len(words[start:end]) >= min_words:
                out.append(chunk)
            start += max_words
    return out


def _inject_attack(para: str, attack: str) -> str:
    """Splice attack text at a random sentence boundary inside para."""
    # Split on sentence-ending punctuation; keep the delimiter.
    sentences = re.split(r"(?<=[.!?])\s+", para.strip())
    if len(sentences) < 2:
        # No sentence boundary — prepend so it's still present.
        return attack.strip() + " " + para
    idx = random.randint(1, len(sentences) - 1)
    sentences.insert(idx, attack.strip())
    return " ".join(sentences)


def build_dataset(attacks_path: Path, out_train: Path, out_val: Path) -> None:
    rng = random.Random(SEED)

    # ------------------------------------------------------------------ #
    # 1. Load attack examples from main train.jsonl                       #
    # ------------------------------------------------------------------ #
    attack_rows = read_jsonl(attacks_path)
    pure_attacks = [
        r for r in attack_rows
        if set(r.get("labels", [])) & ATTACK_LABELS
    ]
    rng.shuffle(pure_attacks)
    pure_attacks = pure_attacks[:_PURE_ATTACK_LIMIT]
    print(f"pure attacks: {len(pure_attacks)}")

    attack_texts = [r["text"] for r in pure_attacks]
    # Repeat if we have fewer attacks than needed for injection.
    while len(attack_texts) < _INJECTED_LIMIT:
        attack_texts = attack_texts + attack_texts
    rng.shuffle(attack_texts)

    # ------------------------------------------------------------------ #
    # 2. Stream Wikipedia paragraphs                                      #
    # ------------------------------------------------------------------ #
    try:
        from datasets import load_dataset  # type: ignore[import-untyped]
    except ImportError:
        raise SystemExit("Install the 'datasets' package: pip install datasets")

    print("Streaming Wikipedia… (this may take a few minutes on first run)")
    wiki = load_dataset(
        "wikimedia/wikipedia",
        "20231101.en",
        split="train",
        streaming=True,
        trust_remote_code=False,
    )

    benign_paras: list[str] = []
    needed = _BENIGN_LIMIT + _INJECTED_LIMIT  # collect enough for both uses

    for article in wiki:
        if len(benign_paras) >= needed:
            break
        text = article.get("text", "")
        if not text:
            continue
        paras = _split_paragraphs(text, _MIN_WORDS, _MAX_WORDS)
        benign_paras.extend(paras)
        if len(benign_paras) % 5_000 == 0:
            print(f"  collected {len(benign_paras)} paragraphs…")

    rng.shuffle(benign_paras)
    print(f"total Wikipedia paragraphs collected: {len(benign_paras)}")

    # ------------------------------------------------------------------ #
    # 3. Build final dataset                                              #
    # ------------------------------------------------------------------ #
    rows: list[dict] = []

    # Benign examples.
    for para in benign_paras[:_BENIGN_LIMIT]:
        rows.append({"text": para, "labels": []})

    # Injected examples: benign paragraph + attack phrase.
    injection_base = benign_paras[_BENIGN_LIMIT:_BENIGN_LIMIT + _INJECTED_LIMIT]
    for i, para in enumerate(injection_base):
        attack = attack_texts[i % len(attack_texts)]
        injected = _inject_attack(para, attack)
        rows.append({"text": injected, "labels": ["prompt_injection"]})

    # Pure attacks.
    for r in pure_attacks:
        rows.append({"text": r["text"], "labels": r.get("labels", [])})

    rng.shuffle(rows)

    # ------------------------------------------------------------------ #
    # 4. Train / val split                                                #
    # ------------------------------------------------------------------ #
    n_val = max(1, int(len(rows) * _VAL_FRACTION))
    val_rows = rows[:n_val]
    train_rows = rows[n_val:]

    out_train.parent.mkdir(parents=True, exist_ok=True)
    out_val.parent.mkdir(parents=True, exist_ok=True)

    with out_train.open("w", encoding="utf-8") as f:
        for row in train_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    with out_val.open("w", encoding="utf-8") as f:
        for row in val_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    label_counts: dict[str, int] = {}
    for row in rows:
        key = ",".join(sorted(row["labels"])) if row["labels"] else "benign"
        label_counts[key] = label_counts.get(key, 0) + 1

    print(f"\nDataset summary ({len(rows)} total, {len(train_rows)} train, {len(val_rows)} val):")
    for label, count in sorted(label_counts.items(), key=lambda x: -x[1]):
        print(f"  {label}: {count}")
    print(f"\nWrote {out_train}")
    print(f"Wrote {out_val}")

    # Force-exit to prevent the HuggingFace datasets streaming background
    # threads from hanging after we broke out of the iterator early.
    os._exit(0)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=textwrap.dedent("""\
            Prepare tool_result classifier training data.
            Requires: pip install datasets (Hugging Face)
        """)
    )
    parser.add_argument(
        "--attacks",
        default="training/data/train.jsonl",
        help="Path to main train.jsonl (source of attack examples)",
    )
    parser.add_argument(
        "--out",
        default="training/data/tool_result_train.jsonl",
        help="Output path for training JSONL",
    )
    parser.add_argument(
        "--val-out",
        default="training/data/tool_result_val.jsonl",
        help="Output path for validation JSONL",
    )
    args = parser.parse_args()

    build_dataset(
        attacks_path=Path(args.attacks),
        out_train=Path(args.out),
        out_val=Path(args.val_out),
    )


if __name__ == "__main__":
    main()
