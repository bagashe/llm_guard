#!/usr/bin/env python3
"""Cross-validate that Python tokenizer matches the shared fixture file used by Go tests."""

import json
import sys
from pathlib import Path

from train_classifier import tokenize_text_char_ngram_wb

FIXTURES = Path(__file__).parent / "tokenizer_fixtures.json"
NGRAM_MIN, NGRAM_MAX = 3, 5


def test_parity() -> None:
    cases = json.loads(FIXTURES.read_text(encoding="utf-8"))
    for case in cases:
        got = tokenize_text_char_ngram_wb(case["input"], NGRAM_MIN, NGRAM_MAX)
        assert got == case["tokens"], (
            f"mismatch for {case['input']!r}\n  got:  {got}\n  want: {case['tokens']}"
        )


if __name__ == "__main__":
    cases = json.loads(FIXTURES.read_text(encoding="utf-8"))
    test_parity()
    print(f"all {len(cases)} fixture cases passed")
    sys.exit(0)
