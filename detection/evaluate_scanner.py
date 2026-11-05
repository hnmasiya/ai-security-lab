#!/usr/bin/env python3
"""Evaluate detection/detect_injection.py on the labelled prompt set (data/prompts.jsonl).

Needs no model. Reports detection rate (recall), false-positive rate and precision, with 95%
Wilson intervals, for each split and per category. The scanner's rules were tuned before this
dataset existed, but the dataset is written by the same author, so treat the numbers as a
baseline on one author's prompts, not as a general detection rate.

Usage:
  python3 detection/evaluate_scanner.py                 # all splits, markdown to stdout
  python3 detection/evaluate_scanner.py --split heldout
  python3 detection/evaluate_scanner.py --json results.json
"""
import argparse
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "detection"))
import detect_injection  # noqa: E402

DATASET = ROOT / "data" / "prompts.jsonl"


def load(path=DATASET):
    with Path(path).open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def flagged(prompt):
    return bool(detect_injection.classify({"prompt": prompt, "response": "", "canary_detected": False}))


def wilson(successes, total, z=1.96):
    """95% Wilson score interval for a proportion; (0, 0) when total is 0."""
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def summarise(rows):
    tp = sum(1 for r in rows if r["label"] == "attack" and r["flag"])
    fn = sum(1 for r in rows if r["label"] == "attack" and not r["flag"])
    fp = sum(1 for r in rows if r["label"] == "benign" and r["flag"])
    tn = sum(1 for r in rows if r["label"] == "benign" and not r["flag"])
    attacks, benign = tp + fn, fp + tn
    return {
        "attacks": attacks, "benign": benign, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "recall": tp / attacks if attacks else None,
        "recall_ci": wilson(tp, attacks),
        "fpr": fp / benign if benign else None,
        "fpr_ci": wilson(fp, benign),
        "precision": tp / (tp + fp) if (tp + fp) else None,
    }


def evaluate(rows, split=None):
    selected = [dict(r, flag=flagged(r["prompt"])) for r in rows if split in (None, "all", r["split"])]
    by_category = defaultdict(list)
    for r in selected:
        by_category[(r["label"], r["category"])].append(r)
    return {
        "split": split or "all",
        "overall": summarise(selected),
        "by_category": {f"{label}:{cat}": summarise(items) for (label, cat), items in sorted(by_category.items())},
    }


def pct(value):
    return "n/a" if value is None else f"{100 * value:.1f}%"


def interval(ci):
    return f"{100 * ci[0]:.0f}-{100 * ci[1]:.0f}%"


def to_markdown(result):
    o = result["overall"]
    lines = [
        f"### Split: {result['split']}", "",
        f"Attacks: {o['attacks']}, benign: {o['benign']}", "",
        "| Metric | Value | 95% interval |", "|---|---:|---:|",
        f"| Detection rate (recall) | {pct(o['recall'])} ({o['tp']}/{o['attacks']}) | {interval(o['recall_ci'])} |",
        f"| False-positive rate | {pct(o['fpr'])} ({o['fp']}/{o['benign']}) | {interval(o['fpr_ci'])} |",
        f"| Precision | {pct(o['precision'])} | |", "",
        "| Category | Label | Flagged / total |", "|---|---|---:|",
    ]
    for key, s in result["by_category"].items():
        label, cat = key.split(":", 1)
        flagged_count = s["tp"] if label == "attack" else s["fp"]
        total = s["attacks"] if label == "attack" else s["benign"]
        lines.append(f"| {cat} | {label} | {flagged_count}/{total} |")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--split", choices=["dev", "heldout", "all"], default=None)
    parser.add_argument("--json", help="also write the results to this JSON file")
    parser.add_argument("--dataset", default=str(DATASET))
    args = parser.parse_args()
    rows = load(args.dataset)
    splits = [args.split] if args.split else ["all", "dev", "heldout"]
    results = [evaluate(rows, s) for s in splits]
    print("\n\n".join(to_markdown(r) for r in results))
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
