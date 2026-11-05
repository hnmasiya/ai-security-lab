#!/usr/bin/env python3
"""Turn the dataset runner's JSONL log into the dissertation's Table 5.4 (canary leaks by attack category).

Usage: python3 lab/table54.py [logs/ai_assistant_dataset.jsonl] [--split heldout|dev|all]
Prints a pipe table with one column per model and mode, cells as leaks/attack events, then a
benign-prompt table (input-filter blocks and refusal heuristic). Counts are events (prompt x repeat).
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "detection"))
from evaluate_scanner import wilson  # noqa: E402

DEFAULT = ROOT / "logs" / "ai_assistant_dataset.jsonl"


def load(path, split="all"):
    with Path(path).open(encoding="utf-8") as handle:
        events = [json.loads(line) for line in handle if line.strip()]
    return [e for e in events if split == "all" or e.get("split") == split]


def pretty(category):
    return category.replace("-", " ").capitalize()


def tables(events):
    cols = sorted({(e["model"], e["mode"]) for e in events})
    attacks = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for e in events:
        if e["label"] == "attack":
            cell = attacks[e["category"]][(e["model"], e["mode"])]
            cell[0] += bool(e["canary_detected"])
            cell[1] += 1
    head = "| Category | " + " | ".join(f"{m} {mode}" for m, mode in cols) + " |"
    lines = [head, "|" + "---|" * (len(cols) + 1)]
    for cat in sorted(attacks):
        lines.append(f"| {pretty(cat)} | " + " | ".join("{}/{}".format(*attacks[cat][c]) for c in cols) + " |")
    totals = [(sum(attacks[k][c][0] for k in attacks), sum(attacks[k][c][1] for k in attacks)) for c in cols]
    lines.append("| All attacks | " + " | ".join(f"{a}/{n}" for a, n in totals) + " |")
    lines.append("| 95% interval | " + " | ".join(f"{100*wilson(a, n)[0]:.0f} to {100*wilson(a, n)[1]:.0f}%" if n else "n/a" for a, n in totals) + " |")
    out = ["Table 5.4 rows (canary leaks / attack events):", ""] + lines + ["", "Benign prompts:", "",
           "| Model and mode | Benign events | Blocked by filter | Refusal heuristic |", "|---|---|---|---|"]
    for c in cols:
        b = [e for e in events if e["label"] == "benign" and (e["model"], e["mode"]) == c]
        out.append(f"| {c[0]} {c[1]} | {len(b)} | {sum(e['blocked_by'] == 'input-filter' for e in b)} | {sum(bool(e['refused_heuristic']) for e in b)} |")
    return "\n".join(out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log", nargs="?", default=str(DEFAULT))
    parser.add_argument("--split", choices=["dev", "heldout", "all"], default="all")
    args = parser.parse_args()
    print(tables(load(args.log, args.split)))
