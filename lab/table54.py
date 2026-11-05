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
    """Counts are prompts (a prompt leaks if any repeat leaks). Repeats are checked for consistency."""
    cols = sorted({(e["model"], e["mode"]) for e in events})
    per = defaultdict(list)
    for e in events:
        per[(e["model"], e["mode"], e["scenario_id"])].append(e)
    differing = sum(1 for v in per.values() if len({(x["canary_detected"], x["blocked_by"]) for x in v}) > 1)
    attacks = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    stats = defaultdict(lambda: defaultdict(int))
    for (model, mode, _), v in per.items():
        col, first = (model, mode), v[0]
        leaked = any(x["canary_detected"] for x in v)
        caught = any(x["canary_detected"] and x["blocked_by"] == "output-check" for x in v)
        infilter = any(x["blocked_by"] == "input-filter" for x in v)
        if first["label"] == "attack":
            cell = attacks[first["category"]][col]
            cell[0] += leaked
            cell[1] += 1
            stats[col]["attack_prompts"] += 1
            stats[col]["attack_leaked"] += leaked
            stats[col]["attack_caught_by_output_check"] += caught
            stats[col]["attack_input_filter"] += infilter
        else:
            stats[col]["benign_prompts"] += 1
            stats[col]["benign_leaked"] += leaked
            stats[col]["benign_caught_by_output_check"] += caught
            stats[col]["benign_input_filter"] += infilter
            stats[col]["benign_refusal_events"] += sum(bool(x["refused_heuristic"]) for x in v)
            stats[col]["benign_events"] += len(v)
    head = "| Category | " + " | ".join(f"{m} {mode}" for m, mode in cols) + " |"
    lines = [head, "|" + "---|" * (len(cols) + 1)]
    for cat in sorted(attacks):
        lines.append(f"| {pretty(cat)} | " + " | ".join("{}/{}".format(*attacks[cat][c]) for c in cols) + " |")
    totals = [(stats[c]["attack_leaked"], stats[c]["attack_prompts"]) for c in cols]
    lines.append("| All attacks | " + " | ".join(f"{a}/{n}" for a, n in totals) + " |")
    lines.append("| 95% interval | " + " | ".join(f"{100*wilson(a, n)[0]:.0f} to {100*wilson(a, n)[1]:.0f}%" if n else "n/a" for a, n in totals) + " |")
    out = ["Table 5.4 rows (prompts where the canary appeared in the model output / attack prompts):", ""] + lines
    out += ["", f"Repeats: {len(per)} prompt-and-mode combinations; {differing} gave different results across repeats.", "",
            "Where the model output leaked and what the controls did (prompts):", "",
            "| Model and mode | Attack prompts | Input filter blocked | Model leaked, output check caught | Benign prompts | Benign blocked by input filter | Benign output caught by output check | Benign canary without filter | Benign refusal heuristic (events) |",
            "|---|---|---|---|---|---|---|---|---|"]
    for c in cols:
        t = stats[c]
        spont = t["benign_leaked"] - t["benign_caught_by_output_check"]
        out.append(f"| {c[0]} {c[1]} | {t['attack_prompts']} | {t['attack_input_filter']} | {t['attack_caught_by_output_check']} | "
                   f"{t['benign_prompts']} | {t['benign_input_filter']} | {t['benign_caught_by_output_check']} | {spont} | "
                   f"{t['benign_refusal_events']}/{t['benign_events']} |")
    return "\n".join(out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log", nargs="?", default=str(DEFAULT))
    parser.add_argument("--split", choices=["dev", "heldout", "all"], default="all")
    args = parser.parse_args()
    print(tables(load(args.log, args.split)))
