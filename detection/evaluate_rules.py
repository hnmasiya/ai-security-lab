#!/usr/bin/env python3
"""Evaluate the content-based Wazuh rules (rules 100010-100021) on data/prompts.jsonl, offline.

Reads the regular expressions from wazuh/rules/ai-security-lab-content.xml, normalises each prompt
with detection/normalise.py and applies them with Python's `re`. This is an offline equivalent of
Wazuh's PCRE2 matching, not Wazuh itself: confirm with wazuh-logtest on the manager before
quoting the numbers as Wazuh results. Reports each detector (D1 scanner, D2 rules, D1 or D2) by
split, with 95% Wilson intervals, per-category counts and per-rule counts.

Usage: python3 detection/evaluate_rules.py [--split dev|heldout|all] [--json out.json]
"""
import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "detection"))
import evaluate_scanner as es  # noqa: E402
from normalise import normalise  # noqa: E402

RULES_XML = ROOT / "wazuh" / "rules" / "ai-security-lab-content.xml"


def load_rules(path=RULES_XML):
    rules = []
    for rule in ET.parse(path).getroot().iter("rule"):
        field = rule.find("field")
        if field is not None and field.get("name") == "prompt_normalised":
            rules.append((int(rule.get("id")), re.compile(field.text)))
    return rules


def rules_hit(prompt, rules):
    text = normalise(prompt)
    return [rid for rid, pattern in rules if pattern.search(text)]


def evaluate(rows, rules, detector, split=None):
    selected = []
    for r in rows:
        if split not in (None, "all", r["split"]):
            continue
        hits = rules_hit(r["prompt"], rules)
        flag = {"D1": es.flagged(r["prompt"]), "D2": bool(hits), "D1+D2": es.flagged(r["prompt"]) or bool(hits)}[detector]
        selected.append(dict(r, flag=flag, hits=hits))
    by_cat = {}
    for r in selected:
        by_cat.setdefault((r["label"], r["category"]), []).append(r)
    per_rule = Counter((r["label"], rid) for r in selected for rid in r["hits"])
    return {"detector": detector, "split": split or "all", "overall": es.summarise(selected),
            "by_category": {f"{k[0]}:{k[1]}": es.summarise(v) for k, v in sorted(by_cat.items())},
            "per_rule": {f"{label}:{rid}": n for (label, rid), n in sorted(per_rule.items())},
            "false_positives": [r["id"] for r in selected if r["label"] == "benign" and r["flag"]],
            "misses": [r["id"] for r in selected if r["label"] == "attack" and not r["flag"]]}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--split", choices=["dev", "heldout", "all"], default=None)
    parser.add_argument("--json")
    args = parser.parse_args()
    rows, rules = es.load(), load_rules()
    results = []
    for split in ([args.split] if args.split else ["dev", "heldout", "all"]):
        for det in ("D1", "D2", "D1+D2"):
            results.append(evaluate(rows, rules, det, split))
    print("| Split | Detector | Recall | 95% CI | FPR | 95% CI | Precision |\n|---|---|---:|---:|---:|---:|---:|")
    for res in results:
        o = res["overall"]
        print(f"| {res['split']} | {res['detector']} | {es.pct(o['recall'])} ({o['tp']}/{o['attacks']}) | {es.interval(o['recall_ci'])} "
              f"| {es.pct(o['fpr'])} ({o['fp']}/{o['benign']}) | {es.interval(o['fpr_ci'])} | {es.pct(o['precision'])} |")
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
