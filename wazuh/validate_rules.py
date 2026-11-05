"""Run every dataset prompt through wazuh-logtest and report which rule fires and how long it takes.

Usage (on the machine running the Wazuh Docker stack):
    python wazuh/validate_rules.py --container <manager-container-name> [--split heldout]

It builds one JSON event per prompt (the fields the content rules read), pipes it
to /var/ossec/bin/wazuh-logtest inside the container, parses the matched rule id,
and writes results/wazuh_logtest_<timestamp>.csv plus a summary.
Latency is the wall-clock time of one logtest call and includes docker exec
start-up, so treat it as an upper bound, not as in-manager analysis time.
"""
import argparse, csv, json, re, statistics, subprocess, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection"))
from normalise import normalise  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def logtest(container, line):
    t0 = time.perf_counter()
    p = subprocess.run(["docker", "exec", "-i", container, "/var/ossec/bin/wazuh-logtest"],
                       input=line + "\n", capture_output=True, text=True, timeout=60)
    dt = time.perf_counter() - t0
    out = p.stdout + p.stderr
    m = re.search(r"Rule id: '(\d+)'", out)
    return (m.group(1) if m else ""), dt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", required=True)
    ap.add_argument("--split", default="heldout", choices=["dev", "heldout", "all"])
    a = ap.parse_args()
    rows = [json.loads(l) for l in (ROOT / "data/prompts.jsonl").read_text().splitlines() if l.strip()]
    if a.split != "all":
        rows = [r for r in rows if r["split"] == a.split]
    out = []
    for r in rows:
        ev = {"scenario_id": r["id"], "label": r["label"], "category": r["category"],
              "prompt": r["prompt"], "prompt_normalised": normalise(r["prompt"]),
              "canary_detected": False, "blocked_by": ""}
        rule, dt = logtest(a.container, json.dumps(ev, ensure_ascii=False))
        out.append({"id": r["id"], "label": r["label"], "category": r["category"],
                    "rule": rule, "seconds": round(dt, 3)})
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = ROOT / "results" / f"wazuh_logtest_{ts}.csv"
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0])); w.writeheader(); w.writerows(out)
    content = {str(i) for i in range(100010, 100022)}
    att = [o for o in out if o["label"] == "attack"]; ben = [o for o in out if o["label"] == "benign"]
    tp = sum(o["rule"] in content for o in att); fp = sum(o["rule"] in content for o in ben)
    lat = sorted(o["seconds"] for o in out)
    print(f"events {len(out)}  attacks flagged by 100010-100021: {tp}/{len(att)}  benign flagged: {fp}/{len(ben)}")
    print(f"latency s: median {statistics.median(lat):.3f}  p95 {lat[int(0.95*(len(lat)-1))]:.3f}  max {lat[-1]:.3f}")
    print("Expected for held-out from evaluate_rules.py: 22/48 attacks, 1/48 benign. Wrote", path)


if __name__ == "__main__":
    main()
