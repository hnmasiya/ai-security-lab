#!/usr/bin/env python3
"""Identify known public AI service domains in dnsmasq/Pi-hole-style logs."""
import re
import sys
from collections import Counter
from pathlib import Path

SERVICES = {
    "chatgpt.com": "ChatGPT", "chat.openai.com": "ChatGPT",
    "api.openai.com": "OpenAI API", "claude.ai": "Claude",
    "gemini.google.com": "Gemini", "copilot.microsoft.com": "Copilot",
    "perplexity.ai": "Perplexity", "api.deepseek.com": "DeepSeek",
    "deepseek.com": "DeepSeek", "poe.com": "Poe",
}
APPROVED = set()  # Populate only after an organisation formally approves a tool.
QUERY = re.compile(r"query\[\w+\]\s+(\S+)\s+from\s+(\S+)", re.I)

def identify(domain: str):
    domain = domain.lower().rstrip(".")
    for suffix, service in SERVICES.items():
        if domain == suffix or domain.endswith("." + suffix):
            return service
    return None

def scan(path: Path) -> int:
    hits = Counter()
    lines = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        lines += 1
        match = QUERY.search(line)
        if not match:
            continue
        domain, client = match.groups()
        service = identify(domain)
        if service and service not in APPROVED:
            hits[(client, service)] += 1
    print(f"Scanned {lines} DNS log line(s).")
    for (client, service), count in sorted(hits.items()):
        print(f"Possible unapproved AI domain: client={client} service={service} queries={count}")
    print("DNS matches are indicators only; they do not prove use, data disclosure, or policy violation.")
    return 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 detection/shadow_ai_scan.py <dns-log>")
    raise SystemExit(scan(Path(sys.argv[1])))
