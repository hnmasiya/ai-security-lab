# Wazuh integration for the AI Security Lab

Custom Wazuh rules that turn the lab's JSONL telemetry (`logs/ai_assistant.jsonl`) into searchable alerts.

```
AI Security Lab (Ollama) -> JSONL telemetry -> Wazuh Manager (rules 100000-100002)
  -> Filebeat -> Wazuh Indexer -> Wazuh Dashboard
```

Tested with Wazuh 4.14.7 (single-node, Docker Compose). Evidence: [`reports/WAZUH-DETECTION-PIPELINE-EVIDENCE-2026-10-31.md`](../reports/WAZUH-DETECTION-PIPELINE-EVIDENCE-2026-10-31.md).

## Files

| File | Purpose |
|---|---|
| `wazuh/rules/ai-security-lab.xml` | Rules 100000-100002 |
| `wazuh/ossec-localfile.xml` | `<localfile>` block that makes Wazuh read the telemetry file |

## Rules

| Rule | Meaning | Level |
|---|---|---|
| 100000 | Any lab event (parent rule): JSON with `scenario_id` and `canary_detected` true/false | 3 |
| 100001 | `canary_detected` is `true` (synthetic canary leaked: injection succeeded) | 12 |
| 100002 | `blocked_by` is non-empty (the input filter blocked the prompt) | 8 |

Each event matches exactly one rule. The `ai_security_lab` group label appears twice because it is declared on both the group and the rule; this is cosmetic.

## Install

1. Copy `ai-security-lab.xml` to `/var/ossec/etc/rules/` on the Manager (owner `root:wazuh`, mode `660`).
2. Add the block from `ossec-localfile.xml` to `/var/ossec/etc/ossec.conf`.
3. Create the telemetry file, owned by `wazuh`:
   ```
   touch /var/ossec/logs/ai-security-lab.jsonl && chown wazuh:wazuh /var/ossec/logs/ai-security-lab.jsonl && chmod 660 /var/ossec/logs/ai-security-lab.jsonl
   ```
4. Validate and restart the Wazuh daemons:
   ```
   /var/ossec/bin/wazuh-analysisd -t
   /var/ossec/bin/wazuh-control restart
   ```
5. Append records produced by `lab/prompt_injection_test.py` to the telemetry file.

## Test the rules without touching the telemetry file

Run `/var/ossec/bin/wazuh-logtest`, paste a synthetic record and check which rule fires:

```
{"timestamp":"2026-10-31T00:00:00Z","scenario_id":"T1","model":"test","mode":"baseline","canary_detected":true,"blocked_by":null,"user":"logtest"}
```

Expected: rule 100001. Use `"canary_detected":false,"blocked_by":"input_filter"` for 100002 and `"blocked_by":null` for 100000.

## Privacy

- Do not commit raw telemetry: it contains prompts and responses. `logs/` and `results/` stay git-ignored.
- Remove prompt and response text from any exported alert before sharing it.
- Never commit Wazuh, Indexer or API credentials.

## Limits

These rules were verified on 38 real lab records (32 in the final runs). The results describe those specific synthetic tests and are not evidence of general protection against prompt injection.
