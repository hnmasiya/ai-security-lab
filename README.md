# AI Cybersecurity & Governance Lab

Part of my cybersecurity portfolio: [hnmasiya/cybersecurity-portfolio](https://github.com/hnmasiya/cybersecurity-portfolio).

A safe, local portfolio lab applying concepts from **AI Cybersecurity and Governance**
(Columbia+ / Columbia Engineering, October 2026).

Credential: https://www.credential.net/c291f4f2-a326-4a4f-ba4f-b9fc6d981b85

> **Evidence status:** Project scaffold and offline unit tests are prepared. Live LLM
> attack outcomes are intentionally not claimed until Ollama tests have actually run
> and their results have been reviewed.

## Objectives

- Explore direct and indirect prompt injection against a fictional assistant.
- Compare a baseline configuration with layered defensive controls.
- Produce privacy-conscious security event logs and run local detection.
- Build an AI inventory, risk register, threat model and governance artefacts.
- Map controls to ISO/IEC 42001 themes and Google SAIF elements without inventing
  clause numbers or claiming certification.

## Lab architecture

```text
Untrusted user/document
        |
        v
Local test harness ----> Ollama API (127.0.0.1:11434)
        |                         |
        +---- defensive controls <-+
        |
        +--> redacted JSONL logs --> local detection scanner
        +--> CSV / Markdown results
```

All test content is fictional. The canary is a synthetic marker, not a credential.
No external service, real customer data, mailbox, production system or agent tool is used.

## Requirements

- Python 3.10+ (standard library only)
- Ollama installed locally
- A model downloaded locally, e.g. `llama3.2` (model size and hardware requirements vary)

## Quick start

```bash
ollama pull llama3.2
ollama serve
# In another terminal, from this repository:
python3 lab/prompt_injection_test.py --model llama3.2
python3 detection/detect_injection.py logs/ai_assistant.jsonl\npython3 detection/detect_injection.py detection/sample_ai_events.jsonl
python3 detection/shadow_ai_scan.py detection/sample_dns.log
python3 -m unittest discover -s tests -v
```

The harness contacts only the local Ollama endpoint. It does not install packages
or upload prompts. If Ollama is unavailable, the live test exits with an error;
offline unit tests remain runnable.

## Project layout

| Path | Purpose |
|---|---|
| `lab/prompt_injection_test.py` | Eight-scenario baseline/defended test harness |
| `lab/controls.py` | Testable input, document and output controls |
| `detection/detect_injection.py` | JSONL event scanner |
| `detection/injection_detection.yml` | Sigma-style application-log detection examples (not a validated Sigma backend rule) |
| `detection/shadow_ai_scan.py` | DNS log scanner for fictional Shadow AI indicators |
| `detection/sample_dns.log` | Synthetic DNS events |
| `tests/` | Offline unit tests |
| `ai-inventory.md` | Fictional AI inventory / AI-BOM template |
| `ai-risk-register.md` | Fictional SME risk register |
| `threat-model.md` | STRIDE-oriented threat model |
| `framework-mapping.md` | ISO/IEC 42001 theme and Google SAIF mapping |
| `security-plus-alignment.md` | Cautious mapping to Security+ domains 1–5 |
| `linkedin-and-cv-text.md` | Consistent GitHub, LinkedIn and CV wording |
| `incident-response-playbook.md` | Prompt-injection incident response |
| `ai-acceptable-use-policy.md` | Policy template |
| `ai-vendor-due-diligence.md` | AI vendor checklist |
| `secure-architecture.md` | Mermaid architecture diagrams |
| `executive-summary.md` | Management-facing summary template |
| `prompt-injection-lab.md` | Test procedure and results worksheet |

## Evidence and privacy

- `logs/` and generated `results/` are ignored by Git by default.
- Review local output before sharing. Do not add real prompts, personal data, credentials,
  API keys, private business content or unredacted production logs.
- Screenshots belong in `screenshots/`; inspect them for sensitive information first.
- Never replace placeholders with invented metrics. Report actual run counts and outcomes.
- The DNS scanner only identifies configured domain strings in supplied logs; it does
  not prove that a user accessed a service or uploaded data.

## Security+ alignment

See [`security-plus-alignment.md`](security-plus-alignment.md) for a cautious mapping to all five Security+ domains. This is supporting evidence, not complete objective coverage.

## Governance notes

This is an educational project, not an ISO/IEC 42001 audit, certification, legal opinion,
or assurance assessment. Framework mapping is thematic. Verify exact requirements and
controls against licensed/current source material before making compliance claims.

## Current validation status

- [x] Project files generated
- [x] Python syntax compilation
- [x] Offline unit tests
- [ ] Live Ollama test run
- [ ] Human review of model outputs and generated results
- [ ] Screenshots captured and reviewed
- [ ] Framework mapping independently checked
- [ ] Publication review
