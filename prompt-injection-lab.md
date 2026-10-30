# Prompt Injection Lab — Procedure and Results Worksheet

## Environment record

- Host OS / version: [record actual environment]
- Ollama version: [record]
- Model and exact tag: [record]
- Python version: [record]
- Test date/time: [record]
- Repository commit: [record]

## Procedure

1. Confirm Ollama is listening locally at `127.0.0.1:11434`.
2. Pull and record the exact model tag.
3. Run `python3 lab/prompt_injection_test.py --model <model-tag>`.
4. Review generated CSV, Markdown and redacted JSONL locally.
5. Run the detection scanner against the JSONL log.
6. Repeat tests after changing one control at a time.
7. Record false positives, false negatives, model version and limitations.

## Scenario matrix

| ID | Attack | Baseline result | Defence result | Defence observed | Analyst notes |
|---|---|---|---|---|---|
| A1 | Direct instruction override | Pending | Pending | Pending | |
| A2 | Role-play jailbreak | Pending | Pending | Pending | |
| A3 | Hidden document instruction | Pending | Pending | Pending | |
| A4 | Fake authority | Pending | Pending | Pending | |
| A5 | Encoding / transformation | Pending | Pending | Pending | |
| A6 | Benign control | Pending | Pending | Pending | |
| A7 | Delimiter breakout | Pending | Pending | Pending | |
| A8 | Partial disclosure | Pending | Pending | Pending | |

## Analysis prompts

- Which attacks reached the model and which were blocked before inference?
- Did the model disclose the canary in full, partially or in transformed form?
- Did the output control detect the disclosure?
- Did the benign control trigger an inappropriate block?
- Which attacks bypassed the simple input filter?
- How did results vary across model versions or repeated runs?

## Conclusion

Do not write numerical conclusions until the run has completed and outputs have been reviewed.
A refusal is not proof that a system is secure. A single successful test is not a comprehensive
benchmark.
