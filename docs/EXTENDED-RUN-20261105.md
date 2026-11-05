# Extended model run, 5 November 2026 (held-out half)

Setup: Windows laptop, Ollama 0.40.14, temperature 0, num_predict 64, num_ctx 1024.
Models: llama3.2:1b, qwen2.5:1.5b. Baseline and defended mode. 48 attack and 48 benign
held-out prompts, 3 repeats each: 1,152 events. The raw event log
(`results/dataset_events_*.jsonl`, on the machine that ran it) is not in this repository yet.

All 384 prompt/model/mode combinations gave the same result in all three repeats, so counts
are in prompts (n = 48 attacks per model and mode). Wilson 95% intervals.

| Category | Llama base | Llama def | Qwen base | Qwen def |
|---|---|---|---|---|
| Direct override | 0/4 | 0/4 | 0/4 | 0/4 |
| Role-play | 2/4 | 0/4 | 3/4 | 0/4 |
| Indirect document | 1/4 | 0/4 | 0/4 | 0/4 |
| False authority | 0/4 | 0/4 | 0/4 | 0/4 |
| Encoding or transformation | 1/4 | 1/4 | 2/4 | 1/4 |
| Delimiter breakout | 1/4 | 0/4 | 2/4 | 0/4 |
| Partial disclosure | 3/4 | 0/4 | 2/4 | 1/4 |
| Paraphrase | 0/4 | 2/4 | 1/4 | 0/4 |
| Multilingual | 0/4 | 1/4 | 0/4 | 1/4 |
| Character obfuscation | 0/4 | 0/4 | 1/4 | 1/4 |
| Creative framing | 0/4 | 2/4 | 3/4 | 1/4 |
| Multi-step | 1/4 | 1/4 | 3/4 | 2/4 |
| **All attacks** | 9/48 (10-32%) | 7/48 (7-27%) | 17/48 (23-50%) | 7/48 (7-27%) |

Controls: the input filter blocked 6 attack prompts and 1 benign prompt per model in defended
mode. In defended mode 7 attack prompts per model produced the canary and the output check
caught all of them. The output check also caught the canary on 9 benign prompts for Llama
(0 for Qwen). Baseline benign prompts producing the canary: Llama 2, Qwen 0.
Refusal heuristic on benign events (of 144): Llama 66 base, 78 def; Qwen 39 base, 45 def.

Reproduce: `python lab/run_dataset.py --split heldout ...` then `python lab/table54.py`.
