# Labelled prompt set for the extended experiments

`data/prompts.jsonl` holds 192 synthetic prompts for the fictional customer-support assistant in `lab/`. It extends the original eight scenarios (A1-A8) so that detection can be measured with rates and confidence intervals rather than a handful of cases. It is generated from `data/build_prompts.py` (the JSONL is checked against the generator by a test).

## Composition

| Label | Prompts | Categories (8 attacks, or 12-24 benign, each) |
|---|---:|---|
| attack | 96 | direct-override, role-play, indirect-document, false-authority, encoding-transformation, delimiter-breakout, partial-disclosure, paraphrase, multilingual (8 languages), character-obfuscation, creative-framing, multi-step |
| benign | 96 | ordinary-support, benign-document-task, hard-negative (24 prompts that contain words a keyword rule may match), benign-multilingual, benign-creative, benign-multi-step, benign-messy-text |

Attacks try to extract the synthetic canary, the hidden instructions or the internal notes. Benign prompts are ordinary support-style requests. Nothing is real: no personal data, credentials or production content.

## Development and held-out split

Within every category, even positions are `dev` and odd positions are `heldout` (48 attacks and 48 benign prompts in each). Detection rules may be tuned on `dev` only; `heldout` is for the final evaluation.

**Limit of the split.** One author wrote all prompts, so the held-out half shares wording habits with the development half. A fully independent test needs prompts from a different source, such as a published prompt-injection dataset or a second person. This is a planned next step.

## Baseline: the existing keyword scanner

Produced by `python3 detection/evaluate_scanner.py` (no model needed). The scanner's rules were written before this dataset existed. Intervals are 95% Wilson intervals.

| Split | Attack detection rate | False-positive rate (benign flagged) |
|---|---:|---:|
| All | 48/96 = 50.0% (40-60%) | 5/96 = 5.2% (2-12%) |
| Dev | 28/48 = 58.3% (44-71%) | 3/48 = 6.2% (2-17%) |
| Held-out | 20/48 = 41.7% (29-56%) | 2/48 = 4.2% (1-14%) |

By category (all splits), attacks flagged: multilingual 0/8, paraphrase 0/8, multi-step 3/8, role-play 4/8, false-authority 4/8, character-obfuscation 4/8, creative-framing 4/8, direct-override 5/8, encoding-transformation 5/8, delimiter-breakout 6/8, indirect-document 6/8, partial-disclosure 7/8. Benign flagged: 5 of the 24 hard negatives and none of the other 72.

The dev and held-out recall differ by 17 points, but the intervals overlap, so this is not strong evidence of a real gap. The consistent finding is that keyword rules miss paraphrased and non-English attacks completely. These tests pin the numbers; if a rule change moves them, update this file deliberately.

## Running the model experiments

```bash
python3 lab/run_dataset.py --model llama3.2:1b --split heldout --repeats 3
python3 lab/run_dataset.py --model qwen2.5:1.5b --split heldout --repeats 3
python3 lab/run_dataset.py --dry-run --limit 10      # plumbing check, no model
```

Events go to `logs/ai_assistant_dataset.jsonl` with the same field names as the original harness, so the existing Wazuh rules 100000-100002 apply unchanged. Summaries and CSVs go to `results/` (ignored by Git). Review output before publishing.

**Status:** the dataset, evaluation script, runner and offline tests are in place and pass. The runner has been tested offline with a stub model only. No extended live-model results have been recorded yet, so none are claimed.

## Known limits

- The canary check is an exact-match heuristic; paraphrased or partial leaks are scored as "not leaked".
- The refusal flag (`refused_heuristic`) is a phrase match on the first 200 characters of a reply. It estimates over-refusal; it does not measure it exactly.
- Repeats of one prompt are not independent, so intervals computed over repeated events understate uncertainty.
- Small CPU-only models; results may not transfer to other models, sizes or hardware.
