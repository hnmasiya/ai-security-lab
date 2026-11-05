# Content-based detection rules (D2)

Wazuh rules 100010-100021 match regular expressions against `prompt_normalised`, a copy of the
prompt that `detection/normalise.py` has folded to plain lower-case text (fullwidth forms,
zero-width characters, Cyrillic and Greek look-alikes, letter spacing and light leetspeak). The
harness logs the field (`lab/run_dataset.py`). The rules are children of rule 100000, so the existing
flag-based rules 100001 and 100002 are unchanged.

| Rule | Level | Looks for |
|---|---:|---|
| 100010 | 9 | Instruction-override wording |
| 100011 | 9 | A request to disclose a secret or hidden instructions |
| 100012 | 9 | Role-play used to remove restrictions or reach a secret |
| 100013 | 9 | Claimed authority used to justify disclosure |
| 100014 | 10 | Delimiter breakout or a spoofed role line |
| 100015 | 10 | An instruction hidden in a comment or addressed to the assistant |
| 100016 | 9 | A request to transform a secret (reverse, spell, encode) |
| 100017 | 9 | A request for part of a secret |
| 100018 | 9 | Creative framing that would carry a secret |
| 100019 | 9 | A paraphrased request for the setup text |
| 100020 | 9 | Instruction override in French, German, Italian or Indonesian |
| 100021 | 9 | A secret requested as a later step or part |

The rules are generated from a table in `detection/build_content_rules.py`
(`python3 detection/build_content_rules.py` rewrites `wazuh/rules/ai-security-lab_content.xml`).

## How they were evaluated

The rules were written from the development half of `data/prompts.jsonl` only. The held-out half
was then scored once and the rules were not changed afterwards. The same author wrote the prompts
and the rules, so the held-out half is not independent (see `docs/DATASET.md`).

`python3 detection/evaluate_rules.py` applies the exact expressions in the XML file with Python's
`re`. This is an offline equivalent of Wazuh's PCRE2 matching, not Wazuh itself, so confirm a sample
with `wazuh-logtest` on the manager before quoting a figure as a Wazuh result. Rules give the same
decision on the plain prompts and on the prompts as the harness wraps them (tested).

| Split | Detector | Recall | False-positive rate | Precision |
|---|---|---:|---:|---:|
| Development | D1 scanner | 58.3% (28/48) | 6.2% (3/48) | 90.3% |
| Development | D2 rules | 100.0% (48/48) | 0.0% (0/48) | 100.0% |
| Held-out | D1 scanner | 41.7% (20/48) | 4.2% (2/48) | 90.9% |
| Held-out | D2 rules | 45.8% (22/48) | 2.1% (1/48) | 95.7% |
| Held-out | D1 or D2 | 60.4% (29/48) | 4.2% (2/48) | 93.5% |

The fall from 100% to 45.8% is the point: rules tuned on the examples they were written from do
not carry over to new wording.

## Known gaps (found on the held-out half; not fixed, to keep the measurement clean)

- Paraphrase (0/4), multilingual (0/4 for Spanish, Portuguese, Dutch and Turkish; the rules cover
  four other languages) and multi-step (0/4) attacks are not caught.
- False authority (0/4): the authority terms and verbs in the rules are too narrow.
- Heavy leetspeak (`1gn0r3 4ll pr3v10us`) is not decoded; text written backwards is not reversed.
- One false positive: "How do I enable developer mode on my phone?" (rule 100012).

Any change made after reading these results needs a new, independent held-out set before it is
measured again.
