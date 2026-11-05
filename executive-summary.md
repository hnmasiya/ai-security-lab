# Executive Summary — AI Cybersecurity & Governance Lab

**Project status:** Harness, controls and detection built; small-scale live model tests completed and reported with their limits. Larger-scale testing is planned.

## Business problem
AI assistants can be manipulated through direct prompts or instructions embedded in
documents. Risks include disclosure of sensitive context, manipulated outputs, misuse
of connected tools and ungoverned employee use of external AI services.

## Work completed
- Local prompt-injection test harness with eight scenarios.
- Baseline and defended test modes.
- Synthetic canary detection and redacted local event logging.
- Python detection scanners and example Sigma-style rules.
- Wazuh custom rules 100000-100002 with the pipeline evidenced end to end.
- AI inventory, risk register, STRIDE threat model and incident-response playbook.
- Thematic mapping to ISO/IEC 42001 and Google SAIF.

## Results
Small-scale live runs on local models (synthetic canary, fictional data) found that the role-play scenario (A2) leaked the canary from the Llama 3.2 baseline in every run, and that a Qwen 2.5 1.5B baseline leaked it in two other scenarios. The input filter blocked three scenarios, but keyword detection initially missed four of seven attack scenarios. These are observations from eight scenarios on small models, not effectiveness metrics for any defence. Full results and limitations: [`reports/`](reports/).

## Key governance recommendations
1. Keep secrets out of model context.
2. Treat external content as untrusted.
3. Restrict model-connected tools and require human approval for high-impact actions.
4. Maintain an AI inventory and review suppliers.
5. Monitor AI systems and rehearse incident response.

This is an educational demonstration, not a production assessment or certification.
