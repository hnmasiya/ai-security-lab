# Executive Summary — AI Cybersecurity & Governance Lab

**Project status:** Scaffold prepared; live model testing pending.

## Business problem
AI assistants can be manipulated through direct prompts or instructions embedded in
documents. Risks include disclosure of sensitive context, manipulated outputs, misuse
of connected tools and ungoverned employee use of external AI services.

## Work prepared
- Local prompt-injection test harness with eight scenarios.
- Baseline and defended test modes.
- Synthetic canary detection and redacted local event logging.
- Python detection scanners and example Sigma-style rules.
- AI inventory, risk register, STRIDE threat model and incident-response playbook.
- Thematic mapping to ISO/IEC 42001 and Google SAIF.

## Results
Live model results: **Pending execution and review.** No effectiveness metrics are claimed.

## Key governance recommendations
1. Keep secrets out of model context.
2. Treat external content as untrusted.
3. Restrict model-connected tools and require human approval for high-impact actions.
4. Maintain an AI inventory and review suppliers.
5. Monitor AI systems and rehearse incident response.

This is an educational demonstration, not a production assessment or certification.
