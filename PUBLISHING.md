# Publishing checklist

The GitHub repository `hnmasiya/ai-security-lab` has already been created. `publish.sh` now clones that existing remote first, preserving its initial README/history, overlays the prepared project files, runs offline validation, and pushes a normal fast-forward commit. It does not force-push.

Before publishing:
1. Extract this project ZIP.
2. Review `CHECKLIST.md`; live Ollama tests and review are still pending.
3. Keep generated `logs/` and `results/` out of the public repository.
4. Install Git and Python 3. Authenticate GitHub access for Git over HTTPS (or configure SSH).
5. From this project folder, run `chmod +x publish.sh && ./publish.sh`.
6. Verify the public README and repository files after the push.

If GitHub CLI (`gh`) is installed and authenticated, the script also applies the repository description and topics. Otherwise, set them manually:

- Description: `Local AI security lab covering prompt injection, detection engineering, threat modelling and AI governance.`
- Topics: `ai-security`, `prompt-injection`, `llm-security`, `ai-governance`, `iso-42001`, `google-saif`, `threat-modeling`, `blue-team`

See [`PORTFOLIO-LINKS.md`](PORTFOLIO-LINKS.md) for reciprocal README snippets, profile links, pin order and post-publication checks.
