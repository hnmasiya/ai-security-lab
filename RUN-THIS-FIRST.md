# AI Security Lab — execution runbook

## Downloads

- `ai-security-lab-prepared.zip` — complete prepared project, tests, documentation and `publish.sh`.
- `publish.sh` — standalone publication script (also included in the ZIP).

## 1. Extract and enter the project

```bash
unzip ai-security-lab-prepared.zip
cd ai-security-lab
```

## 2. Prerequisites

Install Git, Python 3 and (for the live LLM exercise) Ollama. Confirm:

```bash
git --version
python3 --version
ollama --version
```

Ollama is not needed for the offline unit tests or synthetic detection checks.

## 3. Run offline validation first

```bash
python3 -m compileall -q lab detection tests
python3 -m unittest discover -s tests -v
python3 detection/detect_injection.py detection/sample_ai_events.jsonl
python3 detection/shadow_ai_scan.py detection/sample_dns.log
bash -n publish.sh
```

Expected unit-test result: 9 tests pass. Detection outputs are synthetic examples, not production telemetry.

## 4. Run the live local-model exercise (optional, but still outstanding)

In one terminal:

```bash
ollama pull llama3.2
ollama serve
```

In a second terminal, from the project directory:

```bash
python3 lab/prompt_injection_test.py --model llama3.2
```

The harness runs six scenarios in baseline and defended modes. It writes local output under `logs/` and `results/`. Review the results and record the exact model/version and environment. Do not publish raw logs or results without reviewing and redacting them. `publish.sh` intentionally stops if generated files are present in those folders.

## 5. Publish to the repository that already exists

The public repository `hnmasiya/ai-security-lab` already exists and has an initial README commit. The included script clones that remote first, preserving its history; it does not force-push.

```bash
chmod +x publish.sh
./publish.sh
```

Git must be authenticated to GitHub using your configured HTTPS credential manager or SSH key. If `gh` is installed and authenticated, the script also sets the repository description/topics; otherwise set them manually using `linkedin-and-cv-text.md`.

## 6. After the push

- Confirm `https://github.com/hnmasiya/ai-security-lab` contains the project files.
- Add the AI Security & Governance section to `hnmasiya/cybersecurity-portfolio` using `PORTFOLIO-LINKS.md`.
- Add the profile README badge (repo `hnmasiya/hnmasiya`) and pin the main portfolio first, AI lab second.
- Add the project to LinkedIn Featured/Projects and the verified Columbia+ credential under Licenses & Certifications; use the exact credential title shown on the badge.
- Add the project and credential to the CV.
- Check both repo links and the credential in a private/incognito browser window.

The GitHub README edits, repository pins, LinkedIn updates and CV updates are not automatically completed by running `publish.sh`.
