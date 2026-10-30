#!/usr/bin/env bash
# Safely publish the prepared lab into the already-created GitHub repository.
# It clones the remote first, preserving the existing initial README/history.
set -Eeuo pipefail

OWNER="hnmasiya"
REPO="ai-security-lab"
REMOTE="https://github.com/${OWNER}/${REPO}.git"
DESCRIPTION="Local AI security lab covering prompt injection, detection engineering, threat modelling and AI governance."
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK=""
cleanup() { if [[ -n "$WORK" && -d "$WORK" ]]; then rm -rf "$WORK"; fi; }
trap cleanup EXIT

command -v git >/dev/null || { echo "ERROR: Git is required." >&2; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: Python 3 is required." >&2; exit 1; }

cd "$ROOT"
# Generated logs and results are excluded from the publication archive.
if find . -type f \( -name '.env' -o -name '.env.*' \) -not -path './.git/*' -print -quit | grep -q .; then
  echo "ERROR: Environment file detected. Remove it from the publication folder." >&2
  exit 1
fi

python3 -m compileall -q lab detection tests
python3 -m unittest discover -s tests -v
python3 detection/detect_injection.py detection/sample_ai_events.jsonl
python3 detection/shadow_ai_scan.py detection/sample_dns.log

# Clone existing remote history into a temporary working tree. This avoids
# non-fast-forward errors when GitHub already has its initial README commit.
WORK="$(mktemp -d)"
git clone "$REMOTE" "$WORK/repo"
# Copy project files, preserving .github and other dotfiles, but never copy a
# local .git directory or generated runtime evidence.
(
  cd "$ROOT"
  tar --exclude='./.git' --exclude='./logs/*' --exclude='./results/*' \
      --exclude='*/prompt_injection_test.py.backup' \
      --exclude='*/prompt_injection_test.pilot-backup' \
      --exclude='./publish.sh.pre-report-backup' \
      --exclude='./__pycache__' --exclude='*/__pycache__' \
      -cf - .
) | tar -xf - -C "$WORK/repo"

cd "$WORK/repo"
git add -A
if git diff --cached --quiet; then
  echo "No file changes to publish; remote already matches the project files."
else
  git -c user.name="Hazvinei Masiya" -c user.email="$(git config user.email || printf 'noreply@users.noreply.github.com')" \
    commit -m "Publish AI cybersecurity and governance lab"
  git push origin main
fi

# Metadata is best-effort and does not block a successful code publication.
if command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
  gh repo edit "${OWNER}/${REPO}" --description "$DESCRIPTION" || true
  gh repo edit "${OWNER}/${REPO}" --add-topic ai-security,prompt-injection,llm-security,ai-governance,iso-42001,google-saif,threat-modeling,blue-team || true
else
  echo "NOTE: GitHub CLI is not installed/authenticated. Set repo description/topics in GitHub Settings."
fi

echo "Published and pushed: https://github.com/${OWNER}/${REPO}"
