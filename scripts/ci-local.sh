#!/usr/bin/env bash
# Local CI — the primary development gate. GitHub Actions is the final external verification,
# not the development loop (runner minutes are limited and a push-then-watch cycle is slower
# than this script).
#
# What this reproduces, and from where:
#   .github/workflows/ci.yml  job "test"      -> ruff check .; mypy src/jdlib; pytest -q
#   .github/workflows/ci.yml  job "security"  -> python -m build; clean-venv install + import
#                                                smoke; (pip-audit / gitleaks / bandit / SBOM
#                                                are NOT run here — see "not reproduced" below)
#
# Deliberate differences from GitHub CI, all of them additions or documented gaps:
#   * pytest runs with coverage, because Phase 1 requires a reproducible baseline. The tests
#     executed are identical to `pytest -q`.
#   * No coverage threshold. A number chosen to make a gate green measures the gate.
#   * The security job's scanners need network downloads (pip-audit, gitleaks, cyclonedx) and
#     a full git history; run those via the workflow, or see docs/security/ for the local
#     equivalents used during the hardening programme.
#   * SKIPPED is reported as SKIPPED, never as PASS: integration tests skip with a reason when
#     Docker is unavailable, and this script fails if that ever becomes an error instead.
#
# Usage: bash scripts/ci-local.sh [--fast]
#   --fast  skip the packaging steps (build + clean-venv install); useful mid-slice.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FAST=0
[ "${1:-}" = "--fast" ] && FAST=1

VENV_PY=".venv/Scripts/python.exe"
[ -x "$VENV_PY" ] || VENV_PY=".venv/bin/python"
[ -x "$VENV_PY" ] || { echo "no virtualenv python found at .venv/{Scripts,bin}"; exit 1; }

step() { printf '\n==> %s\n' "$1"; }

step "git diff --check (whitespace errors in the working tree)"
git diff --check

step "ruff check ."
"$VENV_PY" -m ruff check .

step "mypy src/jdlib"
"$VENV_PY" -m mypy src/jdlib

step "pytest -q (with coverage; integration skips cleanly without Docker)"
set +e
"$VENV_PY" -m pytest -q -W error --cov=jdlib --cov-report=term:skip-covered 2>&1 | tail -40
PYTEST_STATUS=${PIPESTATUS[0]}
set -e
if [ "$PYTEST_STATUS" -ne 0 ]; then
  echo "FAIL: pytest exited $PYTEST_STATUS"
  exit "$PYTEST_STATUS"
fi

if [ "$FAST" -eq 0 ]; then
  step "python -m build (sdist + wheel)"
  rm -rf dist
  "$VENV_PY" -m build >/dev/null
  ls -1 dist/
  for artefact in dist/*.tar.gz dist/*.whl; do
    [ -e "$artefact" ] || { echo "FAIL: expected artefact missing: $artefact"; exit 1; }
  done

  step "clean-environment install + import smoke"
  # A native interpreter must be handed a native path. On a host where MSYS path
  # translation is disabled, mktemp's /tmp/... reaches Windows python as
  # J:\tmp\... (relative to the current drive), the venv is created there, and
  # the script then fails to find the interpreter it just made. `pwd -W` gives
  # the Windows form; elsewhere it is absent and plain pwd is already right.
  SMOKE_DIR="$(cd "$(mktemp -d)" && { pwd -W 2>/dev/null || pwd; })"
  trap 'rm -rf "$SMOKE_DIR"' EXIT
  "$VENV_PY" -m venv "$SMOKE_DIR/venv"
  SMOKE_PY="$SMOKE_DIR/venv/Scripts/python.exe"
  [ -x "$SMOKE_PY" ] || SMOKE_PY="$SMOKE_DIR/venv/bin/python"
  "$SMOKE_PY" -m pip install -q --upgrade pip
  "$SMOKE_PY" -m pip install -q dist/*.whl
  # Import the three surfaces the security job smoke-tests, then prove a documented command
  # exists for an installed user: the console script must answer.
  "$SMOKE_PY" -c "import jdlib, jdlib.security, jdlib.security.compliance; print('import smoke ok: jdlib', jdlib.__version__)"
  "$SMOKE_PY" -c "from importlib.metadata import entry_points; names = [e.name for e in entry_points(group='console_scripts') if e.value.startswith('jdlib')]; print('console scripts:', names); assert names, 'no jdlib console script installed'"
fi

step "local CI complete"
echo "PASS: every step above reported its own result."
echo "NOTE: skip counts are the pytest summary's, not this script's — read that line."
