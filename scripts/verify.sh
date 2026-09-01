#!/usr/bin/env bash
# Runs the test suite and lint.
#
# Uses ./.venv if present (create it with:
#   python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
# ), otherwise falls back to whatever python3/pytest/ruff are on PATH.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -x .venv/bin/python ]; then
    PYTHON=.venv/bin/python
    RUFF=.venv/bin/ruff
else
    PYTHON=python3
    command -v python3 >/dev/null 2>&1 || PYTHON=python
    RUFF=ruff
fi

echo "==> pytest"
"$PYTHON" -m pytest tests/

echo "==> ruff check"
"$RUFF" check app/ tests/
