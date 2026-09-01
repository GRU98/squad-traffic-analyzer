#!/usr/bin/env bash
# Runs the test suite and lint. Requires requirements-dev.txt installed
# (pip install -r requirements-dev.txt).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> pytest"
python -m pytest tests/

echo "==> ruff check"
ruff check app/ tests/
