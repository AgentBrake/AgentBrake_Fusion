#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT/src:${PYTHONPATH:-}"

python -m pytest -q tests/test_studio_pro.py
(cd web/studio && npm run build)
python scripts/healthcheck.py --ensure-backend --ci
