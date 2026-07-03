#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python_cmd="${PYTHON:-python3}"
if ! command -v "$python_cmd" >/dev/null 2>&1; then
  python_cmd="python"
fi
node_cmd="${NODE:-node}"

"$python_cmd" --version
"$node_cmd" --version

if [ ! -d ".venv" ]; then
  "$python_cmd" -m venv .venv
fi

if [ -f ".venv/bin/activate" ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

python -m pip install --upgrade pip
python -m pip install -r backend/requirements.txt
python -m pip install -e ".[test]"

if [ ! -f ".env" ]; then
  cp .env.example .env
fi
if [ ! -f "backend/.env" ]; then
  cp backend/.env.example backend/.env
fi
if [ ! -f "web/studio/.env" ]; then
  cp web/studio/.env.example web/studio/.env
fi

mkdir -p data/scenarios data/agentdojo_results data/sample_traces artifacts/logs artifacts/reports artifacts/screenshots artifacts/figures artifacts/videos

cd web/studio
npm install

cat <<'MSG'

Bootstrap complete.
Next:
  bash scripts/run_all.sh
  bash scripts/run_demo.sh
  bash scripts/run_tests.sh
MSG
