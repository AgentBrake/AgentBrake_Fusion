#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -f "$ROOT/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT/.env"
  set +a
fi

HOST="${AGENTBRAKE_HOST:-127.0.0.1}"
BACKEND_PORT="${AGENTBRAKE_BACKEND_PORT:-8765}"
FRONTEND_PORT="${AGENTBRAKE_FRONTEND_PORT:-5173}"
API_KEY="${AGENTBRAKE_STUDIO_API_KEY:-agentbrake-fusion-local}"
BACKEND_URL="http://${HOST}:${BACKEND_PORT}"
FRONTEND_URL="http://${HOST}:${FRONTEND_PORT}/react.html"

mkdir -p artifacts/logs .agentbrake

export PYTHONPATH="$ROOT/src:${PYTHONPATH:-}"
export AGENTBRAKE_STUDIO_API_KEY="$API_KEY"
export AGENTBRAKE_SANDBOX="${AGENTBRAKE_SANDBOX:-true}"
export ALLOW_REAL_TOOLS="${ALLOW_REAL_TOOLS:-false}"
export VITE_AGENTBRAKE_BACKEND_URL="$BACKEND_URL"

if [ -n "${OPENCLAW_GATEWAY_URL:-}" ]; then
  if python - <<PY
from urllib.request import urlopen
import sys
try:
    urlopen("${OPENCLAW_GATEWAY_URL.rstrip('/')}/health", timeout=2)
    print("OpenClaw Gateway available: ${OPENCLAW_GATEWAY_URL}")
except Exception:
    print("OpenClaw Gateway unavailable, switching to mock demo mode.")
PY
  then :; fi
else
  echo "OPENCLAW_GATEWAY_URL not set; using mock demo mode."
fi

python -m agentbrake.cli studio-server --repo . --host "$HOST" --port "$BACKEND_PORT" --demo-mode > artifacts/logs/backend.log 2> artifacts/logs/backend.err.log &
backend_pid=$!

(
  cd web/studio
  npm run dev -- --host "$HOST" --port "$FRONTEND_PORT" > "$ROOT/artifacts/logs/frontend.log" 2> "$ROOT/artifacts/logs/frontend.err.log"
) &
frontend_pid=$!

cleanup() {
  kill "$frontend_pid" "$backend_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "Frontend: $FRONTEND_URL"
echo "Backend:  $BACKEND_URL"
echo "Health:   $BACKEND_URL/api/health"
echo "Sandbox:  ${AGENTBRAKE_SANDBOX}"
echo "Real tools allowed: ${ALLOW_REAL_TOOLS}"
echo "Logs: artifacts/logs/backend.log and artifacts/logs/frontend.log"

wait
