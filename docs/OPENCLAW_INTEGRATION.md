# OpenClaw Integration Guide

AgentBrake-Fusion can run without OpenClaw in mock demo mode, or connect to a local OpenClaw runtime through Gateway, A2A Gateway, CLI fallback, or Tool Proxy mode.

## 1. Local OpenClaw Gateway Mode

Set:

```bash
OPENCLAW_GATEWAY_URL=http://127.0.0.1:18789
```

Then start:

```bash
bash scripts/run_all.sh
```

or:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_all.ps1
```

The Studio health card checks Gateway status and keeps sandbox enabled.

## 2. A2A Gateway Mode

Set:

```bash
A2A_GATEWAY_URL=http://127.0.0.1:18800
A2A_AGENT_ID=main
```

Use this mode when OpenClaw exposes an A2A agent card. If the card is not available, the UI reports mock mode and does not fake connectivity.

## 3. CLI Fallback Mode

Set:

```bash
OPENCLAW_CLI_PATH=openclaw
```

CLI fallback is for local demonstrations where OpenClaw can emit candidate tool calls through a command-line interface. Dangerous tool execution remains disabled by default.

## 4. Tool Proxy Mode

Tool Proxy Mode places AgentBrake-Fusion in front of side-effecting tools:

```text
OpenClaw candidate tool call -> /api/toolgate/review -> allow / require_confirmation / block
```

Only `allow` should proceed to actual tool execution, and the default configuration never executes real tools.

## 5. Token Configuration

Studio API auth uses:

```bash
AGENTBRAKE_STUDIO_API_KEY=agentbrake-fusion-local
```

For real OpenClaw tokens, use environment variables outside the repository. Do not commit secrets or `.env`.

## 6. Gateway Status Check

Check local backend:

```bash
python scripts/healthcheck.py --ensure-backend
```

Check Studio API:

```text
GET /api/openclaw/status
GET /api/openclaw/health
```

## 7. Connectivity Verification

Run:

```bash
python scripts/healthcheck.py --ensure-backend --ci
```

This verifies health, ToolGate review, four demo scenarios, ActionGraph, MSJ Engine, Constraint Product Lattice, BrakeTrace, and audit export.

## 8. Switching to Mock Mode

Unset OpenClaw variables:

```bash
unset OPENCLAW_GATEWAY_URL
unset A2A_GATEWAY_URL
```

or leave them blank in `.env`. The system then runs built-in mock scenarios.

## 9. Common Errors

- Gateway 404: verify `OPENCLAW_GATEWAY_URL` and health path.
- Token error: verify `AGENTBRAKE_STUDIO_API_KEY` and OpenClaw token env vars.
- CORS: use the local Vite proxy or configure OpenClaw CORS for `127.0.0.1`.
- Tool call returns natural language only: enable Tool Proxy or configure OpenClaw to emit structured tool calls.
- OpenClaw not started: use mock demo mode for the defense demo.
- A2A agent card missing: verify `A2A_AGENT_ID` and A2A Gateway URL.
