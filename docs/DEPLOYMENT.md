# Deployment Guide

## Environment Requirements

- Python 3.10 or 3.11 recommended
- Node.js 20 LTS recommended
- npm 10+
- Windows PowerShell or bash
- Docker optional

## Local Deployment

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
powershell -ExecutionPolicy Bypass -File scripts/run_all.ps1
```

Linux/macOS:

```bash
bash scripts/bootstrap.sh
bash scripts/run_all.sh
```

## Docker Deployment

```bash
docker compose up --build
```

The container exposes the backend on port 8765. For the React dev frontend, use local `scripts/run_all.*`.

## Ports

- Frontend: `127.0.0.1:5173`
- Backend: `127.0.0.1:8765`
- Backend health: `127.0.0.1:8765/api/health`

## Configuration

Use `.env.example` as a template:

```bash
cp .env.example .env
```

Important values:

- `AGENTBRAKE_STUDIO_API_KEY`
- `OPENCLAW_GATEWAY_URL`
- `A2A_GATEWAY_URL`
- `OPENCLAW_CLI_PATH`
- `AGENTBRAKE_SANDBOX`
- `ALLOW_REAL_TOOLS`

## Logs

Scripts write logs to:

```text
artifacts/logs/backend.log
artifacts/logs/backend.err.log
artifacts/logs/frontend.log
artifacts/logs/frontend.err.log
```

Audit logs default to:

```text
.agentbrake/gateway_audit.jsonl
.agentbrake/gateway_approvals.jsonl
```

## Data Directories

- `data/scenarios`: scenario definitions
- `data/sample_traces`: sample traces
- `data/agentdojo_results`: experiment result tables
- `artifacts/reports`: generated reports and healthcheck outputs
- `artifacts/screenshots`: UI screenshots
- `artifacts/figures`: paper/report figures

## Reset

Stop running scripts, then remove generated logs and reports:

```bash
rm -rf artifacts/logs/* artifacts/reports/healthcheck_report.json .agentbrake/*.jsonl
```

Windows:

```powershell
Remove-Item artifacts\logs\* -Force -ErrorAction SilentlyContinue
Remove-Item artifacts\reports\healthcheck_report.json -Force -ErrorAction SilentlyContinue
Remove-Item .agentbrake\*.jsonl -Force -ErrorAction SilentlyContinue
```

## Export Audit Logs

Use the Audit Center in the UI or:

```text
GET /api/audit/export
```

## Defense Demo Usage

Use mock mode for stable live demonstrations. Open `http://127.0.0.1:5173/react.html`, start from Onboarding, then run scenarios and show the Decision Workbench.
