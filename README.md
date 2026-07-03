# AgentBrake-Fusion

AgentBrake-Fusion is a pre-execution safety adjudication system for LLM agents. It intercepts candidate tool calls before execution, builds evidence with **ActionGraph**, extracts structured facts with **MSJ Engine**, resolves conflicts with **Constraint Product Lattice**, and outputs `allow`, `require_confirmation`, or `block` together with a reproducible **BrakeTrace**.

The repository is packaged for the National College Student Information Security Contest topic track, with runnable source code, a React Studio frontend, a local Python Studio backend, OpenClaw integration adapters, mock demo mode, reproducible scripts, documentation, and a one-command submission packager.

## Features

- Pre-execution ToolGate for candidate tool calls.
- Mock demo mode when OpenClaw is unavailable.
- Real OpenClaw Gateway, A2A Gateway, and CLI fallback configuration.
- Six AgentDojo-style indirect prompt-injection scenarios: workspace, slack, banking, travel, file sharing, command/API.
- Decision Workbench showing ActionGraph, MSJ Engine, Constraint Product Lattice, and BrakeTrace.
- Audit center with replay and export.
- Experiment dashboard for ASR, Security, User Utility, Secure Utility, latency, and ablation data.
- Default sandbox/dry-run mode. Real tools are disabled unless explicitly enabled.

## Directory Structure

```text
AgentBrake-Fusion/
  src/agentbrake/              Python backend and policy/runtime code
  web/studio/                  React + Vite Studio frontend
  frontend/                    Submission wrapper for the frontend
  backend/                     Submission dependency/env wrapper for backend
  configs/                     Default policies, scenarios, OpenClaw examples
  data/                        Demo scenarios, sample traces, experiment tables
  docs/                        Deployment, OpenClaw, demo, security, evaluation docs
  scripts/                     One-click install, run, demo, test, package scripts
  artifacts/                   Screenshots, figures, reports, logs, videos
  dist/                        Generated submission package
```

## Quick Start

### Windows PowerShell

```powershell
powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
powershell -ExecutionPolicy Bypass -File scripts/run_all.ps1
```

Open:

- Frontend: <http://127.0.0.1:5173/react.html>
- Backend health: <http://127.0.0.1:8765/api/health>

### Linux/macOS

```bash
bash scripts/bootstrap.sh
bash scripts/run_all.sh
```

Open:

- Frontend: <http://127.0.0.1:5173/react.html>
- Backend health: <http://127.0.0.1:8765/api/health>

### Docker

```bash
docker compose up --build
```

Backend is exposed at <http://127.0.0.1:8765>. For local frontend development, use `scripts/run_all.*`.

## One-Click Commands

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
powershell -ExecutionPolicy Bypass -File scripts/run_all.ps1
powershell -ExecutionPolicy Bypass -File scripts/run_demo.ps1
powershell -ExecutionPolicy Bypass -File scripts/run_tests.ps1
python scripts/package_submission.py
```

Linux/macOS:

```bash
bash scripts/bootstrap.sh
bash scripts/run_all.sh
bash scripts/run_demo.sh
bash scripts/run_tests.sh
python scripts/package_submission.py
```

Generated zip:

```text
dist/AgentBrake-Fusion_Submission.zip
```

## OpenClaw Integration

AgentBrake-Fusion supports four modes:

- Mock Demo Mode: default, no OpenClaw required.
- Local OpenClaw Gateway: set `OPENCLAW_GATEWAY_URL`.
- A2A Gateway: set `A2A_GATEWAY_URL` and `A2A_AGENT_ID`.
- CLI fallback: set `OPENCLAW_CLI_PATH`.

If OpenClaw is unavailable, the system automatically falls back to mock demo mode and the UI shows mock status. See [docs/OPENCLAW_INTEGRATION.md](docs/OPENCLAW_INTEGRATION.md).

## Tool Proxy Mode

Tool Proxy Mode places AgentBrake-Fusion between OpenClaw and side-effecting tools. Candidate tool calls must pass through `/api/toolgate/review` before execution. By default `AGENTBRAKE_SANDBOX=true` and `ALLOW_REAL_TOOLS=false`, so dangerous actions are dry-run only.

## Demo Scenarios

Run:

```bash
python scripts/healthcheck.py --ensure-backend --demo
```

The script executes at least four demos:

- `workspace_email_exfiltration`
- `slack_private_exfiltration`
- `banking_recipient_swap`
- `travel_booking_hijack`

Each demo emits CandidateToolCall, ActionGraph, MSJ Evidence, LatticeState, BrakeTrace, and a traceId under `artifacts/reports/`.

## Decision Workbench

The Decision Workbench is the main explanation surface:

1. **ActionGraph** shows concrete user goals, low-trust content, candidate action, arguments, destinations, side effects, and decision edges.
2. **MSJ Engine** shows structured facts only. It does not show score bars, weighted averages, or fused confidence scores.
3. **Constraint Product Lattice** joins dimensions such as action, intent, provenance, sensitivity, destination, history, and confirmation, then maps them to governance actions.
4. **BrakeTrace** records reason codes, trusted evidence, unsafe evidence, allowed next steps, and disallowed next steps.

## Experiment Dashboard

The dashboard shows supporting results for:

- ASR
- Security
- User Utility
- Secure Utility
- Dangerous Action Blocking Rate
- Safe Action Pass Rate
- MSJ latency
- Ablation studies
- Suite breakdown

Source tables are stored in `data/agentdojo_results/` and related experiment docs are in `docs/EVALUATION_REPRODUCTION.md`.

## Audit Logs

Default audit files:

```text
.agentbrake/gateway_audit.jsonl
.agentbrake/gateway_approvals.jsonl
```

Audit API:

```text
GET /api/audit
GET /api/audit/export
GET /api/toolgate/trace/:traceId
```

## Packaging

```bash
python scripts/package_submission.py
```

The packager creates:

- `dist/AgentBrake-Fusion_Submission/`
- `dist/AgentBrake-Fusion_Submission.zip`
- `SUBMISSION_MANIFEST.md`
- `CHECKSUMS.sha256`
- `RUN_INSTRUCTIONS.md`
- `SECURITY_BOUNDARY.md`

It excludes `.git`, `node_modules`, `.venv`, `.env`, cache directories, and key-like files.

## FAQ

**Q: OpenClaw is not installed. Can the demo still run?**  
A: Yes. The scripts and UI automatically use mock demo mode.

**Q: Will the demo send real emails or payments?**  
A: No. Sandbox/dry-run is enabled by default and real tools are disabled.

**Q: How do I enable a real OpenClaw Gateway?**  
A: Set `OPENCLAW_GATEWAY_URL` in `.env` or the shell environment, then restart `scripts/run_all.*`.

**Q: Why is the backend port 8765?**  
A: Final delivery scripts standardize on 8765. Vite proxies `/api` to that backend by default.

## Security Boundary

AgentBrake-Fusion is a defensive, auditing, and educational evaluation system. Built-in attack examples are local simulations. The project does not provide illegal attack capabilities. Real side effects require explicit `ALLOW_REAL_TOOLS=true` plus additional human confirmation. See [docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md).

## Contest Submission Materials

Included in the zip:

- Source code
- Frontend and backend dependency files
- One-click scripts
- Deployment and OpenClaw integration docs
- Demo guide
- Security boundary statement
- Evaluation reproduction guide
- Experiment data tables and sample traces
- Screenshot and figure directories
- Placeholders for final report PDF/Word, signed originality statement, defense PPT, and demo video
