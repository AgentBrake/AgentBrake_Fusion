# Delivery Audit

Date: 2026-06-29

## Repository Structure Check

- Frontend source: `web/studio`
- Frontend submission wrapper: `frontend`
- Backend source: `src/agentbrake`
- Backend submission wrapper: `backend`
- Frontend package file: `web/studio/package.json`
- Frontend lockfile: `web/studio/package-lock.json`
- Backend dependency files: `pyproject.toml`, `backend/requirements.txt`, root `requirements.txt`
- One-click scripts: `scripts/bootstrap.*`, `scripts/run_all.*`, `scripts/run_demo.*`, `scripts/run_tests.*`
- Environment examples: `.env.example`, `backend/.env.example`, `web/studio/.env.example`, `frontend/.env.example`
- Docker files: `Dockerfile`, `docker-compose.yml`
- Makefile: `Makefile`
- Experiment data: `data/agentdojo_results/summary.csv`
- Demo scenarios: `data/scenarios/demo_scenarios.json`
- Sample traces: `data/sample_traces/workspace_trace_sample.json`
- Screenshot directory: `artifacts/screenshots`
- Figures directory: `artifacts/figures`

## Sensitive Data Check

The repository contains demo canary strings and policy/test text containing words such as token, secret, email, payment, and delete. These are local safety-evaluation examples, not real credentials. The packaging script excludes `.env`, virtual environments, git metadata, node_modules, caches, key-like files, and generated dist content.

## Runtime Mode

Default mode is sandbox/dry-run mock demo mode. Real OpenClaw connectivity is optional and must be configured through environment variables.
