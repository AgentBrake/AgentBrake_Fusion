# Backend Source Layout

The runnable backend source is kept in `src/agentbrake`. This `backend/` directory is a submission-friendly compatibility entry point that contains dependency and environment files expected by reviewers.

Start the backend through:

```bash
python -m agentbrake.cli studio-server --repo . --host 127.0.0.1 --port 8765 --demo-mode
```

The server exposes the Studio API, ToolGate review endpoints, OpenClaw mock/real connector configuration, audit export, policy dry-run, and experiment result endpoints.
