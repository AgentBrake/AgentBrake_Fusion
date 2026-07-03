from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from agentbrake.studio import serve_studio_pro


def app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="AgentBrake-Fusion packaged Studio launcher")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--repo", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--demo-mode", action="store_true", default=True)
    args = parser.parse_args()

    root = Path(args.repo).resolve() if args.repo else app_root()
    os.environ.setdefault("AGENTBRAKE_STUDIO_API_KEY", args.api_key or "agentbrake-fusion-local")
    os.environ.setdefault("AGENTBRAKE_SANDBOX", "true")
    os.environ.setdefault("ALLOW_REAL_TOOLS", "false")
    os.environ.setdefault("AGENTBRAKE_STUDIO_STATIC_ROOT", str(root / "web" / "studio"))

    agentbrake_dir = root / ".agentbrake"
    agentbrake_dir.mkdir(parents=True, exist_ok=True)
    (root / "artifacts" / "logs").mkdir(parents=True, exist_ok=True)

    serve_studio_pro(
        audit_path=agentbrake_dir / "gateway_audit.jsonl",
        approvals_path=agentbrake_dir / "gateway_approvals.jsonl",
        repo_root=root,
        host=args.host,
        port=args.port,
        api_key=args.api_key,
        demo_mode=args.demo_mode,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
