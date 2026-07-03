from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[1]
    script = root / "START_AGENTBRAKE_FUSION.ps1"
    if not script.exists():
        print("Cannot find START_AGENTBRAKE_FUSION.ps1")
        print(f"Expected: {script}")
        input("Press Enter to exit...")
        return 1

    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script),
        *sys.argv[1:],
    ]
    try:
        return subprocess.call(cmd, cwd=str(root))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to start AgentBrake-Fusion: {exc}")
        input("Press Enter to exit...")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
