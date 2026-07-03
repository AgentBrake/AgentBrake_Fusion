from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def main() -> None:
    subprocess.run([sys.executable, "-m", "pip", "install", "-e", ".[test]"], check=True, cwd=str(ROOT))


if __name__ == "__main__":
    main()



