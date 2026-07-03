#!/usr/bin/env python
"""Build dist/AgentBrake-Fusion_Submission.zip for contest delivery."""

from __future__ import annotations

import hashlib
import os
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
STAGING = DIST / "AgentBrake-Fusion_Submission"
ZIP_PATH = DIST / "AgentBrake-Fusion_Submission.zip"

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".pytest_tmp",
    ".ruff_cache",
    "dist",
    "tmp",
}
EXCLUDED_FILES = {".env", ".DS_Store"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".pem", ".key"}

ROOT_FILES = [
    "README.md",
    "README.zh-CN.md",
    "LICENSE",
    "pyproject.toml",
    "requirements.txt",
    "package.json",
    ".env.example",
    "Dockerfile",
    "docker-compose.yml",
    "Makefile",
]
ROOT_DIRS = [
    "src",
    "tests",
    "web/studio",
    "frontend",
    "backend",
    "configs",
    "data",
    "docs",
    "scripts",
    "artifacts",
    "policies",
]


def main() -> int:
    if DIST.exists():
        shutil.rmtree(DIST)
    STAGING.mkdir(parents=True, exist_ok=True)

    for file_name in ROOT_FILES:
        copy_file(ROOT / file_name, STAGING / file_name)

    for dir_name in ROOT_DIRS:
        copy_tree(ROOT / dir_name, STAGING / dir_name)

    create_submission_placeholders()
    write_run_instructions()
    write_manifest_and_checksums()
    zip_submission()

    print(f"Created {ZIP_PATH}")
    return 0


def copy_file(src: Path, dst: Path) -> None:
    if not src.exists() or should_exclude(src):
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def copy_tree(src: Path, dst: Path) -> None:
    if not src.exists():
        return
    for path in src.rglob("*"):
        rel = path.relative_to(src)
        target = dst / rel
        if should_exclude(path):
            continue
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            copy_file(path, target)


def should_exclude(path: Path) -> bool:
    parts = set(path.parts)
    if parts & EXCLUDED_DIRS:
        return True
    if path.name in EXCLUDED_FILES:
        return True
    if path.suffix in EXCLUDED_SUFFIXES:
        return True
    if path.name.lower() in {"npm-debug.log", "yarn-error.log"}:
        return True
    return False


def create_submission_placeholders() -> None:
    placeholders = {
        "submission_materials/report_pdf/README.md": "Put the final work report PDF here before official submission.\n",
        "submission_materials/report_word/README.md": "Put the final work report Word document here before official submission.\n",
        "submission_materials/originality_statement/README.md": "Put the signed originality statement here before official submission.\n",
        "submission_materials/ppt/README.md": "Put the defense PPT here before official submission.\n",
    }
    for rel, content in placeholders.items():
        path = STAGING / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def write_run_instructions() -> None:
    content = """# Run Instructions

## Windows

```powershell
powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
powershell -ExecutionPolicy Bypass -File scripts/run_all.ps1
powershell -ExecutionPolicy Bypass -File scripts/run_demo.ps1
powershell -ExecutionPolicy Bypass -File scripts/run_tests.ps1
python scripts/package_submission.py
```

## Linux/macOS

```bash
bash scripts/bootstrap.sh
bash scripts/run_all.sh
bash scripts/run_demo.sh
bash scripts/run_tests.sh
python scripts/package_submission.py
```

Default UI: http://127.0.0.1:5173/react.html
Default backend: http://127.0.0.1:8765/api/health
"""
    (STAGING / "RUN_INSTRUCTIONS.md").write_text(content, encoding="utf-8")
    security = ROOT / "docs" / "SECURITY_BOUNDARY.md"
    if security.exists():
        shutil.copy2(security, STAGING / "SECURITY_BOUNDARY.md")


def write_manifest_and_checksums() -> None:
    files = sorted(path for path in STAGING.rglob("*") if path.is_file())
    manifest_lines = [
        "# AgentBrake-Fusion Submission Manifest",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Files",
        "",
    ]
    checksum_lines = []
    for path in files:
        rel = path.relative_to(STAGING).as_posix()
        digest = sha256(path)
        manifest_lines.append(f"- `{rel}` ({path.stat().st_size} bytes)")
        checksum_lines.append(f"{digest}  {rel}")
    (STAGING / "SUBMISSION_MANIFEST.md").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
    (STAGING / "CHECKSUMS.sha256").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def zip_submission() -> None:
    with zipfile.ZipFile(ZIP_PATH, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(STAGING.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(DIST))


if __name__ == "__main__":
    raise SystemExit(main())
