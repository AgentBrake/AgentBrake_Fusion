from __future__ import annotations

import hashlib
import os
import shutil
import zipfile
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT_ROOT = ROOT / "deliverables"
DELIVERY = OUT_ROOT / "AgentBrake-Fusion_Contest_Delivery"

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    ".pytest_cache",
    ".pytest_tmp",
    ".ruff_cache",
    "__pycache__",
    "dist",
    "node_modules",
    ".runtime",
}

EXCLUDED_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".log",
}

EXCLUDED_FILES = {
    ".env",
    "npm-debug.log",
    "yarn-error.log",
    "pnpm-debug.log",
}


def should_ignore(path: Path) -> bool:
    if path.name in EXCLUDED_FILES:
        return True
    if path.name in EXCLUDED_DIRS:
        return True
    if path.suffix in EXCLUDED_SUFFIXES:
        return True
    return False


def copy_tree(src: Path, dst: Path) -> None:
    if not src.exists():
        return
    for item in src.rglob("*"):
        rel = item.relative_to(src)
        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue
        if should_ignore(item):
            continue
        target = dst / rel
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)


def copy_file(src: Path, dst: Path) -> None:
    if not src.exists() or should_ignore(src):
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoding = "utf-8-sig" if path.suffix.lower() == ".ps1" else "utf-8"
    path.write_text(text.strip() + "\n", encoding=encoding)


def zip_dir(src: Path, zip_path: Path) -> None:
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for file in sorted(src.rglob("*")):
            if file.is_file():
                zf.write(file, file.relative_to(src.parent))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_launchers(exe_dir: Path) -> None:
    write_text(
        exe_dir / "AgentBrake-Fusion-启动.bat",
        r"""
@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0AgentBrake-Fusion-启动.ps1"
endlocal
""",
    )
    write_text(
        exe_dir / "AgentBrake-Fusion-健康检查.bat",
        r"""
@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0AgentBrake-Fusion-健康检查.ps1"
endlocal
""",
    )
    write_text(
        exe_dir / "AgentBrake-Fusion-启动.ps1",
        r"""
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DeliveryRoot = Split-Path -Parent $ScriptDir
$BackendRoot = Join-Path $DeliveryRoot "02_backend_source"
$FrontendRoot = Join-Path $DeliveryRoot "01_frontend_source\web\studio"
$RuntimeRoot = Join-Path $DeliveryRoot ".runtime"
$VenvRoot = Join-Path $RuntimeRoot ".venv"
$BackendPort = if ($env:AGENTBRAKE_STUDIO_PORT) { $env:AGENTBRAKE_STUDIO_PORT } else { "8765" }
$FrontendPort = if ($env:AGENTBRAKE_FRONTEND_PORT) { $env:AGENTBRAKE_FRONTEND_PORT } else { "5173" }
$StudioToken = if ($env:AGENTBRAKE_STUDIO_API_KEY) { $env:AGENTBRAKE_STUDIO_API_KEY } else { "agentbrake-fusion-local" }
$env:AGENTBRAKE_STUDIO_API_KEY = $StudioToken
$AuthHeaders = @{ Authorization = "Bearer $StudioToken" }

function Test-BackendReady {
  try {
    Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$BackendPort/api/health" -Headers $AuthHeaders -TimeoutSec 2 | Out-Null
    return $true
  } catch {
    return $false
  }
}

function Test-FrontendReady {
  try {
    Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$FrontendPort/react.html" -TimeoutSec 2 | Out-Null
    return $true
  } catch {
    return $false
  }
}

if (!(Test-Path (Join-Path $BackendRoot "src\agentbrake"))) {
  throw "未找到后端源码目录: $BackendRoot"
}
if (!(Test-Path (Join-Path $FrontendRoot "package.json"))) {
  throw "未找到前端源码目录: $FrontendRoot"
}

New-Item -ItemType Directory -Force -Path $RuntimeRoot | Out-Null

if (!(Test-Path (Join-Path $BackendRoot ".env")) -and (Test-Path (Join-Path $BackendRoot ".env.example"))) {
  Copy-Item (Join-Path $BackendRoot ".env.example") (Join-Path $BackendRoot ".env")
  Write-Host "已从 .env.example 生成本地 .env。请在前端接入配置页填写 OpenClaw / 模型 API Key，或手动编辑 02_backend_source\.env。" -ForegroundColor Yellow
}

if (!(Test-Path (Join-Path $VenvRoot "Scripts\python.exe"))) {
  Write-Host "首次运行：创建 Python 虚拟环境..." -ForegroundColor Cyan
  $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
  if ($pyLauncher) {
    & py -3 -m venv $VenvRoot
  } else {
    & python -m venv $VenvRoot
  }
}

$PythonExe = Join-Path $VenvRoot "Scripts\python.exe"
Write-Host "安装/校验后端依赖..." -ForegroundColor Cyan
Push-Location $BackendRoot
& $PythonExe -m pip install --upgrade pip
& $PythonExe -m pip install -r requirements.txt
Pop-Location

Write-Host "安装/校验前端依赖..." -ForegroundColor Cyan
Push-Location $FrontendRoot
if (!(Test-Path "node_modules")) {
  & npm install
}
Pop-Location

$backendScript = {
  param($PythonExe, $BackendRoot, $BackendPort)
  $env:PYTHONPATH = Join-Path $BackendRoot "src"
  $env:AGENTBRAKE_STUDIO_API_KEY = if ($env:AGENTBRAKE_STUDIO_API_KEY) { $env:AGENTBRAKE_STUDIO_API_KEY } else { "agentbrake-fusion-local" }
  Set-Location $BackendRoot
  & $PythonExe -m agentbrake.cli studio-server --repo $BackendRoot --host 127.0.0.1 --port ([int]$BackendPort)
}

$frontendScript = {
  param($FrontendRoot, $FrontendPort, $BackendPort)
  $env:VITE_AGENTBRAKE_API_BASE = "http://127.0.0.1:$BackendPort/api"
  Set-Location $FrontendRoot
  & npm run dev -- --host 127.0.0.1 --port ([int]$FrontendPort)
}

Write-Host "启动 AgentBrake-Fusion 后端: http://127.0.0.1:$BackendPort/api/health" -ForegroundColor Green
if (Test-BackendReady) {
  Write-Host "检测到后端已在运行，直接复用。" -ForegroundColor Yellow
  $backendJob = $null
} else {
  $backendJob = Start-Job -Name "AgentBrake-Fusion-Backend" -ScriptBlock $backendScript -ArgumentList $PythonExe, $BackendRoot, $BackendPort
  Start-Sleep -Seconds 2
  if (!(Test-BackendReady)) {
    Write-Host "后端暂未通过健康检查，请查看下方 backend 日志。" -ForegroundColor Yellow
  }
}

Write-Host "启动前端工作台: http://127.0.0.1:$FrontendPort/react.html" -ForegroundColor Green
if (Test-FrontendReady) {
  Write-Host "检测到前端已在运行，直接复用。" -ForegroundColor Yellow
  $frontendJob = $null
} else {
  $frontendJob = Start-Job -Name "AgentBrake-Fusion-Frontend" -ScriptBlock $frontendScript -ArgumentList $FrontendRoot, $FrontendPort, $BackendPort
  Start-Sleep -Seconds 3
}
Start-Process "http://127.0.0.1:$FrontendPort/react.html"

Write-Host ""
Write-Host "服务已启动。关闭本窗口会停止后端和前端。" -ForegroundColor Yellow
Write-Host "实时日志如下："
try {
  while ($true) {
    if ($backendJob -ne $null) {
      Receive-Job $backendJob -Keep | ForEach-Object { Write-Host "[backend] $_" }
    }
    if ($frontendJob -ne $null) {
      Receive-Job $frontendJob -Keep | ForEach-Object { Write-Host "[frontend] $_" }
    }
    Start-Sleep -Seconds 2
  }
}
finally {
  if ($backendJob -ne $null) {
    Stop-Job $backendJob -ErrorAction SilentlyContinue
    Remove-Job $backendJob -Force -ErrorAction SilentlyContinue
  }
  if ($frontendJob -ne $null) {
    Stop-Job $frontendJob -ErrorAction SilentlyContinue
    Remove-Job $frontendJob -Force -ErrorAction SilentlyContinue
  }
}
""",
    )
    write_text(
        exe_dir / "AgentBrake-Fusion-健康检查.ps1",
        r"""
$ErrorActionPreference = "Continue"
$BackendPort = if ($env:AGENTBRAKE_STUDIO_PORT) { $env:AGENTBRAKE_STUDIO_PORT } else { "8765" }
$FrontendPort = if ($env:AGENTBRAKE_FRONTEND_PORT) { $env:AGENTBRAKE_FRONTEND_PORT } else { "5173" }
$StudioToken = if ($env:AGENTBRAKE_STUDIO_API_KEY) { $env:AGENTBRAKE_STUDIO_API_KEY } else { "agentbrake-fusion-local" }
$AuthHeaders = @{ Authorization = "Bearer $StudioToken" }

Write-Host "检查 AgentBrake-Fusion 后端..." -ForegroundColor Cyan
try {
  $health = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$BackendPort/api/health" -Headers $AuthHeaders -TimeoutSec 5
  Write-Host "后端正常: HTTP $($health.StatusCode)" -ForegroundColor Green
} catch {
  Write-Host "后端未就绪或端口不通: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "检查前端..." -ForegroundColor Cyan
try {
  $front = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$FrontendPort/react.html" -TimeoutSec 5
  Write-Host "前端正常: HTTP $($front.StatusCode)" -ForegroundColor Green
} catch {
  Write-Host "前端未就绪或端口不通: $($_.Exception.Message)" -ForegroundColor Red
}
""",
    )
    write_text(
        exe_dir / "README_可执行文件.md",
        """
# AgentBrake-Fusion 可执行文件说明

## Windows 一键启动

双击 `AgentBrake-Fusion-启动.bat`，脚本会：

1. 创建本地 Python 虚拟环境；
2. 安装后端依赖；
3. 安装前端依赖；
4. 启动 AgentBrake-Fusion Studio 后端；
5. 启动 React/Vite 前端；
6. 自动打开 `http://127.0.0.1:5173/react.html`。

## 运行前要求

- Windows 10/11
- Python 3.10+
- Node.js 18+
- npm

## 配置 OpenClaw / 模型 API

启动后进入“接入配置”页面，在页面中填写：

- OpenClaw Gateway 地址
- OpenClaw Token，如本地网关不需要鉴权可留空
- Agent ID
- OpenAI-compatible Base URL
- 模型 API Key
- 模型名称，例如 `qwen-plus`

配置只会写入本地运行目录的 `.env` 或 runtime config，不应提交到源码仓库。

## 健康检查

服务启动后可双击 `AgentBrake-Fusion-健康检查.bat` 检查前后端端口。
""",
    )


def build_readmes(frontend_dir: Path, backend_dir: Path, docs_dir: Path) -> None:
    write_text(
        frontend_dir / "README_FRONTEND.md",
        """
# AgentBrake-Fusion 前端源码

主前端位于 `web/studio`，技术栈为 React + TypeScript + Vite。

## 本地运行

```powershell
cd web/studio
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

默认访问地址：`http://127.0.0.1:5173/react.html`

## 主要页面

- 接入配置：配置 OpenClaw Gateway、模型 API、ToolGate 策略。
- 实时对话：与本地 OpenClaw 对话，候选工具调用先进入 AgentBrake-Fusion 审查。
- 场景演示：workspace / slack / banking / travel 间接提示注入案例。
- 裁决工作台：展示 ActionGraph、MSJ Engine、Constraint Product Lattice 与 BrakeTrace。
- 实验成绩：展示 ASR、Security、User Utility、Secure Utility 等实验结果。
""",
    )
    write_text(
        backend_dir / "README_BACKEND.md",
        """
# AgentBrake-Fusion 后端源码

后端核心位于 `src/agentbrake`，Studio API 位于 `src/agentbrake/studio`。

## 本地运行

```powershell
python -m venv .venv
.\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt
$env:PYTHONPATH = "src"
.\\.venv\\Scripts\\python.exe -m agentbrake.cli studio-server --repo . --host 127.0.0.1 --port 8765
```

健康检查：`http://127.0.0.1:8765/api/health`

## 主要模块

- `studio/server.py`：前端 API、OpenClaw 接入配置、实时对话、审计与外部材料扫描。
- `studio/openclaw_connector.py`：OpenClaw Gateway HTTP / WebSocket / A2A / CLI / Mock 统一连接层。
- `gateway/`：OpenAI-compatible Gateway 与 ToolGate 拦截链路。
- `action_graphing/`、`policy_engine/`、`policy_runtime/`：执行前安全裁决相关实现。

## 安全说明

提交包不包含 `.env`、API Key、node_modules、Python 虚拟环境和 git 元数据。
""",
    )
    write_text(
        docs_dir / "README_交付说明.md",
        """
# AgentBrake-Fusion 比赛交付说明

本目录按比赛要求拆分为：

- `01_frontend_source`：前端源码。
- `02_backend_source`：后端源码。
- `03_executable`：Windows 一键启动脚本和健康检查脚本。
- `04_docs`：项目说明、部署说明、演示说明等文档。

建议提交平台如要求分项上传，可分别上传同级目录下生成的：

- `AgentBrake-Fusion_frontend_source.zip`
- `AgentBrake-Fusion_backend_source.zip`
- `AgentBrake-Fusion_executable_files.zip`
- `AgentBrake-Fusion_Contest_Delivery.zip`

注意：所有密钥应由评测者或演示者在本地配置页面填写，交付包不包含真实 token。
""",
    )


def main() -> None:
    if DELIVERY.exists():
        shutil.rmtree(DELIVERY)
    DELIVERY.mkdir(parents=True, exist_ok=True)

    frontend_dir = DELIVERY / "01_frontend_source"
    backend_dir = DELIVERY / "02_backend_source"
    exe_dir = DELIVERY / "03_executable"
    docs_dir = DELIVERY / "04_docs"

    copy_tree(ROOT / "web" / "studio", frontend_dir / "web" / "studio")
    copy_tree(ROOT / "frontend", frontend_dir / "legacy_frontend")

    for rel in ["src", "backend", "configs", "policies", "data", "examples", "samples", "samples_stage2", "samples_stage3", "tests"]:
        copy_tree(ROOT / rel, backend_dir / rel)

    for rel in [
        ".env.example",
        "pyproject.toml",
        "requirements.txt",
        "README.md",
        "README.zh-CN.md",
        "LICENSE",
        "Makefile",
        "Dockerfile",
        "docker-compose.yml",
    ]:
        copy_file(ROOT / rel, backend_dir / rel)

    copy_tree(ROOT / "docs", docs_dir / "docs")
    for rel in ["README.md", "README.zh-CN.md", "LICENSE"]:
        copy_file(ROOT / rel, docs_dir / rel)

    built_dist = ROOT / "web" / "studio" / "dist"
    if built_dist.exists():
        copy_tree(built_dist, exe_dir / "built_frontend_dist")

    build_launchers(exe_dir)
    build_readmes(frontend_dir, backend_dir, docs_dir)

    write_text(
        DELIVERY / "MANIFEST.md",
        f"""
# AgentBrake-Fusion Contest Delivery Manifest

Generated at: {datetime.now().isoformat(timespec="seconds")}

## Layout

- `01_frontend_source/`: React + TypeScript + Vite frontend source.
- `02_backend_source/`: Python backend source and runtime configuration templates.
- `03_executable/`: Windows launchers, health-check scripts, and built frontend assets when available.
- `04_docs/`: project documentation.

## Excluded

- `.env`
- API keys and tokens
- `.git`
- `.venv`
- `node_modules`
- Python and test caches
- transient logs
""",
    )

    zip_targets = [
        (frontend_dir, OUT_ROOT / "AgentBrake-Fusion_frontend_source.zip"),
        (backend_dir, OUT_ROOT / "AgentBrake-Fusion_backend_source.zip"),
        (exe_dir, OUT_ROOT / "AgentBrake-Fusion_executable_files.zip"),
        (DELIVERY, OUT_ROOT / "AgentBrake-Fusion_Contest_Delivery.zip"),
    ]
    for src, zip_path in zip_targets:
        zip_dir(src, zip_path)

    checksum_lines = []
    for _, zip_path in zip_targets:
        checksum_lines.append(f"{sha256(zip_path)}  {zip_path.name}")
    write_text(DELIVERY / "CHECKSUMS.sha256", "\n".join(checksum_lines))
    write_text(OUT_ROOT / "AgentBrake-Fusion_Contest_CHECKSUMS.sha256", "\n".join(checksum_lines))

    print("Contest delivery generated:")
    print(DELIVERY)
    for _, zip_path in zip_targets:
        print(f"{zip_path} ({zip_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
