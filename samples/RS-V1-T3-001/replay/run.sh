#!/usr/bin/env bash
set -euo pipefail
agentbrake bench --sample "$(cd "$(dirname "$0")/.." && pwd)"
