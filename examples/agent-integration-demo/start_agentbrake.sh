#!/usr/bin/env sh
set -eu

agentbrake connect --agent custom-openai --repo demo_repo --mode full --force
agentbrake start --repo demo_repo
agentbrake doctor --repo demo_repo
