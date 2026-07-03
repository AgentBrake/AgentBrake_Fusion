# Security Boundary

AgentBrake-Fusion is a defensive, auditing, and educational evaluation system for pre-execution safety judgment of LLM agent tool calls.

## Default Safety Properties

1. Built-in attack examples only run in local mock mode or AgentDojo-style replay data.
2. Sandbox/dry-run is enabled by default.
3. Real email sending is not enabled.
4. Real payment execution is not enabled.
5. Real file deletion is not enabled.
6. Dangerous command execution is not enabled.
7. Command adapters must use safe allowlists by default.
8. Real tool execution requires explicit `ALLOW_REAL_TOOLS=true`.
9. Even when real tools are enabled, high-risk actions require second confirmation.
10. Dangerous operations are written to audit logs.
11. The project does not provide illegal attack capability.

## What the Demo Does

The demo constructs candidate tool calls such as `send_email`, `send_money`, `share_file`, or `run_command`, then stops them at ToolGate. It demonstrates how ActionGraph, MSJ Engine, and Constraint Product Lattice produce a pre-execution decision.

## What the Demo Does Not Do

- It does not send real emails.
- It does not transfer money.
- It does not delete user files.
- It does not upload secrets to external APIs.
- It does not run dangerous commands.
- It does not store real credentials.

## Required Operator Practice

Use `.env.example` as a template. Keep real tokens outside git and outside the final submission zip. Before any real OpenClaw integration, verify sandbox and audit settings in the Onboarding page.
