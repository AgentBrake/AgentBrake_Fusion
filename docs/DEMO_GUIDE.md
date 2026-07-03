# Demo Guide

This guide follows a defense presentation flow for the contest.

## 1. Start the System

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_all.ps1
```

Linux/macOS:

```bash
bash scripts/run_all.sh
```

Open `http://127.0.0.1:5173/react.html`.

## 2. Onboarding

Open the 接入配置 page. Show:

- AgentBrake API status
- OpenClaw Gateway status
- Local Model status
- Tool Guard status
- Audit Stream status

If OpenClaw is unavailable, point out the visible mock demo mode.

## 3. Configure OpenClaw or Mock Mode

Select one:

- Local OpenClaw Gateway
- A2A Gateway
- CLI fallback
- Mock Demo Mode
- Replay AgentDojo Trace

Apply guard configuration and run harmless/block dry-run tests.

## 4. Scenario Gallery

Run the Workspace email exfiltration demo first. Then optionally run Slack, Banking, and Travel demos.

## 5. Decision Workbench

Show the top summary:

- User task
- Low-trust context
- Candidate tool call
- Final decision

## 6. ActionGraph

Explain how concrete evidence nodes show:

- User goal
- Trusted tool result
- Low-trust content
- Private data
- Candidate tool action
- Recipient/content/destination/side effect
- Pre-execution block

## 7. MSJ Engine

Show structured facts:

- task_authorized
- tool_group
- arg_provenance
- private_data_seen
- injection_seen
- args_match_user_entity
- args_match_untrusted_entity
- external_sink
- ruleHits
- trustedEvidence
- unsafeEvidence

No score bar or confidence average is used.

## 8. Constraint Product Lattice

Explain that conflicts are joined by dimension and are not averaged away. Show how the final governance action maps to execution environment, network scope, data scope, human gate, and audit scope.

## 9. BrakeTrace

Show reason codes, trusted evidence, unsafe evidence, allowed next steps, and disallowed next steps.

## 10. Audit Center

Open 审计中心 to replay and export traces.

## 11. Experiment Dashboard

Open 实验成绩 to show ASR, Security, User Utility, Secure Utility, latency, and ablation support.

## 12. Security Boundary

End by stating that all dangerous tools are sandbox/dry-run by default and no real email, payment, deletion, external upload, or dangerous command is executed.
