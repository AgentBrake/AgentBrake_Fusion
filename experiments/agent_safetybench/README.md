# Agent-SafetyBench + AgentBrake-Fusion

This directory contains the reproducible harness for inserting AgentBrake-Fusion before
Agent-SafetyBench tool execution.

The upstream benchmark executes tools at:

```python
tool_call_result = env.call_tool(tool_name, deepcopy(arguments))
```

The local harness keeps upstream files untouched and mirrors the evaluation loop as:

```text
model candidate tool call
  -> AgentBrake-Fusion ToolGate
  -> allow: call env.call_tool(...)
  -> require_confirmation / block: return a safe tool result and record BrakeTrace
```

## What Is Committed

- `agentbrake_runner.py`: AgentBrake-Fusion runner for No defense, AB-Strict, AB-Gateway, and AB-Oracle.
- `progent_runner.py`: Progent-compatible comparison runner.
- `scripts/prepare_upstream.ps1`: verify the vendored Agent-SafetyBench tree or clone and pin it when missing.
- `scripts/run_agentbrake_full.ps1`: run full AgentBrake-Fusion modes.
- `scripts/run_shield_score.ps1`: call upstream ShieldAgent scorer on a generated `gen_res.json`.
- `scripts/summarize_shield_results.py`: compute official safe / unsafe rates, optionally counting missing rows as unsafe.
- `tests/eval/agent_safetybench/`: regression tests for the ToolGate adapter.

Generated outputs are intentionally ignored by Git:

- `experiments/agent_safetybench/upstream/`
- `experiments/agent_safetybench/baselines/`
- `experiments/agent_safetybench/reports/`
- `experiments/agent_safetybench/case_plans/`

Do not commit API keys, raw paid-model outputs, local server credentials, or ShieldAgent cache files.

## Reproduction Protocol

The paper experiments use:

- Benchmark: `thu-coai/Agent-SafetyBench`
- Upstream commit: `74feea8de601b3a1449a93fcf70017fe61556f73`
- Data file: `experiments/agent_safetybench/upstream/data/released_data.json`
- Total cases: `2000`
- Generation temperature: `0.0`
- Main modes: `none`, `ab_strict`, `ab_gateway`, `ab_oracle`
- Optional responder modes: `ab_strict_responder`, `ab_gateway_responder`, `ab_oracle_responder`

API-based LLM runs are not bitwise deterministic across provider revisions, but the benchmark
version, sample set, runner parameters, output format, and scoring rules are fixed here.

## 1. Environment Setup

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e .[eval,test]
```

Prepare the upstream benchmark. If a vendored Agent-SafetyBench tree is already present,
the script verifies the required data, environment, and scorer files; otherwise it clones
the upstream repository and checks out the pinned commit.

```powershell
.\experiments\agent_safetybench\scripts\prepare_upstream.ps1
```

If the scorer dependencies are already installed, use:

```powershell
.\experiments\agent_safetybench\scripts\prepare_upstream.ps1 -SkipPipInstall
```

Run the adapter tests:

```powershell
python -m pytest tests\eval\agent_safetybench -q
```

Expected result:

```text
4 passed
```

## 2. Configure Model Access

Set API keys only in the current shell or a local `.env` file. Never commit them.

DeepSeek official-compatible endpoint:

```powershell
$env:DEEPSEEK_API_KEY="your key"
$env:DEEPSEEK_API_BASE="https://api.deepseek.com/v1"
```

DashScope OpenAI-compatible endpoint for qwen-plus:

```powershell
$env:DASHSCOPE_API_KEY="your key"
$env:DASHSCOPE_BASE_URL="https://dashscope.aliyuncs.com/compatible-mode/v1"
```

## 3. Run a Smoke Test

DeepSeek, 10 cases, AB-Strict:

```powershell
python experiments\agent_safetybench\agentbrake_runner.py `
  --model deepseek-v4-flash `
  --api-key-env DEEPSEEK_API_KEY `
  --base-url https://api.deepseek.com/v1 `
  --defense ab_strict `
  --limit 10 `
  --workers 2 `
  --out-dir experiments\agent_safetybench\reports\smoke\deepseek_ab_strict
```

Main outputs:

- `gen_res.json`: Agent-SafetyBench trajectory in upstream-compatible format.
- `guard_trace.jsonl`: one AgentBrake-Fusion ToolGate decision per candidate tool call.
- `summary.json`: machine-readable ToolGate metrics.
- `summary.md`: readable summary for reports.

## 4. Run Full AgentBrake-Fusion Modes

DeepSeek full 2000 cases:

```powershell
.\experiments\agent_safetybench\scripts\run_agentbrake_full.ps1 `
  -Model deepseek-v4-flash `
  -BaseUrl https://api.deepseek.com/v1 `
  -ApiKeyEnv DEEPSEEK_API_KEY `
  -Limit 2000 `
  -Workers 8 `
  -Resume
```

Qwen-plus full 2000 cases:

```powershell
.\experiments\agent_safetybench\scripts\run_agentbrake_full.ps1 `
  -Model qwen-plus `
  -BaseUrl https://dashscope.aliyuncs.com/compatible-mode/v1 `
  -ApiKeyEnv DASHSCOPE_API_KEY `
  -Limit 2000 `
  -Workers 8 `
  -Resume
```

To reproduce the `+Responder` variants used in the main comparison table:

```powershell
.\experiments\agent_safetybench\scripts\run_agentbrake_full.ps1 `
  -Model qwen-plus `
  -BaseUrl https://dashscope.aliyuncs.com/compatible-mode/v1 `
  -ApiKeyEnv DASHSCOPE_API_KEY `
  -Limit 2000 `
  -Workers 8 `
  -Responder `
  -Resume
```

The script runs:

| Script mode | Paper label |
|---|---|
| `none` | No defense |
| `ab_strict` | AB-Strict |
| `ab_gateway` | AB-Gateway |
| `ab_oracle` | AB-Oracle |
| `ab_strict_responder` | AB-Strict+Responder |
| `ab_gateway_responder` | AB-Gateway+Responder |
| `ab_oracle_responder` | AB-Oracle+Responder |

## 5. Run Progent Comparison

DeepSeek official endpoint:

```powershell
.\experiments\agent_safetybench\scripts\resume_progent_deepseek_official.ps1 `
  -Workers 12 `
  -BaseUrl https://api.deepseek.com/v1 `
  -ApiKeyEnv DEEPSEEK_API_KEY `
  -Model deepseek-v4-flash
```

DashScope-compatible qwen-plus:

```powershell
.\experiments\agent_safetybench\scripts\resume_progent_asb_rerun.ps1 `
  -Workers 8 `
  -BaseUrl https://dashscope.aliyuncs.com/compatible-mode/v1 `
  -ApiKeyEnv DASHSCOPE_API_KEY
```

## 6. Compute Official ShieldAgent Safety Rate

Agent-SafetyBench official safety scoring uses ShieldAgent. This step needs `torch`,
`transformers`, and enough GPU/CPU memory for the scorer model.

Example for one generated trajectory:

```powershell
.\experiments\agent_safetybench\scripts\run_shield_score.ps1 `
  -GenRes experiments\agent_safetybench\reports\qwen-plus\ab_gateway_responder\gen_res.json `
  -TargetName qwen_plus_ab_gateway_responder `
  -ModelPath thu-coai/ShieldAgent `
  -BatchSize 4
```

The upstream scorer writes results under:

```text
experiments/agent_safetybench/upstream/score/shield_results/<TargetName>/
```

Then summarize official rates. To match the conservative rule used in the report,
count missing or invalid rows as unsafe:

```powershell
python experiments\agent_safetybench\scripts\summarize_shield_results.py `
  --results experiments\agent_safetybench\upstream\score\shield_results\qwen_plus_ab_gateway_responder\qwen_plus_ab_gateway_responder_gen_res_outputs_results.json `
  --total 2000 `
  --missing-as-unsafe `
  --out experiments\agent_safetybench\reports\qwen-plus\ab_gateway_responder\official_summary.json
```

The fields used in the paper table are:

- `safety_rate`
- `unsafe_rate`
- `safe_count`
- `unsafe_count`
- `missing_count`

## 7. Reproducibility Checklist

Before reporting a number, record:

- Git commit of AgentBrake-Fusion.
- Agent-SafetyBench upstream commit: `74feea8de601b3a1449a93fcf70017fe61556f73`.
- Model name and API base URL.
- Defense mode.
- `limit`, `workers`, `max_rounds`, and whether `-Responder` was used.
- Path to `gen_res.json`.
- Path to ShieldAgent `*_outputs_results.json`.
- Whether missing / invalid rows were counted as unsafe.
