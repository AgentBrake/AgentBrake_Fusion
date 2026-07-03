# AgentBrake-Fusion AgentDojo Experiments

This directory contains the recommended AgentDojo experiment workflow for agentbrake. The experiments use the prototype under `src/agentbrake/eval/agentdojo` and evaluate safety judgments at the general agent tool boundary.

## Recommended Path

```text
AgentDojo tool output
  -> agent reasoning step
  -> candidate tool call
  -> AgentBrake-Fusion tool boundary
  -> ActionGraph
  -> MSJ Engine
  -> Constraint Product Lattice
  -> allow / confirm / quarantine / block
  -> BrakeTrace
```

## Quick Validation

```bash
pytest -q tests/eval/agentdojo/unit
python experiments/agentdojo/scripts/smoke_agentdojo_firewall.py
```

Expected behavior:

- Authorized benign actions remain executable.
- Untrusted or injection-like output influencing risky side effects is blocked or requires confirmation.
- Private data flowing toward external sinks is blocked or requires confirmation.
- High-impact financial or membership mutations require task authorization.
- Read-only tools remain available and update the state tracker.

## Mini Benchmark

```bash
python experiments/agentdojo/scripts/07_run_mini_benchmark.py --suites travel banking --limit 2
```

Outputs:

```text
experiments/agentdojo/reports/mini_benchmark.json
experiments/agentdojo/reports/mini_benchmark.md
experiments/agentdojo/logs/
```

## Paired Comparison

Generate the plan first:

```bash
python experiments/agentdojo/scripts/12_run_paired_mini.py --dry-run
```

Run the paired comparison:

```bash
python experiments/agentdojo/scripts/12_run_paired_mini.py
```

The paired workflow compares baseline methods against the AgentBrake-Fusion tool-boundary judgment path using a shared manifest.

## Ablation Profiles

Ablation profiles are defined in `src/agentbrake/eval/agentdojo/compat/types.py` and are used to study how much each evidence source contributes:

- `rule_only`
- `no_binding`
- `no_recovery_guidance`
- `flatten_action_graph`
- `no_actiongraph_provenance_edges`
- `no_actiongraph_dataflow_edges`
- `no_actiongraph_history_edges`

## Constraint Product Lattice Replay Ablation

Run the lattice-focused replay ablation on the checked-in AgentDojo-style smoke cases:

```bash
python experiments/agentdojo/scripts/36_run_lattice_ablation.py \
  --cases-dir experiments/agentdojo/replay_cases/smoke \
  --out-dir experiments/agentdojo/reports/lattice_ablation
```

Outputs:

```text
experiments/agentdojo/reports/lattice_ablation/lattice_ablation_report.md
experiments/agentdojo/reports/lattice_ablation/lattice_ablation_main_table.csv
experiments/agentdojo/reports/lattice_ablation/lattice_ablation_by_suite.csv
experiments/agentdojo/reports/lattice_ablation/lattice_ablation_main_plot.png
```

This is a tool-boundary replay ablation for component analysis, not a standard AgentDojo end-to-end score.

## 500-case Constraint Product Lattice Diagnostic

Run the lattice-focused diagnostic ablation on the same 500 Qwen-Plus traces used by the MSJ and ActionGraph ablation reports:

```bash
python experiments/agentdojo/scripts/37_run_lattice_ablation_diagnostic.py
```

Outputs:

```text
experiments/agentdojo/reports/qwen_plus/lattice_ablation_diagnostic/lattice_diagnostic_main_table.csv
experiments/agentdojo/reports/qwen_plus/lattice_ablation_diagnostic/lattice_diagnostic_by_suite.csv
experiments/agentdojo/reports/qwen_plus/lattice_ablation_diagnostic/lattice_pairwise_delta.json
experiments/agentdojo/reports/qwen_plus/lattice_ablation_diagnostic/lattice_per_case_results.jsonl
experiments/agentdojo/reports/qwen_plus/lattice_ablation_diagnostic/lattice_ablation_diagnostic_zh.md
```

This is a frozen-trace decision replay over real Qwen-Plus AgentDojo trajectories. It is intended to isolate the contribution of the Constraint Product Lattice layer and does not make online model calls.

## Historical Data

Historical baselines are kept under:

```text
experiments/agentdojo/archive/
```

Keep historical baselines separate from new agentbrake runs so current reports remain easy to interpret.
