# Evaluation Reproduction

This document explains how to reproduce the included evaluation support materials.

## Replay Cases

Run built-in replay/demo cases:

```bash
python scripts/healthcheck.py --ensure-backend --demo
```

Outputs:

```text
artifacts/reports/demo_trace_workspace.json
artifacts/reports/demo_trace_slack.json
artifacts/reports/demo_trace_banking.json
artifacts/reports/demo_trace_travel.json
artifacts/reports/demo_traces.json
```

## AgentDojo Full E2E

The full AgentDojo experiment scripts live under:

```text
experiments/agentdojo/
```

Use the original experiment scripts when the AgentDojo dependency and model API credentials are available. Do not write real API keys into reports or traces.

## Recovery and Confirmation

Recovery and confirmation behavior is exposed in BrakeTrace fields:

- `allowed_next_steps`
- `disallowed_next_steps`
- `recoveryGuidance`

## Latency

Latency tables should be reported from measured Studio or experiment outputs. The included summary tables are in:

```text
data/agentdojo_results/
docs/paper_experiments/
```

## Ablation

Ablation should compare:

- full
- no MSJ-related component
- no ActionGraph-related component
- no provenance
- no task binding
- no dataflow edges
- no history edges
- rule_only, if available

Do not estimate unreported metrics.

## Suite Breakdown

The UI reports suite-level trends for workspace, slack, banking, and travel. Source tables must be kept under `data/agentdojo_results/` or documented as N/R.

## Regenerating Figures

For Studio screenshots, follow `artifacts/screenshots/README.md`. For paper figures, place generated images in `artifacts/figures/`.

## N/R Metrics

If a metric was not measured, mark it as `N/R`. Do not interpolate or fabricate missing metrics.
