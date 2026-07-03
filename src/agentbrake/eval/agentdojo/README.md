# AgentBrake-Fusion AgentDojo Prototype

This package is the current prototype substrate for agentbrake. It places the safety decision point at the general agent tool boundary: every candidate tool call is converted into evidence, judged before execution, and recorded as a BrakeTrace audit event.

## Module Mapping

| AgentBrake-Fusion concept | Code | Role |
| --- | --- | --- |
| Tool boundary | `gate/tool_firewall.py` | Builds evidence before a tool executes and resolves the public decision. |
| ActionGraph | `evidence/action_graph.py` | Builds a tool-relation evidence graph over current call, prior outputs, private data, suspicious targets, and history. |
| Evidence facts | `evidence/evidence.py` | Normalizes task authorization, argument provenance, state history, tool taxonomy, and ActionGraph facts. |
| MSJ Engine | `evidence/fusion.py` | Fuses generic rules, suite policies, graph facts, and state evidence into one judgment. |
| Constraint Product Lattice | `compat/types.py` | Stores multi-dimensional constraints that are joined before mapping to public decisions. |
| BrakeTrace | `ToolExecutionDecision.to_audit_event()` | Emits reason codes, rule hits, graph facts, module switches, confirmation state, and recovery guidance. |

## Decision Flow

```text
ToolCallContext
  -> AgentDojoToolTaxonomy
  -> AgentDojoStateTracker
  -> AgentDojoActionGraphBuilder
  -> AgentDojoEvidenceBuilder
  -> AgentDojoEvidenceFusion
  -> ToolExecutionDecision
  -> BrakeTrace
```

## Outputs

- `agentdojo.*` facts in the evidence fact space.
- ActionGraph facts under the `graph.*` namespace.
- Public decision: `allow`, `allow_in_sandbox`, `require_confirmation`, `quarantine`, or `block`.
- BrakeTrace audit event with `reason_codes`, `rule_hits`, `action_graph_id`, module execution metadata, and recovery guidance.

