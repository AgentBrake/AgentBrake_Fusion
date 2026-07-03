export type Severity = "critical" | "warning" | "normal" | "info";
export type Decision = "allow" | "require_confirmation" | "block" | "observing";
export type ScenarioId = "workspace" | "slack" | "banking" | "travel" | "file_sharing" | "command_api";

export interface StudioEvent {
  schema_version: string;
  event_id: string;
  timestamp: string;
  run_id: string;
  session_id: string;
  request_id: string;
  span_id: string;
  parent_span_id?: string | null;
  event_index: number;
  type: string;
  phase: string;
  severity: Severity;
  summary: string;
  agent_name: string;
  demo_scenario_id?: string | null;
  payload: Record<string, unknown>;
}

export interface RunSummary {
  run_id: string;
  session_id: string;
  started_at: string;
  updated_at: string;
  event_count: number;
  blocked_count: number;
  approval_count: number;
  action_count: number;
  critical_count: number;
  latest_decision: string;
  agent_name: string;
  demo_scenario_id?: string | null;
}

export interface ActionDetail {
  action_id: string;
  run_id: string;
  action: Record<string, unknown>;
  decision: Record<string, unknown>;
  runtime: Record<string, unknown>;
  instruction: Record<string, unknown>;
  sources: Array<Record<string, unknown>>;
  evidence_events: StudioEvent[];
  action_graph?: Record<string, unknown>;
  session_state?: Record<string, unknown>;
  policy_fact_set?: Record<string, unknown>;
  policy_eval_trace?: PolicyEvalTrace;
  policy_predicates?: PolicyPredicateRow[];
  policy_lattice_path?: Array<Record<string, unknown>>;
  policy_causal_graph?: PolicyCausalGraph;
}

export interface PolicyPredicateRow {
  rule_id?: string;
  rule_decision?: string;
  rule_invariant?: boolean;
  predicate_id?: string;
  path?: string;
  operator?: string;
  expected?: unknown;
  actual?: unknown;
  matched?: boolean;
  matched_fact_ids?: string[];
  evidence_refs?: string[];
}

export interface PolicyCausalGraph {
  fact_nodes?: Array<Record<string, unknown>>;
  predicate_nodes?: Array<Record<string, unknown>>;
  rule_nodes?: Array<Record<string, unknown>>;
  lattice_nodes?: Array<Record<string, unknown>>;
  retrieval_nodes?: Array<Record<string, unknown>>;
  action_graph_nodes?: Array<Record<string, unknown>>;
  history_nodes?: Array<Record<string, unknown>>;
  constraint_nodes?: Array<Record<string, unknown>>;
  invariant_nodes?: Array<Record<string, unknown>>;
  edges?: Array<Record<string, unknown>>;
}

export interface PolicyEvalTrace extends PolicyCausalGraph {
  action_id?: string;
  policy_eval_trace_id?: string;
  final_decision?: string;
  engine_mode?: string;
  policy_version?: string;
  fact_hash?: string;
  invariant_hits?: string[];
  decision_lattice_path?: Array<Record<string, unknown>>;
  constraint_product_lattice_path?: Array<Record<string, unknown>>;
  skipped_rules_summary?: Record<string, unknown>;
  constraints?: Record<string, unknown>;
}

export type JudgmentSourceModule =
  | "ActionIR"
  | "ContextGraph"
  | "AssetGraph"
  | "SecretSentry"
  | "PackageGuard"
  | "MCPProxy"
  | "MemoryStore"
  | "SandboxRunner"
  | "TaskContract"
  | "MSJ Engine";

export interface JudgmentEvidenceItem {
  id: string;
  label: string;
  value: unknown;
  evidence_refs: string[];
  source_module: JudgmentSourceModule;
}

export interface JudgmentEvidenceGroup {
  group_id: string;
  label: string;
  severity: Severity;
  items: JudgmentEvidenceItem[];
}

export interface JudgmentTraceViewModel {
  schema_version: string;
  action_id: string;
  run_id: string;
  action_summary: Record<string, unknown>;
  evidence_groups: JudgmentEvidenceGroup[];
  fact_set: Record<string, unknown>;
  fact_nodes: Array<Record<string, unknown>>;
  invariant_hits: Array<Record<string, unknown>>;
  candidate_rules: Array<Record<string, unknown>>;
  predicate_rows: PolicyPredicateRow[];
  lattice_path: Array<Record<string, unknown>>;
  causal_graph: PolicyCausalGraph;
  final_decision: string;
  reason_codes: string[];
  required_controls: string[];
  evidence_refs: string[];
  why_text: string;
  skipped_rules_summary?: Record<string, unknown>;
  retrieval_trace?: Record<string, unknown>;
  constraints?: Record<string, unknown>;
  policy_eval_trace_id?: string;
  fact_hash?: string;
}

export interface ScenarioSpec {
  id: string;
  name: string;
  kind: "normal" | "attack";
  description: string;
  source_type: string;
  attack_body: string;
  expected_decision: string;
  dangerous_action: string;
}

export interface GraphNode {
  id: string;
  type: string;
  phase: string;
  severity: Severity;
  label: string;
}

export interface GraphEdge {
  from: string;
  to: string;
  relation: string;
}

export interface ApprovalEvent {
  event_type: "request" | "grant" | "denial" | string;
  created_at?: string;
  payload: Record<string, unknown>;
}

export interface BenchReport {
  metrics: Record<string, unknown>;
  samples: Array<Record<string, unknown>>;
}

export interface CoverageRow {
  capability: string;
  declared: boolean;
  verified: boolean;
  status: "protected" | "partial" | "missing" | string;
  evidence: string;
}

export interface CoverageReport {
  ok: boolean;
  mode: string;
  missing: string[];
  matrix: CoverageRow[];
  config_path?: string;
}

export type ServiceStatus = "online" | "offline" | "mock" | "checking";

export interface ServiceHealth {
  agentbrakeApi: ServiceStatus;
  openclawGateway: ServiceStatus;
  a2aGateway?: ServiceStatus;
  cliFallback?: ServiceStatus;
  localModel: ServiceStatus;
  toolGuard: ServiceStatus;
  auditStream: ServiceStatus;
  policyMode: "enforce" | "observe_only" | "mock";
  endpoint: string;
  lastCheckedAt: string;
}

export interface GuardConfig {
  mode: "gateway_ws" | "gateway_http" | "a2a" | "cli" | "mock";
  baseUrl: string;
  gatewayUrl?: string;
  authToken?: string;
  a2aUrl?: string;
  a2aAgentId?: string;
  openclawAgentId?: string;
  cliPath?: string;
  modelRef?: string;
  chatEndpoint?: string;
  eventsEndpoint?: string;
  toolCallEndpoint?: string;
  openaiCompatible?: boolean;
  modelBaseUrl?: string;
  modelApiKey?: string;
  gatewayPaths?: Record<string, string>;
  policyMode: "enforce" | "observe_only";
  auditStream: boolean;
  preExecutionGate: boolean;
  sandbox?: boolean;
  allowRealTools?: boolean;
}

export interface SetupCheck {
  id: string;
  label: string;
  status: ServiceStatus;
  detail: string;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system";
  text: string;
  timestamp: string;
}

export interface CandidateToolCall {
  id: string;
  toolName: string;
  status: "under_review" | "blocked" | "requires_confirmation" | "allowed";
  args: Record<string, string>;
  risk: "low" | "medium" | "high" | "critical";
  source: string;
  preview: string;
  decision: Decision;
}

export interface ToolTimelineItem {
  id: string;
  time: string;
  title: string;
  state: "observed" | "candidate" | "reviewing" | "decided";
  decision?: Decision;
}

export interface DemoScenario {
  id: ScenarioId;
  title: string;
  tagline: string;
  userTask: string;
  lowTrustSource: string;
  injectedContent: string;
  dangerousToolCall: CandidateToolCall;
  expectedDecision: Decision;
  designHighlights: {
    actionGraph: string[];
    msjFacts: string[];
    latticeDimensions: string[];
  };
}

export interface ActionGraphNode {
  id: string;
  label: string;
  kind: "source" | "candidate" | "trusted" | "untrusted" | "private" | "arg" | "side_effect" | "decision";
  column: "left" | "center" | "right";
  data?: Record<string, unknown>;
}

export interface ActionGraphEdge {
  from: string;
  to: string;
  relation: "derived_from" | "uses_arg" | "conflicts_with" | "sends_to" | "writes_to" | "blocked_by" | "reads_from" | "mutates" | "influenced_by" | "recovered_by";
}

export interface MSJFacts {
  task_authorized: boolean;
  tool_group: string;
  arg_provenance: Record<string, string>;
  private_data_seen: boolean;
  injection_seen: boolean;
  args_match_user_entity: boolean;
  args_match_untrusted_entity: boolean;
  external_sink: boolean;
  ruleHits: string[];
  trustedEvidence: string[];
  unsafeEvidence: string[];
}

export interface LatticeDimension {
  id: "action" | "intent" | "provenance" | "sensitivity" | "destination" | "history" | "confirmation";
  label: string;
  value: string;
  severity: Severity;
}

export interface LatticeOutput {
  execution_env: string;
  network_scope: string;
  data_scope: string;
  human_gate: string;
  audit_scope: string;
  decision: Decision;
  joinPath: string[];
}

export interface BrakeTrace {
  reason_codes: string[];
  trusted_evidence: string[];
  unsafe_evidence: string[];
  allowed_next_steps: string[];
  disallowed_next_steps: string[];
  recovery_guidance?: string[];
}

export interface DecisionRun {
  id: string;
  traceId?: string;
  sessionId?: string;
  turnId?: string;
  timestamp?: string;
  scenarioId: ScenarioId;
  scenarioTitle?: string;
  severity?: "low" | "medium" | "high" | "critical";
  latencyMs?: number;
  toolExecuted?: boolean;
  sandboxed?: boolean;
  openclawRawResponse?: string;
  userTask: string;
  lowTrustContext: string;
  candidateToolCall: CandidateToolCall;
  finalDecision: Decision;
  actionGraph: {
    nodes: ActionGraphNode[];
    edges: ActionGraphEdge[];
  };
  msjFacts: MSJFacts;
  lattice: {
    dimensions: LatticeDimension[];
    output: LatticeOutput;
  };
  brakeTrace: BrakeTrace;
  timeline: ToolTimelineItem[];
  recoveryGuidance?: string[];
}

export interface AuditTraceSummary {
  traceId: string;
  scenarioId: string;
  scenarioTitle: string;
  timestamp: string;
  decision: Decision;
  severity: string;
  toolName: string;
  reasonCodes: string[];
  toolExecuted: boolean;
}

export interface ExperimentMetric {
  label: string;
  value: string;
  trend?: string;
  tone: "defense" | "attack" | "confirm" | "allow";
}

export interface ExperimentDashboardData {
  headline: ExperimentMetric[];
  fullE2E: Array<Record<string, string>>;
  latency: Array<Record<string, string>>;
  ablation: Array<Record<string, string>>;
}
