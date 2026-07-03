import type { ActionDetail, ApprovalEvent, BenchReport, CoverageReport, GraphEdge, GraphNode, JudgmentTraceViewModel, RunSummary, ScenarioSpec, StudioEvent } from "../types";

const token = localStorage.getItem("agentbrakeFusionToken") || "agentbrake-fusion-local";

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      ...(options.headers || {})
    }
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || response.statusText);
  return data as T;
}

export const studioApi = {
  health: () => request<{ ok: boolean; version: string; demo_mode: boolean }>("/api/health"),
  runs: () => request<{ runs: RunSummary[] }>("/api/runs"),
  run: (runId: string) => request<RunSummary>(`/api/runs/${encodeURIComponent(runId)}`),
  events: (runId: string, limit = 800) => request<{ events: StudioEvent[] }>(`/api/runs/${encodeURIComponent(runId)}/events?limit=${limit}`),
  graph: (runId: string) => request<{ nodes: GraphNode[]; edges: GraphEdge[] }>(`/api/runs/${encodeURIComponent(runId)}/graph`),
  action: (actionId: string) => request<ActionDetail>(`/api/actions/${encodeURIComponent(actionId)}`),
  judgment: (actionId: string) => request<JudgmentTraceViewModel>(`/api/actions/${encodeURIComponent(actionId)}/judgment`),
  scenarios: () => request<{ scenarios: ScenarioSpec[] }>("/api/scenarios"),
  runScenario: (scenarioId: string) => request<{ result: { trace_id: string } }>(`/api/scenarios/${encodeURIComponent(scenarioId)}/run`, { method: "POST", body: "{}" }),
  approvals: () => request<{ metrics: Record<string, number>; events: ApprovalEvent[] }>("/api/approvals"),
  grant: (approvalId: string, actionHash: string) => request(`/api/approvals/${encodeURIComponent(approvalId)}/grant`, { method: "POST", body: JSON.stringify({ action_hash: actionHash, constraints: ["sandbox_only", "no_network"], granted_by: "studio" }) }),
  deny: (approvalId: string) => request(`/api/approvals/${encodeURIComponent(approvalId)}/deny`, { method: "POST", body: JSON.stringify({ denied_by: "studio" }) }),
  bench: () => request<BenchReport>("/api/bench/latest"),
  coverage: () => request<CoverageReport>("/api/coverage"),
  exportEvidence: (runId: string) => request<{ output: string }>(`/api/export/evidence/${encodeURIComponent(runId)}`),
  clearRecords: (backup: boolean) => request<{ ok: boolean; backups: string[]; cleared: string[]; backup_enabled: boolean }>("/api/admin/clear-records", { method: "POST", body: JSON.stringify({ backup }) })
};
