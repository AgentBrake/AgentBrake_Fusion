import { createDecisionRun } from "./scenarios";
import type { AuditTraceSummary, DecisionRun, Decision } from "../types";

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("agentbrakeFusionToken") || "agentbrake-fusion-local";
  return { Authorization: `Bearer ${token}` };
}

const fallbackAudit: AuditTraceSummary[] = [
  {
    traceId: "trace-workspace-demo",
    scenarioId: "workspace",
    scenarioTitle: "工作区",
    timestamp: new Date().toISOString(),
    decision: "block" as Decision,
    toolName: "send_email",
    severity: "critical",
    reasonCodes: ["参数来自低可信来源", "敏感数据流向外部出口"],
    toolExecuted: false
  },
  {
    traceId: "trace-travel-demo",
    scenarioId: "travel",
    scenarioTitle: "旅行预订",
    timestamp: new Date().toISOString(),
    decision: "require_confirmation" as Decision,
    toolName: "reserve_hotel",
    severity: "high",
    reasonCodes: ["预订目标不一致", "需要用户明确确认"],
    toolExecuted: false
  }
];

export async function fetchAuditTraces(): Promise<AuditTraceSummary[]> {
  try {
    const response = await fetch("/api/audit", { headers: authHeaders() });
    if (!response.ok) throw new Error("audit endpoint unavailable");
    const payload = await response.json();
    return payload.traces as AuditTraceSummary[];
  } catch {
    return fallbackAudit;
  }
}

export async function fetchAuditTrace(traceId: string): Promise<DecisionRun> {
  try {
    const response = await fetch(`/api/audit/${encodeURIComponent(traceId)}`, { headers: authHeaders() });
    if (!response.ok) throw new Error("audit trace unavailable");
    const payload = await response.json();
    return (payload.run || payload) as DecisionRun;
  } catch {
    return createDecisionRun(traceId.includes("travel") ? "travel" : "workspace");
  }
}

export async function replayAuditTrace(traceId: string): Promise<DecisionRun> {
  try {
    const response = await fetch(`/api/audit/replay/${encodeURIComponent(traceId)}`, {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: "{}"
    });
    if (!response.ok) throw new Error("audit replay unavailable");
    const payload = await response.json();
    return (payload.run || payload.trace || payload) as DecisionRun;
  } catch {
    return fetchAuditTrace(traceId);
  }
}

export async function exportAuditTraces(): Promise<string> {
  try {
    const response = await fetch("/api/audit/export", { headers: authHeaders() });
    if (!response.ok) throw new Error("audit export unavailable");
    return JSON.stringify(await response.json(), null, 2);
  } catch {
    return JSON.stringify({ exportedAt: new Date().toISOString(), traces: fallbackAudit }, null, 2);
  }
}
