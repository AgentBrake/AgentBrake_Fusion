import { Download, FileSearch, PlayCircle, RefreshCw, Search, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { exportAuditTraces, fetchAuditTrace, fetchAuditTraces, replayAuditTrace } from "../api/audit";
import type { AuditTraceSummary, Decision, DecisionRun } from "../types";
import { decisionLabel, toolActionLabel } from "../utils/display";

const decisionOptions: Array<{ value: Decision | "all"; label: string }> = [
  { value: "all", label: "全部裁决" },
  { value: "block", label: "阻断" },
  { value: "require_confirmation", label: "需要确认" },
  { value: "allow", label: "放行" }
];

export function AuditCenter({ onOpenTrace }: { onOpenTrace: (run: DecisionRun) => void }) {
  const [traces, setTraces] = useState<AuditTraceSummary[]>([]);
  const [decision, setDecision] = useState<Decision | "all">("all");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<AuditTraceSummary | null>(null);
  const [message, setMessage] = useState("审计中心展示所有执行前裁决轨迹，支持回放和导出。");

  async function refresh() {
    const next = await fetchAuditTraces();
    setTraces(next);
    setSelected(next[0] || null);
  }

  useEffect(() => {
    void refresh();
  }, []);

  const filtered = useMemo(() => {
    const text = query.trim().toLowerCase();
    return traces.filter((trace) => {
      const decisionMatched = decision === "all" || trace.decision === decision;
      const textMatched =
        !text ||
        trace.traceId.toLowerCase().includes(text) ||
        trace.scenarioTitle.toLowerCase().includes(text) ||
        trace.toolName.toLowerCase().includes(text) ||
        trace.reasonCodes.join(" ").toLowerCase().includes(text);
      return decisionMatched && textMatched;
    });
  }, [decision, query, traces]);

  async function openTrace(trace: AuditTraceSummary) {
    setSelected(trace);
    const run = await fetchAuditTrace(trace.traceId);
    onOpenTrace(run);
  }

  async function replay(trace: AuditTraceSummary) {
    setSelected(trace);
    const run = await replayAuditTrace(trace.traceId);
    setMessage(`已回放轨迹 ${trace.traceId}，裁决工作台已切换到该运行。`);
    onOpenTrace(run);
  }

  async function downloadAll() {
    const content = await exportAuditTraces();
    downloadText("agentbrake-audit-traces.json", content);
    setMessage("审计轨迹已导出为 JSON。");
  }

  return (
    <div className="page-grid audit-page">
      <div className="page-hero">
        <div>
          <span className="eyebrow">审计中心</span>
          <h1>可回放的执行前裁决轨迹</h1>
          <p>每一次候选工具动作都会形成 ActionGraph、MSJ Engine 事实、Constraint Product Lattice join path 和 BrakeTrace，便于复盘与复现实验。</p>
        </div>
        <div className="hero-actions">
          <button onClick={refresh}><RefreshCw size={16} /> 刷新</button>
          <button className="primary" onClick={downloadAll}><Download size={16} /> 导出</button>
        </div>
      </div>

      <section className="card audit-toolbar">
        <label className="search-field">
          <Search size={16} />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索轨迹、场景、工具或原因码" />
        </label>
        <div className="segmented">
          {decisionOptions.map((option) => (
            <button key={option.value} className={decision === option.value ? "active" : ""} onClick={() => setDecision(option.value)}>
              {option.label}
            </button>
          ))}
        </div>
      </section>

      <div className="audit-layout">
        <section className="card audit-list">
          <div className="section-heading compact">
            <h2>轨迹列表</h2>
            <p>{filtered.length} 条匹配记录</p>
          </div>
          {filtered.map((trace) => (
            <button
              key={trace.traceId}
              className={selected?.traceId === trace.traceId ? "audit-row active" : "audit-row"}
              onClick={() => setSelected(trace)}
            >
              <span className={`decision-dot ${trace.decision}`} />
              <span>
                <b>{trace.scenarioTitle}</b>
                <em>{trace.traceId}</em>
              </span>
              <strong>{decisionLabel(trace.decision)}</strong>
            </button>
          ))}
        </section>

        <section className="card audit-detail">
          {selected ? (
            <>
              <div className="section-heading">
                <div>
                  <h2><FileSearch size={18} /> {selected.scenarioTitle}</h2>
                  <p>{new Date(selected.timestamp).toLocaleString()} · {toolActionLabel(selected.toolName)}</p>
                </div>
                <span className={`pill decision ${selected.decision}`}>{decisionLabel(selected.decision)}</span>
              </div>
              <div className="trace-kv-grid">
                <TraceKv label="轨迹编号" value={selected.traceId} />
                <TraceKv label="候选工具" value={selected.toolName} />
                <TraceKv label="执行状态" value={selected.toolExecuted ? "已执行" : "未执行，停在执行前网关"} />
                <TraceKv label="风险级别" value={selected.severity} />
              </div>
              <div className="reason-stack">
                {selected.reasonCodes.map((code) => <span key={code}>{code}</span>)}
              </div>
              <p className="audit-message"><ShieldAlert size={16} /> {message}</p>
              <div className="button-row">
                <button className="primary" onClick={() => openTrace(selected)}>打开裁决工作台</button>
                <button onClick={() => replay(selected)}><PlayCircle size={16} /> 回放轨迹</button>
              </div>
            </>
          ) : (
            <div className="empty-state">暂无审计轨迹。先运行一个场景或实时对话即可生成记录。</div>
          )}
        </section>
      </div>
    </div>
  );
}

function TraceKv({ label, value }: { label: string; value: string }) {
  return (
    <div className="trace-kv">
      <span>{label}</span>
      <b>{value}</b>
    </div>
  );
}

function downloadText(filename: string, content: string) {
  const blob = new Blob([content], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
