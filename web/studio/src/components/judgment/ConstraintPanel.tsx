import type { JudgmentTraceViewModel } from "../../types";

const LABELS: Record<string, string> = {
  execution_env: "执行环境",
  network_scope: "网络权限",
  data_scope: "数据访问",
  human_gate: "人工审批",
  persistence_scope: "持久化",
  audit_scope: "审计级别",
};

export function ConstraintPanel({ judgment }: { judgment: JudgmentTraceViewModel }) {
  const constraints = judgment.constraints || {};
  const entries = Object.entries(constraints).filter(([, value]) => value !== undefined && value !== null && value !== "");
  const nodes = judgment.causal_graph.constraint_nodes || [];
  if (!entries.length && !nodes.length) return null;
  return (
    <section className="judgment-panel">
      <div className="judgment-panel-head">
        <span className="policy-eyebrow">Constraint Lattice</span>
        <h3>治理约束</h3>
      </div>
      <div className="fact-table compact">
        {entries.map(([key, value]) => (
          <button className="fact-row" key={key} type="button">
            <span>{LABELS[key] || key}</span>
            <b>{String(value)}</b>
          </button>
        ))}
        {nodes.slice(0, 6).map((node, index) => (
          <button className="fact-row" key={String(node.id || index)} type="button">
            <span>{String(node.via || node.kind || "constraint")}</span>
            <b>{String((node.constraints as Record<string, unknown> | undefined)?.execution_env || node.id || "")}</b>
          </button>
        ))}
      </div>
    </section>
  );
}
