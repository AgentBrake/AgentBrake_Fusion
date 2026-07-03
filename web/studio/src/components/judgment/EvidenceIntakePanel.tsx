import type { JudgmentTraceViewModel } from "../../types";
import { evidenceRefText, valueText } from "./format";

export function EvidenceIntakePanel({ judgment, activeFactRefs = [] }: { judgment: JudgmentTraceViewModel; activeFactRefs?: string[] }) {
  const refs = new Set(activeFactRefs);
  return (
    <section className="judgment-panel evidence-intake">
      <div className="judgment-panel-head">
        <span className="policy-eyebrow">Evidence Intake</span>
        <h3>进入 MSJ Engine 的多源证据</h3>
      </div>
      <div className="evidence-group-grid">
        {judgment.evidence_groups.map((group) => (
          <article className={`evidence-group-card ${group.severity}`} key={group.group_id}>
            <b>{group.label}</b>
            <span className="muted">{group.items.length} 条证据 · {group.items[0]?.source_module || "MSJ Engine"}</span>
            {group.items.length ? group.items.slice(0, 5).map((item) => (
              <div className={`evidence-item ${item.evidence_refs.some((ref) => refs.has(ref)) ? "highlight" : ""}`} key={item.id}>
                <span>{item.label}</span>
                <code>{valueText(item.value)}</code>
                <small>证据：{evidenceRefText(item.evidence_refs)}</small>
              </div>
            )) : <p className="muted">当前动作没有这一类证据。</p>}
          </article>
        ))}
      </div>
    </section>
  );
}
