import type { JudgmentTraceViewModel } from "../../types";
import { DecisionBadge } from "../DecisionBadge";
import { evidenceRefText, reasonText, severityForDecision } from "./format";

export function WhyDecisionPanel({ judgment }: { judgment: JudgmentTraceViewModel }) {
  return (
    <section className="judgment-panel why-panel">
      <div className="judgment-panel-head">
        <span className="policy-eyebrow">PolicyDecision / Why</span>
        <h3>最终 why_text 是什么</h3>
      </div>
      <DecisionBadge label={judgment.final_decision} severity={severityForDecision(judgment.final_decision)} />
      <p>{judgment.why_text || "当前动作没有额外自然语言解释。"}</p>
      <div className="why-grid">
        <div><b>原因码</b><span>{reasonText(judgment)}</span></div>
        <div><b>强制控制</b><span>{judgment.required_controls.length ? judgment.required_controls.join("、") : "无"}</span></div>
        <div><b>可审计证据</b><span>{evidenceRefText(judgment.evidence_refs)}</span></div>
        <div><b>fact hash</b><span>{judgment.fact_hash || "无"}</span></div>
      </div>
    </section>
  );
}
