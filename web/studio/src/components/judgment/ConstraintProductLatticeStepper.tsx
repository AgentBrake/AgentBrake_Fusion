import type { JudgmentTraceViewModel } from "../../types";
import { displayLabel } from "../DecisionBadge";
import { ruleTitle } from "./format";

const decisionOrder = ["allow", "allow_in_sandbox", "require_confirmation", "sandbox_then_approval", "quarantine", "block"];

export function ConstraintProductLatticeStepper({ judgment }: { judgment: JudgmentTraceViewModel }) {
  return (
    <section className="judgment-panel lattice-stepper-panel">
      <div className="judgment-panel-head">
        <span className="policy-eyebrow">Constraint Product Lattice</span>
        <h3>约束乘积格如何从 allow 升级到 {displayLabel(judgment.final_decision)}</h3>
      </div>
      <div className="lattice-rail">
        {decisionOrder.map((decision) => <span className={rank(decision) <= rank(judgment.final_decision) ? "active" : ""} key={decision}>{displayLabel(decision)}</span>)}
      </div>
      <div className="lattice-step-list">
        {judgment.lattice_path.map((step, index) => (
          <div className="lattice-step-card" key={`${step.via}-${index}`}>
            <span>{displayLabel(String(step.from || "开始"))} → {displayLabel(String(step.to || "决策"))}</span>
            <b>{ruleTitle({ rule_id: step.via })}</b>
            <small>因为这条规则或不变量的风险等级更高，约束乘积格选择更严格的结果。</small>
          </div>
        ))}
      </div>
      {!judgment.lattice_path.length ? <div className="empty-state">该动作没有约束乘积格升级路径，最终结论见页面顶部。</div> : null}
    </section>
  );
}

function rank(decision: string): number {
  const idx = decisionOrder.indexOf(decision);
  return idx >= 0 ? idx : 0;
}
