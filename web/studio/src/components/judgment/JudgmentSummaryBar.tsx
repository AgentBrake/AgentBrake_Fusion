import type { JudgmentTraceViewModel } from "../../types";
import { DecisionBadge } from "../DecisionBadge";
import { evidenceRefText, factName, oneLineAction, reasonText, severityForDecision, valueText } from "./format";

export function JudgmentSummaryBar({ judgment }: { judgment: JudgmentTraceViewModel }) {
  const sourceGroup = judgment.evidence_groups.find((group) => group.group_id === "source");
  const keyFacts = judgment.fact_nodes.slice(0, 4).map((fact) => `${factName(fact.namespace, fact.key)}=${valueText(fact.value)}`);
  const invariants = judgment.invariant_hits.map((rule) => String(rule.rule_id || rule.id)).filter(Boolean);
  return (
    <section className="judgment-summary-bar">
      <div>
        <span className="policy-eyebrow">Policy Judgment Workspace</span>
        <h3>{oneLineAction(judgment)}</h3>
        <p>{judgment.why_text || reasonText(judgment)}</p>
      </div>
      <DecisionBadge label={judgment.final_decision} severity={severityForDecision(judgment.final_decision)} />
      <dl>
        <div><dt>证据来源</dt><dd>{sourceGroup?.items.map((item) => `${item.label}/${valueText(item.value)}`).join("、") || "暂无来源证据"}</dd></div>
        <div><dt>关键事实</dt><dd>{keyFacts.join("、") || "暂无事实节点"}</dd></div>
        <div><dt>命中不变量</dt><dd>{invariants.join("、") || "无"}</dd></div>
        <div><dt>证据引用</dt><dd>{evidenceRefText(judgment.evidence_refs)}</dd></div>
      </dl>
    </section>
  );
}
