import type { JudgmentTraceViewModel } from "../../types";
import { DecisionBadge } from "../DecisionBadge";
import { evidenceRefText, predicatePath, ruleTitle, valueText } from "./format";

export function PredicateMatrix({ judgment }: { judgment: JudgmentTraceViewModel }) {
  const grouped = groupRows(judgment);
  return (
    <section className="judgment-panel predicate-matrix-panel">
      <div className="judgment-panel-head">
        <span className="policy-eyebrow">PredicateEval</span>
        <h3>哪些 predicate 成立</h3>
      </div>
      {grouped.map((group) => (
        <article className="predicate-rule-card" key={group.ruleId}>
          <div className="predicate-rule-head">
            <b>{ruleTitle(group.rule)}</b>
            <DecisionBadge label={String(group.rule.decision || judgment.final_decision)} severity={group.ruleId.startsWith("INV-") ? "critical" : "warning"} />
          </div>
          <div className="predicate-table">
            <div className="predicate-row predicate-head"><span>检查项</span><span>期望值</span><span>实际证据</span><span>结论</span></div>
            {group.rows.map((row) => (
              <div className="predicate-row" key={`${group.ruleId}-${row.predicate_id}-${row.path}`}>
                <span>{predicatePath(row)}</span>
                <span>{row.expected === undefined ? String(row.operator || "事实存在") : valueText(row.expected)}</span>
                <span>{valueText(row.actual)}<small>证据：{evidenceRefText(row.evidence_refs)}</small></span>
                <span className={row.matched ? "predicate-ok" : "predicate-miss"}>{row.matched ? "成立" : "未成立"}</span>
              </div>
            ))}
          </div>
        </article>
      ))}
      {!grouped.length ? <div className="empty-state">没有 predicate 级轨迹。旧日志仍可查看 matched_rules，但无法拆到条件级。</div> : null}
    </section>
  );
}

function groupRows(judgment: JudgmentTraceViewModel) {
  const ruleMap = new Map(judgment.candidate_rules.map((rule) => [String(rule.rule_id || rule.id || ""), rule]));
  const groups = new Map<string, { ruleId: string; rule: Record<string, unknown>; rows: typeof judgment.predicate_rows }>();
  for (const row of judgment.predicate_rows) {
    const ruleId = row.rule_id || "unknown_rule";
    const group = groups.get(ruleId) || { ruleId, rule: ruleMap.get(ruleId) || { rule_id: ruleId }, rows: [] };
    group.rows.push(row);
    groups.set(ruleId, group);
  }
  return [...groups.values()];
}
