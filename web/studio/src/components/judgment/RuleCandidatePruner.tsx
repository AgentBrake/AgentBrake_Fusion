import type { ReactNode } from "react";
import type { JudgmentTraceViewModel } from "../../types";
import { asRecordArray, asStringArray, factTokenText } from "./format";

export function RuleCandidatePruner({ judgment }: { judgment: JudgmentTraceViewModel }) {
  const trace = judgment.retrieval_trace || {};
  const stats = Object.keys(trace).length ? trace : judgment.skipped_rules_summary || {};
  const total = Number(stats.total_rules || judgment.candidate_rules.length || 0);
  const candidates = Number(stats.candidate_rules || judgment.candidate_rules.length || 0);
  const residual = Number(stats.residual_rules || 0);
  const pruned = Number(stats.pruned_rules || 0);
  const hits = judgment.invariant_hits.length + judgment.predicate_rows.filter((row) => row.matched).length;
  const reduction = Number(stats.candidate_reduction_ratio || 0);
  const postings = asRecordArray(trace.postings);
  const compositeHits = asRecordArray(trace.composite_hits);
  const prunedRows = asRecordArray(trace.pruned);
  const candidateRuleIds = asStringArray(trace.candidate_rule_ids);
  const indexedFactKeys = asStringArray(trace.indexed_fact_keys);

  return (
    <section className="judgment-panel rule-pruner">
      <div className="judgment-panel-head">
        <span className="policy-eyebrow">EvidenceIndex / RuleIndex</span>
        <h3>RuleIndex 用哪些证据键召回了哪些规则</h3>
      </div>
      <p className="panel-note">索引阶段只负责召回候选规则，不直接下最终结论。它允许多召回，但不能漏召回；复杂条件会进入残余规则兜底。</p>
      <div className="pruner-steps">
        <PrunerStep label="全部规则" value={total} />
        <PrunerStep label="事实索引命中" value={uniquePostingRuleCount(postings)} />
        <PrunerStep label="残余规则兜底" value={residual} />
        <PrunerStep label="安全剪枝移除" value={pruned} />
        <PrunerStep label="最终候选规则" value={candidates} />
        <PrunerStep label="实际命中条件" value={hits} />
      </div>
      <div className="retrieval-detail-grid">
        <TraceSection title="用于检索的事实键" empty="暂无可索引事实">
          {indexedFactKeys.slice(0, 12).map((key) => <span key={key}>{factTokenText(key)}</span>)}
        </TraceSection>
        <TraceSection title="单事实召回" empty="暂无单事实命中">
          {postings.slice(0, 10).map((posting) => (
            <span key={String(posting.key)}>
              {factTokenText(String(posting.key))}：召回 {String(posting.rules || 0)} 条，{asStringArray(posting.rule_ids).slice(0, 4).join("、")}
            </span>
          ))}
        </TraceSection>
        <TraceSection title="组合证据召回" empty="暂无组合证据命中">
          {compositeHits.slice(0, 8).map((hit, index) => (
            <span key={index}>
              {asStringArray(hit.keys).map(factTokenText).join(" + ")}：召回 {String(hit.rules || 0)} 条
            </span>
          ))}
        </TraceSection>
        <TraceSection title="残余规则为什么保留" empty="暂无残余规则">
          <span>包含 regex、not_exists、unless 等复杂判断的规则会保留到精确评估阶段。</span>
          <span>当前残余规则：{residual} 条</span>
        </TraceSection>
        <TraceSection title="安全剪枝说明" empty="暂无安全剪枝">
          {prunedRows.map((row, index) => (
            <span key={index}>{String(row.rule_id)} 因 {String(row.path)} 与事实值不可能同时成立而移除</span>
          ))}
        </TraceSection>
        <TraceSection title="最终候选集" empty="暂无候选规则">
          {candidateRuleIds.slice(0, 14).map((ruleId) => <span key={ruleId}>{ruleId}</span>)}
          {candidateRuleIds.length > 14 ? <span>还有 {candidateRuleIds.length - 14} 条未展开</span> : null}
        </TraceSection>
        <TraceSection title="压缩效果" empty="暂无压缩数据">
          <span>{reduction ? `候选集约为全部规则的 ${Math.round(reduction * 100)}%` : "暂无"}</span>
          <span>{trace.safe_prune_enabled ? "安全剪枝已启用" : "安全剪枝处于保守模式，优先保证不漏召回"}</span>
        </TraceSection>
      </div>
    </section>
  );
}

function TraceSection({ title, empty, children }: { title: string; empty: string; children: ReactNode }) {
  const items = Array.isArray(children) ? children.filter(Boolean) : children;
  const isEmpty = Array.isArray(items) ? items.length === 0 : !items;
  return (
    <section>
      <b>{title}</b>
      {isEmpty ? <span>{empty}</span> : items}
    </section>
  );
}

function PrunerStep({ label, value }: { label: string; value: number }) {
  return <div className="pruner-step"><span>{label}</span><b>{value}</b></div>;
}

function uniquePostingRuleCount(postings: Array<Record<string, unknown>>): number {
  const ids = new Set<string>();
  postings.forEach((posting) => asStringArray(posting.rule_ids).forEach((id) => ids.add(id)));
  return ids.size || postings.reduce((sum, posting) => sum + Number(posting.rules || 0), 0);
}
