import type { JudgmentTraceViewModel } from "../../types";
import { displayLabel } from "../DecisionBadge";
import { asRecordArray } from "./format";

export function AlgorithmTracePanel({ judgment }: { judgment: JudgmentTraceViewModel }) {
  const trace = judgment.retrieval_trace || {};
  const postings = asRecordArray(trace.postings);
  const latticeSteps = judgment.lattice_path.length;
  const matchedPredicates = judgment.predicate_rows.filter((row) => row.matched).length;
  const steps = [
    { title: "Fact Extraction", value: judgment.fact_nodes.length, text: "把动作、来源、资产、任务边界、沙箱记录抽成标准事实" },
    { title: "Invariants", value: judgment.invariant_hits.length, text: "先检查不可降级安全门，命中后不能被普通规则放行" },
    { title: "EvidenceIndex", value: postings.length, text: "用事实键召回候选规则，并保留残余规则兜底" },
    { title: "PredicateEval", value: matchedPredicates, text: "逐条判断候选规则的条件是否成立" },
    { title: "Constraint Product Lattice", value: latticeSteps, text: `把多个结论按约束乘积格合并为 ${displayLabel(judgment.final_decision)}` },
    { title: "EvidenceGraph", value: judgment.evidence_refs.length, text: "输出可审计证据引用和因果图" },
  ];
  return (
    <section className="judgment-panel algorithm-trace-panel">
      <div className="judgment-panel-head">
        <span className="policy-eyebrow">MSJ Engine</span>
        <h3>多源证据综合判断算法</h3>
      </div>
      <div className="pruner-steps">
        {steps.map((step) => (
          <div className="pruner-step" key={step.title}>
            <span>{step.title}</span>
            <b>{step.value}</b>
            <small>{step.text}</small>
          </div>
        ))}
      </div>
    </section>
  );
}
