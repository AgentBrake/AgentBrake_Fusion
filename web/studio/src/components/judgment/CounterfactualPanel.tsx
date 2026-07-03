import type { JudgmentTraceViewModel } from "../../types";

export function CounterfactualPanel({ judgment }: { judgment: JudgmentTraceViewModel }) {
  const hasSecret = judgment.fact_nodes.some((fact) => fact.namespace === "asset" && String(fact.value).includes("secret"));
  const hasUntrusted = judgment.fact_nodes.some((fact) => fact.namespace === "source" && (String(fact.value) === "untrusted" || fact.value === true));
  const hasContractViolation = judgment.fact_nodes.some((fact) => fact.namespace === "contract" && String(fact.value) === "violation");
  const lines = [
    hasUntrusted ? "如果没有 source.has_untrusted=true：低可信来源带来的风险会下降，但敏感资产或外传证据仍可能继续阻断。" : "当前没有低可信来源事实，判断主要依赖动作、资产、任务边界或安全事件。",
    hasSecret ? "如果没有 asset.touched_type=secret_file：密钥保护类不变量可能不命中，决策可能降为沙箱或审批。" : "当前没有 secret_file 资产事实，系统不会把它解释为密钥资产硬阻断。",
    hasContractViolation ? "如果 contract.match=match：任务边界不再贡献阻断理由，但 secret 外传、供应链或 CI 风险仍不能自动放行。" : "当前任务边界没有明确 violation，决策更依赖其他证据源。",
  ];
  return (
    <details className="judgment-panel counterfactual-panel">
      <summary>反事实解释：如果关键事实不存在会怎样</summary>
      <div>{lines.map((line) => <p key={line}>{line}</p>)}</div>
    </details>
  );
}
