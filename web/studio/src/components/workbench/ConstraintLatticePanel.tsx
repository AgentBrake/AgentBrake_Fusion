import type { LatticeDimension, LatticeOutput } from "../../types";
import { decisionLabel } from "../../utils/display";

const outputLabels: Record<keyof Omit<LatticeOutput, "decision" | "joinPath">, string> = {
  execution_env: "执行环境",
  network_scope: "网络范围",
  data_scope: "数据范围",
  human_gate: "人工门控",
  audit_scope: "审计范围"
};

export function ConstraintLatticePanel({ dimensions, output }: { dimensions: LatticeDimension[]; output: LatticeOutput }) {
  return (
    <section className="card workbench-panel" data-testid="lattice-panel">
      <div className="section-heading compact">
        <h2>Constraint Product Lattice</h2>
        <p>冲突证据不会被平均掉；每个维度先做 join，再映射到治理动作。</p>
      </div>
      <div className="dimension-row">
        {dimensions.map((dimension) => (
          <div className={`dimension-chip ${dimension.severity}`} key={dimension.id}>
            <span>{dimension.label}</span>
            <b>{dimension.value}</b>
          </div>
        ))}
      </div>
      <div className="join-path">
        {output.joinPath.map((step, index) => (
          <div key={step}><span>{index + 1}</span>{step}</div>
        ))}
      </div>
      <div className="lattice-output">
        <Output label={outputLabels.execution_env} value={output.execution_env} />
        <Output label={outputLabels.network_scope} value={output.network_scope} />
        <Output label={outputLabels.data_scope} value={output.data_scope} />
        <Output label={outputLabels.human_gate} value={output.human_gate} />
        <Output label={outputLabels.audit_scope} value={output.audit_scope} />
      </div>
      <div className={`lattice-decision ${output.decision}`}>{decisionLabel(output.decision)}</div>
    </section>
  );
}

function Output({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span>{label}</span>
      <b>{value}</b>
    </div>
  );
}
