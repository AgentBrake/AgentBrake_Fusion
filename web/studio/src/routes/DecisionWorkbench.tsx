import { CandidateActionCard } from "../components/chat/CandidateActionCard";
import { ActionGraphPanel } from "../components/workbench/ActionGraphPanel";
import { BrakeTracePanel } from "../components/workbench/BrakeTracePanel";
import { ConstraintLatticePanel } from "../components/workbench/ConstraintLatticePanel";
import { ExternalSourceCard } from "../components/workbench/ExternalSourceCard";
import { MSJFactPanel } from "../components/workbench/MSJFactPanel";
import { ThreeStageStepper } from "../components/workbench/ThreeStageStepper";
import type { DecisionRun } from "../types";
import { decisionLabel } from "../utils/display";

export function DecisionWorkbench({ run }: { run: DecisionRun }) {
  return (
    <div className="page-grid workbench-page">
      <div className="workbench-summary card">
        <div>
          <span className="eyebrow">裁决工作台</span>
          <h1>执行前安全裁决工作台</h1>
          <p>{run.userTask}</p>
        </div>
        <div className={`decision-stamp ${run.finalDecision}`}>{decisionLabel(run.finalDecision)}</div>
      </div>
      <div className="context-strip">
        <ExternalSourceCard run={run} />
        <div className="low-trust-context-card"><b>低可信上下文原文</b><span>{run.lowTrustContext}</span></div>
        <CandidateActionCard call={run.candidateToolCall} />
      </div>
      <ThreeStageStepper decision={run.finalDecision} />
      <div className="triple-screen">
        <ActionGraphPanel nodes={run.actionGraph.nodes} edges={run.actionGraph.edges} />
        <MSJFactPanel facts={run.msjFacts} />
        <ConstraintLatticePanel dimensions={run.lattice.dimensions} output={run.lattice.output} />
      </div>
      <BrakeTracePanel trace={run.brakeTrace} />
    </div>
  );
}
