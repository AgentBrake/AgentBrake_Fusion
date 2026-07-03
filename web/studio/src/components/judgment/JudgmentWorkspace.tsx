import { useState } from "react";
import type { JudgmentTraceViewModel } from "../../types";
import { AlgorithmTracePanel } from "./AlgorithmTracePanel";
import { CausalEvidenceGraph } from "./CausalEvidenceGraph";
import { CounterfactualPanel } from "./CounterfactualPanel";
import { ConstraintPanel } from "./ConstraintPanel";
import { ConstraintProductLatticeStepper } from "./ConstraintProductLatticeStepper";
import { EvidenceIntakePanel } from "./EvidenceIntakePanel";
import { FactMatrix } from "./FactMatrix";
import { InvariantGateView } from "./InvariantGateView";
import { JudgmentSummaryBar } from "./JudgmentSummaryBar";
import { PredicateMatrix } from "./PredicateMatrix";
import { RuleCandidatePruner } from "./RuleCandidatePruner";
import { WhyDecisionPanel } from "./WhyDecisionPanel";

export function JudgmentWorkspace({ judgment }: { judgment: JudgmentTraceViewModel }) {
  const [activeFactId, setActiveFactId] = useState("");
  const [activeRefs, setActiveRefs] = useState<string[]>([]);
  return (
    <div className="judgment-workspace">
      <JudgmentSummaryBar judgment={judgment} />
      <AlgorithmTracePanel judgment={judgment} />
      <div className="judgment-layout">
        <div className="judgment-column left">
          <EvidenceIntakePanel judgment={judgment} activeFactRefs={activeRefs} />
          <FactMatrix judgment={judgment} activeFactId={activeFactId} onSelectFact={(factId, refs) => { setActiveFactId(factId); setActiveRefs(refs); }} />
        </div>
        <div className="judgment-column right">
          <InvariantGateView judgment={judgment} />
          <RuleCandidatePruner judgment={judgment} />
          <PredicateMatrix judgment={judgment} />
          <ConstraintProductLatticeStepper judgment={judgment} />
          <ConstraintPanel judgment={judgment} />
          <WhyDecisionPanel judgment={judgment} />
          <CounterfactualPanel judgment={judgment} />
        </div>
      </div>
      <CausalEvidenceGraph judgment={judgment} activeFactId={activeFactId} />
    </div>
  );
}
