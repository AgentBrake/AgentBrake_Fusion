import type { JudgmentTraceViewModel, StudioEvent } from "../types";
import { JudgmentWorkspace } from "../components/judgment/JudgmentWorkspace";
import { actionLabel } from "../components/displayText";

export function PolicyJudgment({ judgment, events, onInspectAction }: { judgment: JudgmentTraceViewModel | null; events: StudioEvent[]; onInspectAction: (actionId: string) => void }) {
  const actionEvents = events.filter((event) => event.type === "action_parsed");
  if (!judgment) {
    return (
      <div className="judgment-empty">
        <h3>请选择一个动作查看综合判断过程</h3>
        <p>Studio 会展示 MSJ Engine 链路：Evidence → Facts → Invariants → RuleIndex → Predicates → Constraint Product Lattice → Why。</p>
        <div className="judgment-action-list">
          {actionEvents.map((event) => (
            <button key={event.event_id} onClick={() => onInspectAction(String(event.payload.action_id || event.span_id))}>
              <b>{actionLabel(event.payload.semantic_action || event.payload.action_id)}</b>
              <span>{String(event.payload.raw_action || event.summary || "")}</span>
            </button>
          ))}
        </div>
      </div>
    );
  }
  return <JudgmentWorkspace judgment={judgment} />;
}
