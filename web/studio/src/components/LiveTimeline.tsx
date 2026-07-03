import type { StudioEvent } from "../types";
import { DecisionBadge, displayLabel } from "./DecisionBadge";
import { eventDetail, eventSummary } from "./displayText";

function decisionOf(event: StudioEvent): string {
  return String(event.payload.decision || event.payload.effective_decision || event.payload.semantic_action || event.type);
}

export function LiveTimeline({ events, criticalOnly, activeActionId, onInspectAction }: { events: StudioEvent[]; criticalOnly: boolean; activeActionId: string; onInspectAction: (actionId: string) => void }) {
  const visible = criticalOnly ? events.filter((event) => event.severity === "critical" || ["policy", "approval"].includes(event.phase)) : events;
  return (
    <div className="timeline">
      {visible.map((event) => {
        const actionId = String(event.payload.action_id || "");
        return (
          <button className={`event-card ${actionId && actionId === activeActionId ? "active" : ""}`} key={event.event_id} onClick={() => actionId && onInspectAction(actionId)}>
            <div>
              <div className="phase">{displayLabel(event.phase)}</div>
              <div className="muted">#{event.event_index}</div>
            </div>
            <div>
              <b>{eventSummary(event)}</b>
              <div className="muted">{eventDetail(event)}</div>
              <div className="tiny-meta">{displayLabel(event.type)} · {event.timestamp}</div>
            </div>
            <DecisionBadge label={decisionOf(event)} severity={event.severity} />
          </button>
        );
      })}
    </div>
  );
}
