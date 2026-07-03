import type { RunSummary, StudioEvent } from "../types";
import { LiveTimeline } from "../components/LiveTimeline";
import { displayLabel } from "../components/DecisionBadge";

export function RunCockpit({ run, events, criticalOnly, activeActionId, setCriticalOnly, onInspectAction }: { run: RunSummary | null; events: StudioEvent[]; criticalOnly: boolean; activeActionId: string; setCriticalOnly: (value: boolean) => void; onInspectAction: (actionId: string) => void }) {
  const metrics = [
    ["事件", run?.event_count || 0],
    ["动作", run?.action_count || 0],
    ["阻断", run?.blocked_count || 0],
    ["审批", run?.approval_count || 0],
    ["高危", run?.critical_count || 0],
    ["最新", displayLabel(run?.latest_decision || "observing")]
  ];
  return (
    <>
      <div className="metric-grid">{metrics.map(([label, value]) => <div className="metric" key={label}><span className="muted">{label}</span><b>{value}</b></div>)}</div>
      <div className="panel-head inline">
        <h3>实时时间线</h3>
        <label><input type="checkbox" checked={criticalOnly} onChange={(e) => setCriticalOnly(e.target.checked)} /> 只看高危</label>
      </div>
      <LiveTimeline events={events} criticalOnly={criticalOnly} activeActionId={activeActionId} onInspectAction={onInspectAction} />
    </>
  );
}
