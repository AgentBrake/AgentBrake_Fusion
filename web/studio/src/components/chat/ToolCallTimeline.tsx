import { Circle, CircleCheck, CircleDot, Shield } from "lucide-react";
import type { ToolTimelineItem } from "../../types";
import { decisionLabel } from "../../utils/display";

export function ToolCallTimeline({ items }: { items: ToolTimelineItem[] }) {
  return (
    <section className="card timeline-panel" data-testid="toolcall-timeline">
      <div className="section-heading compact">
        <h2>工具调用时间线</h2>
        <p>所有工具调用先进入候选审查，不直接执行。</p>
      </div>
      <div className="tool-timeline">
        {items.map((item) => (
          <div className={`tool-step ${item.state}`} key={item.id}>
            {icon(item.state)}
            <div>
              <b>{item.title}</b>
              <span>{new Date(item.time).toLocaleTimeString()}</span>
            </div>
            {item.decision ? <em>{decisionLabel(item.decision)}</em> : null}
          </div>
        ))}
      </div>
    </section>
  );
}

function icon(state: ToolTimelineItem["state"]) {
  if (state === "decided") return <CircleCheck size={18} />;
  if (state === "reviewing") return <Shield size={18} />;
  if (state === "candidate") return <CircleDot size={18} />;
  return <Circle size={18} />;
}
