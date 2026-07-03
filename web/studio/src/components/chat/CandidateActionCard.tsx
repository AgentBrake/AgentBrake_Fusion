import { Ban, CheckCircle2, Clock3, ShieldAlert } from "lucide-react";
import { EMPTY_TOOL_NAME } from "../../api/liveTrace";
import type { CandidateToolCall } from "../../types";
import { argLabel, decisionLabel, toolActionLabel } from "../../utils/display";

export function CandidateActionCard({ call }: { call: CandidateToolCall | null }) {
  if (!call || call.toolName === EMPTY_TOOL_NAME || call.decision === "observing") {
    return (
      <article className="candidate-card observing" data-testid="candidate-toolcall-card">
        <div className="candidate-head">
          <span className="candidate-state"><Clock3 size={15} /> 等待候选工具动作</span>
        </div>
        <h3>暂无工具调用</h3>
        <p>OpenClaw 当前只返回自然语言内容。只有当它提出候选 tool call 时，AgentBrake-Fusion 才会展开具体裁决。</p>
        <div className="candidate-foot">
          <span>来源：实时 OpenClaw 对话</span>
          <b>状态：观察中</b>
        </div>
      </article>
    );
  }
  return (
    <article className={`candidate-card ${call.decision}`} data-testid="candidate-toolcall-card">
      <div className="candidate-head">
        <span className="candidate-state"><Clock3 size={15} /> 候选工具动作正在审查</span>
        <DecisionIcon decision={call.decision} />
      </div>
      <h3>{toolActionLabel(call.toolName)}</h3>
      <p>{call.preview}</p>
      <dl className="arg-grid">
        {Object.entries(call.args).map(([key, value]) => (
          <div key={key}>
            <dt>{argLabel(key)}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
      <div className="candidate-foot">
        <span>来源：{call.source}</span>
        <b>裁决：{decisionLabel(call.decision)}</b>
      </div>
    </article>
  );
}

function DecisionIcon({ decision }: { decision: CandidateToolCall["decision"] }) {
  if (decision === "allow") return <CheckCircle2 className="icon allow" size={22} />;
  if (decision === "require_confirmation") return <ShieldAlert className="icon confirm" size={22} />;
  return <Ban className="icon attack" size={22} />;
}
