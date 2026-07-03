import type { ApprovalEvent } from "../types";
import { DecisionBadge, displayLabel } from "../components/DecisionBadge";
import { actionLabel, shortId } from "../components/displayText";

function statusFor(request: ApprovalEvent, events: ApprovalEvent[]): "pending" | "granted" | "denied" {
  const payload = request.payload;
  const requestId = String(payload.approval_request_id || "");
  if (events.some((event) => event.event_type === "denial" && event.payload.approval_request_id === requestId)) return "denied";
  if (events.some((event) => event.event_type === "grant" && event.payload.action_id === payload.action_id && event.payload.approved_action_hash === payload.action_hash)) return "granted";
  return "pending";
}

function actionFromSummary(summary: string): string {
  const [semantic] = summary.split(":");
  return actionLabel(semantic);
}

function commandFromSummary(summary: string): string {
  const index = summary.indexOf(":");
  return index >= 0 ? summary.slice(index + 1).trim() : summary;
}

function sourceText(value: unknown): string {
  if (!Array.isArray(value) || !value.length) return "没有检测到外部来源影响";
  return value.map((item) => {
    const record = item as Record<string, unknown>;
    const trust = displayLabel(String(record.trust || "unknown"));
    const id = String(record.source_id || "来源");
    if (id.includes("attack_secret")) return `攻击 Issue（${trust}）`;
    if (id.includes("attack_ci")) return `可疑 PR 评论（${trust}）`;
    if (id.includes("attack_dependency")) return `可疑 Issue（${trust}）`;
    return `${shortId(id)}（${trust}）`;
  }).join("、");
}

function assetsText(value: unknown): string {
  if (!Array.isArray(value) || !value.length) return "未声明影响资产";
  return value.map((item) => String(item)).join("、");
}

function approvalExplanation(decision: string): string {
  if (decision === "block") return "系统建议拒绝。这个动作触碰了高危资产或明显越权，审批中心只保留人工确认入口。";
  if (decision === "sandbox_then_approval") return "系统建议先限制到沙箱，再由人确认是否允许这一次精确动作。";
  if (decision === "allow_in_sandbox") return "系统建议只在沙箱中执行，避免影响真实仓库和外部环境。";
  return "这个动作需要人工确认后才能继续。";
}

export function ApprovalCenter({ events, onGrant, onDeny }: { events: ApprovalEvent[]; onGrant: (approvalId: string, actionHash: string) => void; onDeny: (approvalId: string) => void }) {
  const requests = events.filter((event) => event.event_type === "request").reverse();
  if (!requests.length) return <div className="empty-state">暂无审批请求。只有当代理想执行高风险动作，且策略要求人工确认时，这里才会出现待处理卡片。</div>;
  return (
    <div className="approval-center">
      <div className="approval-explainer">
        <b>审批中心看什么？</b>
        <span>这里不是普通确认弹窗，而是“是否允许这一次精确危险动作”。批准会绑定动作 hash，避免代理把命令偷偷换成别的内容。</span>
      </div>
      <div className="approval-list">
      {requests.map((event) => {
        const payload = event.payload;
        const approvalId = String(payload.approval_request_id || "");
        const actionHash = String(payload.action_hash || "");
        const status = statusFor(event, events);
        const summary = String(payload.human_readable_summary || approvalId);
        const action = actionFromSummary(summary);
        const command = commandFromSummary(summary);
        const recommended = String(payload.recommended_decision || "request");
        return (
          <div className="approval-card" key={approvalId}>
            <div className="approval-card-head">
              <div>
                <span className="policy-eyebrow">待确认动作</span>
                <h3>{action}</h3>
                <p>{approvalExplanation(recommended)}</p>
              </div>
              <DecisionBadge label={status} severity={status === "pending" ? "warning" : status === "granted" ? "normal" : "critical"} />
            </div>

            <div className="approval-summary-grid">
              <section>
                <b>代理想执行</b>
                <code>{command}</code>
              </section>
              <section>
                <b>可能影响</b>
                <span>{assetsText(payload.affected_assets)}</span>
              </section>
              <section>
                <b>来源影响</b>
                <span>{sourceText(payload.source_influence)}</span>
              </section>
              <section>
                <b>系统建议</b>
                <DecisionBadge label={recommended} severity={recommended === "block" ? "critical" : "warning"} />
              </section>
            </div>

            <div className="approval-binding">
              <b>为什么说“只批准这一次”？</b>
              <span>审批绑定当前动作内容、任务和计划摘要。只要命令、目标资产或计划变化，hash 就会变，旧批准不能复用。</span>
              <div className="binding-grid">
                <span>审批编号</span><code>{shortId(approvalId)}</code>
                <span>动作指纹</span><code>{shortId(actionHash)}</code>
                <span>任务编号</span><code>{shortId(String(payload.task_id || "无"))}</code>
                <span>计划指纹</span><code>{shortId(String(payload.plan_hash || "无"))}</code>
              </div>
            </div>

            {status === "pending" ? (
              <div className="approval-actions">
                <button className="primary" onClick={() => {
                  const ok = window.confirm(`确认只允许这一次动作在沙箱中执行吗？\n\n${action}\n${command}\n\n动作指纹=${actionHash}`);
                  if (ok) onGrant(approvalId, actionHash);
                }}>仅批准沙箱执行</button>
                <button className="danger" onClick={() => {
                  const ok = window.confirm(`确认拒绝这次高风险动作吗？\n\n${action}\n${command}`);
                  if (ok) onDeny(approvalId);
                }}>拒绝</button>
              </div>
            ) : <div className="muted">该审批请求已结束，状态为 {displayLabel(status)}。</div>}
          </div>
        );
      })}
      </div>
    </div>
  );
}
