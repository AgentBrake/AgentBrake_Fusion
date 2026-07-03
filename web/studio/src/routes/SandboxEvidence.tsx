import type { StudioEvent } from "../types";
import { DecisionBadge, displayLabel } from "../components/DecisionBadge";
import { actionLabel } from "../components/displayText";

function listText(value: unknown[], empty = "无"): string {
  if (!value.length) return empty;
  return value.map((item) => String(item)).join("、");
}

function riskText(value: unknown[]): string {
  if (!value.length) return "没有观察到额外风险";
  return value.map((item) => displayLabel(String(item))).join("、");
}

function sandboxProfile(value: unknown): string {
  const raw = String(value || "");
  if (raw === "edit_overlay") return "隔离写入层：可观察改动，不直接污染真实仓库";
  if (raw === "readonly") return "只读沙箱：禁止写入";
  if (raw === "network_disabled") return "禁用网络沙箱";
  return raw || "未声明沙箱配置";
}

function verdict(decision: string): string {
  if (decision === "block") return "沙箱已经看到高危行为，建议阻断。";
  if (decision === "allow_in_sandbox") return "可以在沙箱里执行，但不要直接影响真实环境。";
  if (decision === "sandbox_then_approval") return "需要先看沙箱结果，再由人决定是否继续。";
  return "沙箱结果已记录，可供策略决策引用。";
}

export function SandboxEvidence({ events }: { events: StudioEvent[] }) {
  const traces = events.filter((event) => event.type === "exec_trace");
  if (!traces.length) return <div className="empty-state">当前运行暂无沙箱预检证据。只有当 AgentBrake-Fusion 需要先隔离观察工具动作时，这里才会出现文件、网络和进程证据。</div>;
  return (
    <div className="sandbox-evidence-view">
      <div className="sandbox-explainer">
        <b>沙箱预检看什么？</b>
        <span>这里展示危险动作在隔离环境里的“预演结果”：读了什么文件、想不想联网、会不会写入，以及这些现象如何支持最终决策。</span>
      </div>
      <div className="evidence-grid">
      {traces.map((event) => {
        const payload = event.payload;
        const networkAttempts = Array.isArray(payload.network_attempts) ? payload.network_attempts : [];
        const filesRead = Array.isArray(payload.files_read) ? payload.files_read : [];
        const filesWritten = Array.isArray(payload.files_written) ? payload.files_written : [];
        const processTree = Array.isArray(payload.process_tree) ? payload.process_tree : [];
        const diffSummary = Array.isArray(payload.diff_summary) ? payload.diff_summary : [];
        const decision = String(payload.recommended_decision || "sandbox");
        const risks = Array.isArray(payload.risk_observed) ? payload.risk_observed : [];
        return (
          <div className="sandbox-card" key={event.event_id}>
            <div className="sandbox-card-head">
              <div>
                <span className="policy-eyebrow">沙箱预检结论</span>
                <h3>{verdict(decision)}</h3>
                <p>{actionLabel(payload.semantic_action || payload.action_id)}：沙箱记录了这个动作在隔离环境中的行为。</p>
              </div>
              <DecisionBadge label={decision} severity={event.severity} />
            </div>

            <div className="sandbox-command">
              <b>代理想执行的命令</b>
              <code>{String(payload.command || event.summary)}</code>
            </div>

            <div className="sandbox-grid">
              <div><b>隔离方式</b><span>{sandboxProfile(payload.sandbox_profile)}</span></div>
              <div><b>观测风险</b><span>{riskText(risks)}</span></div>
              <div><b>网络意图</b><span>{networkAttempts.length ? `${networkAttempts.length} 次尝试：${listText(networkAttempts)}` : "没有观察到联网尝试"}</span></div>
              <div><b>文件访问</b><span>{filesRead.length} 个读取 / {filesWritten.length} 个写入</span></div>
            </div>

            <div className="sandbox-evidence-grid">
              <section>
                <h4>读取的文件</h4>
                <p>{listText(filesRead, "没有读取文件")}</p>
              </section>
              <section>
                <h4>写入的文件</h4>
                <p>{listText(filesWritten, "没有写入文件")}</p>
              </section>
              <section>
                <h4>进程链</h4>
                <p>{listText(processTree, "没有进程链记录")}</p>
              </section>
              <section>
                <h4>文件差异</h4>
                <p>{diffSummary.length ? listText(diffSummary) : "没有产生文件差异"}</p>
              </section>
            </div>

            <details className="raw-graph">
              <summary>查看脱敏原始记录</summary>
              <pre>{JSON.stringify(payload, null, 2)}</pre>
            </details>
          </div>
        );
      })}
      </div>
    </div>
  );
}
