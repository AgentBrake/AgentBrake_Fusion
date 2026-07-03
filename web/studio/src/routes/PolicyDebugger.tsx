import { useMemo, useState } from "react";
import type { PolicyEvalTrace, StudioEvent } from "../types";
import { DecisionBadge, displayLabel } from "../components/DecisionBadge";
import { actionLabel, reasonLabels } from "../components/displayText";
import { factSetFromEvents, PolicyTraceDebugger, predicatesFromTrace, traceFromEvents } from "../components/PolicyTraceDebugger";

function decisionEvents(events: StudioEvent[]): StudioEvent[] {
  return events.filter((event) => event.type === "policy_decision");
}

function explainDecision(decision: string): string {
  if (decision === "block") return "这个动作不能执行，因为它越过了用户授权边界或触碰了高危资产。";
  if (decision === "allow_in_sandbox") return "这个动作可以执行，但必须限制在沙箱中，避免影响真实仓库或外部环境。";
  if (decision === "sandbox_then_approval") return "这个动作需要先沙箱预检，再交给人确认。";
  if (decision === "allow") return "这个动作符合任务边界，可以继续执行。";
  return "策略引擎根据动作、来源和证据给出了当前结论。";
}

function traceForDecision(events: StudioEvent[], decision: StudioEvent): PolicyEvalTrace | null {
  const traceId = Array.isArray(decision.payload.evidence_refs)
    ? decision.payload.evidence_refs.map(String).find((ref) => ref.startsWith("peval_"))
    : "";
  const trace = events.find((event) => {
    if (event.type !== "policy_eval_trace") return false;
    if (traceId && event.payload.policy_eval_trace_id === traceId) return true;
    return event.payload.action_id === decision.payload.action_id;
  });
  return (trace?.payload || traceFromEvents(events, String(decision.payload.action_id || ""))) as PolicyEvalTrace | null;
}

export function PolicyDebugger({ events }: { events: StudioEvent[] }) {
  const decisions = decisionEvents(events);
  const [selectedAction, setSelectedAction] = useState<string>("all");
  const visible = selectedAction === "all" ? decisions : decisions.filter((event) => event.payload.action_id === selectedAction);
  const stats = useMemo(() => {
    const blocked = decisions.filter((event) => event.payload.decision === "block").length;
    const sandboxed = decisions.filter((event) => String(event.payload.decision || "").includes("sandbox")).length;
    const traces = events.filter((event) => event.type === "policy_eval_trace").length;
    const predicates = events.filter((event) => event.type === "policy_eval_trace").reduce((sum, event) => {
      const nodes = Array.isArray(event.payload.predicate_nodes) ? event.payload.predicate_nodes.length : 0;
      return sum + nodes;
    }, 0);
    return { blocked, sandboxed, traces, predicates };
  }, [decisions, events]);

  if (!decisions.length) return <div className="empty-state">当前运行还没有策略决策。运行一个场景后，这里会解释每个动作为什么被放行、沙箱、审批或阻断。</div>;

  return (
    <div className="policy-debugger">
      <div className="policy-explainer">
        <b>完整 Policy Debugger 看什么？</b>
        <span>上半部分是人能读懂的结论，下半部分把 MSJ Engine 的事实、规则谓词、约束乘积格路径和因果图串起来，方便定位误报、漏报或规则缺口。</span>
      </div>

      <div className="policy-debug-metrics">
        <div><span>策略决策</span><b>{decisions.length}</b></div>
        <div><span>阻断动作</span><b>{stats.blocked}</b></div>
        <div><span>沙箱相关</span><b>{stats.sandboxed}</b></div>
        <div><span>谓词检查</span><b>{stats.predicates}</b></div>
      </div>

      <div className="rule-filter" aria-label="筛选动作">
        <button className={selectedAction === "all" ? "active" : ""} onClick={() => setSelectedAction("all")}>全部动作</button>
        {decisions.map((event) => {
          const actionId = String(event.payload.action_id || event.event_id);
          return <button className={selectedAction === actionId ? "active" : ""} key={event.event_id} onClick={() => setSelectedAction(actionId)}>{actionLabel(event.payload.semantic_action || actionId)}</button>;
        })}
      </div>

      {visible.map((event) => {
        const payload = event.payload;
        const decision = String(payload.decision || "decision");
        const action = actionLabel(payload.semantic_action || payload.action_id);
        const reasons = reasonLabels(payload.reason_codes);
        const trace = traceForDecision(events, event);
        const factSet = factSetFromEvents(events, String(payload.action_id || ""), trace?.policy_eval_trace_id);
        return (
          <div className={`policy-card ${event.severity}`} key={event.event_id}>
            <div className="policy-card-head">
              <div>
                <span className="policy-eyebrow">策略结论</span>
                <h3>{displayLabel(decision)}：{action}</h3>
                <p>{explainDecision(decision)}</p>
              </div>
              <DecisionBadge label={decision} severity={event.severity} />
            </div>

            <div className="policy-summary-grid">
              <section>
                <b>1. 代理想做什么</b>
                <span>{action}</span>
                <small>风险分：{String(payload.risk_score || "未知")}</small>
              </section>
              <section>
                <b>2. 为什么触发策略</b>
                <div className="reason-list">
                  {(reasons.length ? reasons : ["策略规则已命中"]).map((reason) => <span key={reason}>{reason}</span>)}
                </div>
              </section>
              <section>
                <b>3. MSJ Engine 证据</b>
                <span>{trace ? `${trace.fact_nodes?.length || 0} 个事实、${trace.rule_nodes?.length || 0} 条规则` : "等待评估轨迹"}</span>
                <small>{trace?.policy_eval_trace_id || "未找到 policy_eval_trace"}</small>
              </section>
            </div>

            <PolicyTraceDebugger
              trace={trace}
              predicates={predicatesFromTrace(trace)}
              factSet={factSet}
              decision={payload}
              action={payload}
              title="运行级 Policy Debugger"
            />
          </div>
        );
      })}
    </div>
  );
}
