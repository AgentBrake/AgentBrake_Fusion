import type { ActionDetail } from "../types";
import { DecisionBadge, displayLabel } from "./DecisionBadge";
import { actionLabel, reasonLabels, shortId } from "./displayText";
import { factSetFromEvents, PolicyTraceDebugger, predicatesFromTrace, traceFromEvents } from "./PolicyTraceDebugger";

function sourcesText(sources: Array<Record<string, unknown>>): string {
  if (!sources.length) return "没有外部来源影响";
  return sources.map((source) => {
    const id = String(source.source_id || "来源");
    const trust = displayLabel(String(source.trust_level || source.trust || "unknown"));
    return `${shortId(id)}（${trust}）`;
  }).join("、");
}

function ruleNames(decision: Record<string, unknown>): string[] {
  const rules = Array.isArray(decision.matched_rules) ? decision.matched_rules as Array<Record<string, unknown>> : [];
  return rules.map((rule) => {
    const id = String(rule.rule_id || rule.name || "");
    if (id.includes("SECRET")) return "密钥保护规则";
    if (id.includes("SANDBOX")) return "沙箱约束规则";
    if (id.includes("PACKAGE")) return "依赖安全规则";
    if (id.includes("CI")) return "发布流程保护规则";
    return String(rule.name || rule.rule_id || "策略规则");
  });
}

function listValue(value: unknown): string[] {
  return Array.isArray(value) ? value.map((item) => String(item)).filter(Boolean) : [];
}

function graphNodes(graph?: Record<string, unknown>): Array<Record<string, unknown>> {
  return Array.isArray(graph?.nodes) ? graph.nodes as Array<Record<string, unknown>> : [];
}

function graphEdges(graph?: Record<string, unknown>): Array<Record<string, unknown>> {
  return Array.isArray(graph?.edges) ? graph.edges as Array<Record<string, unknown>> : [];
}

function relationLabel(relation: unknown): string {
  const raw = String(relation || "sequence");
  const labels: Record<string, string> = {
    pipe: "管道传递",
    sequence: "顺序执行",
    redirect: "重定向写入",
    dataflow: "数据流",
    controlflow: "条件控制",
    memoryflow: "记忆影响",
  };
  return labels[raw] || raw;
}

function nodeTitle(node: Record<string, unknown>, index: number): string {
  return actionLabel(node.semantic_action || node.action || `step-${index + 1}`);
}

function nodeTarget(node: Record<string, unknown>): string {
  const target = String(node.target || "");
  const assets = listValue(node.affected_assets);
  return target || assets.join("、") || "未识别具体目标";
}

function riskText(action: Record<string, unknown>, graph?: Record<string, unknown>): string {
  const nodes = graphNodes(graph);
  const sideEffects = nodes.filter((node) => node.side_effect).length;
  const edges = graphEdges(graph);
  if (nodes.length > 1 && edges.some((edge) => String(edge.relation) === "pipe")) return "这是复合命令，存在管道或数据传递，需要按整体风险判断。";
  if (sideEffects > 0) return `动作图中有 ${sideEffects} 个步骤会改变环境或访问外部资源。`;
  if (String(action.risk || "") === "critical") return "该动作被归为高危类型，即使单步执行也不能直接放行。";
  return "动作结构较简单，主要根据来源、资产和任务边界继续判断。";
}

function stateFlag(value: unknown): { label: string; className: string } {
  return value ? { label: "已出现", className: "active" } : { label: "未出现", className: "" };
}

function latestDecisionText(state?: Record<string, unknown>): string {
  const decisions = listValue(state?.last_decisions);
  return decisions.length ? decisions.slice(-4).map(displayLabel).join(" → ") : "暂无历史决策";
}

function ActionGraphView({ action, graph }: { action: Record<string, unknown>; graph?: Record<string, unknown> }) {
  const nodes = graphNodes(graph);
  const edges = graphEdges(graph);
  return (
    <section className="product-view action-graph-view">
      <div className="product-view-head">
        <div>
          <span className="policy-eyebrow">ActionGraph View</span>
          <h3>AgentBrake-Fusion 怎样拆解这次工具动作</h3>
          <p>{riskText(action, graph)}</p>
        </div>
        <div className="mini-metrics">
          <div><b>{nodes.length || 1}</b><span>步骤</span></div>
          <div><b>{edges.length}</b><span>关系</span></div>
        </div>
      </div>
      {nodes.length ? (
        <div className="action-graph-steps">
          {nodes.map((node, index) => (
            <div className="action-step" key={String(node.node_id || index)}>
              <div className="step-index">{index + 1}</div>
              <div>
                <b>{nodeTitle(node, index)}</b>
                <span>{nodeTarget(node)}</span>
                <small>{node.side_effect ? "会产生副作用" : "只读或观察"} · 置信度 {String(node.confidence ?? action.parser_confidence ?? "未知")}</small>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="action-graph-steps">
          <div className="action-step">
            <div className="step-index">1</div>
            <div><b>{actionLabel(action.semantic_action || "动作")}</b><span>{String(action.raw_action || "没有原始命令")}</span><small>旧数据自动按单步动作展示</small></div>
          </div>
        </div>
      )}
      {edges.length ? (
        <div className="edge-explainer">
          {edges.slice(0, 5).map((edge, index) => <span key={String(edge.edge_id || index)}>{relationLabel(edge.relation)}</span>)}
        </div>
      ) : <p className="muted compact-note">没有发现管道、重定向或跨步骤数据传递。</p>}
    </section>
  );
}

function SessionStateView({ state }: { state?: Record<string, unknown> }) {
  const secret = stateFlag(state?.secret_taint);
  const untrusted = stateFlag(state?.untrusted_source_seen);
  const packageRisk = stateFlag(state?.package_taint);
  const ciRisk = stateFlag(state?.ci_taint);
  const secretAssets = listValue(state?.touched_secret_assets);
  const sinks = listValue(state?.prior_external_sinks);
  return (
    <section className="product-view session-state-view">
      <div className="product-view-head">
        <div>
          <span className="policy-eyebrow">Session State View</span>
          <h3>这次运行已经积累了哪些风险状态</h3>
          <p>这里展示的是脱敏历史摘要，用来发现“先读密钥、后外联”这类拆分式风险。</p>
        </div>
      </div>
      <div className="state-flag-grid">
        <div className={secret.className}><b>密钥污染</b><span>{secret.label}</span></div>
        <div className={untrusted.className}><b>低可信来源</b><span>{untrusted.label}</span></div>
        <div className={packageRisk.className}><b>依赖风险</b><span>{packageRisk.label}</span></div>
        <div className={ciRisk.className}><b>CI 风险</b><span>{ciRisk.label}</span></div>
      </div>
      <div className="state-history-grid">
        <div><b>触碰过的敏感资产</b><span>{secretAssets.length ? secretAssets.map(shortId).join("、") : "暂无"}</span></div>
        <div><b>历史外部目标</b><span>{sinks.length ? sinks.slice(-4).join("、") : "暂无"}</span></div>
        <div><b>最近决策</b><span>{latestDecisionText(state)}</span></div>
        <div><b>状态指纹</b><code>{state?.state_hash ? shortId(String(state.state_hash)) : "暂无"}</code></div>
      </div>
    </section>
  );
}

export function ActionDetailDrawer({ detail, onOpenJudgment }: { detail: ActionDetail | null; onOpenJudgment?: () => void }) {
  if (!detail) return (
    <div className="action-empty-state">
      <h3>还没有选中具体动作</h3>
      <p>在“本次运行”的时间线里点击“识别到动作”卡片，右侧会显示 AgentBrake-Fusion 如何理解这条工具调用。</p>
      <p>这里适合回答：代理原本想做什么、被识别成什么风险动作、为什么危险、证据在哪里。</p>
    </div>
  );
  const action = detail.action;
  const decision = detail.decision;
  const label = String(decision.decision || detail.runtime.effective_decision || "unknown");
  const semanticAction = actionLabel(action.semantic_action || detail.action_id);
  const reasons = reasonLabels(decision.reason_codes);
  const rules = ruleNames(decision);
  const trace = detail.policy_eval_trace || traceFromEvents(detail.evidence_events, detail.action_id);
  const factSet = detail.policy_fact_set || factSetFromEvents(detail.evidence_events, detail.action_id, trace?.policy_eval_trace_id);
  const predicates = detail.policy_predicates?.length ? detail.policy_predicates : predicatesFromTrace(trace);
  return (
    <div id="action-detail" className="action-detail-view">
      <section className="action-summary-card">
        <div>
          <span className="policy-eyebrow">AgentBrake-Fusion 识别到的动作</span>
          <h3>{semanticAction}</h3>
          <p>{label === "block" ? "这个动作被判定为不能执行。" : "这个动作需要受限执行或进一步确认。"}</p>
        </div>
        <DecisionBadge label={label} severity={label === "block" ? "critical" : "warning"} />
      </section>
      <section className="action-readable-grid">
        <div><b>代理原本想做什么</b><code>{String(action.raw_action || "没有原始命令")}</code></div>
        <div><b>为什么危险</b><span>{reasons.length ? reasons.join("、") : "没有额外原因码"}</span></div>
        <div><b>来源影响</b><span>{sourcesText(detail.sources)}</span></div>
        <div><b>命中规则</b><span>{rules.length ? rules.join("、") : "没有规则明细"}</span></div>
      </section>
      <ActionGraphView action={action} graph={detail.action_graph} />
      <SessionStateView state={detail.session_state} />
      <button className="primary judgment-open-button" onClick={onOpenJudgment}>打开综合判断过程</button>
      <PolicyTraceDebugger
        trace={trace}
        predicates={predicates}
        factSet={factSet}
        decision={decision}
        action={action}
        title="动作级 Policy Debugger"
        compact
      />
      <details className="raw-graph">
        <summary>查看取证细节</summary>
        <section className="detail-section"><h3>来源信任</h3><pre>{JSON.stringify(detail.sources, null, 2)}</pre></section>
        <section className="detail-section"><h3>规则轨迹</h3><pre>{JSON.stringify(decision.rule_trace || [], null, 2)}</pre></section>
        <section className="detail-section"><h3>证据引用</h3><pre>{JSON.stringify(decision.evidence_refs || [], null, 2)}</pre></section>
        <section className="detail-section"><h3>动作图</h3><pre>{JSON.stringify(detail.action_graph || {}, null, 2)}</pre></section>
        <section className="detail-section"><h3>会话历史摘要</h3><pre>{JSON.stringify(detail.session_state || {}, null, 2)}</pre></section>
        <section className="detail-section"><h3>结构化动作原文</h3><pre>{JSON.stringify(action, null, 2)}</pre></section>
      </details>
    </div>
  );
}
