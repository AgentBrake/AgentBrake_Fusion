import { useMemo, useState } from "react";
import type { PolicyCausalGraph, PolicyEvalTrace, PolicyPredicateRow, Severity } from "../types";
import { DecisionBadge, displayLabel } from "./DecisionBadge";
import { actionLabel, reasonLabels, shortId } from "./displayText";

type RuleNode = Record<string, unknown>;

interface PolicyTraceDebuggerProps {
  trace?: PolicyEvalTrace | null;
  predicates?: PolicyPredicateRow[];
  factSet?: Record<string, unknown>;
  decision?: Record<string, unknown>;
  action?: Record<string, unknown>;
  title?: string;
  compact?: boolean;
}

export function traceFromEvents(events: Array<{ type: string; payload: Record<string, unknown> }>, actionId?: string): PolicyEvalTrace | null {
  const traceEvent = [...events].reverse().find((event) => {
    if (event.type !== "policy_eval_trace") return false;
    return !actionId || event.payload.action_id === actionId;
  });
  return (traceEvent?.payload || null) as PolicyEvalTrace | null;
}

export function factSetFromEvents(events: Array<{ type: string; payload: Record<string, unknown> }>, actionId?: string, traceId?: string): Record<string, unknown> {
  const factEvent = [...events].reverse().find((event) => {
    if (event.type !== "policy_fact_set") return false;
    if (traceId) return event.payload.policy_eval_trace_id === traceId;
    if (actionId) return event.payload.action_id === actionId;
    return true;
  });
  return factEvent?.payload || {};
}

export function predicatesFromTrace(trace?: PolicyEvalTrace | null): PolicyPredicateRow[] {
  if (!trace) return [];
  const rules = new Map<string, RuleNode>();
  for (const rule of trace.rule_nodes || []) {
    const ruleId = String(rule.rule_id || rule.id || "");
    if (ruleId) rules.set(ruleId, rule);
  }
  return (trace.predicate_nodes || []).map((predicate) => {
    const ruleId = String(predicate.rule_id || "");
    const rule = rules.get(ruleId) || {};
    const path = predicate.path || [predicate.namespace, predicate.key].filter(Boolean).join(".");
    const matchedFactIds = Array.isArray(predicate.matched_fact_ids)
      ? predicate.matched_fact_ids.map(String)
      : predicate.fact_id
        ? [String(predicate.fact_id)]
        : [];
    return {
      rule_id: ruleId,
      rule_decision: String(rule.decision || ""),
      rule_invariant: Boolean(rule.invariant),
      predicate_id: String(predicate.predicate_id || predicate.id || predicate.fact_id || ""),
      path: String(path || "证据事实"),
      operator: String(predicate.operator || "事实命中"),
      expected: predicate.expected,
      actual: predicate.actual ?? predicate.value,
      matched: Boolean(predicate.matched),
      matched_fact_ids: matchedFactIds,
      evidence_refs: Array.isArray(predicate.evidence_refs) ? predicate.evidence_refs.map(String) : []
    };
  });
}

export function PolicyTraceDebugger({ trace, predicates, factSet, decision, action, title = "MSJ Engine 交互式调试器", compact = false }: PolicyTraceDebuggerProps) {
  const rows = useMemo(() => predicates?.length ? predicates : predicatesFromTrace(trace), [predicates, trace]);
  const ruleNodes = Array.isArray(trace?.rule_nodes) ? trace.rule_nodes : [];
  const ruleIds = useMemo(() => {
    const ids = new Set<string>();
    for (const rule of ruleNodes) ids.add(String(rule.rule_id || rule.id || ""));
    for (const row of rows) if (row.rule_id) ids.add(row.rule_id);
    return [...ids].filter(Boolean);
  }, [rows, ruleNodes]);
  const [selectedRule, setSelectedRule] = useState<string>(ruleIds[0] || "all");
  const activeRule = ruleIds.includes(selectedRule) ? selectedRule : "all";
  const visibleRows = activeRule === "all" ? rows : rows.filter((row) => row.rule_id === activeRule);
  const graph: PolicyCausalGraph = trace || {};
  const latticePath = Array.isArray(trace?.constraint_product_lattice_path)
    ? trace.constraint_product_lattice_path
    : Array.isArray(trace?.decision_lattice_path)
      ? trace.decision_lattice_path
      : [];
  const finalDecision = String(trace?.final_decision || decision?.decision || decision?.effective_decision || "unknown");
  const severity: Severity = finalDecision === "block" || finalDecision === "quarantine" ? "critical" : finalDecision.includes("sandbox") ? "warning" : "normal";

  if (!trace && !decision) {
    return <div className="policy-debug-empty">这个动作还没有 MSJ Engine 评估轨迹。运行真实请求或攻击演示后，这里会显示规则、谓词和证据链。</div>;
  }

  return (
    <section className={`policy-trace-debugger ${compact ? "compact" : ""}`}>
      <div className="policy-trace-head">
        <div>
          <span className="policy-eyebrow">{title}</span>
          <h3>{actionLabel(action?.semantic_action || trace?.action_id || decision?.action_id)} 的判定过程</h3>
          <p>从“事实提取”到“规则谓词命中”，再到“约束乘积格合并”，逐步解释为什么得到这个安全结论。</p>
        </div>
        <DecisionBadge label={finalDecision} severity={severity} />
      </div>

      <div className="policy-debug-metrics">
        <Metric label="事实数量" value={factSet?.fact_count ?? graph.fact_nodes?.length ?? 0} />
        <Metric label="命中规则" value={ruleIds.length} />
        <Metric label="谓词检查" value={rows.length} />
        <Metric label="决策步骤" value={latticePath.length} />
      </div>

      {decision?.reason_codes ? (
        <div className="reason-list">
          {reasonLabels(decision.reason_codes).map((reason) => <span key={reason}>{reason}</span>)}
        </div>
      ) : null}

      {ruleIds.length ? (
        <div className="rule-filter" aria-label="筛选规则">
          <button className={activeRule === "all" ? "active" : ""} onClick={() => setSelectedRule("all")}>全部规则</button>
          {ruleIds.map((ruleId) => <button className={activeRule === ruleId ? "active" : ""} key={ruleId} onClick={() => setSelectedRule(ruleId)}>{readableRule(ruleId)}</button>)}
        </div>
      ) : null}

      <div className="policy-rule-debug-list">
        {groupByRule(visibleRows, ruleNodes).map((group) => (
          <article className="policy-rule-debug-card" key={group.ruleId}>
            <div className="policy-rule-debug-head">
              <div>
                <b>{readableRule(group.ruleId)}</b>
                <span>{group.invariant ? "不可降级安全不变量" : "策略包规则"} · {group.rows.filter((row) => row.matched).length}/{group.rows.length} 个条件通过</span>
              </div>
              <DecisionBadge label={group.decision || finalDecision} severity={severity} />
            </div>
            <div className="predicate-table">
              <div className="predicate-row predicate-head"><span>检查项</span><span>条件</span><span>实际证据</span><span>结论</span></div>
              {group.rows.map((row) => (
                <div className="predicate-row" key={`${group.ruleId}-${row.predicate_id}-${row.path}`}>
                  <span>{readablePath(row.path)}</span>
                  <span>{displayLabel(String(row.operator || "检查"))}{row.expected !== undefined ? `：${formatValue(row.expected)}` : ""}</span>
                  <span>{formatValue(row.actual)}{row.evidence_refs?.length ? <small>证据：{row.evidence_refs.map(shortId).join("、")}</small> : null}</span>
                  <span className={row.matched ? "predicate-ok" : "predicate-miss"}>{row.matched ? "命中" : "未命中"}</span>
                </div>
              ))}
            </div>
          </article>
        ))}
      </div>

      {latticePath.length ? (
        <div className="lattice-path">
          <b>约束乘积格合并路径</b>
          <div>
            {latticePath.map((step, index) => (
              <span key={`${step.via}-${index}`}>
                {displayLabel(String(step.from || "开始"))} → {displayLabel(String(step.to || "决策"))}
                <small>{readableRule(String(step.via || ""))}</small>
              </span>
            ))}
          </div>
        </div>
      ) : null}

      <details className="raw-graph">
        <summary>查看因果图节点与边</summary>
        <div className="causal-summary">
          <span>事实节点：{graph.fact_nodes?.length || 0}</span>
          <span>谓词节点：{graph.predicate_nodes?.length || 0}</span>
          <span>规则节点：{graph.rule_nodes?.length || 0}</span>
          <span>因果边：{graph.edges?.length || 0}</span>
        </div>
        <pre>{JSON.stringify({ graph, skipped_rules_summary: trace?.skipped_rules_summary, fact_hash: trace?.fact_hash }, null, 2)}</pre>
      </details>
    </section>
  );
}

function Metric({ label, value }: { label: string; value: unknown }) {
  return <div><span>{label}</span><b>{String(value ?? 0)}</b></div>;
}

function groupByRule(rows: PolicyPredicateRow[], ruleNodes: RuleNode[]) {
  const meta = new Map<string, RuleNode>();
  for (const rule of ruleNodes) {
    const ruleId = String(rule.rule_id || rule.id || "");
    if (ruleId) meta.set(ruleId, rule);
  }
  const groups = new Map<string, { ruleId: string; decision: string; invariant: boolean; rows: PolicyPredicateRow[] }>();
  for (const row of rows) {
    const ruleId = row.rule_id || "unknown_rule";
    const rule = meta.get(ruleId) || {};
    const group = groups.get(ruleId) || {
      ruleId,
      decision: String(row.rule_decision || rule.decision || ""),
      invariant: Boolean(row.rule_invariant || rule.invariant),
      rows: []
    };
    group.rows.push(row);
    groups.set(ruleId, group);
  }
  for (const rule of ruleNodes) {
    const ruleId = String(rule.rule_id || rule.id || "");
    if (ruleId && !groups.has(ruleId)) {
      groups.set(ruleId, { ruleId, decision: String(rule.decision || ""), invariant: Boolean(rule.invariant), rows: [] });
    }
  }
  return [...groups.values()];
}

function readableRule(ruleId: string): string {
  if (!ruleId) return "策略规则";
  if (ruleId.includes("SECRET")) return `${ruleId} · 密钥保护`;
  if (ruleId.includes("EGRESS") || ruleId.includes("NET")) return `${ruleId} · 网络外传`;
  if (ruleId.includes("CI")) return `${ruleId} · CI 发布保护`;
  if (ruleId.includes("REGISTRY") || ruleId.includes("PACKAGE")) return `${ruleId} · 依赖来源`;
  if (ruleId.includes("SANDBOX")) return `${ruleId} · 沙箱约束`;
  return ruleId.replaceAll("_", " ");
}

function readablePath(path?: string): string {
  const raw = String(path || "证据事实");
  const map: Record<string, string> = {
    "action.semantic_action": "动作类型",
    "action.risk": "动作风险",
    "source.trust_floor": "来源可信度",
    "asset.touched_type": "触碰资产类型",
    "asset.touched_path": "触碰文件路径",
    "contract.match": "是否符合任务边界",
    "contract.forbidden_file_touch": "是否触碰禁止文件",
    "secret.event": "密钥事件",
    "package.source": "依赖来源",
    "mcp.capability": "MCP 能力",
    "sandbox.observation": "沙箱观察"
  };
  return map[raw] || displayLabel(raw);
}

function formatValue(value: unknown): string {
  if (value === undefined || value === null || value === "") return "无";
  if (Array.isArray(value)) return value.map((item) => formatValue(item)).join("、");
  if (typeof value === "object") return JSON.stringify(value);
  return displayLabel(String(value));
}
