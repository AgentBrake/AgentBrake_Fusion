import { Background, Controls, MarkerType, MiniMap, ReactFlow, type Edge, type Node } from "@xyflow/react";
import { useMemo, useState } from "react";
import type { JudgmentTraceViewModel } from "../../types";
import { displayLabel } from "../DecisionBadge";
import { factName, ruleTitle, valueText } from "./format";

const columns = { history: 0, graph: 1, fact: 2, retrieval: 3, predicate: 4, rule: 5, constraint: 6, lattice: 7, final: 8 };

export function CausalEvidenceGraph({ judgment, activeFactId }: { judgment: JudgmentTraceViewModel; activeFactId: string }) {
  const rawNodes = useMemo(() => causalNodes(judgment), [judgment]);
  const [selectedId, setSelectedId] = useState<string>("");
  const nodes = useMemo(() => toNodes(rawNodes, activeFactId, selectedId), [rawNodes, activeFactId, selectedId]);
  const edges = useMemo(() => toEdges(judgment, activeFactId), [judgment, activeFactId]);
  const selectedNode = rawNodes.find((node) => String(node.id) === selectedId) || rawNodes[0];
  return (
    <section className="judgment-panel causal-graph-panel">
      <div className="judgment-panel-head">
        <span className="policy-eyebrow">Causal Evidence Graph</span>
        <h3>证据如何一步步变成最终判断</h3>
        <p>点击任意节点，查看它在判断链里的作用；箭头表示“这条证据为什么能支撑下一步”。</p>
      </div>
      <div className="causal-legend">
        <span>历史状态</span><span>动作结构</span><span>事实证据</span><span>规则召回</span><span>条件检查</span><span>安全规则</span><span>约束合并</span><span>最终结论</span>
      </div>
      <div className="judgment-flow">
        {nodes.length ? (
          <ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.25} maxZoom={1.4} onNodeClick={(_, node) => setSelectedId(node.id)}>
            <MiniMap zoomable pannable />
            <Controls />
            <Background />
          </ReactFlow>
        ) : <div className="empty-state">暂无因果图节点。</div>}
      </div>
      <CausalInspector node={selectedNode} edges={judgment.causal_graph.edges || []} />
    </section>
  );
}

function causalNodes(judgment: JudgmentTraceViewModel): Array<Record<string, unknown>> {
  const graph = judgment.causal_graph || {};
  return [
    ...(graph.fact_nodes || []).map((node) => ({ ...node, kind: "fact" })),
    ...(graph.action_graph_nodes || []).map((node) => ({ ...node, kind: "graph" })),
    ...(graph.history_nodes || []).map((node) => ({ ...node, kind: "history" })),
    ...(graph.retrieval_nodes || []).map((node) => ({ ...node, kind: "retrieval" })),
    ...(graph.predicate_nodes || []).map((node) => ({ ...node, kind: "predicate" })),
    ...(graph.rule_nodes || []).map((node) => ({ ...node, kind: "rule" })),
    ...(graph.constraint_nodes || []).map((node) => ({ ...node, kind: "constraint" })),
    ...(graph.lattice_nodes || []).map((node) => ({ ...node, kind: "lattice" })),
    { id: "final_decision", kind: "final", label: judgment.final_decision },
  ];
}

function toNodes(all: Array<Record<string, unknown>>, activeFactId: string, selectedId: string): Node[] {
  const counters = new Map<string, number>();
  return all.filter((node) => node.id).slice(0, 140).map((node) => {
    const kind = String(node.kind);
    const count = counters.get(kind) || 0;
    counters.set(kind, count + 1);
    const label = nodeLabel(node);
    const explanation = nodeExplanation(node);
    const active = Boolean((activeFactId && node.id === activeFactId) || (selectedId && node.id === selectedId));
    return {
      id: String(node.id),
      position: { x: (columns[kind as keyof typeof columns] || 0) * 240, y: count * 92 },
      data: { label: <div className={`judgment-node ${kind} ${active ? "active" : ""}`}><span>{kindLabel(kind)}</span><b>{label}</b><small>{explanation}</small></div> },
      style: { width: 210, border: 0, padding: 0, background: "transparent" },
    };
  });
}

function toEdges(judgment: JudgmentTraceViewModel, activeFactId: string): Edge[] {
  return (judgment.causal_graph.edges || []).slice(0, 220).map((edge, index) => {
    const source = String(edge.from || edge.source || "");
    const target = String(edge.to || edge.target || "");
    const relation = String(edge.relation || "related_to");
    const active = activeFactId && (source === activeFactId || target === activeFactId);
    return {
      id: `${source}-${target}-${relation}-${index}`,
      source,
      target,
      label: relationLabel(relation),
      type: "smoothstep",
      animated: relation === "matched" || relation === "candidate" || active,
      markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16 },
      style: { stroke: active ? "#b42318" : relation === "final" ? "#175cd3" : "#98a2b3", strokeWidth: active ? 2.5 : 1.4 },
    };
  }).filter((edge) => edge.source && edge.target);
}

function nodeLabel(node: Record<string, unknown>): string {
  if (node.kind === "fact") return `${factName(node.namespace, node.key)}=${valueText(node.value)}`;
  if (node.kind === "retrieval") return `用 ${factTokenText(String(node.key || node.id))} 召回规则`;
  if (node.kind === "graph") return `${factName("graph", node.key)}=${valueText(node.value)}`;
  if (node.kind === "history") return `${factName("history", node.key)}=${valueText(node.value)}`;
  if (node.kind === "constraint") return `约束合并：${displayLabel(String(node.via || node.id))}`;
  if (node.kind === "predicate") return String(node.path || node.key || node.id);
  if (node.kind === "rule") return ruleTitle(node);
  if (node.kind === "lattice") return `${displayLabel(String(node.from || "start"))} -> ${displayLabel(String(node.to || ""))}`;
  return displayLabel(String(node.label || node.id));
}

function factTokenText(token: string): string {
  const [path, rawValue] = token.split("=");
  const [namespace, key] = path.split(".");
  return rawValue ? `${factName(namespace, key)}=${valueText(rawValue)}` : factName(namespace, key);
}

function kindLabel(kind: string): string {
  const labels: Record<string, string> = {
    history: "历史状态",
    graph: "动作结构",
    fact: "事实证据",
    retrieval: "规则召回",
    predicate: "条件检查",
    rule: "安全规则",
    constraint: "约束合并",
    lattice: "决策升级",
    final: "最终结论",
  };
  return labels[kind] || displayLabel(kind);
}

function nodeExplanation(node: Record<string, unknown>): string {
  if (node.kind === "history") return "说明之前动作留下的风险状态会影响当前判断。";
  if (node.kind === "graph") return "说明命令内部是否有管道、顺序或数据流关系。";
  if (node.kind === "fact") return "这是 MSJ Engine 消费的标准化证据。";
  if (node.kind === "retrieval") return "RuleIndex 用这个证据键找到需要评估的规则。";
  if (node.kind === "predicate") return "检查规则条件是否被当前证据满足。";
  if (node.kind === "rule") return "命中的安全规则会给出最低治理要求。";
  if (node.kind === "constraint") return "把执行、网络、数据、审批等要求合并成约束。";
  if (node.kind === "lattice") return "把多个规则结论按风险等级合成更严格的判断。";
  if (node.kind === "final") return "这是 AgentBrake-Fusion 返回给网关和前端的最终安全结论。";
  return "该节点参与了这次动作的可追溯判断链。";
}

function relationLabel(relation: string): string {
  const labels: Record<string, string> = {
    derived_from: "来自",
    evidence: "作为证据",
    supports: "支撑",
    candidate: "召回",
    matched: "命中",
    evaluates: "检查",
    upgrades: "升级",
    final: "形成结论",
    finalizes: "形成结论",
    constraint_join: "合并约束",
    history_supports: "历史支撑",
    action_graph_supports: "结构支撑",
    related_to: "相关",
  };
  return labels[relation] || displayLabel(relation);
}

function relationExplanation(relation: string): string {
  const labels: Record<string, string> = {
    derived_from: "左侧节点是右侧节点的来源，说明这个判断不是凭空产生的。",
    evidence: "这条记录作为后续判断的证据。",
    supports: "前一个证据支持后一个条件或规则成立。",
    candidate: "RuleIndex 根据证据键把相关规则召回出来。",
    matched: "当前证据满足了规则里的某个检查条件。",
    evaluates: "策略引擎正在用事实检查谓词条件。",
    upgrades: "更强的规则结论把决策推向更严格等级。",
    final: "约束乘积格输出最终安全结论。",
    finalizes: "约束乘积格输出最终安全结论。",
    constraint_join: "多个治理要求被合并，保留更严格的约束。",
  };
  return labels[relation] || "这条箭头表示前一个节点对后一个节点有因果或证据支撑关系。";
}

function CausalInspector({ node, edges }: { node?: Record<string, unknown>; edges: Array<Record<string, unknown>> }) {
  if (!node) return null;
  const nodeId = String(node.id || "");
  const incoming = edges.filter((edge) => String(edge.to || edge.target || "") === nodeId).slice(0, 4);
  const outgoing = edges.filter((edge) => String(edge.from || edge.source || "") === nodeId).slice(0, 4);
  return (
    <div className="causal-inspector">
      <div>
        <span className="policy-eyebrow">{kindLabel(String(node.kind))}</span>
        <h4>{nodeLabel(node)}</h4>
        <p>{nodeExplanation(node)}</p>
      </div>
      <div className="causal-edge-list">
        <b>它为什么会出现</b>
        {incoming.length ? incoming.map((edge, index) => <span key={`in-${index}`}>{relationLabel(String(edge.relation || "related_to"))}：{relationExplanation(String(edge.relation || "related_to"))}</span>) : <span>这是判断链的起点或基础证据。</span>}
      </div>
      <div className="causal-edge-list">
        <b>它怎样影响后续结论</b>
        {outgoing.length ? outgoing.map((edge, index) => <span key={`out-${index}`}>{relationLabel(String(edge.relation || "related_to"))}：{relationExplanation(String(edge.relation || "related_to"))}</span>) : <span>这一步已经接近或形成最终结论。</span>}
      </div>
    </div>
  );
}
