import { Background, Controls, MarkerType, ReactFlow, type Edge as FlowEdge, type Node as FlowNode } from "@xyflow/react";
import { Download } from "lucide-react";
import { useMemo } from "react";
import type { ActionGraphEdge, ActionGraphNode } from "../../types";

const relationLabels: Record<ActionGraphEdge["relation"], string> = {
  derived_from: "来源于",
  uses_arg: "使用参数",
  conflicts_with: "冲突",
  sends_to: "发送到",
  writes_to: "写入",
  blocked_by: "阻断",
  reads_from: "读取自",
  mutates: "修改",
  influenced_by: "受影响",
  recovered_by: "由恢复动作修正"
};

const layout: Record<string, { x: number; y: number; w: number; h: number }> = {
  external_source: { x: 0, y: 250, w: 240, h: 170 },
  user_goal: { x: 285, y: 40, w: 255, h: 120 },
  trusted_result: { x: 285, y: 190, w: 255, h: 128 },
  untrusted_content: { x: 285, y: 370, w: 255, h: 168 },
  private_data: { x: 285, y: 575, w: 255, h: 112 },
  candidate: { x: 590, y: 285, w: 280, h: 190 },
  recipient: { x: 930, y: 60, w: 245, h: 112 },
  content: { x: 930, y: 220, w: 245, h: 132 },
  destination: { x: 930, y: 410, w: 245, h: 112 },
  side_effect: { x: 930, y: 570, w: 245, h: 112 },
  decision: { x: 1235, y: 315, w: 245, h: 132 }
};

export function ActionGraphPanel({ nodes, edges }: { nodes: ActionGraphNode[]; edges: ActionGraphEdge[] }) {
  const flowNodes = useMemo<FlowNode[]>(() => nodes.map((node) => {
    const box = layout[node.id] || { x: 0, y: 0, w: 280, h: 120 };
    return {
      id: node.id,
      position: { x: box.x, y: box.y },
      data: { label: <GraphNodeLabel node={node} /> },
      className: `flow-graph-node ${node.kind}`,
      style: { width: box.w, minHeight: box.h }
    };
  }), [nodes]);

  const flowEdges = useMemo<FlowEdge[]>(() => edges.map((edge) => ({
    id: `${edge.from}-${edge.to}-${edge.relation}`,
    source: edge.from,
    target: edge.to,
    type: "smoothstep",
    label: relationLabels[edge.relation],
    markerEnd: { type: MarkerType.ArrowClosed, width: 18, height: 18, color: colorFor(edge.relation) },
    style: { stroke: colorFor(edge.relation), strokeWidth: edge.relation === "conflicts_with" || edge.relation === "blocked_by" ? 3 : 2 },
    labelStyle: { fill: colorFor(edge.relation), fontWeight: 700, fontSize: 12 },
    labelBgStyle: { fill: "#ffffff", fillOpacity: 0.92 },
    labelBgPadding: [8, 5],
    labelBgBorderRadius: 8
  })), [edges]);

  return (
    <section className="card workbench-panel action-graph-panel" data-testid="actiongraph-panel">
      <div className="section-heading compact">
        <div>
          <h2>ActionGraph</h2>
          <p>以候选工具动作为中心，明确展示外部来源、低可信内容、参数污染、目的地和副作用之间的执行前证据流。</p>
        </div>
        <div className="graph-actions">
          <button title="导出 JSON" onClick={() => downloadJson(nodes, edges)}><Download size={14} /> JSON</button>
          <button title="导出 SVG" onClick={() => downloadSvg(nodes, edges)}><Download size={14} /> SVG</button>
          <button title="导出 PNG" onClick={() => downloadPng(nodes, edges)}><Download size={14} /> PNG</button>
        </div>
      </div>
      <div className="graph-lane-labels">
        <span>外部来源</span>
        <span>证据内容</span>
        <span>候选动作</span>
        <span>参数与副作用</span>
        <span>裁决</span>
      </div>
      <div className="action-graph-flow" aria-label="执行前动作证据图">
        <ReactFlow
          nodes={flowNodes}
          edges={flowEdges}
          fitView
          fitViewOptions={{ padding: 0.12 }}
          minZoom={0.35}
          maxZoom={1.25}
          proOptions={{ hideAttribution: true }}
          nodesDraggable
          nodesConnectable={false}
          elementsSelectable
        >
          <Background gap={28} size={1} color="#dbe4f0" />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
      <div className="graph-legend">
        <span className="source">外部不可信来源</span>
        <span className="trusted">可信目标/证据</span>
        <span className="untrusted">低可信内容</span>
        <span className="candidate">候选工具动作</span>
        <span className="effect">参数与副作用</span>
        <span className="decision">执行前裁决</span>
      </div>
    </section>
  );
}

function GraphNodeLabel({ node }: { node: ActionGraphNode }) {
  const [title, ...details] = node.label.split("\n");
  return (
    <div className="flow-node-content">
      <b>{title}</b>
      {details.map((detail, index) => <span key={`${node.id}-${index}`}>{detail}</span>)}
    </div>
  );
}

function colorFor(relation: ActionGraphEdge["relation"]) {
  if (relation === "conflicts_with" || relation === "blocked_by") return "#b42318";
  if (relation === "sends_to" || relation === "writes_to" || relation === "mutates") return "#b45309";
  if (relation === "derived_from") return "#dc2626";
  if (relation === "influenced_by") return "#2563eb";
  return "#2563eb";
}

function downloadJson(nodes: ActionGraphNode[], edges: ActionGraphEdge[]) {
  downloadText("actiongraph.json", JSON.stringify({ nodes, edges }, null, 2), "application/json;charset=utf-8");
}

function downloadSvg(nodes: ActionGraphNode[], edges: ActionGraphEdge[]) {
  downloadText("actiongraph.svg", buildSvg(nodes, edges), "image/svg+xml;charset=utf-8");
}

function downloadPng(nodes: ActionGraphNode[], edges: ActionGraphEdge[]) {
  const canvas = document.createElement("canvas");
  canvas.width = 1840;
  canvas.height = 820;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  drawCanvasGraph(ctx, nodes, edges);
  canvas.toBlob((blob) => {
    if (!blob) return;
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "actiongraph.png";
    link.click();
    URL.revokeObjectURL(url);
  }, "image/png");
}

function downloadText(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function buildSvg(nodes: ActionGraphNode[], edges: ActionGraphEdge[]) {
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const edgeSvg = edges.map((edge) => {
    const source = nodeMap.get(edge.from);
    const target = nodeMap.get(edge.to);
    if (!source || !target) return "";
    const start = centerRight(source);
    const end = centerLeft(target);
    const color = colorFor(edge.relation);
    return `<path d="M ${start.x} ${start.y} C ${start.x + 120} ${start.y}, ${end.x - 120} ${end.y}, ${end.x} ${end.y}" fill="none" stroke="${color}" stroke-width="3" marker-end="url(#arrow-${edge.relation})" />`;
  }).join("");
  const nodeSvg = nodes.map((node) => {
    const box = layout[node.id];
    if (!box) return "";
    const lines = escapeXml(node.label).split("\n").slice(0, 5);
    return `<g><rect x="${box.x}" y="${box.y}" width="${box.w}" height="${box.h}" rx="16" fill="${fillFor(node.kind)}" stroke="${strokeFor(node.kind)}" stroke-width="2"/><text x="${box.x + 18}" y="${box.y + 32}" font-family="Arial" font-size="18" font-weight="700" fill="#111827">${lines[0] || ""}</text>${lines.slice(1).map((line, index) => `<text x="${box.x + 18}" y="${box.y + 62 + index * 22}" font-family="Arial" font-size="14" fill="#374151">${line}</text>`).join("")}</g>`;
  }).join("");
  const markers = Array.from(new Set(edges.map((edge) => edge.relation))).map((relation) => `<marker id="arrow-${relation}" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="${colorFor(relation)}"/></marker>`).join("");
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1840" height="820" viewBox="-40 0 1840 820"><defs>${markers}</defs><rect x="-40" y="0" width="1840" height="820" fill="#ffffff"/>${edgeSvg}${nodeSvg}</svg>`;
}

function drawCanvasGraph(ctx: CanvasRenderingContext2D, nodes: ActionGraphNode[], edges: ActionGraphEdge[]) {
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  edges.forEach((edge) => {
    const source = nodeMap.get(edge.from);
    const target = nodeMap.get(edge.to);
    if (!source || !target) return;
    const start = centerRight(source);
    const end = centerLeft(target);
    ctx.strokeStyle = colorFor(edge.relation);
    ctx.lineWidth = edge.relation === "conflicts_with" || edge.relation === "blocked_by" ? 3 : 2;
    ctx.beginPath();
    ctx.moveTo(start.x + 40, start.y);
    ctx.bezierCurveTo(start.x + 160, start.y, end.x - 160, end.y, end.x + 40, end.y);
    ctx.stroke();
  });
  nodes.forEach((node) => {
    const box = layout[node.id];
    if (!box) return;
    roundRect(ctx, box.x + 40, box.y, box.w, box.h, 16, fillFor(node.kind), strokeFor(node.kind));
    const lines = node.label.split("\n").slice(0, 5);
    ctx.fillStyle = "#111827";
    ctx.font = "700 18px Arial";
    ctx.fillText(lines[0] || "", box.x + 58, box.y + 34, box.w - 36);
    ctx.fillStyle = "#374151";
    ctx.font = "14px Arial";
    lines.slice(1).forEach((line, index) => ctx.fillText(line, box.x + 58, box.y + 64 + index * 22, box.w - 36));
  });
}

function centerRight(node: ActionGraphNode) {
  const box = layout[node.id];
  return { x: box.x + box.w, y: box.y + box.h / 2 };
}

function centerLeft(node: ActionGraphNode) {
  const box = layout[node.id];
  return { x: box.x, y: box.y + box.h / 2 };
}

function fillFor(kind: ActionGraphNode["kind"]) {
  return {
    source: "#fff7f7",
    trusted: "#ecfdf3",
    untrusted: "#fff1f2",
    private: "#fff7ed",
    candidate: "#eff6ff",
    arg: "#f8fafc",
    side_effect: "#fff7ed",
    decision: "#fef2f2"
  }[kind];
}

function strokeFor(kind: ActionGraphNode["kind"]) {
  return {
    source: "#ef4444",
    trusted: "#86efac",
    untrusted: "#fca5a5",
    private: "#fdba74",
    candidate: "#60a5fa",
    arg: "#cbd5e1",
    side_effect: "#fdba74",
    decision: "#f87171"
  }[kind];
}

function escapeXml(value: string) {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function roundRect(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  width: number,
  height: number,
  radius: number,
  fill: string,
  stroke: string
) {
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.arcTo(x + width, y, x + width, y + height, radius);
  ctx.arcTo(x + width, y + height, x, y + height, radius);
  ctx.arcTo(x, y + height, x, y, radius);
  ctx.arcTo(x, y, x + width, y, radius);
  ctx.closePath();
  ctx.fillStyle = fill;
  ctx.fill();
  ctx.strokeStyle = stroke;
  ctx.lineWidth = 2;
  ctx.stroke();
}
