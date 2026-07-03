import type {
  ActionGraphEdge,
  ActionGraphNode,
  CandidateToolCall,
  DecisionRun,
  LatticeDimension,
  ScenarioId,
  ToolTimelineItem
} from "../types";
import { scenarioById } from "./scenarios";

export const EMPTY_TOOL_NAME = "__none__";

interface LiveTraceInput {
  scenarioId: ScenarioId;
  userTask?: string;
  assistantText?: string;
  status?: "idle" | "waiting" | "answered";
}

export function createLiveObservationRun({
  scenarioId,
  userTask = "",
  assistantText = "",
  status = "idle"
}: LiveTraceInput): DecisionRun {
  const scenario = scenarioById(scenarioId);
  const timestamp = new Date().toISOString();
  const taskText = userTask.trim() || "尚未输入任务。等待用户向本地 OpenClaw 发起对话。";
  const responseText =
    assistantText.trim() ||
    (status === "waiting" ? "正在等待 OpenClaw 回复；若回复中包含工具调用，会先进入执行前审查。" : "尚未收到 OpenClaw 回复。");
  const candidate = emptyCandidate(status);
  const nodes = liveGraphNodes(taskText, responseText, status);
  const edges = liveGraphEdges();
  const dimensions = liveDimensions(status);

  return {
    id: `live-observe-${Date.now()}`,
    traceId: `live-trace-${Date.now()}`,
    sessionId: "live-openclaw-session",
    turnId: `live-turn-${Date.now()}`,
    timestamp,
    scenarioId,
    scenarioTitle: scenario.title,
    severity: "low",
    latencyMs: 0,
    toolExecuted: false,
    sandboxed: true,
    userTask: taskText,
    lowTrustContext: status === "idle" ? "暂无低可信上下文进入本轮对话。" : "本轮暂未观察到低可信上下文污染工具参数。",
    candidateToolCall: candidate,
    finalDecision: "observing",
    actionGraph: { nodes, edges },
    msjFacts: {
      task_authorized: true,
      tool_group: "无候选工具动作",
      arg_provenance: { message: "用户任务或可信对话上下文" },
      private_data_seen: false,
      injection_seen: false,
      args_match_user_entity: true,
      args_match_untrusted_entity: false,
      external_sink: false,
      ruleHits: ["未触发副作用工具审查规则", "保持执行前观察状态"],
      trustedEvidence: [`用户本轮输入：${shortText(taskText, 120)}`, `OpenClaw 回复：${shortText(responseText, 120)}`],
      unsafeEvidence: ["当前未发现低可信参数、外部出口或副作用工具请求。"]
    },
    lattice: {
      dimensions,
      output: {
        execution_env: "未进入工具运行时",
        network_scope: "未请求网络或外部发送",
        data_scope: "未观察到待外发数据",
        human_gate: "无需人工确认；等待候选动作出现",
        audit_scope: "记录本轮对话观察状态",
        decision: "observing",
        joinPath: [
          "本轮只有自然语言对话，还没有候选工具动作。",
          "ActionGraph 保留用户目标与 OpenClaw 回复，等待工具参数进入图中。",
          "MSJ Engine 与 Constraint Product Lattice 处于观察态，不提前给出阻断诊断。"
        ]
      }
    },
    brakeTrace: {
      reason_codes: ["NO_CANDIDATE_TOOL_CALL"],
      trusted_evidence: [`用户任务：${shortText(taskText, 140)}`, `OpenClaw 回复：${shortText(responseText, 140)}`],
      unsafe_evidence: ["暂无不安全证据。"],
      allowed_next_steps: ["继续与 OpenClaw 对话", "若 OpenClaw 生成工具调用，将自动进入 ToolGate 审查"],
      disallowed_next_steps: ["在没有候选工具调用时展示预置攻击诊断", "绕过 ToolGate 直接执行工具"],
      recovery_guidance: ["保持观察态；只有候选工具动作出现时才构造具体裁决链。"]
    },
    timeline: liveTimeline(status, timestamp)
  };
}

function emptyCandidate(status: LiveTraceInput["status"]): CandidateToolCall {
  return {
    id: "no-candidate-tool-call",
    toolName: EMPTY_TOOL_NAME,
    status: "under_review",
    args: {},
    risk: "low",
    source: "OpenClaw 对话",
    preview: status === "waiting" ? "正在等待 OpenClaw 回复；尚未捕获候选工具动作。" : "当前没有候选工具调用。",
    decision: "observing"
  };
}

function liveGraphNodes(taskText: string, responseText: string, status: LiveTraceInput["status"]): ActionGraphNode[] {
  return [
    { id: "external_source", label: "外部来源\n本轮尚未读取邮件、网页、PDF 或搜索结果。", kind: "source", column: "left" },
    { id: "user_goal", label: `用户目标\n${shortText(taskText, 86)}`, kind: "trusted", column: "left" },
    { id: "trusted_result", label: `OpenClaw 回复\n${shortText(responseText, 88)}`, kind: "trusted", column: "left" },
    { id: "untrusted_content", label: "低可信内容\n本轮暂未观察到外部低可信上下文污染工具参数。", kind: "untrusted", column: "left" },
    { id: "private_data", label: "私密数据\n本轮暂未发现待外发私密数据。", kind: "private", column: "left" },
    {
      id: "candidate",
      label:
        status === "waiting"
          ? "候选工具动作\n等待 OpenClaw 回复\n如果出现工具调用，会在这里暂停"
          : "候选工具动作\n暂无候选工具调用\n没有执行前裁决对象",
      kind: "candidate",
      column: "center"
    },
    { id: "recipient", label: "参数槽\n等待工具参数", kind: "arg", column: "right" },
    { id: "content", label: "内容槽\n等待工具内容", kind: "arg", column: "right" },
    { id: "destination", label: "目的地\n未请求外部目的地", kind: "side_effect", column: "right" },
    { id: "side_effect", label: "副作用\n未执行任何工具", kind: "side_effect", column: "right" },
    { id: "decision", label: "执行前状态\n观察中：等待候选工具动作", kind: "decision", column: "right" }
  ];
}

function liveGraphEdges(): ActionGraphEdge[] {
  return [
    { from: "external_source", to: "untrusted_content", relation: "reads_from" },
    { from: "user_goal", to: "candidate", relation: "derived_from" },
    { from: "trusted_result", to: "candidate", relation: "influenced_by" },
    { from: "candidate", to: "decision", relation: "influenced_by" }
  ];
}

function liveDimensions(status: LiveTraceInput["status"]): LatticeDimension[] {
  return [
    { id: "action", label: "动作类型", value: "尚无工具动作", severity: "info" },
    { id: "intent", label: "意图一致性", value: status === "idle" ? "等待用户任务" : "仅自然语言回复", severity: "normal" },
    { id: "provenance", label: "参数来源", value: "未产生工具参数", severity: "info" },
    { id: "sensitivity", label: "数据敏感性", value: "未观察到敏感数据流", severity: "normal" },
    { id: "destination", label: "目的地", value: "无外部出口", severity: "normal" },
    { id: "history", label: "历史上下文", value: "记录本轮对话", severity: "info" },
    { id: "confirmation", label: "确认条件", value: "暂无需确认", severity: "info" }
  ];
}

function liveTimeline(status: LiveTraceInput["status"], timestamp: string): ToolTimelineItem[] {
  if (status === "idle") {
    return [{ id: "live-idle", time: timestamp, title: "等待用户输入任务", state: "observed" }];
  }
  if (status === "waiting") {
    return [
      { id: "live-user-message", time: timestamp, title: "收到用户任务", state: "observed" },
      { id: "live-wait-openclaw", time: timestamp, title: "等待 OpenClaw 回复或候选工具动作", state: "reviewing" }
    ];
  }
  return [
    { id: "live-user-message", time: timestamp, title: "收到用户任务", state: "observed" },
    { id: "live-openclaw-response", time: timestamp, title: "OpenClaw 返回自然语言回复", state: "observed" },
    { id: "live-no-tool", time: timestamp, title: "未捕获候选工具调用，三层链路保持观察态", state: "decided", decision: "observing" }
  ];
}

function shortText(value: string, limit: number): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= limit) return compact;
  return `${compact.slice(0, Math.max(0, limit - 1))}…`;
}
