import type { ChatMessage, DecisionRun, ScenarioId, ToolTimelineItem } from "../types";
import { createDecisionRun } from "./scenarios";

let sessionId = `studio-session-${Date.now()}`;
let sessionReady = false;

export async function createChatSession(): Promise<string> {
  const response = await fetch("/api/chat/session", {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: "{}"
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || "无法创建 OpenClaw 会话");
  sessionId = payload.sessionId || payload.session_id || payload.session?.id || sessionId;
  sessionReady = true;
  return sessionId;
}

async function ensureChatSession(): Promise<string> {
  if (sessionReady) return sessionId;
  return createChatSession();
}

export async function sendOpenClawMessage(
  message: string,
  scenarioId: ScenarioId = "workspace"
): Promise<{
  assistant: ChatMessage;
  run: DecisionRun | null;
  timeline: ToolTimelineItem[];
  fallbackUsed?: boolean;
  connectorError?: string;
}> {
  await ensureChatSession();
  const response = await fetch(`/api/chat/session/${encodeURIComponent(sessionId)}/message`, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify({ message, userTask: message, scenarioId, scenario_id: scenarioId })
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || payload.connectorError || "OpenClaw 对话接口不可用");
  return normalizeChatPayload(payload);
}

export async function fetchLatestDecisionRun(): Promise<DecisionRun> {
  try {
    const response = await fetch("/api/runs/latest-decision", { headers: authHeaders() });
    if (!response.ok) throw new Error("latest decision endpoint unavailable");
    return (await response.json()) as DecisionRun;
  } catch {
    return createDecisionRun("workspace");
  }
}

function normalizeChatPayload(payload: any): {
  assistant: ChatMessage;
  run: DecisionRun | null;
  timeline: ToolTimelineItem[];
  fallbackUsed?: boolean;
  connectorError?: string;
} {
  const assistantRaw = payload.assistant || {};
  const assistant: ChatMessage = {
    id: assistantRaw.id || `assistant-${Date.now()}`,
    role: "assistant",
    timestamp: assistantRaw.timestamp || new Date().toISOString(),
    text:
      assistantRaw.text ||
      assistantRaw.content ||
      (payload.candidateToolCall ? "OpenClaw 生成了候选工具调用，已进入 AgentBrake-Fusion 审查。" : "OpenClaw 已返回响应。")
  };
  const run = (payload.run || null) as DecisionRun | null;
  return {
    assistant,
    run,
    timeline: (payload.timeline || run?.timeline || []) as ToolTimelineItem[],
    fallbackUsed: Boolean(payload.fallbackUsed),
    connectorError: payload.connectorError || ""
  };
}

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("agentbrakeFusionToken") || "agentbrake-fusion-local";
  return { Authorization: `Bearer ${token}` };
}
