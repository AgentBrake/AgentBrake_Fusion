import type { GuardConfig, ServiceHealth, SetupCheck } from "../types";

export interface OpenClawStatus {
  ok: boolean;
  mode: GuardConfig["mode"];
  health: ServiceHealth & { connector?: Record<string, unknown> };
  config?: Record<string, unknown>;
  connector?: Record<string, unknown>;
  nativeEventMode?: boolean;
  toolProxyMode?: boolean;
  repairHints?: string[];
}

export interface OpenClawConnector {
  mode: "gateway_ws" | "gateway_http" | "a2a" | "cli" | "mock";
  checkStatus(): Promise<OpenClawStatus>;
  sendMessage(input: { sessionId: string; message: string; userTask?: string }): Promise<unknown>;
  streamEvents(input: { sessionId: string }): AsyncIterable<unknown>;
  invokeTool?(input: { toolName: string; args: Record<string, unknown>; sessionId: string; traceId?: string }): Promise<unknown>;
  parseCandidateToolCall(input: { event?: unknown; text?: string; raw?: unknown }): unknown | null;
}

const offlineHealth: ServiceHealth = {
  agentbrakeApi: "offline",
  openclawGateway: "offline",
  a2aGateway: "offline",
  cliFallback: "offline",
  localModel: "offline",
  toolGuard: "offline",
  auditStream: "offline",
  policyMode: "enforce",
  endpoint: "http://127.0.0.1:8765",
  lastCheckedAt: new Date().toISOString()
};

export async function getServiceHealth(): Promise<ServiceHealth> {
  const response = await fetch("/api/openclaw/health", { headers: authHeaders() });
  if (!response.ok) {
    return {
      ...offlineHealth,
      lastCheckedAt: new Date().toISOString()
    };
  }
  return (await response.json()) as ServiceHealth;
}

export async function getOpenClawStatus(): Promise<OpenClawStatus> {
  const response = await fetch("/api/openclaw/status", { headers: authHeaders() });
  if (!response.ok) {
    return {
      ok: false,
      mode: "gateway_http",
      health: { ...offlineHealth, lastCheckedAt: new Date().toISOString() },
      repairHints: ["AgentBrake Studio 后端不可用，请先启动后端服务。"],
      toolProxyMode: false
    };
  }
  return (await response.json()) as OpenClawStatus;
}

export async function applyGuardConfig(config: GuardConfig): Promise<{ ok: boolean; config: GuardConfig; message: string; status?: OpenClawStatus }> {
  const normalized = normalizeConfig(config);
  const response = await fetch("/api/openclaw/config", {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify(normalized)
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || "OpenClaw 配置接口不可用");
  }
  return payload as { ok: boolean; config: GuardConfig; message: string; status?: OpenClawStatus };
}

export async function runGuardTests(): Promise<SetupCheck[]> {
  const response = await fetch("/api/openclaw/test", {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: "{}"
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || "接入测试失败");
  return (payload.checks || payload.results || []) as SetupCheck[];
}

export function guardConfigSnippet(config: GuardConfig): string {
  const normalized = normalizeConfig(config);
  const tokenText = normalized.authToken ? "<已配置，前端不显示明文>" : "<未配置>";
  const modelKeyText = normalized.modelApiKey ? "<已配置，前端不显示明文>" : "<未配置>";
  return [
    "AgentBrake-Fusion:",
    `  策略模式: ${normalized.policyMode === "enforce" ? "强制执行" : "仅观察"}`,
    "  执行前网关: 开启",
    "  ActionGraph: 开启",
    "  MSJ Engine: 开启",
    "  Constraint Product Lattice: 开启",
    "OpenClaw:",
    `  运行模式: ${modeLabel(normalized.mode)}`,
    `  Gateway: ${normalized.gatewayUrl}`,
    `  Token: ${tokenText}`,
    `  Agent ID: ${normalized.openclawAgentId}`,
    `  Chat endpoint: ${normalized.chatEndpoint || "(自动)"}`,
    `  Events endpoint: ${normalized.eventsEndpoint || "(自动)"}`,
    `  Tool proxy endpoint: /api/tool-proxy/invoke`,
    `  A2A: ${normalized.a2aUrl} / ${normalized.a2aAgentId}`,
    `  CLI: ${normalized.cliPath}`,
    `  模型: ${normalized.modelRef}`,
    `  模型 Base URL: ${normalized.modelBaseUrl || "(由 OpenClaw 本地配置决定)"}`,
    `  模型 API Key: ${modelKeyText}`,
    "  工具执行: 先审查，再按 allow / require_confirmation / block 治理",
    `  审计流: ${normalized.auditStream ? "开启" : "关闭"}`,
    `  Sandbox: ${normalized.sandbox === false ? "关闭" : "开启"}`,
    `  真实工具: ${normalized.allowRealTools ? "显式允许，仍需 ToolGate allow" : "默认禁止"}`
  ].join("\n");
}

export function normalizeConfig(config: GuardConfig): GuardConfig {
  const mode = config.mode || "gateway_http";
  const gatewayUrl = normalizeGatewayUrl(config.gatewayUrl || config.baseUrl || "http://127.0.0.1:18789", mode);
  return {
    ...config,
    mode,
    gatewayUrl,
    baseUrl: gatewayUrl,
    authToken: config.authToken || "",
    a2aUrl: config.a2aUrl || "http://127.0.0.1:18800",
    a2aAgentId: config.a2aAgentId || "main",
    openclawAgentId: config.openclawAgentId || "main",
    cliPath: config.cliPath || "openclaw",
    modelRef: config.modelRef || "local-model",
    modelBaseUrl: config.modelBaseUrl || "https://dashscope.aliyuncs.com/compatible-mode/v1",
    modelApiKey: config.modelApiKey || "",
    chatEndpoint: config.chatEndpoint || "",
    eventsEndpoint: config.eventsEndpoint || "",
    toolCallEndpoint: config.toolCallEndpoint || "",
    openaiCompatible: config.openaiCompatible !== false,
    gatewayPaths: {
      health: "/health",
      status: "/status",
      chat: "/chat",
      events: "/events",
      toolCalls: "/tool-calls",
      ...(config.gatewayPaths || {})
    },
    sandbox: config.sandbox !== false,
    allowRealTools: config.allowRealTools === true
  };
}

function normalizeGatewayUrl(value: string, mode: GuardConfig["mode"]): string {
  const trimmed = value.trim() || "http://127.0.0.1:18789";
  if (mode === "gateway_ws") {
    return trimmed.replace(/^http:\/\//i, "ws://").replace(/^https:\/\//i, "wss://");
  }
  if (mode === "gateway_http") {
    return trimmed.replace(/^ws:\/\//i, "http://").replace(/^wss:\/\//i, "https://");
  }
  return trimmed;
}

function modeLabel(mode: GuardConfig["mode"]): string {
  return {
    gateway_ws: "Gateway WebSocket",
    gateway_http: "Gateway HTTP",
    a2a: "A2A Gateway",
    cli: "CLI fallback",
    mock: "Mock Demo"
  }[mode];
}

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("agentbrakeFusionToken") || "agentbrake-fusion-local";
  return { Authorization: `Bearer ${token}` };
}
