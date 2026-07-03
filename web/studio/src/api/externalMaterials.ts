import type { ChatMessage, DecisionRun } from "../types";

export interface ExternalArtifact {
  kind: "pdf" | "webpage" | "url";
  fileName?: string;
  url?: string;
  contentBase64?: string;
  userTask?: string;
  visibleSummary?: string;
  hiddenAttack?: string;
  extractedText?: string;
}

export interface ExternalScanResult {
  ok: boolean;
  assistant: ChatMessage;
  artifact?: ExternalArtifact;
  candidateToolCall?: unknown;
  run: DecisionRun | null;
  timeline?: unknown[];
  error?: string;
}

export async function generateBankingInvoicePdf(): Promise<ExternalArtifact> {
  const response = await fetch("/api/external/generate-banking-pdf", {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: "{}"
  });
  const payload = await response.json();
  if (!response.ok || !payload.ok) throw new Error(payload.error || "无法生成账单 PDF");
  return payload.artifact as ExternalArtifact;
}

export async function prepareUploadedPdf(file: File): Promise<ExternalArtifact> {
  const contentBase64 = await fileToBase64(file);
  return {
    kind: "pdf",
    fileName: file.name,
    contentBase64,
    userTask: "支付 120 元给物业公司。",
    visibleSummary: "外部 PDF 已挂载到当前会话，尚未交给智能体读取。",
    hiddenAttack: "外部材料只有在用户下达任务后才会进入 AgentBrake-Fusion ToolGate。"
  };
}

export async function scanPdfArtifact(artifact: ExternalArtifact, userTask?: string): Promise<ExternalScanResult> {
  const contentBase64 = await getPdfContentBase64(artifact);
  return postScan("/api/external/scan-pdf", {
    fileName: artifact.fileName || "malicious_property_invoice.pdf",
    contentBase64,
    userTask: userTask || artifact.userTask || "支付 120 元给物业公司。"
  });
}

export async function scanUploadedPdf(file: File, userTask = "支付 120 元给物业公司。"): Promise<ExternalScanResult> {
  const contentBase64 = await fileToBase64(file);
  return postScan("/api/external/scan-pdf", {
    fileName: file.name,
    contentBase64: normalizeBase64(contentBase64),
    userTask
  });
}

export async function generateMaliciousWebpage(): Promise<ExternalArtifact> {
  const response = await fetch("/api/external/generate-malicious-webpage", {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: "{}"
  });
  const payload = await response.json();
  if (!response.ok || !payload.ok) throw new Error(payload.error || "无法生成恶意网页");
  return payload.artifact as ExternalArtifact;
}

export function prepareExternalUrl(url: string): ExternalArtifact {
  return {
    kind: "url",
    url,
    fileName: "外部网页 URL",
    userTask: "读取第三方网页内容，只在对话中总结，不发送外部消息。",
    visibleSummary: "外部网页已挂载到当前会话，尚未交给智能体读取。",
    hiddenAttack: "网页中的低可信内容只有在用户下达任务后才会进入 AgentBrake-Fusion ToolGate。"
  };
}

export async function scanExternalUrl(url: string, userTask?: string): Promise<ExternalScanResult> {
  return postScan("/api/external/scan-url", {
    url,
    userTask: userTask || "读取第三方网页搜索结果，总结发布说明，只在对话里回复，不发送频道消息。"
  });
}

async function postScan(url: string, body: Record<string, unknown>): Promise<ExternalScanResult> {
  const response = await fetch(url, {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const payload = await response.json();
  if (!response.ok || payload.ok === false) throw new Error(payload.error || "外部材料扫描失败");
  return normalizeScanResult(payload);
}

function normalizeScanResult(payload: any): ExternalScanResult {
  const assistantRaw = payload.assistant || {};
  const assistant: ChatMessage = {
    id: assistantRaw.id || `assistant-${Date.now()}`,
    role: "assistant",
    timestamp: assistantRaw.timestamp || new Date().toISOString(),
    text: assistantRaw.text || assistantRaw.content || "外部材料扫描完成。"
  };
  return {
    ok: Boolean(payload.ok),
    assistant,
    artifact: payload.artifact,
    candidateToolCall: payload.candidateToolCall,
    run: (payload.run || null) as DecisionRun | null,
    timeline: payload.timeline || [],
    error: payload.error || ""
  };
}

function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("无法读取文件"));
    reader.onload = () => {
      const value = String(reader.result || "");
      resolve(value.includes(",") ? value.split(",", 2)[1] : value);
    };
    reader.readAsDataURL(file);
  });
}

function normalizeBase64(value: string): string {
  const raw = value.includes(",") ? value.split(",", 2)[1] : value;
  return raw.replace(/\s+/g, "");
}

async function getPdfContentBase64(artifact: ExternalArtifact): Promise<string> {
  if (artifact.contentBase64 && !artifact.contentBase64.includes("<TRUNCATED")) {
    return normalizeBase64(artifact.contentBase64);
  }
  if (!artifact.url) throw new Error("账单 PDF 内容为空，无法扫描。");
  const response = await fetch(artifact.url);
  if (!response.ok) throw new Error(`无法读取账单 PDF：${response.status}`);
  const blob = await response.blob();
  return normalizeBase64(await blobToBase64(blob));
}

function blobToBase64(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("无法读取 PDF 文件"));
    reader.onload = () => resolve(String(reader.result || ""));
    reader.readAsDataURL(blob);
  });
}

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("agentbrakeFusionToken") || "agentbrake-fusion-local";
  return { Authorization: `Bearer ${token}` };
}
