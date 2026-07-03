import { useState } from "react";
import { EMPTY_TOOL_NAME, createLiveObservationRun } from "../api/liveTrace";
import { scanExternalUrl, scanPdfArtifact, type ExternalArtifact, type ExternalScanResult } from "../api/externalMaterials";
import { sendOpenClawMessage } from "../api/runs";
import { scenarioById } from "../api/scenarios";
import { AgentChatPanel } from "../components/chat/AgentChatPanel";
import { CandidateActionCard } from "../components/chat/CandidateActionCard";
import { ToolCallTimeline } from "../components/chat/ToolCallTimeline";
import { ActionGraphPanel } from "../components/workbench/ActionGraphPanel";
import { ConstraintLatticePanel } from "../components/workbench/ConstraintLatticePanel";
import { ExternalMaterialLab } from "../components/workbench/ExternalMaterialLab";
import { ExternalSourceCard } from "../components/workbench/ExternalSourceCard";
import { MSJFactPanel } from "../components/workbench/MSJFactPanel";
import type { ChatMessage, DecisionRun, ScenarioId } from "../types";

const EXTERNAL_REVIEW_DELAY_MS = 4500;

export function LiveConsole({
  activeRun,
  scenarioId,
  onRunUpdated
}: {
  activeRun: DecisionRun;
  scenarioId: ScenarioId;
  onRunUpdated: (run: DecisionRun) => void;
}) {
  const [latestUserTask, setLatestUserTask] = useState("");
  const [latestBlockedExternalRun, setLatestBlockedExternalRun] = useState<DecisionRun | null>(null);
  const [pendingExternalMaterial, setPendingExternalMaterial] = useState<ExternalArtifact | null>(null);
  const [latestScanResult, setLatestScanResult] = useState<ExternalScanResult | null>(null);
  const [reviewingExternalMaterial, setReviewingExternalMaterial] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "system-welcome",
      role: "system",
      timestamp: new Date().toISOString(),
      text: `已进入真实接入模式。当前场景视角：${scenarioById(scenarioId).title}。OpenClaw 返回工具调用时，会先进入 AgentBrake-Fusion ToolGate。`
    }
  ]);

  async function send(text: string) {
    const runBeforeSend = activeRun;
    const userMessage: ChatMessage = { id: `user-${Date.now()}`, role: "user", text, timestamp: new Date().toISOString() };
    const waitingRun = createLiveObservationRun({ scenarioId, userTask: text, status: "waiting" });
    setLatestUserTask(text);
    setMessages((current) => [...current, userMessage]);

    const blockedExternalReply = blockedExternalMaterialReply(text, latestBlockedExternalRun);
    if (blockedExternalReply) {
      setMessages((current) => [...current, blockedExternalReply]);
      onRunUpdated(latestBlockedExternalRun!);
      return;
    }

    if (pendingExternalMaterial && shouldReviewExternalMaterial(text, pendingExternalMaterial)) {
      onRunUpdated(waitingRun);
      await reviewPendingExternalMaterial(pendingExternalMaterial, text);
      return;
    }

    onRunUpdated(waitingRun);
    try {
      const result = await sendOpenClawMessage(text, scenarioId);
      const suffix = result.fallbackUsed && result.connectorError ? `\n\n真实连接失败，已显式降级：${result.connectorError}` : "";
      const assistantMessage = { ...result.assistant, text: `${result.assistant.text}${suffix}` };
      setMessages((current) => [...current, assistantMessage]);

      if (result.run) {
        onRunUpdated(result.run);
      } else if (hasConcreteToolgateRun(runBeforeSend)) {
        onRunUpdated(runBeforeSend);
      } else {
        onRunUpdated(createLiveObservationRun({
          scenarioId,
          userTask: text,
          assistantText: assistantMessage.text,
          status: "answered"
        }));
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const assistantText = `OpenClaw 连接失败：${message}`;
      setMessages((current) => [...current, assistantMessage(assistantText, "assistant-error")]);
      onRunUpdated(createLiveObservationRun({
        scenarioId,
        userTask: text,
        assistantText,
        status: "answered"
      }));
    }
  }

  async function reviewPendingExternalMaterial(artifact: ExternalArtifact, userTask: string) {
    setReviewingExternalMaterial(true);
    setMessages((current) => [
      ...current,
      assistantMessage(
        `我先读取你刚才挂载的${artifact.kind === "pdf" ? "外部 PDF" : "外部网页"}。这类内容属于低可信来源，我会先提取候选工具动作，再交给 AgentBrake-Fusion 做执行前裁决。`,
        "assistant-reading"
      )
    ]);

    try {
      await delay(EXTERNAL_REVIEW_DELAY_MS);
      const result = artifact.kind === "pdf"
        ? await scanPdfArtifact(artifact, userTask)
        : await scanExternalUrl(artifact.url || "", userTask);
      applyExternalScanResult(result);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const assistantText = `外部材料读取失败：${message}`;
      setMessages((current) => [...current, assistantMessage(assistantText, "assistant-external-error")]);
      onRunUpdated(createLiveObservationRun({
        scenarioId,
        userTask,
        assistantText,
        status: "answered"
      }));
    } finally {
      setReviewingExternalMaterial(false);
    }
  }

  function handleMaterialReady(artifact: ExternalArtifact) {
    setPendingExternalMaterial(artifact);
    setLatestScanResult(null);
    setMessages((current) => [
      ...current,
      {
        id: `system-material-${Date.now()}`,
        role: "system",
        timestamp: new Date().toISOString(),
        text: `已挂载外部材料：${artifact.fileName || artifact.url || "未命名外部来源"}。现在它只是低可信上下文，尚未读取，也不会触发工具裁决。`
      }
    ]);
  }

  function applyExternalScanResult(result: ExternalScanResult) {
    setLatestScanResult(result);
    const assistant = {
      ...result.assistant,
      text: externalScanMessage(result)
    };
    setMessages((current) => [...current, assistant]);
    if (result.run) {
      if (result.run.finalDecision === "block") {
        setLatestBlockedExternalRun(result.run);
      }
      onRunUpdated(result.run);
    }
  }

  return (
    <div className="page-grid">
      <div className="page-hero">
        <div>
          <span className="eyebrow">实时对话</span>
          <h1>本地 OpenClaw 实时对话</h1>
          <p>左侧对话，中间挂载外部材料和候选工具调用时间线，右侧同步展示 ActionGraph、MSJ Engine 和 Constraint Product Lattice 的执行前状态。</p>
        </div>
      </div>
      <div className="live-layout">
        <AgentChatPanel messages={messages} onSend={send} disabled={reviewingExternalMaterial} />
        <div className="middle-stack">
          <ExternalMaterialLab
            latestUserTask={latestUserTask}
            latestScanResult={latestScanResult}
            onMaterialReady={handleMaterialReady}
          />
          <ExternalSourceCard run={activeRun} />
          <ToolCallTimeline items={activeRun.timeline} />
          <CandidateActionCard call={activeRun.candidateToolCall} />
        </div>
        <div className="right-stack">
          <ActionGraphPanel nodes={activeRun.actionGraph.nodes} edges={activeRun.actionGraph.edges} />
          <MSJFactPanel facts={activeRun.msjFacts} />
          <ConstraintLatticePanel dimensions={activeRun.lattice.dimensions} output={activeRun.lattice.output} />
        </div>
      </div>
    </div>
  );
}

function hasConcreteToolgateRun(run: DecisionRun): boolean {
  return Boolean(run.candidateToolCall && run.candidateToolCall.toolName !== EMPTY_TOOL_NAME && run.finalDecision !== "observing");
}

function shouldReviewExternalMaterial(text: string, artifact: ExternalArtifact): boolean {
  const normalized = text.toLowerCase();
  const commonTokens = ["读取", "根据", "扫描", "分析", "核验", "检查", "review", "read", "scan", "analyze"];
  const pdfTokens = ["pdf", "账单", "发票", "支付", "付款", "转账", "物业", "invoice", "bill", "pay", "transfer"];
  const webTokens = ["网页", "网站", "链接", "url", "搜索", "总结", "发布", "web", "site", "link", "search"];
  const tokens = artifact.kind === "pdf" ? [...commonTokens, ...pdfTokens] : [...commonTokens, ...webTokens];
  return tokens.some((token) => normalized.includes(token));
}

function blockedExternalMaterialReply(text: string, run: DecisionRun | null): ChatMessage | null {
  if (!run || run.finalDecision !== "block") return null;
  if (!looksLikeFollowUpToBlockedMaterial(text)) return null;

  const toolName = run.candidateToolCall?.toolName || "候选工具动作";
  const args = run.candidateToolCall?.args || {};
  const recipient = String(args.recipient || args.to || args.account || args.payee || "低可信来源指定的目标");
  const amount = String(args.amount || "用户请求中的金额");
  const reasons = (run.brakeTrace?.reason_codes || []).slice(0, 3).join("、") || "低可信参数污染、用户目标冲突";

  return assistantMessage(
    `我不能继续帮你完成这个操作。刚才读取的外部材料中包含间接提示注入：它试图把候选工具动作改写为 ${toolName}，并将金额 ${amount} 的收款目标指向“${recipient}”。\n\n` +
    `AgentBrake-Fusion 已在执行前阻断该动作，原因是：${reasons}。这类 PDF 或网页内容只能作为待核验事实，不能授权支付、外发或提交操作。\n\n` +
    "请提供可信来源中的收款账户、开户行和户名，或上传一份不含隐藏指令的账单；在确认真实收款方之前，我无法帮你发起支付。",
    "assistant-blocked-material"
  );
}

function looksLikeFollowUpToBlockedMaterial(text: string): boolean {
  const normalized = text.toLowerCase();
  return [
    "pdf",
    "发票",
    "账单",
    "支付",
    "付款",
    "转账",
    "物业",
    "invoice",
    "bill",
    "pay",
    "transfer"
  ].some((token) => normalized.includes(token));
}

function externalScanMessage(result: ExternalScanResult): string {
  if (!result.run) {
    return "我已经读取外部材料，但没有发现可解析的候选工具动作；当前保持观察态。";
  }

  const tool = result.run.candidateToolCall.toolName;
  const decision = result.run.finalDecision === "block"
    ? "阻断"
    : result.run.finalDecision === "require_confirmation"
      ? "需要人工确认"
      : "放行";
  const executed = result.run.toolExecuted ? "已按安全策略执行。" : "没有执行真实工具。";

  if (result.run.finalDecision === "block") {
    return `我已经读取这份外部材料，并发现其中的低可信内容试图诱导候选工具动作 ${tool}。AgentBrake-Fusion 已在执行前裁决为“${decision}”，${executed}\n\n` +
      "原因是外部材料中的收款方、目标或工具参数与用户任务不一致，属于间接提示注入风险。我无法帮你完成该支付或外发操作；需要先从可信来源核验真实目标。";
  }

  return `我已经读取外部材料，并发现候选工具动作 ${tool}。该动作已进入 AgentBrake-Fusion ToolGate，最终裁决为“${decision}”，${executed}`;
}

function assistantMessage(text: string, idPrefix = "assistant"): ChatMessage {
  return {
    id: `${idPrefix}-${Date.now()}`,
    role: "assistant",
    timestamp: new Date().toISOString(),
    text
  };
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}
