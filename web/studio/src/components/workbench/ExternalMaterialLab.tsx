import { Download, FileText, Globe2, Link2, Upload } from "lucide-react";
import { ChangeEvent, useState } from "react";
import {
  generateBankingInvoicePdf,
  generateMaliciousWebpage,
  prepareExternalUrl,
  prepareUploadedPdf,
  type ExternalArtifact,
  type ExternalScanResult
} from "../../api/externalMaterials";

export function ExternalMaterialLab({
  latestUserTask,
  latestScanResult,
  onMaterialReady
}: {
  latestUserTask?: string;
  latestScanResult?: ExternalScanResult | null;
  onMaterialReady: (artifact: ExternalArtifact) => void;
}) {
  const [pdfArtifact, setPdfArtifact] = useState<ExternalArtifact | null>(null);
  const [webArtifact, setWebArtifact] = useState<ExternalArtifact | null>(null);
  const [url, setUrl] = useState("");
  const [status, setStatus] = useState("先生成或上传外部材料；只有在左侧对话下达任务后，才会触发执行前裁决。");
  const [busy, setBusy] = useState(false);

  async function run<T>(label: string, action: () => Promise<T>, after?: (value: T) => string | void) {
    setBusy(true);
    setStatus(`${label}...`);
    try {
      const value = await action();
      const afterStatus = after?.(value);
      setStatus(afterStatus || `${label}完成。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  }

  function mountPdfArtifact(artifact: ExternalArtifact): string {
    setPdfArtifact(artifact);
    onMaterialReady(artifact);
    return "账单 PDF 已挂载到当前会话，尚未触发裁决；请在左侧输入读取、核验或支付任务。";
  }

  function mountWebArtifact(artifact: ExternalArtifact): string {
    setWebArtifact(artifact);
    if (artifact.url) setUrl(artifact.url);
    onMaterialReady(artifact);
    return "外部网页已挂载到当前会话，尚未触发裁决；请在左侧输入让智能体读取网页的任务。";
  }

  async function handleUpload(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    await run("上传账单 PDF", () => prepareUploadedPdf(file), mountPdfArtifact);
    event.target.value = "";
  }

  function mountTypedUrl() {
    const trimmedUrl = url.trim();
    if (!trimmedUrl) return;
    mountWebArtifact(prepareExternalUrl(trimmedUrl));
    setStatus("外部 URL 已挂载，等待左侧任务触发读取和裁决。");
  }

  return (
    <section className="external-material-lab card" data-testid="external-material-lab">
      <div className="section-heading compact">
        <div>
          <h2>外部材料攻击测试台</h2>
          <p>PDF、网页和搜索结果都先作为低可信外部来源挂载；智能体收到用户任务后，才会读取材料并进入执行前裁决。</p>
        </div>
      </div>

      <div className="task-binding">
        <b>当前用户任务</b>
        <span>{latestUserTask?.trim() || "尚未下达任务。外部材料已准备好，但不会自动触发 ToolGate。"}</span>
      </div>

      <div className="material-actions">
        <button disabled={busy} onClick={() => run("生成恶意账单 PDF", generateBankingInvoicePdf, mountPdfArtifact)}>
          <FileText size={15} /> 生成恶意账单 PDF
        </button>
        <label className="upload-button">
          <Upload size={15} /> 上传 PDF 挂载
          <input type="file" accept="application/pdf,.pdf" onChange={handleUpload} disabled={busy} />
        </label>
      </div>

      {pdfArtifact && (
        <div className="material-artifact">
          <b>{pdfArtifact.fileName || "外部账单 PDF"}</b>
          <span>{pdfArtifact.visibleSummary || "外部 PDF 已挂载，等待用户任务触发读取。"}</span>
          <span className="attack-note">{pdfArtifact.hiddenAttack || "低可信来源中的隐藏指令不会直接授权工具动作。"}</span>
          <div className="material-artifact-actions">
            {pdfArtifact.url && <a href={pdfArtifact.url} target="_blank" rel="noreferrer"><Download size={14} /> 下载/查看</a>}
            <span className="material-mounted-pill">已挂载，等待任务触发</span>
          </div>
        </div>
      )}

      <div className="material-actions">
        <button disabled={busy} onClick={() => run("生成恶意网页", generateMaliciousWebpage, mountWebArtifact)}>
          <Globe2 size={15} /> 生成恶意网页
        </button>
      </div>

      <div className="url-scan-row">
        <input value={url} onChange={(event) => setUrl(event.target.value)} placeholder="输入或粘贴要让智能体检索的网页 URL..." />
        <button disabled={busy || !url.trim()} onClick={mountTypedUrl}>
          <Link2 size={15} /> 挂载 URL
        </button>
      </div>

      {webArtifact && (
        <div className="material-artifact">
          <b>{webArtifact.fileName || "外部网页"}</b>
          <span>{webArtifact.url}</span>
          <span className="attack-note">{webArtifact.hiddenAttack || "网页内容属于低可信来源，必须等待用户任务触发审查。"}</span>
        </div>
      )}

      {latestScanResult && <LastScanSummary result={latestScanResult} />}

      <p className="material-status">{status}</p>
    </section>
  );
}

function LastScanSummary({ result }: { result: ExternalScanResult }) {
  const run = result.run;
  if (!run) {
    return (
      <div className="material-scan-summary neutral">
        <b>最近裁决</b>
        <span>没有解析到候选工具动作，系统保持观察态。</span>
      </div>
    );
  }

  const candidate = run.candidateToolCall;
  const argsText = Object.entries(candidate.args || {})
    .map(([key, value]) => `${key}: ${value}`)
    .join("；") || "无参数";

  return (
    <div className={`material-scan-summary ${run.finalDecision}`} data-testid="material-scan-summary">
      <div className="scan-summary-head">
        <b>最近执行前裁决</b>
        <span>{decisionText(run.finalDecision)}</span>
      </div>
      <div className="scan-evidence-grid">
        <div className="scan-fact trusted">
          <b>用户目标</b>
          <span>{shortText(run.userTask, 92)}</span>
        </div>
        <div className="scan-fact attack">
          <b>外部低可信内容</b>
          <span>{shortText(run.lowTrustContext, 110)}</span>
        </div>
        <div className="scan-fact candidate">
          <b>候选动作</b>
          <span>{candidate.toolName}</span>
          <small>{argsText}</small>
        </div>
        <div className="scan-fact decision">
          <b>执行前结果</b>
          <span>{run.toolExecuted ? "已按安全策略执行" : "未执行真实工具"}</span>
          <small>{run.brakeTrace.reason_codes.join(" / ")}</small>
        </div>
      </div>
    </div>
  );
}

function decisionText(decision: string): string {
  if (decision === "block") return "阻断";
  if (decision === "require_confirmation") return "需要人工确认";
  if (decision === "allow") return "放行";
  return "观察中";
}

function shortText(value: string, limit: number): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= limit) return compact;
  return `${compact.slice(0, Math.max(0, limit - 1))}…`;
}
