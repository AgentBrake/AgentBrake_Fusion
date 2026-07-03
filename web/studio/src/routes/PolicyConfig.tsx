import { Download, Play, Save, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { dryRunPolicy, exportPolicy, fetchPolicy, savePolicy, type StudioPolicy } from "../api/policy";
import type { DecisionRun, ScenarioId } from "../types";

const scenarioOptions: Array<{ id: ScenarioId; label: string }> = [
  { id: "workspace", label: "工作区" },
  { id: "slack", label: "团队频道" },
  { id: "banking", label: "网银支付" },
  { id: "travel", label: "旅行预订" },
  { id: "file_sharing", label: "文件共享" },
  { id: "command_api", label: "命令与 API" }
];

export function PolicyConfig({ onDryRun }: { onDryRun: (run: DecisionRun) => void }) {
  const [policy, setPolicy] = useState<StudioPolicy | null>(null);
  const [draft, setDraft] = useState("");
  const [scenarioId, setScenarioId] = useState<ScenarioId>("workspace");
  const [message, setMessage] = useState("策略配置会直接影响 ToolGate 的执行前裁决。");

  async function load() {
    const next = await fetchPolicy();
    setPolicy(next);
    setDraft(JSON.stringify(next, null, 2));
  }

  useEffect(() => {
    void load();
  }, []);

  const parsed = useMemo(() => {
    try {
      return JSON.parse(draft) as StudioPolicy;
    } catch {
      return null;
    }
  }, [draft]);

  async function save() {
    if (!parsed) {
      setMessage("JSON 格式有误，无法保存。");
      return;
    }
    const next = await savePolicy(parsed);
    setPolicy(next);
    setDraft(JSON.stringify(next, null, 2));
    setMessage("策略已保存，并会用于后续候选工具动作审查。");
  }

  async function dryRun() {
    const run = await dryRunPolicy(scenarioId);
    setMessage(`已使用当前策略对 ${scenarioOptions.find((item) => item.id === scenarioId)?.label} 场景进行 dry-run。`);
    onDryRun(run);
  }

  async function download() {
    const content = await exportPolicy();
    const blob = new Blob([content], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "agentbrake-policy.json";
    link.click();
    URL.revokeObjectURL(url);
    setMessage("策略已导出。");
  }

  return (
    <div className="page-grid policy-page">
      <div className="page-hero">
        <div>
          <span className="eyebrow">策略配置</span>
          <h1>执行前安全刹车策略</h1>
          <p>策略把 ActionGraph 与 MSJ Engine 输出约束到 Constraint Product Lattice，不用平均分数覆盖冲突证据。</p>
        </div>
        <div className="hero-actions">
          <button onClick={download}><Download size={16} /> 导出策略</button>
          <button className="primary" onClick={save}><Save size={16} /> 保存</button>
        </div>
      </div>

      <div className="policy-layout">
        <section className="card policy-summary">
          <div className="section-heading compact">
            <h2><ShieldCheck size={18} /> 当前策略</h2>
            <p>{message}</p>
          </div>
          {policy ? (
            <div className="policy-card-grid">
              <PolicyTile label="版本" value={policy.version} />
              <PolicyTile label="执行模式" value={policy.enforcementMode} />
              <PolicyTile label="默认动作" value={policy.defaultAction} />
              <PolicyTile label="人工确认超时" value={`${policy.humanGate.timeoutSeconds} 秒`} />
              <PolicyTile label="外部网络" value={policy.networkScope.blockExternalByDefault ? "默认阻断" : "按规则放行"} />
              <PolicyTile label="私密数据外传" value={policy.dataScope.blockExternalTransfer ? "阻断" : "允许"} />
            </div>
          ) : (
            <div className="empty-state">正在加载策略。</div>
          )}
          <div className="dry-run-panel">
            <label>
              Dry-run 场景
              <select value={scenarioId} onChange={(event) => setScenarioId(event.target.value as ScenarioId)}>
                {scenarioOptions.map((item) => <option value={item.id} key={item.id}>{item.label}</option>)}
              </select>
            </label>
            <button className="primary" onClick={dryRun}><Play size={16} /> 运行策略 dry-run</button>
          </div>
        </section>

        <section className="card policy-editor">
          <div className="section-heading compact">
            <h2>JSON 策略编辑器</h2>
            <p>{parsed ? "格式有效" : "格式错误"}</p>
          </div>
          <textarea value={draft} onChange={(event) => setDraft(event.target.value)} spellCheck={false} />
        </section>
      </div>
    </div>
  );
}

function PolicyTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="policy-tile">
      <span>{label}</span>
      <b>{value}</b>
    </div>
  );
}
