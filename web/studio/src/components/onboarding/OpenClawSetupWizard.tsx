import { CheckCircle2, ClipboardList, Play, RadioTower, Shield, TerminalSquare } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { applyGuardConfig, getOpenClawStatus, guardConfigSnippet, normalizeConfig, runGuardTests } from "../../api/openclaw";
import type { GuardConfig, SetupCheck } from "../../types";

const modes: Array<{ id: GuardConfig["mode"]; title: string; text: string; testId?: string }> = [
  { id: "gateway_http", title: "Gateway HTTP", text: "通过本地 OpenClaw Gateway HTTP 接口发送消息并捕获候选工具调用。", testId: "mode-openclaw-gateway" },
  { id: "gateway_ws", title: "Gateway WebSocket", text: "通过 WebSocket 接收 OpenClaw 事件流和候选工具调用。" },
  { id: "a2a", title: "A2A Gateway", text: "通过 A2A Gateway 和 Agent ID 接入本地智能体。" },
  { id: "cli", title: "CLI fallback", text: "本地没有网关时，通过 OpenClaw CLI 发起任务。" },
  { id: "mock", title: "Mock Demo", text: "仅在真实连接失败或现场无 OpenClaw 时使用显式演示模式。" }
];

const modelOptions = [
  { value: "qwen-plus", label: "qwen-plus（推荐演示）" },
  { value: "qwen-max", label: "qwen-max" },
  { value: "qwen-turbo", label: "qwen-turbo" },
  { value: "deepseek-v4-flash", label: "deepseek-v4-flash" },
  { value: "local-model", label: "local-model / OpenClaw 默认模型" },
  { value: "__custom__", label: "自定义模型名称..." }
];

export function OpenClawSetupWizard({ onEnterLive }: { onEnterLive: () => void }) {
  const [step, setStep] = useState(1);
  const [config, setConfig] = useState<GuardConfig>(() =>
    normalizeConfig({
      mode: "gateway_http",
      baseUrl: "http://127.0.0.1:18789",
      gatewayUrl: "http://127.0.0.1:18789",
      authToken: "",
      a2aUrl: "http://127.0.0.1:18800",
      a2aAgentId: "main",
      openclawAgentId: "main",
      cliPath: "openclaw",
      modelRef: "qwen-plus",
      modelBaseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1",
      modelApiKey: "",
      chatEndpoint: "",
      eventsEndpoint: "",
      toolCallEndpoint: "",
      openaiCompatible: true,
      policyMode: "enforce",
      auditStream: true,
      preExecutionGate: true,
      sandbox: true,
      allowRealTools: false
    })
  );
  const [checks, setChecks] = useState<SetupCheck[]>([]);
  const [message, setMessage] = useState("请先检测服务，然后应用本地 OpenClaw 接入配置。");
  const [checking, setChecking] = useState(false);
  const snippet = useMemo(() => guardConfigSnippet(config), [config]);

  useEffect(() => {
    void detectServices(false);
  }, []);

  async function detectServices(showMessage = true) {
    setChecking(true);
    try {
      const status = await getOpenClawStatus();
      if (status.config) {
        const cfg = status.config as Partial<GuardConfig>;
        setConfig((current) =>
          normalizeConfig({
            ...current,
            ...cfg,
            authToken: current.authToken || "",
            modelApiKey: current.modelApiKey || "",
            modelRef: cfg.modelRef || current.modelRef || "qwen-plus"
          } as GuardConfig)
        );
      }
      if (showMessage) {
        setMessage(status.ok ? "检测成功：OpenClaw 接入链路可用。" : `检测失败：${status.repairHints?.join("；") || "请检查网关地址、token 和 endpoint。"}`);
      }
    } catch (error) {
      if (showMessage) setMessage(`检测失败：${error instanceof Error ? error.message : String(error)}`);
    } finally {
      setChecking(false);
    }
  }

  async function applyConfig() {
    try {
      const result = await applyGuardConfig(config);
      setMessage(result.status?.ok ? "配置已应用，真实连接检测通过。" : "配置已应用，但真实连接仍未通过；可检查状态卡中的失败原因。");
      setStep(4);
    } catch (error) {
      setMessage(`配置失败：${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async function testGuard() {
    try {
      setChecks(await runGuardTests());
      setStep(5);
    } catch (error) {
      setMessage(`接入测试失败：${error instanceof Error ? error.message : String(error)}`);
    }
  }

  return (
    <section className="card setup-wizard">
      <div className="wizard-steps" aria-label="OpenClaw 接入步骤">
        {[
          ["1", "检测服务"],
          ["2", "选择模式"],
          ["3", "应用配置"],
          ["4", "运行测试"],
          ["5", "实时对话"]
        ].map(([num, label]) => (
          <button key={num} className={step === Number(num) ? "active" : ""} onClick={() => setStep(Number(num))}>
            <span>{num}</span>
            {label}
          </button>
        ))}
      </div>

      {step === 1 && (
        <div className="wizard-panel">
          <h2><RadioTower size={20} /> 检测本地接入链路</h2>
          <p>后端会真实检测 AgentBrake API、OpenClaw Gateway、A2A Gateway、CLI fallback、ToolGate 和审计流，不会伪造在线状态。</p>
          <div className="check-grid">
            {["AgentBrake API", "OpenClaw Gateway", "A2A Gateway", "CLI fallback", "ToolGate", "Audit Stream"].map((item) => (
              <div className="check-card" key={item}><CheckCircle2 size={18} /> {item}<span>点击检测服务后查看状态卡</span></div>
            ))}
          </div>
          <div className="button-row">
            <button onClick={() => void detectServices()} disabled={checking}>{checking ? "检测中..." : "检测服务"}</button>
            <button className="primary" onClick={() => setStep(2)}>继续选择接入模式</button>
          </div>
          <p className="audit-message">{message}</p>
        </div>
      )}

      {step === 2 && (
        <div className="wizard-panel">
          <h2><ClipboardList size={20} /> 选择运行模式</h2>
          <div className="mode-grid">
            {modes.map((mode) => (
              <button
                key={mode.id}
                data-testid={mode.testId}
                className={config.mode === mode.id ? "mode-card active" : "mode-card"}
                onClick={() => setConfig(normalizeConfig({ ...config, mode: mode.id }))}
              >
                <b>{mode.title}</b>
                <span>{mode.text}</span>
              </button>
            ))}
          </div>
          <div className="form-grid">
            <Field testId="gateway-url-input" label="OpenClaw Gateway 地址" value={config.gatewayUrl || ""} onChange={(value) => setConfig(normalizeConfig({ ...config, gatewayUrl: value, baseUrl: value }))} />
            <Field label="OpenClaw Token" type="password" value={config.authToken || ""} onChange={(value) => setConfig(normalizeConfig({ ...config, authToken: value }))} />
            <Field label="OpenClaw Agent ID" value={config.openclawAgentId || ""} onChange={(value) => setConfig(normalizeConfig({ ...config, openclawAgentId: value }))} />
            <Field label="Chat endpoint" value={config.chatEndpoint || ""} placeholder="/chat 或 /chat/completions" onChange={(value) => setConfig(normalizeConfig({ ...config, chatEndpoint: value }))} />
            <Field label="Events endpoint" value={config.eventsEndpoint || ""} placeholder="/events 或 /ws/events" onChange={(value) => setConfig(normalizeConfig({ ...config, eventsEndpoint: value }))} />
            <Field label="Tool endpoint" value={config.toolCallEndpoint || ""} placeholder="/tool-calls/invoke，可留空走 dry-run" onChange={(value) => setConfig(normalizeConfig({ ...config, toolCallEndpoint: value }))} />
            <Field label="A2A 地址" value={config.a2aUrl || ""} onChange={(value) => setConfig(normalizeConfig({ ...config, a2aUrl: value }))} />
            <Field label="A2A Agent ID" value={config.a2aAgentId || ""} onChange={(value) => setConfig(normalizeConfig({ ...config, a2aAgentId: value }))} />
            <Field label="OpenClaw CLI" value={config.cliPath || ""} onChange={(value) => setConfig(normalizeConfig({ ...config, cliPath: value }))} />
            <ModelSelector value={config.modelRef || "qwen-plus"} onChange={(value) => setConfig(normalizeConfig({ ...config, modelRef: value }))} />
            <Field label="模型 API URL" value={config.modelBaseUrl || ""} placeholder="https://dashscope.aliyuncs.com/compatible-mode/v1" onChange={(value) => setConfig(normalizeConfig({ ...config, modelBaseUrl: value }))} />
            <Field label="Qwen / DashScope API Key" type="password" value={config.modelApiKey || ""} placeholder="录制时可现场填写，页面不会回显明文" onChange={(value) => setConfig(normalizeConfig({ ...config, modelApiKey: value }))} />
            <label className="field-label">
              策略模式
              <select value={config.policyMode} onChange={(event) => setConfig(normalizeConfig({ ...config, policyMode: event.target.value as GuardConfig["policyMode"] }))}>
                <option value="enforce">强制执行</option>
                <option value="observe_only">仅观察</option>
              </select>
            </label>
          </div>
          <div className="toggle-row">
            <label><input type="checkbox" checked={config.openaiCompatible !== false} onChange={(event) => setConfig(normalizeConfig({ ...config, openaiCompatible: event.target.checked }))} /> OpenAI-compatible</label>
            <label><input type="checkbox" checked={config.auditStream} onChange={(event) => setConfig(normalizeConfig({ ...config, auditStream: event.target.checked }))} /> 开启审计流</label>
            <label><input type="checkbox" checked={config.preExecutionGate} onChange={(event) => setConfig(normalizeConfig({ ...config, preExecutionGate: event.target.checked }))} /> 强制执行前网关</label>
            <label><input type="checkbox" checked={config.sandbox !== false} onChange={(event) => setConfig(normalizeConfig({ ...config, sandbox: event.target.checked }))} /> 沙箱 dry-run</label>
            <label><input type="checkbox" checked={config.allowRealTools === true} onChange={(event) => setConfig(normalizeConfig({ ...config, allowRealTools: event.target.checked }))} /> 允许真实工具执行</label>
          </div>
          <button className="primary" onClick={() => setStep(3)}>生成安全刹车配置</button>
        </div>
      )}

      {step === 3 && (
        <div className="wizard-panel">
          <h2><TerminalSquare size={20} /> AgentBrake-Fusion guard 配置</h2>
          <p>应用后，后端会把配置写入本地 .env/runtime config。Token 只保存在本地，不会进入前端截图、README 或打包材料。</p>
          <pre className="code-block">{snippet}</pre>
          <button className="primary" data-testid="apply-config-button" onClick={applyConfig}>应用配置</button>
          <p className="audit-message">{message}</p>
        </div>
      )}

      {step === 4 && (
        <div className="wizard-panel">
          <h2><Shield size={20} /> 运行放行与阻断测试</h2>
          <p>{message}</p>
          <button className="primary" data-testid="run-test-button" onClick={testGuard}><Play size={16} /> 运行接入测试</button>
        </div>
      )}

      {step === 5 && (
        <div className="wizard-panel">
          <h2><CheckCircle2 size={20} /> 准备进入实时对话</h2>
          <div className="check-grid">
            {checks.map((check) => (
              <div className="check-card" key={check.id}><CheckCircle2 size={18} /> {check.label}<span>{check.detail}</span></div>
            ))}
          </div>
          <button className="primary" onClick={onEnterLive}>进入实时对话</button>
        </div>
      )}
    </section>
  );
}

function ModelSelector({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const known = modelOptions.some((option) => option.value === value && option.value !== "__custom__");
  const selected = known ? value : "__custom__";
  return (
    <label className="field-label">
      模型名称
      <select value={selected} onChange={(event) => {
        const next = event.target.value;
        onChange(next === "__custom__" ? "" : next);
      }}>
        {modelOptions.map((option) => (
          <option key={option.value} value={option.value}>{option.label}</option>
        ))}
      </select>
      {selected === "__custom__" && (
        <input
          value={value === "__custom__" ? "" : value}
          placeholder="输入自定义模型名称，例如 qwen2.5-72b-instruct"
          onChange={(event) => onChange(event.target.value)}
        />
      )}
    </label>
  );
}

function Field({
  label,
  value,
  onChange,
  testId,
  type = "text",
  placeholder
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  testId?: string;
  type?: string;
  placeholder?: string;
}) {
  return (
    <label className="field-label">
      {label}
      <input data-testid={testId} type={type} value={value} placeholder={placeholder} onChange={(event) => onChange(event.target.value)} />
    </label>
  );
}
