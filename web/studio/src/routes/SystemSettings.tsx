import { Activity, CheckCircle2, ClipboardCheck, Shield, TerminalSquare } from "lucide-react";
import { useEffect, useState } from "react";
import { getOpenClawStatus, type OpenClawStatus } from "../api/openclaw";
import { setupModeLabel } from "../utils/display";

export function SystemSettings() {
  const [status, setStatus] = useState<OpenClawStatus | null>(null);

  useEffect(() => {
    getOpenClawStatus()
      .then(setStatus)
      .catch(() => setStatus(null));
  }, []);

  const config = (status?.config || {}) as Record<string, unknown>;

  return (
    <div className="page-grid settings-page">
      <div className="page-hero">
        <div>
          <span className="eyebrow">系统设置</span>
          <h1>接入边界与安全约束</h1>
          <p>默认沙箱和 dry-run。真实工具执行必须同时满足 ToolGate 放行、关闭 sandbox、显式允许真实工具，并配置真实工具 endpoint。</p>
        </div>
      </div>

      <div className="settings-grid">
        <section className="card settings-card">
          <h2><Activity size={18} /> OpenClaw 接入状态</h2>
          <div className="settings-list">
            <SettingRow label="运行模式" value={setupModeLabel(status?.mode || "gateway_http")} />
            <SettingRow label="Gateway 地址" value={String(config.gatewayUrl || config.baseUrl || "http://127.0.0.1:18789")} />
            <SettingRow label="A2A 地址" value={String(config.a2aUrl || "未配置")} />
            <SettingRow label="CLI 路径" value={String(config.cliPath || "openclaw")} />
            <SettingRow label="Chat endpoint" value={String(config.chatEndpoint || "自动")} />
            <SettingRow label="Events endpoint" value={String(config.eventsEndpoint || "自动")} />
            <SettingRow label="Tool endpoint" value={String(config.toolCallEndpoint || "未配置，默认 dry-run")} />
            <SettingRow label="沙箱执行" value={config.sandbox === false ? "关闭" : "开启"} />
            <SettingRow label="真实工具执行" value={config.allowRealTools ? "已允许" : "默认禁止"} />
          </div>
        </section>

        <section className="card settings-card">
          <h2><Shield size={18} /> 安全边界</h2>
          <ul className="plain-list">
            <li>ToolGate 是执行前网关；OpenClaw 可以提出工具调用，但不能绕过审查直接执行。</li>
            <li>低可信上下文只能作为证据进入 ActionGraph，不能直接授权副作用动作。</li>
            <li>MSJ Engine 只输出结构化事实，不输出加权总分或置信度条。</li>
            <li>Constraint Product Lattice 通过维度 join 保留冲突证据，并映射为放行、确认或阻断。</li>
          </ul>
        </section>

        <section className="card settings-card">
          <h2><TerminalSquare size={18} /> 后端接口约定</h2>
          <pre className="code-block">{`GET  /api/openclaw/status
POST /api/openclaw/config
POST /api/chat/session
POST /api/chat/session/:id/message
GET  /api/openclaw/events?sessionId=:id
POST /api/tool-proxy/invoke
POST /api/toolgate/review
GET  /api/toolgate/trace/:traceId
GET  /api/audit`}</pre>
        </section>

        <section className="card settings-card">
          <h2><ClipboardCheck size={18} /> 修复提示</h2>
          {status?.repairHints?.length ? (
            <ul className="plain-list">
              {status.repairHints.map((hint) => <li key={hint}>{hint}</li>)}
            </ul>
          ) : (
            <p className="settings-ok"><CheckCircle2 size={16} /> 当前配置可进入本地接入或显式演示模式。</p>
          )}
        </section>
      </div>
    </div>
  );
}

function SettingRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="setting-row">
      <span>{label}</span>
      <b>{value}</b>
    </div>
  );
}
