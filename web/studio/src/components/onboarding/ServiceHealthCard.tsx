import { Activity, CheckCircle2, CircleAlert, Radio, ShieldCheck } from "lucide-react";
import type { ServiceHealth, ServiceStatus } from "../../types";
import { policyModeLabel, serviceStatusLabel } from "../../utils/display";

const labels: Array<[keyof ServiceHealth, string]> = [
  ["agentbrakeApi", "AgentBrake API"],
  ["openclawGateway", "OpenClaw Gateway"],
  ["a2aGateway", "A2A Gateway"],
  ["cliFallback", "CLI fallback"],
  ["localModel", "Local Model"],
  ["toolGuard", "ToolGate"],
  ["auditStream", "Audit Stream"]
];

export function ServiceHealthCard({ health }: { health: ServiceHealth }) {
  return (
    <section className="card service-health" data-testid="setup-status-panel">
      <div className="section-heading">
        <div>
          <h2>接入状态</h2>
          <p>这里展示后端真实检测结果。OpenClaw 不在线时不会伪造成在线。</p>
        </div>
        <span className="pill defense"><Radio size={15} /> {policyModeLabel(health.policyMode)}</span>
      </div>
      <div className="health-grid">
        {labels.map(([key, label]) => {
          const status = ((health[key] as ServiceStatus | undefined) || "offline") as ServiceStatus;
          return (
            <div className="health-item" key={key} data-testid={key === "openclawGateway" ? "openclaw-gateway-card" : undefined}>
              {statusIcon(status)}
              <div>
                <b>{label}</b>
                <span>{statusText(status)}</span>
              </div>
            </div>
          );
        })}
      </div>
      <div className="health-footer">
        <span>地址：{health.endpoint}</span>
        <span>最近检测：{new Date(health.lastCheckedAt).toLocaleTimeString()}</span>
      </div>
    </section>
  );
}

function statusIcon(status: ServiceStatus) {
  if (status === "online") return <CheckCircle2 className="icon allow" size={22} />;
  if (status === "mock") return <ShieldCheck className="icon defense" size={22} />;
  if (status === "checking") return <Activity className="icon confirm" size={22} />;
  return <CircleAlert className="icon attack" size={22} />;
}

function statusText(status: ServiceStatus): string {
  return serviceStatusLabel(status);
}
