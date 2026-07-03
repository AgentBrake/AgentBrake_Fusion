import { RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";
import { getServiceHealth } from "../api/openclaw";
import { OpenClawSetupWizard } from "../components/onboarding/OpenClawSetupWizard";
import { ServiceHealthCard } from "../components/onboarding/ServiceHealthCard";
import type { ServiceHealth } from "../types";

export function Onboarding({ onEnterLive }: { onEnterLive: () => void }) {
  const [health, setHealth] = useState<ServiceHealth | null>(null);

  async function refresh() {
    setHealth(await getServiceHealth());
  }

  useEffect(() => {
    void refresh();
  }, []);

  return (
    <div className="page-grid onboarding-page">
      <div className="page-hero">
        <div>
          <span className="eyebrow">接入配置</span>
          <h1>把 AgentBrake-Fusion 接到本地 OpenClaw</h1>
          <p>这里完成真实服务检测、Gateway/A2A/CLI 配置、ToolGate 测试和实时对话入口。候选工具调用必须先经过执行前裁决，不能直接执行。</p>
        </div>
        <button onClick={refresh}><RefreshCw size={16} /> 重新检测</button>
      </div>
      {health ? <ServiceHealthCard health={health} /> : null}
      <OpenClawSetupWizard onEnterLive={onEnterLive} />
    </div>
  );
}
