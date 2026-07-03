import {
  BarChart3,
  Bot,
  ClipboardCheck,
  GalleryHorizontalEnd,
  PlugZap,
  Settings,
  ShieldCheck,
  SlidersHorizontal
} from "lucide-react";
import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { createLiveObservationRun } from "../api/liveTrace";
import { AuditCenter } from "../routes/AuditCenter";
import { DecisionWorkbench } from "../routes/DecisionWorkbench";
import { ExperimentDashboard } from "../routes/ExperimentDashboard";
import { LiveConsole } from "../routes/LiveConsole";
import { Onboarding } from "../routes/Onboarding";
import { PolicyConfig } from "../routes/PolicyConfig";
import { ScenarioGallery } from "../routes/ScenarioGallery";
import { SystemSettings } from "../routes/SystemSettings";
import type { DecisionRun, ScenarioId } from "../types";
import { decisionLabel } from "../utils/display";

type NavKey = "onboarding" | "live" | "scenarios" | "workbench" | "audit" | "policy" | "experiments" | "settings";

const navItems: Array<{ id: NavKey; label: string; icon: ReactNode; subtitle: string }> = [
  { id: "onboarding", label: "接入配置", icon: <PlugZap size={18} />, subtitle: "本地网关与安全刹车" },
  { id: "live", label: "实时对话", icon: <Bot size={18} />, subtitle: "工具调用先审查" },
  { id: "scenarios", label: "场景演示", icon: <GalleryHorizontalEnd size={18} />, subtitle: "间接提示注入案例" },
  { id: "workbench", label: "裁决工作台", icon: <ShieldCheck size={18} />, subtitle: "三层裁决链路" },
  { id: "audit", label: "审计中心", icon: <ClipboardCheck size={18} />, subtitle: "轨迹回放与导出" },
  { id: "policy", label: "策略配置", icon: <SlidersHorizontal size={18} />, subtitle: "ToolGate 治理策略" },
  { id: "experiments", label: "实验成绩", icon: <BarChart3 size={18} />, subtitle: "安全与可用性结果" },
  { id: "settings", label: "系统设置", icon: <Settings size={18} />, subtitle: "接入边界说明" }
];

export function App() {
  const recordingMode = typeof window !== "undefined" && new URLSearchParams(window.location.search).has("recording");
  const [activeNav, setActiveNav] = useState<NavKey>(() => (recordingMode ? "live" : "onboarding"));
  const [scenarioId, setScenarioId] = useState<ScenarioId>("workspace");
  const [activeRun, setActiveRun] = useState<DecisionRun>(() => createLiveObservationRun({ scenarioId: "workspace" }));

  const navTitle = useMemo(() => navItems.find((item) => item.id === activeNav)?.label || "AgentBrake-Fusion", [activeNav]);

  function openRun(run: DecisionRun) {
    setActiveRun(run);
    setScenarioId(run.scenarioId);
    setActiveNav("workbench");
  }

  function updateRun(run: DecisionRun) {
    setActiveRun(run);
    setScenarioId(run.scenarioId);
  }

  return (
    <div className={`studio-app${recordingMode ? " recording-mode" : ""}`}>
      <aside className="app-nav">
        <div className="brand-block">
          <span className="brand-mark">AB</span>
          <div>
            <h1>AgentBrake-Fusion</h1>
            <p>执行前安全裁决演示工作台</p>
          </div>
        </div>
        <nav>
          {navItems.map((item) => (
            <button key={item.id} className={activeNav === item.id ? "active" : ""} onClick={() => setActiveNav(item.id)}>
              {item.icon}
              <span>
                <b>{item.label}</b>
                <em>{item.subtitle}</em>
              </span>
            </button>
          ))}
        </nav>
        <div className="nav-explainer">
          <b>5 秒主线</b>
          <p>低可信上下文污染工具参数；候选动作进入执行前网关；ActionGraph、MSJ Engine、Constraint Product Lattice 连续裁决后才允许、确认或阻断。</p>
        </div>
      </aside>

      <main className="app-main">
        <header className="app-header">
          <div>
            <span className="eyebrow">当前页面</span>
            <h2>{navTitle}</h2>
          </div>
          <div className="header-status">
            <span className="pill defense">执行前网关</span>
            <span className={`pill decision ${activeRun.finalDecision}`}>{decisionLabel(activeRun.finalDecision)}</span>
          </div>
        </header>

        <section className="app-content">
          {activeNav === "onboarding" && <Onboarding onEnterLive={() => setActiveNav("live")} />}
          {activeNav === "live" && <LiveConsole activeRun={activeRun} scenarioId={scenarioId} onRunUpdated={updateRun} />}
          {activeNav === "scenarios" && <ScenarioGallery onScenarioRun={openRun} />}
          {activeNav === "workbench" && <DecisionWorkbench run={activeRun} />}
          {activeNav === "audit" && <AuditCenter onOpenTrace={openRun} />}
          {activeNav === "policy" && <PolicyConfig onDryRun={openRun} />}
          {activeNav === "experiments" && <ExperimentDashboard />}
          {activeNav === "settings" && <SystemSettings />}
        </section>
      </main>
    </div>
  );
}
