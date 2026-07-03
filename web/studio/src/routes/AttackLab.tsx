import type { RunSummary, ScenarioSpec } from "../types";
import { DecisionBadge, displayLabel } from "../components/DecisionBadge";
import { actionLabel, runSubtitle, runTitle, scenarioSubtitle, scenarioTitle } from "../components/displayText";

function latestRunFor(scenarioId: string, runs: RunSummary[]): RunSummary | undefined {
  return runs.find((run) => run.demo_scenario_id === scenarioId);
}

function runCard(run?: RunSummary, onOpenRun?: (runId: string) => void) {
  if (!run) return <div className="empty-state">请先运行这一侧的场景。</div>;
  return (
    <button className="compare-column" onClick={() => onOpenRun?.(run.run_id)}>
      <b>{runTitle(run)}</b>
      <div className="run-purpose">{runSubtitle(run)}</div>
      <div className="muted">{run.event_count} 个事件 · {run.action_count} 个动作 · {run.agent_name}</div>
      <DecisionBadge label={run.latest_decision || "observing"} severity={run.blocked_count ? "critical" : "normal"} />
    </button>
  );
}

function diffRow(label: string, normal?: RunSummary, attack?: RunSummary, pick: (run: RunSummary) => string | number = (run) => run.event_count) {
  return (
    <div className="diff-row">
      <span>{label}</span>
        <b>{normal ? displayLabel(pick(normal)) : "无数据"}</b>
        <b>{attack ? displayLabel(pick(attack)) : "无数据"}</b>
    </div>
  );
}

export function AttackLab({ scenarios, runs, onRunScenario, onOpenRun }: { scenarios: ScenarioSpec[]; runs: RunSummary[]; onRunScenario: (scenarioId: string) => void | Promise<void>; onOpenRun: (runId: string) => void }) {
  const normal = runs.find((run) => run.demo_scenario_id === "normal-login-fix");
  const attack = runs.find((run) => run.demo_scenario_id && run.demo_scenario_id !== "normal-login-fix");
  async function runPair(scenarioId: string) {
    await onRunScenario("normal-login-fix");
    if (scenarioId !== "normal-login-fix") await onRunScenario(scenarioId);
  }
  return (
    <>
      <div className="storyboard">
        <div className="story-step normal"><b>1. 正常任务</b><span>构建任务契约，允许源码编辑，将测试执行约束到沙箱。</span></div>
        <div className="story-step warning"><b>2. 低可信上下文</b><span>Issue、README、MCP 或 memory 内容会被标记为低可信来源。</span></div>
        <div className="story-step critical"><b>3. 危险动作</b><span>模型提出依赖安装、读取 secret、修改 CI 或网络外传等动作。</span></div>
        <div className="story-step info"><b>4. AgentBrake-Fusion 决策</b><span>通过结构化动作、命中规则和证据引用解释为什么阻断。</span></div>
      </div>
      <div className="scenario-grid">
        {scenarios.map((scenario) => {
          const latest = latestRunFor(scenario.id, runs);
          return (
          <div className="scenario-card" key={scenario.id}>
            <div className="scenario-card-head">
              <DecisionBadge label={scenario.kind} severity={scenario.kind === "attack" ? "critical" : "normal"} />
              {latest ? <DecisionBadge label={latest.latest_decision || "已观测"} severity={latest.blocked_count ? "critical" : "normal"} /> : <DecisionBadge label="未运行" severity="info" />}
            </div>
            <h3>{scenarioTitle(scenario)}</h3>
            <p className="muted">{scenarioSubtitle(scenario)}</p>
            {scenario.attack_body ? <pre className="attack-input">{scenario.attack_body}</pre> : <div className="empty-state">正常场景，没有攻击载荷。</div>}
            <div className="scenario-expect">
              <span>危险动作</span><b>{actionLabel(scenario.dangerous_action)}</b>
              <span>预期决策</span><b>{displayLabel(scenario.expected_decision)}</b>
            </div>
            <button className="primary" onClick={() => onRunScenario(scenario.id)}>运行场景</button>
            <button onClick={() => runPair(scenario.id)}>运行正常场景并对比</button>
            {latest ? <button onClick={() => onOpenRun(latest.run_id)}>打开最近运行</button> : null}
          </div>
        );})}
      </div>
      <h3>正常 / 攻击对比</h3>
      <div className="comparator">
        {runCard(normal, onOpenRun)}
        {runCard(attack, onOpenRun)}
      </div>
      <div className="diff-table">
        <div className="diff-row diff-head"><span>信号</span><b>正常</b><b>攻击</b></div>
        {diffRow("事件数", normal, attack, (run) => run.event_count)}
        {diffRow("动作数", normal, attack, (run) => run.action_count)}
        {diffRow("阻断数", normal, attack, (run) => run.blocked_count)}
        {diffRow("审批数", normal, attack, (run) => run.approval_count)}
        {diffRow("最新决策", normal, attack, (run) => run.latest_decision || "observing")}
      </div>
    </>
  );
}
