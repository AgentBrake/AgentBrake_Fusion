import { PlayCircle } from "lucide-react";
import type { DemoScenario } from "../../types";
import { argLabel, decisionLabel, toolActionLabel } from "../../utils/display";

export function ScenarioCard({ scenario, onStart }: { scenario: DemoScenario; onStart: (scenario: DemoScenario) => void }) {
  return (
    <article className="scenario-card-v2">
      <div className="scenario-card-head">
        <span>{scenario.title}</span>
        <b>{decisionLabel(scenario.expectedDecision)}</b>
      </div>
      <h2>{scenario.tagline}</h2>
      <section>
        <label>用户任务</label>
        <p>{scenario.userTask}</p>
      </section>
      <section>
        <label>低可信来源</label>
        <p>{scenario.lowTrustSource}</p>
      </section>
      <section className="injection">
        <label>隐藏注入</label>
        <p>{scenario.injectedContent}</p>
      </section>
      <section>
        <label>候选危险动作</label>
        <code>{toolActionLabel(scenario.dangerousToolCall.toolName)}（{Object.keys(scenario.dangerousToolCall.args).map(argLabel).join("、")}）</code>
      </section>
      <div className="highlight-grid">
        <div><b>ActionGraph</b><span>{scenario.designHighlights.actionGraph[0]}</span></div>
        <div><b>MSJ Engine</b><span>{scenario.designHighlights.msjFacts[0]}</span></div>
        <div><b>Constraint Product Lattice</b><span>{scenario.designHighlights.latticeDimensions[0]}</span></div>
      </div>
      <button className="primary" onClick={() => onStart(scenario)}><PlayCircle size={16} /> 开始演示</button>
    </article>
  );
}
