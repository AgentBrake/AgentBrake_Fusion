import { useEffect, useState } from "react";
import { fetchScenarios, runScenario } from "../api/scenarios";
import { ScenarioCard } from "../components/scenarios/ScenarioCard";
import type { DecisionRun, DemoScenario } from "../types";

export function ScenarioGallery({
  onScenarioRun
}: {
  onScenarioRun: (run: DecisionRun) => void;
}) {
  const [scenarios, setScenarios] = useState<DemoScenario[]>([]);

  useEffect(() => {
    void fetchScenarios().then(setScenarios);
  }, []);

  async function start(scenario: DemoScenario) {
    onScenarioRun(await runScenario(scenario.id));
  }

  return (
    <div className="page-grid">
      <div className="page-hero">
        <div>
          <span className="eyebrow">场景演示</span>
          <h1>六类 AgentDojo 风格间接提示注入场景</h1>
          <p>每个场景都聚焦低可信上下文如何污染候选工具动作参数，以及三层设计如何在执行前完成裁决。</p>
        </div>
      </div>
      <div className="scenario-gallery">
        {scenarios.map((scenario) => <ScenarioCard key={scenario.id} scenario={scenario} onStart={start} />)}
      </div>
    </div>
  );
}
