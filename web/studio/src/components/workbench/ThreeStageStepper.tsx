import { GitBranch, Layers3, ShieldCheck } from "lucide-react";
import type { Decision } from "../../types";
import { decisionLabel } from "../../utils/display";

export function ThreeStageStepper({ decision }: { decision: Decision }) {
  const stages = [
    { title: "ActionGraph", text: "把用户目标、低可信上下文、候选工具动作和参数来源连成证据子图。", icon: <GitBranch size={18} /> },
    { title: "MSJ Engine", text: "把图证据转成结构化事实，保留冲突来源和规则命中。", icon: <ShieldCheck size={18} /> },
    { title: "Constraint Product Lattice", text: "按维度 join 冲突证据，映射到执行环境、网络、数据和人工门控。", icon: <Layers3 size={18} /> }
  ];
  return (
    <div className="stage-stepper">
      {stages.map((stage, index) => (
        <div className="stage-step" key={stage.title}>
          <span>{stage.icon}</span>
          <div>
            <b>{index + 1}. {stage.title}</b>
            <p>{stage.text}</p>
          </div>
        </div>
      ))}
      <div className={`final-decision ${decision}`}>最终裁决：{decisionLabel(decision)}</div>
    </div>
  );
}
