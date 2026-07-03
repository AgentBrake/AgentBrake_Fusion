import type { JudgmentTraceViewModel } from "../../types";
import { DecisionBadge } from "../DecisionBadge";
import { ruleTitle, valueText } from "./format";

const invariantCopy: Record<string, string> = {
  "INV-SECRET": "触碰密钥或敏感资产，普通策略不能把它降级为直接放行。",
  "INV-EGRESS": "存在 secret 后外传风险，禁止外部网络 sink。",
  "INV-SOURCE": "低可信上下文不能授权高危动作。",
  "INV-REPO": "动作越过仓库边界，必须阻断。",
  "INV-CI": "CI/CD 修改属于发布边界，不能由低可信来源驱动。",
  "INV-SC": "远程依赖安装存在供应链风险，需要阻断或预检。",
};

export function InvariantGateView({ judgment }: { judgment: JudgmentTraceViewModel }) {
  return (
    <section className="judgment-panel invariant-gate">
      <div className="judgment-panel-head">
        <span className="policy-eyebrow">Invariant Gate</span>
        <h3>哪些 facts 命中了不可降级安全门</h3>
      </div>
      <div className="invariant-list">
        {judgment.invariant_hits.length ? judgment.invariant_hits.map((rule) => {
          const ruleId = String(rule.rule_id || rule.id || "");
          return (
            <article className="invariant-card critical" key={ruleId}>
              <div>
                <b>{ruleTitle(rule)}</b>
                <span>{copyFor(ruleId)}</span>
                {Array.isArray(rule.evidence_refs) && rule.evidence_refs.length ? <small>证据：{rule.evidence_refs.map(valueText).join("、")}</small> : null}
              </div>
              <DecisionBadge label={String(rule.decision || "block")} severity="critical" />
            </article>
          );
        }) : (
          <div className="invariant-card normal">
            <div><b>未命中核心安全门</b><span>当前动作没有触发不可降级不变量，后续由 RuleIndex、谓词规则和约束乘积格继续判断。</span></div>
            <DecisionBadge label="allow" severity="normal" />
          </div>
        )}
      </div>
    </section>
  );
}

function copyFor(ruleId: string): string {
  const key = Object.keys(invariantCopy).find((prefix) => ruleId.startsWith(prefix));
  return key ? invariantCopy[key] : "该不变量命中后，策略结果不能被降级为普通放行。";
}
