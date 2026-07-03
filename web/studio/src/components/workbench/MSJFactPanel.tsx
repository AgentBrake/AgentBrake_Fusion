import type { MSJFacts } from "../../types";
import { argLabel } from "../../utils/display";

const factLabels: Record<string, string> = {
  task_authorized: "用户任务已授权",
  tool_group: "工具动作类别",
  private_data_seen: "发现私密数据",
  injection_seen: "发现注入内容",
  args_match_user_entity: "参数匹配用户指定实体",
  args_match_untrusted_entity: "参数匹配低可信实体",
  external_sink: "外部出口"
};

const provenanceLabels: Record<string, string> = {
  untrusted_context: "低可信上下文",
  user_task_or_trusted_context: "用户任务或可信上下文"
};

export function MSJFactPanel({ facts }: { facts: MSJFacts }) {
  return (
    <section className="card workbench-panel" data-testid="msj-engine-panel">
      <div className="section-heading compact">
        <h2>MSJ Engine</h2>
        <p>结构化事实空间。这里只列离散事实、规则命中和证据来源，不呈现任何数值化聚合结果。</p>
      </div>
      <div className="fact-grid">
        <Fact label={factLabels.task_authorized} value={facts.task_authorized} />
        <Fact label={factLabels.tool_group} value={facts.tool_group} />
        <Fact label={factLabels.private_data_seen} value={facts.private_data_seen} />
        <Fact label={factLabels.injection_seen} value={facts.injection_seen} />
        <Fact label={factLabels.args_match_user_entity} value={facts.args_match_user_entity} />
        <Fact label={factLabels.args_match_untrusted_entity} value={facts.args_match_untrusted_entity} />
        <Fact label={factLabels.external_sink} value={facts.external_sink} />
      </div>
      <div className="fact-section">
        <h3>参数来源</h3>
        {Object.entries(facts.arg_provenance).map(([key, value]) => (
          <code key={key}>{argLabel(key)}：{provenanceLabels[value] || value}</code>
        ))}
      </div>
      <div className="fact-section two">
        <EvidenceList title="规则命中" items={facts.ruleHits} tone="confirm" />
        <EvidenceList title="可信证据" items={facts.trustedEvidence} tone="allow" />
        <EvidenceList title="不安全证据" items={facts.unsafeEvidence} tone="attack" />
      </div>
    </section>
  );
}

function Fact({ label, value }: { label: string; value: string | boolean }) {
  return (
    <div className={`fact ${value === true ? "true" : value === false ? "false" : ""}`}>
      <span>{label}</span>
      <b>{value === true ? "是" : value === false ? "否" : value}</b>
    </div>
  );
}

function EvidenceList({ title, items, tone }: { title: string; items: string[]; tone: "allow" | "attack" | "confirm" }) {
  return (
    <div className={`evidence-list ${tone}`}>
      <h3>{title}</h3>
      <ul>{items.map((item) => <li key={item}>{item}</li>)}</ul>
    </div>
  );
}
