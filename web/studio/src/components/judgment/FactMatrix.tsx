import type { JudgmentTraceViewModel } from "../../types";
import { displayLabel } from "../DecisionBadge";
import { evidenceRefText, factName, valueText } from "./format";

interface FactView {
  id: string;
  namespace: string;
  key: string;
  title: string;
  value: string;
  explanation: string;
  refs: string[];
  important: boolean;
  internal: boolean;
}

const groupMeta: Record<string, { label: string; subtitle: string }> = {
  source: { label: "来源可信度", subtitle: "判断动作受到谁影响，外部 Issue、PR 评论或记忆是否可信。" },
  action: { label: "动作理解", subtitle: "把代理准备执行的命令翻译成安全系统能理解的动作。" },
  asset: { label: "资产影响", subtitle: "判断动作触碰源码、配置、CI、密钥还是仓库边界外资源。" },
  contract: { label: "任务边界", subtitle: "判断动作是否仍在用户真正授权的任务范围内。" },
  secret: { label: "密钥风险", subtitle: "记录密钥读取、外传或凭据暴露风险。" },
  package: { label: "供应链证据", subtitle: "判断依赖安装是否来自 registry、Git 地址或压缩包。" },
  sandbox: { label: "沙箱观察", subtitle: "展示隔离预检中看到的文件、网络或进程行为。" },
  policy: { label: "系统内部状态", subtitle: "策略引擎自用的辅助事实，通常折叠展示。" },
};

export function FactMatrix({ judgment, activeFactId, onSelectFact }: { judgment: JudgmentTraceViewModel; activeFactId: string; onSelectFact: (factId: string, refs: string[]) => void }) {
  const facts = judgment.fact_nodes.map(toFactView);
  const publicFacts = facts.filter((fact) => !fact.internal);
  const internalFacts = facts.filter((fact) => fact.internal);
  const grouped = groupFacts(publicFacts);
  return (
    <section className="judgment-panel fact-matrix-panel">
      <div className="judgment-panel-head">
        <span className="policy-eyebrow">Facts</span>
        <h3>哪些 facts 进入了判断</h3>
        <p className="muted">这里把内部字段翻译成安全含义。点击事实会反向高亮它来自哪条证据。</p>
      </div>
      {[...grouped.entries()].map(([namespace, items]) => (
        <section className="fact-group" key={namespace}>
          <div className="fact-group-head">
            <div><b>{groupMeta[namespace]?.label || displayLabel(namespace)}</b><span>{groupMeta[namespace]?.subtitle || "这些事实会参与策略判断。"}</span></div>
            <small>{items.length} 条</small>
          </div>
          <div className="fact-card-grid">
            {items.map((fact) => (
              <button className={`fact-card ${fact.important ? "important" : ""} ${activeFactId === fact.id ? "active" : ""}`} key={fact.id} onClick={() => onSelectFact(fact.id, fact.refs)}>
                <span>{fact.title}</span>
                <b>{fact.value}</b>
                <p>{fact.explanation}</p>
                <small>证据：{evidenceRefText(fact.refs)}</small>
              </button>
            ))}
          </div>
        </section>
      ))}
      {internalFacts.length ? (
        <details className="internal-facts">
          <summary>查看系统内部状态事实（{internalFacts.length} 条）</summary>
          <div className="fact-card-grid">
            {internalFacts.map((fact) => (
              <button className={`fact-card internal ${activeFactId === fact.id ? "active" : ""}`} key={fact.id} onClick={() => onSelectFact(fact.id, fact.refs)}>
                <span>{fact.title}</span>
                <b>{fact.value}</b>
                <p>{fact.explanation}</p>
                <small>证据：{evidenceRefText(fact.refs)}</small>
              </button>
            ))}
          </div>
        </details>
      ) : null}
      {!judgment.fact_nodes.length ? <div className="empty-state">该动作没有 PolicyFactSet，因此无法复现完整判断链。</div> : null}
    </section>
  );
}

function groupFacts(facts: FactView[]): Map<string, FactView[]> {
  const order = ["source", "action", "asset", "contract", "secret", "package", "sandbox"];
  const grouped = new Map<string, FactView[]>();
  for (const ns of order) grouped.set(ns, []);
  for (const fact of facts) grouped.set(fact.namespace, [...(grouped.get(fact.namespace) || []), fact]);
  return new Map([...grouped.entries()].filter(([, items]) => items.length));
}

function toFactView(fact: Record<string, unknown>): FactView {
  const namespace = String(fact.namespace || "policy");
  const key = String(fact.key || "fact");
  const id = String(fact.fact_id || fact.id || `${namespace}.${key}`);
  const refs = Array.isArray(fact.evidence_refs) ? fact.evidence_refs.map(String) : [];
  const title = factName(namespace, key);
  const value = valueText(fact.value);
  return {
    id,
    namespace,
    key,
    title,
    value,
    explanation: explainFact(namespace, key, value),
    refs,
    important: isImportantFact(namespace, key, value),
    internal: namespace === "policy" || key.includes("hash") || key.includes("version"),
  };
}

function explainFact(namespace: string, key: string, value: string): string {
  const factKey = `${namespace}.${key}`;
  if (factKey === "source.has_untrusted") return value === "是" ? "动作受到低可信文本影响，需要更严格的授权判断。" : "未发现低可信来源影响。";
  if (factKey === "action.semantic_action") return "AgentBrake-Fusion 先把原始命令归类成标准动作，再进入策略判断。";
  if (factKey === "asset.touched_type") return value.includes("密钥") ? "触碰密钥类资产会触发强安全约束。" : "资产类型决定按普通文件、CI、依赖或敏感资产处理。";
  if (factKey === "contract.match") return value.includes("越过") ? "动作超出用户授权任务，不能直接执行。" : "任务边界用于区分正常工作和被外部诱导的危险动作。";
  if (factKey === "secret.event") return "密钥事件会直接参与不可降级安全不变量判断。";
  if (factKey === "package.source") return "可疑依赖来源会触发供应链防护策略。";
  if (namespace === "sandbox") return "沙箱观察用于补强静态判断，说明预检时实际看到了什么。";
  return "这是策略引擎抽取出的标准事实，会影响候选规则或条件判断。";
}

function isImportantFact(namespace: string, key: string, value: string): boolean {
  return ["source.has_untrusted", "asset.touched_type", "contract.match", "contract.forbidden_file_touch", "secret.event", "action.semantic_action"].includes(`${namespace}.${key}`) || value.includes("密钥") || value.includes("越过") || value === "是";
}
