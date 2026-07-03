import type { JudgmentTraceViewModel, PolicyPredicateRow, Severity } from "../../types";
import { displayLabel } from "../DecisionBadge";
import { actionLabel, reasonLabels, shortId } from "../displayText";

export const factLabels: Record<string, string> = {
  "source.trust_floor": "来源可信等级",
  "source.has_untrusted": "是否受不可信来源影响",
  "action.semantic_action": "动作类型",
  "action.risk": "动作风险",
  "action.tool": "调用工具",
  "action.side_effect": "是否有副作用",
  "action.parser_confidence": "动作解析置信度",
  "action.high_risk": "是否高危动作",
  "action.network_capability": "是否可能联网",
  "action.risk_tag": "风险标签",
  "asset.touched_path": "触碰文件路径",
  "asset.touched_type": "触碰资产类型",
  "asset.touched_risk": "资产风险等级",
  "asset.repo_escape": "是否越过仓库边界",
  "asset.symlink_escape": "是否符号链接逃逸",
  "contract.match": "是否符合任务边界",
  "contract.violation_reason": "越界原因",
  "contract.forbidden_file_touch": "是否触碰禁止文件",
  "secret.event": "密钥安全事件",
  "package.source": "依赖来源",
  "package.lifecycle_scripts": "是否存在生命周期脚本",
  "sandbox.risk_observed": "沙箱观察到的风险",
  "sandbox.observation": "沙箱观察结果",
  "mcp.capability": "MCP 能力",
  "memory.authorization": "记忆授权状态",
  "graph.has_dataflow_edge": "是否存在数据流关系",
  "graph.has_sequence": "是否存在多步骤顺序",
  "graph.node_count": "动作步骤数量",
  "flow.secret_to_external": "是否存在密钥外传路径",
  "flow.secret_to_network_reachable": "历史密钥风险是否连到网络动作",
  "history.secret_taint": "历史是否触碰过密钥",
  "history.untrusted_seen": "历史是否出现低可信来源",
  "history.package_taint": "历史是否出现依赖风险",
  "history.ci_taint": "历史是否出现 CI 风险",
  "history.prior_external_sink": "历史外部目标",
  "constraint.execution_env": "执行环境约束",
  "constraint.network_scope": "网络访问约束",
  "constraint.data_scope": "数据访问约束",
};

const valueLabels: Record<string, string> = {
  true: "是",
  false: "否",
  trusted: "可信",
  untrusted: "不可信",
  low: "低风险",
  medium: "中风险",
  high: "高风险",
  critical: "严重风险",
  match: "符合任务",
  partial_match: "部分符合任务",
  violation: "越过任务边界",
  unknown: "无法确认",
  git_url: "Git 地址依赖",
  tarball_url: "压缩包依赖",
  registry: "包仓库依赖",
  secret_file: "密钥文件",
  ci_workflow: "CI 工作流",
  source_file: "源码文件",
  read_secret_file: "读取密钥文件",
  send_network_request: "发送网络请求",
  run_tests: "运行测试",
  edit_source_file: "编辑源码文件",
  install_git_dependency: "安装 Git 依赖",
  install_tarball_dependency: "安装压缩包依赖",
  install_registry_dependency: "安装仓库依赖",
};

export function severityForDecision(decision: string): Severity {
  if (decision === "block" || decision === "quarantine") return "critical";
  if (decision.includes("sandbox") || decision.includes("approval")) return "warning";
  if (decision === "allow") return "normal";
  return "info";
}

export function valueText(value: unknown): string {
  if (value === undefined || value === null || value === "") return "无";
  if (value === "<REDACTED>") return "已脱敏";
  if (Array.isArray(value)) return value.map(valueText).join("、");
  if (typeof value === "boolean") return value ? "是" : "否";
  if (typeof value === "object") return JSON.stringify(value);
  const raw = String(value);
  return valueLabels[raw] || displayLabel(raw);
}

export function factName(namespace: unknown, key: unknown): string {
  const path = `${String(namespace || "policy")}.${String(key || "fact")}`;
  return factLabels[path] || displayLabel(path);
}

export function factTokenText(token: string): string {
  const [path, rawValue] = token.split("=");
  const label = factLabels[path] || path;
  return rawValue ? `${label} = ${valueText(rawValue)}` : label;
}

export function ruleTitle(rule: Record<string, unknown>): string {
  const id = String(rule.rule_id || rule.id || "");
  if (id.includes("SECRET")) return `${id} · 密钥保护`;
  if (id.includes("EGRESS") || id.includes("NET")) return `${id} · 网络外传`;
  if (id.includes("CI")) return `${id} · CI/CD 发布边界`;
  if (id.includes("SC") || id.includes("PACKAGE") || id.includes("REGISTRY")) return `${id} · 供应链风险`;
  if (id.includes("SOURCE")) return `${id} · 低可信来源`;
  if (id.includes("REPO")) return `${id} · 仓库边界`;
  if (id.includes("SANDBOX")) return `${id} · 沙箱预检`;
  return id || "策略规则";
}

export function predicatePath(row: PolicyPredicateRow): string {
  const raw = String(row.path || "证据事实");
  return factLabels[raw] || displayLabel(raw);
}

export function oneLineAction(judgment: JudgmentTraceViewModel): string {
  return actionLabel(judgment.action_summary.semantic_action || judgment.action_id);
}

export function evidenceRefText(refs: unknown): string {
  if (!Array.isArray(refs) || !refs.length) return "无直接证据引用";
  return refs.map((ref) => shortId(String(ref))).join("、");
}

export function reasonText(judgment: JudgmentTraceViewModel): string {
  const labels = reasonLabels(judgment.reason_codes);
  return labels.length ? labels.join("、") : judgment.why_text || "当前判断没有额外原因码。";
}

export function asRecordArray(value: unknown): Array<Record<string, unknown>> {
  return Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && !Array.isArray(item)) : [];
}

export function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map((item) => String(item)) : [];
}
