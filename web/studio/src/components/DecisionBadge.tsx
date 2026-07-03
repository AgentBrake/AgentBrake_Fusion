import type { Severity } from "../types";

const labelMap: Record<string, string> = {
  allow: "放行",
  allowed: "已放行",
  block: "阻断",
  blocked: "已阻断",
  quarantine: "隔离",
  sandbox: "沙箱",
  allow_in_sandbox: "沙箱放行",
  require_confirmation: "需要确认",
  sandbox_then_approval: "沙箱后审批",
  approval: "审批",
  request: "审批请求",
  pending: "待处理",
  granted: "已批准",
  denied: "已拒绝",
  attack: "攻击",
  normal: "正常",
  observing: "观测中",
  observed: "已观测",
  unknown: "未知",
  decision: "决策",
  action: "动作",
  fact: "事实",
  predicate: "条件",
  rule: "规则",
  lattice: "约束乘积格",
  final: "最终决策",
  info: "信息",
  warning: "警告",
  critical: "高危",
  context: "上下文",
  instruction: "指令",
  policy: "策略",
  response: "响应",
  evidence: "证据",
  candidate: "候选召回",
  matched: "命中",
  supports: "支撑",
  finalizes: "形成结论",
  user_request: "用户请求",
  github_issue_body: "GitHub Issue",
  pr_comment: "PR 评论",
  trusted: "可信",
  untrusted: "不可信",
  medium: "中风险",
  high: "高风险",
  low: "低风险",
  secret_access: "访问密钥",
  credential_exposure: "凭据暴露",
  network_egress: "网络外传",
  compound_command: "复合命令",
  other: "其他",
  influenced: "影响",
  contains: "包含",
  derived_from: "派生自",
  related_to: "相关",
  policy_decision: "策略决策",
  policy_runtime: "策略运行时",
  gateway_response: "网关响应",
  exec_trace: "执行轨迹",
  intercepted: "已拦截",
  "not intercepted": "未拦截",
  "security ok": "安全通过",
  "security fail": "安全失败",
};

export function displayLabel(label: string | number | null | undefined): string {
  const raw = String(label ?? "").trim();
  if (!raw) return "信息";
  const countMatch = raw.match(/^([a-z_]+):\s*(\d+)$/i);
  if (countMatch) return `${labelMap[countMatch[1]] || countMatch[1]}：${countMatch[2]}`;
  return labelMap[raw] || raw;
}

export function DecisionBadge({ label, severity = "info" }: { label: string; severity?: Severity }) {
  return <span className={`badge ${severity}`}>{displayLabel(label)}</span>;
}
