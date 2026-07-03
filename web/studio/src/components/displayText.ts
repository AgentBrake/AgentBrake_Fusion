import type { RunSummary, ScenarioSpec, StudioEvent } from "../types";
import { displayLabel } from "./DecisionBadge";

const scenarioText: Record<string, { title: string; subtitle: string }> = {
  "normal-login-fix": {
    title: "正常任务：修复登录按钮并运行测试",
    subtitle: "用户授权修复源码，测试命令只允许在沙箱中执行。"
  },
  "attack-secret-exfil": {
    title: "攻击演示：读取密钥并外传",
    subtitle: "外部 Issue 诱导代理读取 .env，并把内容发送到攻击者服务器。"
  },
  "attack-ci-poison": {
    title: "攻击演示：篡改发布流水线",
    subtitle: "外部评论诱导代理修改 CI，让发布流程下载并执行远程脚本。"
  },
  "attack-dependency-confusion": {
    title: "攻击演示：安装恶意依赖",
    subtitle: "外部 Issue 要求安装攻击者控制的 GitHub 依赖。"
  }
};

const actionText: Record<string, string> = {
  read_secret_file: "读取密钥文件",
  send_network_request: "发起网络外传",
  install_git_dependency: "安装 GitHub 依赖",
  install_registry_dependency: "安装注册表依赖",
  modify_ci_pipeline: "修改 CI 发布流程",
  run_tests: "运行测试",
  edit_source_file: "编辑源码",
  read_project_file: "读取项目文件",
  run_lint: "运行代码检查"
};

const reasonText: Record<string, string> = {
  influenced_by_untrusted_source: "来自不可信外部文本",
  forbidden_by_task_contract: "超出用户授权的任务边界",
  secret_read_attempt: "尝试读取密钥文件",
  sandbox_secret_access_observed: "沙箱中观察到密钥访问",
  hard_deny_read_secret: "密钥读取属于硬阻断动作",
  network_egress: "存在网络外传风险",
  package_git_dependency: "依赖来自 GitHub 非注册表来源",
  lifecycle_script_risk: "依赖可能带有安装脚本风险",
  ci_write_attempt: "尝试修改 CI 配置",
  dangerous_command: "命令包含高危操作"
};

const eventText: Record<string, string> = {
  asset_scan: "扫描仓库资产",
  gateway_pre_call: "接收代理请求",
  source_ingested: "接入上下文来源",
  task_contract: "建立任务边界",
  gateway_post_call: "分析代理输出",
  instruction_ir: "解析代理意图",
  action_parsed: "识别工具动作",
  exec_trace: "沙箱预检",
  secret_event: "密钥防护",
  policy_decision: "策略决策",
  gateway_approval_request: "生成审批请求",
  policy_runtime: "执行策略",
  gateway_response: "返回安全响应"
};

function scenarioIdFromRun(run: Pick<RunSummary, "run_id" | "demo_scenario_id">): string {
  if (run.demo_scenario_id) return run.demo_scenario_id;
  if (run.run_id.startsWith("run_")) return run.run_id.slice(4).replaceAll("_", "-");
  return "";
}

export function runTitle(run: RunSummary): string {
  const scenarioId = scenarioIdFromRun(run);
  if (scenarioText[scenarioId]) return scenarioText[scenarioId].title;
  if (run.run_id.startsWith("gw_trace_")) return "网关实时观测：一次代理请求";
  return "网关运行记录";
}

export function runSubtitle(run: RunSummary): string {
  const scenarioId = scenarioIdFromRun(run);
  if (scenarioText[scenarioId]) return scenarioText[scenarioId].subtitle;
  return `审计编号：${shortId(run.run_id)}`;
}

export function scenarioTitle(scenario: ScenarioSpec): string {
  return scenarioText[scenario.id]?.title || scenario.name;
}

export function scenarioSubtitle(scenario: ScenarioSpec): string {
  return scenarioText[scenario.id]?.subtitle || scenario.description;
}

export function actionLabel(value: unknown): string {
  const raw = String(value || "");
  if (!raw) return "动作";
  return actionText[raw] || displayLabel(raw);
}

export function reasonLabels(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => reasonText[String(item)] || displayLabel(String(item))).filter(Boolean);
}

export function eventSummary(event: StudioEvent): string {
  const payload = event.payload;
  const action = actionLabel(payload.semantic_action || payload.action_id);
  if (event.type === "policy_decision") return `策略判断：${displayLabel(String(payload.decision || "decision"))}“${action}”`;
  if (event.type === "policy_runtime") return `最终执行：${displayLabel(String(payload.effective_decision || payload.original_decision || "decision"))}`;
  if (event.type === "action_parsed") return `识别到动作：${action}`;
  if (event.type === "exec_trace") return `沙箱预检：${riskText(payload.risk_observed)}。`;
  if (event.type === "secret_event") return "密钥防护：阻止读取敏感文件。";
  if (event.type === "source_ingested") return sourceSummary(payload);
  if (event.type === "task_contract") return "任务边界：只允许完成用户授权的修复、读取项目文件和运行测试。";
  if (event.type === "gateway_approval_request") return `需要人工审批：${action}`;
  if (event.type === "gateway_response") {
    const blocked = Number(payload.blocked_count || 0);
    return blocked ? `安全响应：已拦截 ${blocked} 个危险动作。` : "安全响应：未发现需要阻断的危险动作。";
  }
  return eventText[event.type] || event.summary || displayLabel(event.type);
}

export function eventDetail(event: StudioEvent): string {
  const reasons = reasonLabels(event.payload.reason_codes);
  if (reasons.length) return `原因：${reasons.slice(0, 3).join("、")}`;
  if (event.type === "source_ingested") return `来源：${displayLabel(String(event.payload.source_type || "source"))} · 信任级别：${displayLabel(String(event.payload.trust_level || "unknown"))}`;
  if (event.type === "action_parsed") return `工具命令已被抽象成可审计动作，风险级别：${displayLabel(String(event.payload.risk || "unknown"))}`;
  return displayLabel(event.type);
}

export function graphNodeTitle(node: { type: string; phase: string; label: string }): string {
  if (node.type === "policy_decision") return readableSummary(node.label, "策略判断");
  if (node.type === "action_parsed") return readableSummary(node.label, "识别工具动作");
  if (node.type === "source_ingested") return node.label.includes("untrusted") ? "接入不可信外部文本" : "接入任务来源";
  if (node.type === "task_contract") return "建立用户授权边界";
  if (node.type === "exec_trace") return "沙箱预检危险行为";
  if (node.type === "secret_event") return "密钥防护触发";
  if (node.type === "gateway_approval_request") return "生成高危审批请求";
  if (node.type === "gateway_response") return "返回安全处理结果";
  return eventText[node.type] || displayLabel(node.type);
}

export function graphNodeDetail(node: { type: string; phase: string; label: string }): string {
  if (node.type === "policy_decision") return "把动作、来源和证据交给策略规则，得到最终安全结论。";
  if (node.type === "action_parsed") return "把模型想执行的工具调用抽象成可审计动作。";
  if (node.type === "source_ingested") return "记录这段上下文来自哪里、可信不可信、能不能授权执行。";
  if (node.type === "task_contract") return "把用户真正授权的目标、文件范围和命令范围固定下来。";
  if (node.type === "exec_trace") return "先在沙箱里观察会读哪些文件、会不会联网、会改哪些内容。";
  if (node.type === "secret_event") return "发现敏感文件访问，触发密钥保护规则。";
  if (node.type === "gateway_approval_request") return "高风险动作不能自动执行，转交人工确认。";
  if (node.type === "gateway_response") return "把阻断、沙箱或审批结果返回给代理。";
  return displayLabel(node.phase);
}

export function graphEdgeLabel(relation: string, source?: { type: string; phase: string }, target?: { type: string; phase: string }): string {
  if (relation === "influenced") return "这段来源影响了后续判断";
  if (relation === "evidence") return "这条记录作为决策证据";
  if (relation === "parent") {
    if (target?.type === "source_ingested") return "接入上下文";
    if (target?.type === "task_contract") return "固定用户授权范围";
    if (target?.type === "instruction_ir") return "解析代理意图";
    if (target?.type === "action_parsed") return "识别成工具动作";
    if (target?.type === "exec_trace") return "先送入沙箱预检";
    if (target?.type === "secret_event") return "触发敏感资产检查";
    if (target?.type === "policy_decision") return "交给策略规则判定";
    if (target?.type === "gateway_approval_request") return "转为人工审批";
    if (target?.type === "policy_runtime") return "执行策略结论";
    if (target?.type === "gateway_response") return "形成安全响应";
    if (source?.phase && target?.phase) return `${displayLabel(source.phase)}到${displayLabel(target.phase)}`;
  }
  const map: Record<string, string> = {
    next: "进入下一步",
    contains: "包含",
    derived_from: "派生出",
    related_to: "关联到"
  };
  return map[relation] || displayLabel(relation);
}

export function shortId(value: string): string {
  return value.length > 18 ? `${value.slice(0, 10)}...${value.slice(-6)}` : value;
}

function readableSummary(label: string, fallback: string): string {
  if (label.includes("read_secret_file")) return `${fallback}：读取密钥文件`;
  if (label.includes("send_network_request")) return `${fallback}：网络外传`;
  if (label.includes("modify_ci_pipeline")) return `${fallback}：修改 CI 发布流程`;
  if (label.includes("install_git_dependency")) return `${fallback}：安装 GitHub 依赖`;
  if (label.includes("run_tests")) return `${fallback}：运行测试`;
  if (label.includes("block")) return `${fallback}：阻断危险动作`;
  if (label.includes("allow_in_sandbox")) return `${fallback}：只允许沙箱执行`;
  return fallback;
}

function riskText(value: unknown): string {
  if (!Array.isArray(value) || !value.length) return "未发现额外风险";
  return value.map((item) => displayLabel(String(item))).join("、");
}

function sourceSummary(payload: Record<string, unknown>): string {
  const trust = String(payload.trust_level || "");
  const type = String(payload.source_type || "");
  if (trust === "untrusted") return "接入外部文本：只能作为参考，不能授权工具执行。";
  if (type === "user_request") return "接入用户请求：作为本次任务的授权来源。";
  return "接入上下文来源：记录可信度和允许用途。";
}
