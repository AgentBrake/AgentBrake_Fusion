import type { Decision, ServiceStatus } from "../types";

export function decisionLabel(decision: Decision): string {
  if (decision === "observing") return "观察中";
  if (decision === "allow") return "放行";
  if (decision === "require_confirmation") return "需要确认";
  return "阻断";
}

export function serviceStatusLabel(status: ServiceStatus): string {
  if (status === "online") return "在线";
  if (status === "mock") return "显式演示";
  if (status === "checking") return "检测中";
  return "离线";
}

export function policyModeLabel(mode: string): string {
  if (mode === "enforce") return "强制执行";
  if (mode === "observe_only") return "仅观察";
  return "演示模式";
}

export function setupModeLabel(mode: string): string {
  if (mode === "gateway_http") return "Gateway HTTP";
  if (mode === "gateway_ws") return "Gateway WebSocket";
  if (mode === "a2a") return "A2A Gateway";
  if (mode === "cli") return "CLI fallback";
  if (mode === "mock") return "Mock Demo";
  return mode;
}

export function toolActionLabel(toolName: string): string {
  const labels: Record<string, string> = {
    send_email: "发送邮件",
    send_channel_message: "发送频道消息",
    send_slack: "发送 Slack 消息",
    send_money: "提交付款",
    reserve_hotel: "预订酒店",
    share_file: "共享文件",
    run_command: "执行命令",
    external_api: "调用外部 API",
    read_file: "读取文件",
    search_emails: "搜索邮件",
    get_webpage: "读取网页"
  };
  return labels[toolName] || toolName;
}

export function argLabel(key: string): string {
  const labels: Record<string, string> = {
    recipients: "收件人",
    to: "收件人",
    recipient: "目标对象",
    channel: "频道",
    subject: "主题",
    body: "正文",
    memo: "备注",
    amount: "金额",
    hotel: "酒店",
    city: "城市",
    date: "日期",
    file: "文件",
    permission: "权限",
    command: "命令",
    path: "路径",
    url: "地址",
    query: "查询"
  };
  return labels[key] || key;
}
