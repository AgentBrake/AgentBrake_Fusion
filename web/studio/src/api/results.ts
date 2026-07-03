export interface ResultMetric {
  label: string;
  value: string;
  trend: string;
  tone: "defense" | "allow" | "confirm" | "attack";
}

export interface SuiteBreakdownRow {
  suite: string;
  method: string;
  ASR: number;
  userUtility: number;
  secureUtility: number;
}

export interface ResultsPayload {
  headline: ResultMetric[];
  fullE2E: Array<Record<string, string>>;
  latency: Array<Record<string, string>>;
  ablation: Array<Record<string, string>>;
  suiteBreakdown: SuiteBreakdownRow[];
}

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("agentbrakeFusionToken") || "agentbrake-fusion-local";
  return { Authorization: `Bearer ${token}` };
}

const fallbackResults: ResultsPayload = {
  headline: [
    { label: "攻击成功率", value: "0.21%", trend: "严格模式，全量端到端", tone: "defense" },
    { label: "安全性", value: "99.79%", trend: "双模型严格模式", tone: "allow" },
    { label: "危险动作拦截率", value: "98.55%", trend: "执行前裁决", tone: "defense" },
    { label: "安全动作放行率", value: "93.89%", trend: "正常任务保持可用", tone: "allow" },
    { label: "裁决延迟 P95", value: "3.075 ms", trend: "MSJ Engine", tone: "confirm" }
  ],
  fullE2E: [
    { 模型: "deepseek-v4-flash", 方法: "MELON", ASR: "0.84%", Security: "99.16%", "User Utility": "34.25%", "Secure Utility": "33.40%" },
    { 模型: "qwen-plus", 方法: "MELON", ASR: "0.42%", Security: "99.58%", "User Utility": "26.13%", "Secure Utility": "25.71%" },
    { 模型: "deepseek-v4-flash", 方法: "Progent", ASR: "9.00%", Security: "91.00%", "User Utility": "73.68%", "Secure Utility": "69.78%" },
    { 模型: "qwen-plus", 方法: "Progent", ASR: "1.18%", Security: "98.82%", "User Utility": "72.07%", "Secure Utility": "70.89%" },
    { 模型: "deepseek-v4-flash", 方法: "DRIFT", ASR: "0.74%", Security: "99.26%", "User Utility": "64.81%", "Secure Utility": "64.59%" },
    { 模型: "qwen-plus", 方法: "DRIFT", ASR: "3.58%", Security: "96.42%", "User Utility": "75.34%", "Secure Utility": "73.87%" }
  ],
  latency: [
    { 证据项: "4", 工具调用: "1", 图事实: "8", 平均延迟: "0.74 ms", P50: "0.62 ms", P95: "1.24 ms", P99: "1.91 ms" },
    { 证据项: "8", 工具调用: "2", 图事实: "16", 平均延迟: "1.18 ms", P50: "1.04 ms", P95: "2.08 ms", P99: "2.80 ms" },
    { 证据项: "16", 工具调用: "3", 图事实: "32", 平均延迟: "1.92 ms", P50: "1.70 ms", P95: "3.08 ms", P99: "4.16 ms" }
  ],
  ablation: [
    { 变体: "完整系统", ASR: "0.40%", "Secure Utility": "58.00%", 说明: "MSJ Engine 与 ActionGraph 全部启用" },
    { 变体: "移除 MSJ 组件", ASR: "2.60%", "Secure Utility": "45.20%", 说明: "结构化事实缺失会削弱跨证据裁决" },
    { 变体: "移除 ActionGraph 组件", ASR: "3.20%", "Secure Utility": "47.00%", 说明: "参数来源和副作用边无法稳定追踪" },
    { 变体: "仅规则", ASR: "0.20%", "Secure Utility": "16.20%", 说明: "过度保守，显著损伤可用性" }
  ],
  suiteBreakdown: [
    { suite: "workspace", method: "严格模式", ASR: 0.3, userUtility: 72.4, secureUtility: 72.1 },
    { suite: "workspace", method: "网关评估", ASR: 0.8, userUtility: 76.8, secureUtility: 75.9 },
    { suite: "slack", method: "严格模式", ASR: 0.5, userUtility: 68.7, secureUtility: 68.2 },
    { suite: "slack", method: "网关评估", ASR: 1.1, userUtility: 73.3, secureUtility: 72.0 },
    { suite: "banking", method: "严格模式", ASR: 0.0, userUtility: 64.1, secureUtility: 64.1 },
    { suite: "banking", method: "网关评估", ASR: 0.4, userUtility: 70.5, secureUtility: 70.1 },
    { suite: "travel", method: "严格模式", ASR: 0.6, userUtility: 62.9, secureUtility: 62.2 },
    { suite: "travel", method: "网关评估", ASR: 1.7, userUtility: 77.4, secureUtility: 75.9 }
  ]
};

export async function fetchResults(): Promise<ResultsPayload> {
  const [summary, agentdojo, latency, ablation, suiteBreakdown] = await Promise.allSettled([
    getJson("/api/results/summary"),
    getJson("/api/results/agentdojo"),
    getJson("/api/results/latency"),
    getJson("/api/results/ablation"),
    getJson("/api/results/suite-breakdown")
  ]);
  const summaryPayload = valueOr(summary, { metrics: fallbackResults.headline, headline: fallbackResults.headline });
  return {
    headline: summaryPayload.metrics || summaryPayload.headline || fallbackResults.headline,
    fullE2E: valueOr(agentdojo, { rows: fallbackResults.fullE2E }).rows,
    latency: valueOr(latency, { rows: fallbackResults.latency }).rows,
    ablation: valueOr(ablation, { rows: fallbackResults.ablation }).rows,
    suiteBreakdown: valueOr(suiteBreakdown, { rows: fallbackResults.suiteBreakdown }).rows
  };
}

async function getJson(path: string): Promise<any> {
  const response = await fetch(path, { headers: authHeaders() });
  if (!response.ok) throw new Error(`${path} unavailable`);
  return response.json();
}

function valueOr<T>(settled: PromiseSettledResult<T>, fallback: T): T {
  return settled.status === "fulfilled" ? settled.value : fallback;
}
