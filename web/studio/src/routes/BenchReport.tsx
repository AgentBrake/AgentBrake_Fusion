import type { BenchReport } from "../types";
import { DecisionBadge } from "../components/DecisionBadge";
import { useMemo, useState } from "react";

function percent(numerator: number, denominator: number): string {
  if (!denominator) return "无数据";
  return `${Math.round((numerator / denominator) * 100)}%`;
}

function boolValue(value: unknown): boolean {
  return value === true || value === "true" || value === 1;
}

function sampleTitle(sample: Record<string, unknown>): string {
  return String(sample.sample_id || sample.id || "未命名样本");
}

export function BenchReportView({ bench }: { bench: BenchReport }) {
  const [suite, setSuite] = useState("");
  const [security, setSecurity] = useState("");
  const metrics = Object.entries(bench.metrics || {});
  const samples = bench.samples || [];
  const total = samples.length;
  const securityOk = samples.filter((sample) => boolValue(sample.security_ok)).length;
  const intercepted = samples.filter((sample) => boolValue(sample.gateway_intercepted)).length;
  const dangerousExecuted = samples.filter((sample) => boolValue(sample.dangerous_action_executed)).length;
  const failed = samples.filter((sample) => !boolValue(sample.security_ok));
  const suites = useMemo(() => Array.from(new Set(samples.map((sample) => String(sample.suite || "")).filter(Boolean))).sort(), [samples]);
  const visible = samples.filter((sample) => {
    if (suite && sample.suite !== suite) return false;
    if (security === "ok" && !sample.security_ok) return false;
    if (security === "fail" && sample.security_ok) return false;
    return true;
  });
  if (!metrics.length && !samples.length) {
    return (
      <div className="scorecard-empty">
        <h3>还没有附加评测报告</h3>
        <p>安全成绩单用于展示 AgentBrake-Fusion 在一批样本上的整体表现：攻击拦截率、正常任务误伤率、失败样本和需要补强的规则。</p>
        <p>运行网关评测并把报告传给 Studio 后，这里会变成一张可展示的安全成绩单。</p>
      </div>
    );
  }
  return (
    <div className="scorecard-view">
      <div className="scorecard-explainer">
        <b>安全成绩单看什么？</b>
        <span>这里不是看单次拦截，而是看 AgentBrake-Fusion 面对一批正常和攻击样本时，整体拦得准不准、有没有漏拦或误伤。</span>
      </div>
      <div className="scorecard-grid">
        <div className="scorecard-metric"><span>样本总数</span><b>{total || String(bench.metrics?.total_samples || "无数据")}</b></div>
        <div className="scorecard-metric"><span>安全通过率</span><b>{total ? percent(securityOk, total) : String(bench.metrics?.security_pass_rate || "无数据")}</b></div>
        <div className="scorecard-metric"><span>网关拦截数</span><b>{intercepted || String(bench.metrics?.gateway_intercepted || "无数据")}</b></div>
        <div className="scorecard-metric"><span>危险动作执行</span><b>{dangerousExecuted}</b></div>
      </div>
      {metrics.length ? (
        <details className="raw-graph">
          <summary>查看原始指标</summary>
          <div className="metric-grid">
            {metrics.map(([key, value]) => <div className="metric" key={key}><span className="muted">{key}</span><b>{String(value)}</b></div>)}
          </div>
        </details>
      ) : null}
      <div className="bench-filters">
        <label>样本集
          <select value={suite} onChange={(event) => setSuite(event.target.value)}>
            <option value="">全部样本集</option>
            {suites.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </label>
        <label>安全结果
          <select value={security} onChange={(event) => setSecurity(event.target.value)}>
            <option value="">全部结果</option>
            <option value="ok">安全通过</option>
            <option value="fail">安全失败</option>
          </select>
        </label>
        <span className="status-pill">{visible.length} 个样本</span>
      </div>
      {failed.length ? (
        <div className="failure-panel">
          <b>需要关注的失败样本</b>
          <span>{failed.slice(0, 5).map(sampleTitle).join("、")}</span>
        </div>
      ) : <div className="failure-panel success"><b>没有发现失败样本</b><span>当前样本集全部安全通过。</span></div>}
      <div className="sample-table">
        {visible.slice(0, 120).map((sample) => (
          <div className="sample-row" key={String(sample.sample_id)}>
            <b>{String(sample.sample_id || "")}</b>
            <DecisionBadge label={sample.security_ok ? "安全通过" : "安全失败"} severity={sample.security_ok ? "normal" : "critical"} />
            <DecisionBadge label={sample.gateway_intercepted ? "已拦截" : "未拦截"} severity={sample.gateway_intercepted ? "normal" : "warning"} />
            <div className="muted">{String(sample.suite || "")} · 危险动作执行={String(sample.dangerous_action_executed ?? "无数据")}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
