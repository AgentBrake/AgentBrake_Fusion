import { useEffect, useState } from "react";
import { fetchResults, type ResultsPayload, type SuiteBreakdownRow } from "../api/results";

export function ExperimentDashboard() {
  const [data, setData] = useState<ResultsPayload | null>(null);

  useEffect(() => {
    void fetchResults().then(setData);
  }, []);

  if (!data) {
    return <div className="page-grid"><section className="card empty-state">正在加载实验结果。</section></div>;
  }

  return (
    <div className="page-grid">
      <div className="page-hero">
        <div>
          <span className="eyebrow">实验成绩</span>
          <h1>安全性、可用性与执行前裁决开销</h1>
          <p>该页不是主演示入口，只作为结果支撑：展示 AgentDojo 全量结果、分场景表现、延迟和消融实验。</p>
        </div>
      </div>
      <div className="metric-board" data-testid="results-summary">
        {data.headline.map((metric) => (
          <div className={`metric-tile ${metric.tone}`} key={metric.label}>
            <span>{metric.label}</span>
            <b>{metric.value}</b>
            <em>{metric.trend}</em>
          </div>
        ))}
      </div>
      <SuiteBreakdown rows={data.suiteBreakdown} />
      <DashboardTable title="AgentDojo 全量端到端结果" rows={data.fullE2E} />
      <DashboardTable title="MSJ Engine 执行前延迟" rows={data.latency} />
      <DashboardTable title="MSJ Engine 与 ActionGraph 消融实验" rows={data.ablation} />
    </div>
  );
}

function SuiteBreakdown({ rows }: { rows: SuiteBreakdownRow[] }) {
  const suites = Array.from(new Set(rows.map((row) => row.suite)));
  return (
    <section className="card suite-breakdown" data-testid="asr-chart">
      <div className="section-heading compact">
        <h2>四类 AgentDojo 场景分场景表现</h2>
        <p>红色柱表示 ASR，蓝色柱表示 User Utility，绿色折点表示 Secure Utility。</p>
      </div>
      <div className="suite-chart-grid">
        {suites.map((suite) => (
          <div className="suite-chart" key={suite}>
            <h3>{suite}</h3>
            {rows.filter((row) => row.suite === suite).map((row) => (
              <div className="combo-row" key={`${row.suite}-${row.method}`}>
                <span>{row.method}</span>
                <div className="combo-bars">
                  <i className="bar asr" style={{ height: `${Math.max(row.ASR, 2)}%` }} title={`ASR ${row.ASR}%`} />
                  <i className="bar utility" style={{ height: `${row.userUtility}%` }} title={`User Utility ${row.userUtility}%`} />
                  <i className="secure-point" style={{ bottom: `${row.secureUtility}%` }} title={`Secure Utility ${row.secureUtility}%`} />
                </div>
              </div>
            ))}
          </div>
        ))}
      </div>
    </section>
  );
}

function DashboardTable({ title, rows }: { title: string; rows: Array<Record<string, string>> }) {
  const headers = Object.keys(rows[0] || {});
  return (
    <section className="card dashboard-table" data-testid={title.includes("延迟") ? "latency-chart" : title.includes("消融") ? "ablation-table" : undefined}>
      <h2>{title}</h2>
      <table>
        <thead><tr>{headers.map((header) => <th key={header}>{header}</th>)}</tr></thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index}>{headers.map((header) => <td key={header}>{row[header]}</td>)}</tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
