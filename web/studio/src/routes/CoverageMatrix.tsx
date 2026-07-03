import type { CoverageReport } from "../types";

const labels: Record<string, string> = {
  model_response: "模型响应",
  openai_tool_calls: "OpenAI tool_calls",
  gateway: "Gateway",
  stable_session_identity: "多轮会话",
  audit_log: "Audit / EvidenceGraph",
  agent_env: "Agent 环境变量",
  agent_instructions: "Agent 接入说明",
  guarded_tool_shims: "执行 shim",
  file_guard: "文件操作",
  exec_guard: "Shell 命令",
  package_install: "依赖安装",
  mcp_tool: "MCP 工具",
  studio: "Studio",
  approval_api: "Approval API",
  demo_package: "演示包",
  audit_evidence_graph: "审计证据图",
};

export function CoverageMatrix({ coverage }: { coverage: CoverageReport }) {
  return (
    <div className="coverage-view">
      <div className="metric-grid">
        <div className="metric">
          <span>模式</span>
          <b>{coverage.mode || "unknown"}</b>
        </div>
        <div className="metric">
          <span>覆盖状态</span>
          <b>{coverage.ok ? "完整" : "需补强"}</b>
        </div>
        <div className="metric">
          <span>缺口</span>
          <b>{coverage.missing.length}</b>
        </div>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>路径</th>
              <th>状态</th>
              <th>证据</th>
            </tr>
          </thead>
          <tbody>
            {coverage.matrix.map((row) => (
              <tr key={row.capability}>
                <td>{labels[row.capability] || row.capability}</td>
                <td><span className={`status-chip ${row.status}`}>{row.status}</span></td>
                <td>{row.evidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {coverage.config_path ? <p className="muted">Config: {coverage.config_path}</p> : null}
    </div>
  );
}
