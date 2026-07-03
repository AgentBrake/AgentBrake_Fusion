const API_TOKEN = localStorage.getItem("agentbrakeFusionToken") || "agentbrake-fusion-local";

const state = {
  runs: [],
  events: [],
  selectedRun: null,
  selectedAction: null,
  approvals: [],
  bench: null,
  source: null,
};

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${API_TOKEN}`,
    ...(options.headers || {}),
  };
  const response = await fetch(path, { ...options, headers });
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) throw new Error(data.error || response.statusText);
  return data;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function badge(label, severity = "info") {
  return `<span class="badge ${escapeHtml(severity)}">${escapeHtml(label || "info")}</span>`;
}

function decisionOf(event) {
  return event.payload?.decision || event.payload?.effective_decision || event.payload?.semantic_action || event.type;
}

function severityForDecision(decision) {
  if (["block", "quarantine"].includes(decision)) return "critical";
  if (["sandbox_then_approval", "allow_in_sandbox"].includes(decision)) return "warning";
  if (decision === "allow") return "normal";
  return "info";
}

function shortId(id) {
  if (!id) return "";
  const s = String(id);
  return s.length > 28 ? `${s.slice(0, 18)}...${s.slice(-6)}` : s;
}

async function loadHealth() {
  const health = await api("/api/health");
  $("health").textContent = `${health.version} | ${health.demo_mode ? "演示" : "实时"}`;
}

async function loadRuns() {
  const data = await api("/api/runs");
  state.runs = data.runs || [];
  renderRuns();
  if (!state.selectedRun && state.runs[0]) await selectRun(state.runs[0].run_id);
}

function renderRuns() {
  const filter = $("run-filter").value;
  const runs = state.runs.filter((run) => {
    if (!filter) return true;
    if (filter === "sandbox") return String(run.latest_decision).includes("sandbox");
    return String(run.latest_decision).includes(filter);
  });
  $("run-count").textContent = String(runs.length);
  $("runs").innerHTML = runs.map((run) => {
    const severe = run.blocked_count ? "critical" : run.latest_decision?.includes("sandbox") ? "warning" : "normal";
    return `<button class="run-card ${run.run_id === state.selectedRun ? "active" : ""}" data-run="${escapeHtml(run.run_id)}">
      <b>${escapeHtml(run.demo_scenario_id || run.run_id)}</b>
      <div class="muted">${escapeHtml(run.event_count)} events · ${escapeHtml(run.action_count)} actions · ${escapeHtml(run.agent_name)}</div>
      <div>${badge(run.latest_decision || "观测中", severe)}</div>
    </button>`;
  }).join("") || `<div class="empty-state">暂无运行记录。可以在攻击演示中启动可复现场景。</div>`;
  document.querySelectorAll("[data-run]").forEach((el) => {
    el.addEventListener("click", () => selectRun(el.dataset.run));
  });
}

async function selectRun(runId) {
  state.selectedRun = runId;
  $("selected-run").textContent = runId;
  const run = await api(`/api/runs/${encodeURIComponent(runId)}`);
  renderMetrics(run);
  const data = await api(`/api/runs/${encodeURIComponent(runId)}/events?limit=800`);
  state.events = data.events || [];
  renderAllRunViews();
  await loadGraph();
  connectStream(runId);
  renderRuns();
}

function renderMetrics(run) {
  const metrics = [
    ["事件", run.event_count || 0],
    ["动作", run.action_count || 0],
    ["阻断", run.blocked_count || 0],
    ["审批", run.approval_count || 0],
    ["高危", run.critical_count || 0],
    ["最新", run.latest_decision || "观测中"],
  ];
  $("metrics").innerHTML = metrics.map(([label, value]) => `<div class="metric"><span class="muted">${escapeHtml(label)}</span><b>${escapeHtml(value)}</b></div>`).join("");
}

function renderAllRunViews() {
  renderTimeline();
  renderDecisionStream();
  renderPolicyDebugger();
  renderSandboxEvidence();
  renderComparator();
}

function renderTimeline() {
  const criticalOnly = $("critical-only").checked;
  const events = criticalOnly ? state.events.filter((event) => event.severity === "critical" || ["policy", "approval"].includes(event.phase)) : state.events;
  $("timeline").innerHTML = events.map((event) => {
    const action = event.payload?.action_id || "";
    return `<div class="event-card" data-action="${escapeHtml(action)}">
      <div>
        <div class="phase">${escapeHtml(event.phase)}</div>
        <div class="muted">#${escapeHtml(event.event_index)}</div>
      </div>
      <div>
        <b>${escapeHtml(event.summary)}</b>
        <div class="muted">${escapeHtml(event.type)} / ${escapeHtml(event.timestamp)}</div>
      </div>
      <div>${badge(decisionOf(event), event.severity)}</div>
    </div>`;
  }).join("") || `<div class="empty-state">该运行暂无事件。</div>`;
  document.querySelectorAll(".event-card[data-action]").forEach((el) => {
    if (el.dataset.action) el.addEventListener("click", () => loadAction(el.dataset.action));
  });
}

function renderDecisionStream() {
  const decisions = state.events.filter((event) => ["policy_decision", "policy_runtime", "gateway_response"].includes(event.type));
  $("decision-stream").innerHTML = decisions.map((event) => {
    const decision = decisionOf(event);
    return `<div class="decision-card">
      <div>${badge(decision, event.severity)}</div>
      <b>${escapeHtml(event.summary)}</b>
      <div class="muted">${escapeHtml((event.payload?.reason_codes || []).slice(0, 3).join(", "))}</div>
    </div>`;
  }).join("") || `<div class="empty-state">暂无决策事件。</div>`;
}

async function loadAction(actionId) {
  state.selectedAction = actionId;
  const detail = await api(`/api/actions/${encodeURIComponent(actionId)}`);
  $("action-empty").classList.add("hidden");
  $("action-detail").classList.remove("hidden");
  const action = detail.action || {};
  const decision = detail.decision || {};
  const runtime = detail.runtime || {};
  $("action-detail").innerHTML = `
    <div class="detail-section">
      <h3>${escapeHtml(action.semantic_action || actionId)}</h3>
      <div class="kv">
        <span>决策</span><span>${badge(decision.decision || runtime.effective_decision || "未知", severityForDecision(decision.decision || runtime.effective_decision))}</span>
        <span>风险</span><span>${escapeHtml(action.risk || "未知")}</span>
        <span>策略</span><span>${escapeHtml(decision.policy_version || "n/a")}</span>
        <span>来源信任</span><span>${escapeHtml((detail.sources || []).map((s) => `${s.source_id}:${s.trust_level || s.trust || "未知"}`).join(", ") || "n/a")}</span>
      </div>
    </div>
    <div class="detail-section"><h3>原始动作</h3><pre>${escapeHtml(action.raw_action || "")}</pre></div>
    <div class="detail-section"><h3>命中规则</h3><pre>${escapeHtml(JSON.stringify(decision.matched_rules || [], null, 2))}</pre></div>
    <div class="detail-section"><h3>规则轨迹</h3><pre>${escapeHtml(JSON.stringify(decision.rule_trace || [], null, 2))}</pre></div>
    <div class="detail-section"><h3>证据引用</h3><pre>${escapeHtml(JSON.stringify(decision.evidence_refs || [], null, 2))}</pre></div>
    <div class="detail-section"><h3>ActionIR</h3><pre>${escapeHtml(JSON.stringify(action, null, 2))}</pre></div>
  `;
}

async function loadGraph() {
  if (!state.selectedRun) return;
  const graph = await api(`/api/runs/${encodeURIComponent(state.selectedRun)}/graph`);
  $("graph-body").innerHTML = (graph.nodes || []).map((node) => `<span class="graph-node ${escapeHtml(node.severity)}">
    <b>${escapeHtml(node.phase)} / ${escapeHtml(node.type)}</b>
    ${escapeHtml(node.label)}
  </span>`).join("") || `<div class="empty-state">暂无图谱节点。</div>`;
  $("graph-edges").textContent = JSON.stringify((graph.edges || []).slice(0, 160), null, 2);
}

function renderPolicyDebugger() {
  const decisions = state.events.filter((event) => event.type === "policy_decision");
  const runtimes = state.events.filter((event) => event.type === "policy_runtime");
  const ruleRows = [];
  for (const event of decisions) {
    for (const rule of event.payload?.matched_rules || []) {
      ruleRows.push({
        action: event.payload?.semantic_action || event.payload?.action_id,
        rule: rule.rule_id || rule.name,
        category: rule.category,
        decision: rule.decision || event.payload?.decision,
        reasons: rule.reason_codes || (event.payload?.reason_codes || []).join(",")
      });
    }
  }
  $("policy-summary").innerHTML = [
    ["策略决策", decisions.length],
    ["运行时事件", runtimes.length],
    ["已阻断", decisions.filter((d) => d.payload?.decision === "block").length],
    ["沙箱/审批", decisions.filter((d) => String(d.payload?.decision).includes("sandbox")).length],
    ["命中规则", ruleRows.length],
  ].map(([label, value]) => `<div class="metric"><span class="muted">${escapeHtml(label)}</span><b>${escapeHtml(value)}</b></div>`).join("");
  const matrix = ruleRows.length ? `<div class="rule-matrix">
    <div class="rule-matrix-head">动作</div><div class="rule-matrix-head">规则</div><div class="rule-matrix-head">类别</div><div class="rule-matrix-head">决策</div>
    ${ruleRows.map((row) => `<div>${escapeHtml(row.action)}</div><div>${escapeHtml(row.rule)}</div><div>${escapeHtml(row.category)}</div><div>${badge(row.decision, severityForDecision(row.decision))}</div>`).join("")}
  </div>` : "";
  $("policy-rules").innerHTML = matrix + decisions.map((event) => {
    const payload = event.payload || {};
    return `<div class="rule-card">
      <div>${badge(payload.decision, event.severity)} <span class="muted">${escapeHtml(payload.policy_version || "")}</span></div>
      <h3>${escapeHtml(payload.semantic_action || payload.action_id)}</h3>
      <p class="muted">${escapeHtml(payload.explanation || "")}</p>
      <pre>${escapeHtml(JSON.stringify({ matched_rules: payload.matched_rules, evidence_refs: payload.evidence_refs, rule_trace: payload.rule_trace }, null, 2))}</pre>
    </div>`;
  }).join("") || `<div class="empty-state">暂无策略决策事件。</div>`;
}

async function loadScenarios() {
  const data = await api("/api/scenarios");
  const scenarios = data.scenarios || [];
  $("scenarios").innerHTML = scenarios.map((scenario) => `<div class="scenario-card">
    <div>${badge(scenario.kind, scenario.kind === "attack" ? "critical" : "normal")}</div>
    <h3>${escapeHtml(scenario.name)}</h3>
    <p class="muted">${escapeHtml(scenario.description)}</p>
    <div class="muted">预期： ${escapeHtml(scenario.dangerous_action)} -> ${escapeHtml(scenario.expected_decision)}</div>
    <button class="primary" data-scenario="${escapeHtml(scenario.id)}">运行场景</button>
  </div>`).join("");
  document.querySelectorAll("[data-scenario]").forEach((button) => {
    button.addEventListener("click", async () => {
      button.textContent = "运行中...";
      try {
        const result = await api(`/api/scenarios/${encodeURIComponent(button.dataset.scenario)}/run`, { method: "POST", body: "{}" });
        await loadRuns();
        await selectRun(result.result.trace_id);
      } finally {
        button.textContent = "运行场景";
      }
    });
  });
}

function renderComparator() {
  const grouped = new Map();
  for (const run of state.runs) {
    if (!run.demo_scenario_id) continue;
    grouped.set(run.demo_scenario_id, run);
  }
  const normal = grouped.get("normal-login-fix");
  const attackRuns = [...grouped.values()].filter((run) => run.demo_scenario_id && run.demo_scenario_id !== "normal-login-fix");
  const attack = attackRuns[0];
  $("comparator").innerHTML = `
    <div class="compare-column">
      <h3>正常</h3>
      ${normal ? runMini(normal) : `<div class="empty-state">请先运行 normal-login-fix。</div>`}
    </div>
    <div class="compare-column">
      <h3>攻击</h3>
      ${attack ? runMini(attack) : `<div class="empty-state">请先运行一个攻击场景。</div>`}
    </div>`;
}

function runMini(run) {
  return `<b>${escapeHtml(run.demo_scenario_id || run.run_id)}</b>
    <div class="muted">${escapeHtml(run.event_count)} events · ${escapeHtml(run.action_count)} actions</div>
    <div>${badge(run.latest_decision || "观测中", run.blocked_count ? "critical" : "normal")}</div>
    <button data-run="${escapeHtml(run.run_id)}">打开运行</button>`;
}

async function loadApprovals() {
  const data = await api("/api/approvals");
  state.approvals = data.events || [];
  const statuses = approvalStatuses(state.approvals);
  const requests = state.approvals.filter((event) => event.event_type === "request").reverse();
  $("approval-list").innerHTML = requests.map((event) => {
    const payload = event.payload || {};
    const status = statuses.get(payload.approval_request_id) || "pending";
    return `<div class="approval-card">
      <div>${badge(status, status === "pending" ? "warning" : status === "granted" ? "normal" : "critical")} ${badge(payload.recommended_decision || "request", severityForDecision(payload.recommended_decision))}</div>
      <h3>${escapeHtml(payload.human_readable_summary || payload.approval_request_id)}</h3>
      <div class="kv">
        <span>approval_id</span><span>${escapeHtml(payload.approval_request_id)}</span>
        <span>action_hash</span><span>${escapeHtml(payload.action_hash)}</span>
        <span>sources</span><span>${escapeHtml(JSON.stringify(payload.source_influence || []))}</span>
      </div>
      ${status === "pending" ? `<button class="primary" data-grant="${escapeHtml(payload.approval_request_id)}" data-hash="${escapeHtml(payload.action_hash)}">批准 sandbox-only</button>
      <button class="danger" data-deny="${escapeHtml(payload.approval_request_id)}">拒绝</button>` : `<div class="muted">已在 ApprovalStore 中完成：${escapeHtml(status)}。</div>`}
    </div>`;
  }).join("") || `<div class="empty-state">暂无审批请求。</div>`;
  document.querySelectorAll("[data-grant]").forEach((button) => {
    button.addEventListener("click", async () => {
      await api(`/api/approvals/${encodeURIComponent(button.dataset.grant)}/grant`, { method: "POST", body: JSON.stringify({ action_hash: button.dataset.hash, constraints: ["sandbox_only", "no_network"], granted_by: "studio" }) });
      await loadApprovals();
    });
  });
  document.querySelectorAll("[data-deny]").forEach((button) => {
    button.addEventListener("click", async () => {
      await api(`/api/approvals/${encodeURIComponent(button.dataset.deny)}/deny`, { method: "POST", body: JSON.stringify({ denied_by: "studio" }) });
      await loadApprovals();
    });
  });
}

function approvalStatuses(events) {
  const statuses = new Map();
  for (const event of events) {
    const payload = event.payload || {};
    if (event.event_type === "request") statuses.set(payload.approval_request_id, "pending");
    if (event.event_type === "grant") {
      const requestId = findApprovalRequestForGrant(events, payload);
      if (requestId) statuses.set(requestId, "granted");
    }
    if (event.event_type === "denial") statuses.set(payload.approval_request_id, "denied");
  }
  return statuses;
}

function findApprovalRequestForGrant(events, grant) {
  const match = [...events].reverse().find((event) => {
    const payload = event.payload || {};
    return event.event_type === "request" && payload.action_id === grant.action_id && payload.action_hash === grant.approved_action_hash;
  });
  return match?.payload?.approval_request_id;
}

function renderSandboxEvidence() {
  const traces = state.events.filter((event) => event.type === "exec_trace");
  $("sandbox-evidence").innerHTML = traces.map((event) => {
    const p = event.payload || {};
    return `<div class="sandbox-card">
      <div>${badge(p.recommended_decision || "sandbox", event.severity)}</div>
      <h3>${escapeHtml(p.command || event.summary)}</h3>
      <div class="kv">
        <span>配置</span><span>${escapeHtml(p.sandbox_profile || "n/a")}</span>
        <span>网络</span><span>${escapeHtml((p.network_attempts || []).length)}</span>
        <span>风险</span><span>${escapeHtml((p.risk_observed || []).join(", ") || "none")}</span>
      </div>
      <pre>${escapeHtml(JSON.stringify(p, null, 2))}</pre>
    </div>`;
  }).join("") || `<div class="empty-state">该运行暂无沙箱预检证据。</div>`;
}

async function loadBench() {
  state.bench = await api("/api/bench/latest");
  const metrics = state.bench.metrics || {};
  $("bench-metrics").innerHTML = Object.entries(metrics).map(([key, value]) => `<div class="metric"><span class="muted">${escapeHtml(key)}</span><b>${escapeHtml(value)}</b></div>`).join("") || `<div class="empty-state">未附加评测报告。</div>`;
  const samples = state.bench.samples || [];
  $("bench-samples").innerHTML = samples.slice(0, 80).map((sample) => `<div class="sample-row">
    <b>${escapeHtml(sample.sample_id || "")}</b>
    ${badge(sample.security_ok ? "安全通过" : "安全失败", sample.security_ok ? "normal" : "critical")}
    ${badge(sample.gateway_已拦截 ? "已拦截" : "未拦截", sample.gateway_已拦截 ? "normal" : "warning")}
    <div class="muted">${escapeHtml(sample.suite || "")}</div>
  </div>`).join("");
}

function connectStream(runId) {
  if (state.source) state.source.close();
  state.source = new EventSource(`/api/events/stream?run_id=${encodeURIComponent(runId)}`);
  state.source.addEventListener("studio_event", (message) => {
    const event = JSON.parse(message.data);
    if (state.events.find((item) => item.event_id === event.event_id)) return;
    state.events.push(event);
    renderAllRunViews();
    loadRuns();
  });
}

async function exportSelectedRun() {
  if (!state.selectedRun) return;
  const result = await api(`/api/export/evidence/${encodeURIComponent(state.selectedRun)}`);
  alert(`证据包已导出到 ${result.output}`);
}

function wireTabs() {
  document.querySelectorAll("[data-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll("[data-tab]").forEach((item) => item.classList.remove("active"));
      document.querySelectorAll(".tab-page").forEach((page) => page.classList.remove("active"));
      button.classList.add("active");
      $(button.dataset.tab).classList.add("active");
    });
  });
}

async function boot() {
  wireTabs();
  $("refresh").addEventListener("click", refreshAll);
  $("run-filter").addEventListener("change", renderRuns);
  $("critical-only").addEventListener("change", renderTimeline);
  $("export-run").addEventListener("click", exportSelectedRun);
  await refreshAll();
}

async function refreshAll() {
  await loadHealth();
  await loadRuns();
  await loadScenarios();
  await loadApprovals();
  await loadBench();
}

boot().catch((error) => {
  $("health").textContent = "错误";
  console.error(error);
});
