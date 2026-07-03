"""Registry of evidence facts that can safely drive RuleIndex retrieval."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FactKeySpec:
    path: str
    value_type: str
    cardinality: str
    index_strategy: str
    safety_role: str
    monotone_safe: bool
    ui_label: str
    description: str


def _spec(path: str, value_type: str, cardinality: str, strategy: str, role: str, safe: bool, label: str, description: str) -> FactKeySpec:
    return FactKeySpec(path, value_type, cardinality, strategy, role, safe, label, description)


FACT_KEY_REGISTRY: dict[str, FactKeySpec] = {
    "history.restore_source": _spec(
        "history.restore_source",
        "enum",
        "low",
        "exact",
        "history",
        True,
        "Session restore source",
        "SessionState restore source: memory, file, audit, or none.",
    ),
    "history.state_age_seconds": _spec(
        "history.state_age_seconds",
        "number",
        "medium",
        "range_bucket",
        "history",
        False,
        "Session state age",
        "Seconds since the SessionState summary was last updated.",
    ),
    "flow.secret_to_package_script_reachable": _spec(
        "flow.secret_to_package_script_reachable",
        "bool",
        "low",
        "boolean",
        "flow",
        True,
        "Secret to package script",
        "Secret-tainted data can reach a package lifecycle script.",
    ),
    "flow.untrusted_to_high_risk_reachable": _spec(
        "flow.untrusted_to_high_risk_reachable",
        "bool",
        "low",
        "boolean",
        "flow",
        True,
        "Untrusted to high risk",
        "Untrusted or tainted input influenced a high-risk action.",
    ),
    "flow.attempted_secret_to_network_reachable": _spec(
        "flow.attempted_secret_to_network_reachable",
        "bool",
        "low",
        "boolean",
        "flow",
        True,
        "Attempted secret to network",
        "Attempted secret access precedes a network-capable action but secret exposure was not confirmed.",
    ),
    "flow.package_script_to_network": _spec(
        "flow.package_script_to_network",
        "bool",
        "low",
        "boolean",
        "flow",
        True,
        "Package script to network",
        "A package lifecycle script can reach a network sink.",
    ),
    "flow.package_script_access_env": _spec(
        "flow.package_script_access_env",
        "bool",
        "low",
        "boolean",
        "flow",
        True,
        "Package script env access",
        "A package lifecycle script is connected to environment secret access.",
    ),
    "flow.trace_secret_to_network": _spec(
        "flow.trace_secret_to_network",
        "bool",
        "low",
        "boolean",
        "flow",
        True,
        "Trace secret to network",
        "ExecTrace-enriched graph connects a secret source to network.",
    ),
    "flow.trace_env_to_network": _spec(
        "flow.trace_env_to_network",
        "bool",
        "low",
        "boolean",
        "flow",
        True,
        "Trace env to network",
        "ExecTrace-enriched graph connects environment access to network.",
    ),
    "graph.has_package_lifecycle_edge": _spec(
        "graph.has_package_lifecycle_edge",
        "bool",
        "low",
        "boolean",
        "graph",
        True,
        "Package lifecycle edge",
        "ActionGraph contains an install-to-lifecycle controlflow edge.",
    ),
    "graph.exec_trace_enriched": _spec(
        "graph.exec_trace_enriched",
        "bool",
        "low",
        "boolean",
        "graph",
        True,
        "ExecTrace enriched",
        "ActionGraph was enriched with preflight ExecTrace evidence.",
    ),
    "history.attempted_secret_taint": _spec(
        "history.attempted_secret_taint",
        "bool",
        "low",
        "boolean",
        "history",
        True,
        "Attempted secret taint",
        "Session history contains an attempted secret access.",
    ),
    "history.confirmed_secret_taint": _spec(
        "history.confirmed_secret_taint",
        "bool",
        "low",
        "boolean",
        "history",
        True,
        "Confirmed secret taint",
        "Session history confirms secret data entered context or execution.",
    ),
    "history.secret_taint_level": _spec(
        "history.secret_taint_level",
        "enum",
        "low",
        "exact",
        "history",
        True,
        "Secret taint level",
        "Secret taint confidence: none, attempted, or confirmed.",
    ),
    "history.attempted_secret_asset": _spec(
        "history.attempted_secret_asset",
        "list",
        "medium",
        "list_each",
        "history",
        True,
        "Attempted secret asset",
        "Secret asset touched by a blocked or unconfirmed attempt.",
    ),
    "history.confirmed_secret_asset": _spec(
        "history.confirmed_secret_asset",
        "list",
        "medium",
        "list_each",
        "history",
        True,
        "Confirmed secret asset",
        "Secret asset confirmed to have been read.",
    ),
    "action.semantic_action": _spec(
        "action.semantic_action", "enum", "medium", "exact", "action", True, "动作语义", "代理动作的标准化语义。"
    ),
    "action.risk": _spec("action.risk", "enum", "low", "exact", "action", True, "动作风险", "动作解析阶段给出的风险等级。"),
    "action.high_risk": _spec("action.high_risk", "bool", "low", "boolean", "action", True, "高危动作", "动作是否属于高危能力。"),
    "action.network_capability": _spec(
        "action.network_capability", "bool", "low", "boolean", "sink", True, "联网能力", "动作是否可能连接外部网络。"
    ),
    "action.parser_confidence": _spec(
        "action.parser_confidence",
        "number",
        "medium",
        "range_bucket",
        "observation",
        False,
        "解析置信度",
        "低置信副作用规则可用的数值事实。",
    ),
    "source.trust_floor": _spec(
        "source.trust_floor", "enum", "low", "exact", "authority", True, "来源可信度", "影响动作授权强弱的来源证据。"
    ),
    "source.has_untrusted": _spec(
        "source.has_untrusted", "bool", "low", "boolean", "taint", True, "存在低可信来源", "是否受到外部低可信文本影响。"
    ),
    "asset.touched_type": _spec("asset.touched_type", "list", "medium", "list_each", "asset", True, "触碰资产类型", "动作触及的资产类别。"),
    "asset.repo_escape": _spec("asset.repo_escape", "bool", "low", "boolean", "asset", True, "仓库边界逃逸", "是否越过仓库边界。"),
    "asset.symlink_escape": _spec(
        "asset.symlink_escape", "bool", "low", "boolean", "asset", True, "符号链接逃逸", "是否通过符号链接绕过边界。"
    ),
    "contract.match": _spec("contract.match", "enum", "low", "exact", "contract", True, "任务边界匹配", "动作是否符合用户任务契约。"),
    "contract.forbidden_file_touch": _spec(
        "contract.forbidden_file_touch", "bool", "low", "boolean", "contract", True, "触碰禁止文件", "动作是否触碰任务禁止文件。"
    ),
    "package.source": _spec(
        "package.source", "enum", "low", "exact", "sink", True, "依赖来源", "依赖来自 registry、git_url 或 tarball_url。"
    ),
    "package.lifecycle_scripts": _spec(
        "package.lifecycle_scripts", "bool", "low", "boolean", "sink", True, "生命周期脚本", "依赖是否存在安装脚本风险。"
    ),
    "secret.event": _spec("secret.event", "enum", "medium", "exact", "taint", True, "密钥事件", "SecretSentry 产生的安全事件。"),
    "sandbox.risk_observed": _spec(
        "sandbox.risk_observed", "list", "medium", "list_each", "observation", True, "沙箱风险观察", "沙箱预检观察到的风险。"
    ),
    "mcp.capability": _spec("mcp.capability", "string", "medium", "exact", "sink", True, "MCP 能力", "MCP 工具暴露的能力。"),
    "memory.authorization": _spec(
        "memory.authorization", "enum", "low", "exact", "authority", True, "记忆授权", "MemoryStore 授权或拒绝事件。"
    ),
    "memory.authorization_denied": _spec(
        "memory.authorization_denied", "bool", "low", "boolean", "authority", True, "记忆授权拒绝", "MemoryStore 是否拒绝授权高危动作。"
    ),
    "graph.has_dataflow_edge": _spec(
        "graph.has_dataflow_edge",
        "bool",
        "low",
        "boolean",
        "graph",
        True,
        "存在数据流边",
        "动作图是否存在 pipe、redirect 或 dataflow 关系。",
    ),
    "graph.has_memoryflow_edge": _spec(
        "graph.has_memoryflow_edge",
        "bool",
        "low",
        "boolean",
        "graph",
        True,
        "存在记忆流边",
        "动作图是否存在跨工具输出或历史状态推断出的 memoryflow 关系。",
    ),
    "graph.has_pipe_edge": _spec(
        "graph.has_pipe_edge", "bool", "low", "boolean", "graph", True, "存在管道边", "动作图是否存在 shell pipe 关系。"
    ),
    "graph.has_redirect_edge": _spec(
        "graph.has_redirect_edge", "bool", "low", "boolean", "graph", True, "存在重定向边", "动作图是否存在文件重定向关系。"
    ),
    "graph.has_sequence": _spec(
        "graph.has_sequence", "bool", "low", "boolean", "graph", True, "存在顺序执行", "动作图是否包含多节点顺序或控制流。"
    ),
    "graph.node_count": _spec(
        "graph.node_count", "number", "medium", "range_bucket", "graph", False, "动作节点数", "复合动作图中的节点数量。"
    ),
    "graph.edge_count": _spec("graph.edge_count", "number", "medium", "range_bucket", "graph", False, "动作边数", "复合动作图中的边数量。"),
    "graph.complete": _spec("graph.complete", "bool", "low", "boolean", "graph", False, "动作图完整性", "动作图解析器是否认为图结构完整。"),
    "graph.confidence_min": _spec(
        "graph.confidence_min", "number", "medium", "range_bucket", "graph", False, "最低图置信度", "动作图节点与边中的最低置信度。"
    ),
    "flow.secret_to_external": _spec(
        "flow.secret_to_external", "bool", "low", "boolean", "flow", True, "密钥流向外部", "动作图或历史摘要是否表明密钥可能流向网络 sink。"
    ),
    "flow.secret_to_network_reachable": _spec(
        "flow.secret_to_network_reachable",
        "bool",
        "low",
        "boolean",
        "flow",
        True,
        "密钥可达网络",
        "历史密钥污染与当前联网能力是否同时出现。",
    ),
    "history.secret_taint": _spec(
        "history.secret_taint", "bool", "low", "boolean", "history", True, "历史密钥污染", "当前运行历史中是否已经触碰密钥。"
    ),
    "history.untrusted_seen": _spec(
        "history.untrusted_seen", "bool", "low", "boolean", "history", True, "历史低可信来源", "当前运行历史中是否出现过低可信来源。"
    ),
    "history.package_taint": _spec(
        "history.package_taint", "bool", "low", "boolean", "history", True, "历史依赖风险", "当前运行历史中是否出现过依赖风险。"
    ),
    "history.prior_external_sink": _spec(
        "history.prior_external_sink",
        "list",
        "medium",
        "list_each",
        "history",
        True,
        "历史外部 sink",
        "当前运行历史中观察到的外部通信目标。",
    ),
    "history.loaded_from_persistent": _spec(
        "history.loaded_from_persistent",
        "bool",
        "low",
        "boolean",
        "history",
        True,
        "持久状态恢复",
        "SessionState 是否从文件或审计日志恢复。",
    ),
    "history.state_hash": _spec(
        "history.state_hash", "string", "medium", "exact", "history", False, "状态摘要哈希", "SessionState 脱敏摘要的稳定哈希。"
    ),
    "constraint.network_scope": _spec(
        "constraint.network_scope", "enum", "low", "exact", "constraint", True, "网络约束", "内部约束格合并后的网络访问范围。"
    ),
    "constraint.data_scope": _spec(
        "constraint.data_scope", "enum", "low", "exact", "constraint", True, "数据约束", "内部约束格合并后的数据访问范围。"
    ),
    "exec.network_attempts": _spec(
        "exec.network_attempts", "bool", "low", "boolean", "observation", True, "执行网络尝试", "ExecTrace 是否观察到联网尝试。"
    ),
    "exec.package_scripts": _spec(
        "exec.package_scripts", "bool", "low", "boolean", "observation", True, "执行包脚本", "ExecTrace 是否观察到包生命周期脚本。"
    ),
    "trace.enriched_graph": _spec(
        "trace.enriched_graph", "bool", "low", "boolean", "observation", True, "执行轨迹补图", "ActionGraph 是否融合了 ExecTrace 观察。"
    ),
}


def fact_spec(path: str) -> FactKeySpec | None:
    return FACT_KEY_REGISTRY.get(path)
