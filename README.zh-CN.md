# AgentBrake-Fusion

AgentBrake-Fusion 是面向通用智能体的执行前安全裁决框架。系统拦截智能体即将发起的工具调用、外部动作、状态变更或信息外发，将动作候选转换为结构化证据，再通过多源证据融合裁决判断该动作应当放行、隔离执行、请求确认、隔离归档或阻断。

本仓库保留 `agentbrake` 作为 Python 包名和 CLI 命令名，以兼容现有测试、脚本和实验流程；对外项目名称统一为 `AgentBrake-Fusion`。

## 命名口径

| 模块 | 统一名称 | 中文解释 | 功能定位 |
| --- | --- | --- | --- |
| 系统整体 | AgentBrake-Fusion | 基于多源证据融合裁决的智能体安全刹车系统 | 面向通用智能体工具调用的执行前安全裁决框架。 |
| 动作图 | ActionGraph | 智能体动作证据图 | 结构化用户任务、工具调用、参数来源、工具结果和历史审计。 |
| 多源判断引擎 | MSJ Engine | Multi-Source Judgment Engine，多源综合判断引擎 | 融合多源证据并形成执行前安全裁决事实空间。 |
| 证据裁决结构 | Constraint Product Lattice | 约束乘积格 | 显式处理证据冲突，生成稳定不过度粗暴的裁决。 |
| 审计输出 | BrakeTrace | 刹车轨迹 / 工具调用审计记录 | 记录证据链、reason codes、裁决路径和恢复建议。 |

## 总体链路

```text
智能体工具调用候选
  -> ActionGraph
  -> MSJ Engine
  -> Constraint Product Lattice
  -> 执行前裁决
  -> BrakeTrace
```

裁决结果以工具边界为中心表达：

| 裁决 | 含义 |
| --- | --- |
| `allow` | 证据支持当前动作在目标环境中执行。 |
| `allow_in_sandbox` | 仅允许在隔离或受限环境中执行。 |
| `require_confirmation` / `sandbox_then_approval` | 需要用户或上层策略确认后才可继续。 |
| `quarantine` | 动作和证据进入隔离记录，不直接执行。 |
| `block` | 证据显示该动作不应执行。 |

## 原型底层

当前说明以外层 `src/agentbrake/policy_engine` 作为通用裁决模型，以 `src/agentbrake/eval` 作为 AgentDojo 原型验证层，其中 AgentDojo 适配实现位于：

```text
src/agentbrake/eval/agentdojo/
```

关键模块对应关系：

| AgentBrake-Fusion 概念 | 主体/原型代码位置 | 说明 |
| --- | --- | --- |
| 工具边界拦截 | `gate/tool_firewall.py` | 在工具调用前构造证据、执行裁决并返回安全结果。 |
| ActionGraph | `evidence/action_graph.py` | 生成智能体工具关系图，表达不可信输出、私有数据、攻击目标和后续动作之间的关系。 |
| 证据事实空间 | `evidence/evidence.py` | 汇总任务授权、参数来源、历史状态、工具分类和图谱事实。 |
| MSJ Engine | `src/agentbrake/policy_engine/engine.py` | 融合 ActionGraph、任务授权、来源可信度、策略规则、不变量、历史状态和预执行观察，形成外层执行前安全裁决。 |
| Constraint Product Lattice | `src/agentbrake/policy_engine/constraint_lattice.py` 与 `decision_lattice.py` | 以执行环境、网络范围、数据范围、人类确认和审计范围组合裁决，区分 `require_confirmation` 与 `sandbox_then_approval`。 |
| BrakeTrace | `policy_eval_trace`、`constraint_lattice_trace` 与 `policy_decision` 审计事件 | 输出 fact space、reason codes、rule hits、约束合并路径、裁决模型和恢复控制。 |

## 实验流程

AgentDojo 实验步骤位于：

```text
experiments/agentdojo/
```

建议从轻量流程开始：

```bash
python -m pip install -e ".[test,agentdojo]"
pytest -q tests/eval/agentdojo/unit
python experiments/agentdojo/scripts/smoke_agentdojo_firewall.py
python experiments/agentdojo/scripts/07_run_mini_benchmark.py --suites travel banking --limit 2
```

配对对比实验可使用：

```bash
python experiments/agentdojo/scripts/12_run_paired_mini.py --dry-run
python experiments/agentdojo/scripts/12_run_paired_mini.py
```

实验输出默认写入：

```text
experiments/agentdojo/reports/
experiments/agentdojo/logs/
```

## 文档入口

新的介绍文档集中在：

- `docs/README.zh-CN.md`
- `docs/ARCHITECTURE.zh-CN.md`
- `docs/AGENTDOJO_EXPERIMENT.zh-CN.md`
- `src/agentbrake/eval/agentdojo/README.md`
- `experiments/agentdojo/README.md`

## AgentBrake-Fusion Studio 原型

`web/studio` 已重构为面向竞赛演示的执行前安全裁决工作台，主线是：

```text
OpenClaw 对话 -> 候选工具动作 -> ToolGate 执行前审查
  -> ActionGraph
  -> MSJ Engine
  -> Constraint Product Lattice
  -> allow / require_confirmation / block
  -> BrakeTrace 与审计回放
```

启动后端：

```bash
python -m agentbrake.cli studio-server --repo . --host 127.0.0.1 --port 8780 --demo-mode
```

启动前端：

```bash
cd web/studio
npm install
npm run dev -- --host 127.0.0.1
```

主要页面：

- 接入配置：检测 AgentBrake API、OpenClaw Gateway、A2A Gateway、Local Model、Tool Guard、Audit Stream，并生成 guard 配置。
- 实时对话：通过 `/api/chat/session/:id/message` 与本地 OpenClaw 或 mock 模式对话，所有工具调用先停在候选审查状态。
- 场景演示：内置 workspace、slack、banking、travel、file_sharing、command_api 六类间接提示注入案例。
- 裁决工作台：同时展示 ActionGraph、MSJ Engine、Constraint Product Lattice 和 BrakeTrace。
- 审计中心：通过 `/api/audit` 查看、回放和导出执行前裁决轨迹。
- 策略配置：通过 `/api/policy` 编辑、保存、导出和 dry-run ToolGate 策略。
- 实验成绩：通过 `/api/results/*` 展示 ASR、Security、User Utility、Secure Utility、延迟和消融结果。

新增后端接口位于 `src/agentbrake/studio/server.py`，包括：

```text
GET  /api/openclaw/status
POST /api/openclaw/config
POST /api/openclaw/test
POST /api/chat/session
POST /api/chat/session/:id/message
POST /api/toolgate/review
GET  /api/toolgate/trace/:traceId
GET  /api/actiongraph/:traceId
GET  /api/msj/:traceId
GET  /api/lattice/:traceId
GET  /api/audit
GET  /api/policy
PUT  /api/policy
GET  /api/results/summary
GET  /api/results/agentdojo
GET  /api/results/latency
GET  /api/results/ablation
GET  /api/results/suite-breakdown
```

安全边界：

- 默认启用 sandbox / dry-run，`allowRealTools=false` 时不会真实执行工具副作用。
- 非 loopback host 暴露 Studio 时必须显式配置 bearer token。
- MSJ Engine 面板只展示结构化事实、规则命中和证据来源，不使用加权总分或 confidence score。
- Constraint Product Lattice 使用维度 join 保留冲突证据，冲突不会被平均掉。
