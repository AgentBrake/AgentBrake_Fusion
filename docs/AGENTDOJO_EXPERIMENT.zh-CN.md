# AgentDojo 实验步骤

`experiments/agentdojo` 是 AgentBrake-Fusion 当前推荐的实验流程目录。它把 AgentBrake-Fusion 放在 AgentDojo 的工具调用边界上，观察智能体在面对不可信工具输出、注入式内容、私有数据和高风险副作用工具时的裁决效果。

## 1. 安装依赖

```bash
python -m pip install -e ".[test,agentdojo]"
```

如果只跑单元测试，可以先安装：

```bash
python -m pip install -e ".[test]"
```

## 2. 单元测试

```bash
pytest -q tests/eval/agentdojo/unit
```

该步骤验证工具分类、状态跟踪、ActionGraph、证据构造、MSJ Engine、Constraint Product Lattice 和 BrakeTrace 输出的基本行为。

## 3. 快速冒烟

```bash
python experiments/agentdojo/scripts/smoke_agentdojo_firewall.py
```

冒烟测试关注几类最小场景：

- 授权任务中的正常工具调用应当允许。
- 不可信输出诱导的错误预订应当阻断。
- 私有数据之后的外发动作应当阻断或要求确认。
- 未授权金融提交应当阻断。
- 只读工具应当保持可用，并更新历史状态。

## 4. Mini Benchmark

```bash
python experiments/agentdojo/scripts/07_run_mini_benchmark.py --suites travel banking --limit 2
```

默认输出：

```text
experiments/agentdojo/reports/mini_benchmark.json
experiments/agentdojo/reports/mini_benchmark.md
experiments/agentdojo/logs/
```

报告中重点观察：

- Utility Under Attack
- Security
- Targeted ASR
- gated tool call 数量
- blocked tool call 数量
- policy p50 / p95 延迟
- reason code 命中分布

## 5. 配对对比

先生成执行计划：

```bash
python experiments/agentdojo/scripts/12_run_paired_mini.py --dry-run
```

确认计划后运行：

```bash
python experiments/agentdojo/scripts/12_run_paired_mini.py
```

配对对比用于比较无防护、基线工具过滤和 AgentBrake-Fusion 工具边界裁决的差异。

## 6. 消融分析

当前原型支持通过 ablation profile 关闭部分模块，观察各证据源对最终裁决的贡献：

- `rule_only`
- `no_binding`
- `no_recovery_guidance`
- `flatten_action_graph`
- `no_actiongraph_provenance_edges`
- `no_actiongraph_dataflow_edges`
- `no_actiongraph_history_edges`

这些 profile 对应 `src/agentbrake/eval/agentdojo/compat/types.py` 中的配置。

## 7. 结果整理

实验产物统一进入：

```text
experiments/agentdojo/reports/
experiments/agentdojo/logs/
experiments/agentdojo/replay_cases/
```

历史基线保留在：

```text
experiments/agentdojo/archive/
```

不要把历史基线和当前实验混放；当前说明以工具边界裁决流程为主。
