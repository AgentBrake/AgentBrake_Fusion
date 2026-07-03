# AgentBrake-Fusion 文档入口

本目录只保留新的介绍文档，旧的阶段性说明和旧命名口径已经移除。当前统一表述如下：

```text
AgentBrake-Fusion = 面向通用智能体工具调用的执行前安全裁决框架
```

## 阅读顺序

1. `../README.zh-CN.md`
   项目总览、统一命名、原型底层和实验入口。
2. `ARCHITECTURE.zh-CN.md`
   说明 ActionGraph、MSJ Engine、Constraint Product Lattice 和 BrakeTrace 的关系。
3. `AGENTDOJO_EXPERIMENT.zh-CN.md`
   说明如何基于 `experiments/agentdojo` 运行轻量实验、配对对比和消融分析。
4. `../src/agentbrake/eval/agentdojo/README.md`
   说明 `src/agentbrake/eval` 原型底层如何映射到 AgentBrake-Fusion 模块。
5. `../experiments/agentdojo/README.md`
   说明 AgentDojo 实验目录的具体脚本和输出路径。

## 模块口径

| 模块 | 名称 | 说明 |
| --- | --- | --- |
| 系统整体 | AgentBrake-Fusion | 通用智能体工具调用的安全刹车系统。 |
| 动作图 | ActionGraph | 智能体动作证据图。 |
| 多源判断引擎 | MSJ Engine | Multi-Source Judgment Engine。 |
| 证据裁决结构 | Constraint Product Lattice | 约束乘积格。 |
| 审计输出 | BrakeTrace | 刹车轨迹与工具调用审计记录。 |

## 当前边界

本仓库以 `src/agentbrake/eval` 中的 AgentDojo 工具边界原型为底层说明对象，重点展示多源证据融合裁决，而不是绑定某一种智能体形态。`AgentBrake-Fusion` 仍作为包名和命令名存在，这是为了保持代码与测试兼容。
