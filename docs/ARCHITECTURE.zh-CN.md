# AgentBrake-Fusion 架构说明

AgentBrake-Fusion 的核心目标是在智能体动作真正执行之前，用多源证据形成稳定、可解释、不过度粗暴的安全裁决。

## 1. ActionGraph

ActionGraph 是智能体动作证据图。它把当前工具调用候选、历史工具结果、参数来源、任务授权、私有数据读取和不可信内容影响关系放到同一个结构里。

在当前原型中，ActionGraph 由 `src/agentbrake/eval/agentdojo/evidence/action_graph.py` 构造。它不是程序级数据流图，而是面向工具边界的关系图，重点表达：

- 不可信工具输出是否影响后续副作用工具调用。
- 注入式文本是否影响高风险动作。
- 私有数据读取是否流向外部发送或共享动作。
- 私有金融信息是否影响金融提交动作。
- 历史攻击目标是否和当前工具参数重合。

## 2. MSJ Engine

MSJ Engine 是 Multi-Source Judgment Engine，多源综合判断引擎。它接收 ActionGraph、任务授权、工具分类、参数溯源、历史状态和套件策略，形成执行前安全裁决事实空间。

外层仓库中的主要入口是：

```text
src/agentbrake/policy_engine/engine.py
src/agentbrake/policy_engine/fact_extractor.py
src/agentbrake/policy_engine/semantic_invariants.py
```

`fact_extractor.py` 负责构造事实空间，`engine.py` 中的 `MSJEngine` 负责融合事实、规则、不变量、历史状态和预执行观察，并把结果交给 Constraint Product Lattice 合并为公开裁决。`src/agentbrake/eval/agentdojo/evidence/fusion.py` 是 AgentDojo 评测层的专用原型对应实现。

## 3. Constraint Product Lattice

Constraint Product Lattice 是约束乘积格。它不把所有风险都粗暴映射为阻断，而是把裁决拆成多个维度，再进行合并：

- 执行环境：直接执行、隔离执行、不执行。
- 网络范围：允许、限制、拒绝。
- 数据范围：可访问范围、私有数据限制。
- 人类确认：无需确认、需要确认、审批后执行。
- 审计范围：普通记录、完整记录、隔离记录。

这些维度共同生成公开裁决，例如 `allow`、`allow_in_sandbox`、`require_confirmation`、`quarantine` 和 `block`。

## 4. BrakeTrace

BrakeTrace 是刹车轨迹，也就是工具调用审计记录。它需要能回答四个问题：

- 哪些证据参与了裁决。
- 哪些规则或 reason codes 命中。
- 裁决是如何从约束合并中得到的。
- 被阻断或确认时，智能体应该如何恢复到安全路径。

外层仓库中，`policy_eval_trace`、`constraint_lattice_trace` 和 `policy_decision` 共同构成 BrakeTrace 的主要形态，包含 fact space、ActionGraph 摘要、rule hits、reason codes、约束合并路径、裁决模型、确认状态和恢复控制。AgentDojo 评测层中，`ToolExecutionDecision.to_audit_event()` 是同一概念的专用审计事件。

## 5. 端到端裁决流程

```text
工具调用候选
  -> 工具分类与风险标注
  -> 历史状态更新
  -> ActionGraph 构造
  -> 事实空间构造
  -> MSJ Engine 融合判断
  -> Constraint Product Lattice 合并约束
  -> 执行前裁决
  -> BrakeTrace 审计输出
```
