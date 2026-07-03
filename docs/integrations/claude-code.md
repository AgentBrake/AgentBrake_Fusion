# Claude Code 接入说明

该文档保留路径用于兼容测试和外部引用。AgentBrake-Fusion 的统一定位是面向通用智能体工具调用的执行前安全裁决框架。

推荐接入方式：

```bash
agentbrake connect --agent claude-code --repo . --mode standard
agentbrake start --repo .
agentbrake doctor --repo . --agent claude-code
```

接入后，Claude Code 的工具调用候选应统一进入 ActionGraph、MSJ Engine、Constraint Product Lattice 和 BrakeTrace 链路。
