# Aider 接入说明

该文档保留路径用于兼容测试和外部引用。AgentBrake-Fusion 的统一定位是面向通用智能体工具调用的执行前安全裁决框架。

推荐接入方式：

```bash
agentbrake connect --agent aider --repo . --mode standard
agentbrake start --repo .
agentbrake doctor --repo . --agent aider
```

接入后，Aider 产生的工具调用或命令候选会被转换为结构化证据，并进入 AgentBrake-Fusion 裁决流程。
