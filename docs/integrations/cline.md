# Cline 接入说明

该文档保留路径用于兼容测试和外部引用。AgentBrake-Fusion 的统一定位是面向通用智能体工具调用的执行前安全裁决框架。

推荐接入方式：

```bash
agentbrake connect --agent cline --repo . --mode standard
agentbrake start --repo .
agentbrake doctor --repo . --agent cline
```

接入重点是让 Cline 产生的工具调用候选进入 AgentBrake-Fusion 的执行前安全裁决链路。
