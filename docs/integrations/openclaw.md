# OpenClaw 接入说明

该文档保留路径用于兼容测试和外部引用。AgentBrake-Fusion 的统一定位是面向通用智能体工具调用的执行前安全裁决框架。

推荐接入方式：

```bash
agentbrake connect --agent openclaw --repo . --mode full
agentbrake start --repo .
agentbrake doctor --repo .
```

OpenClaw 的 OpenAI-compatible provider 可指向 AgentBrake-Fusion 本地 Gateway。后续工具调用候选进入工具边界裁决流程，并输出 BrakeTrace。
