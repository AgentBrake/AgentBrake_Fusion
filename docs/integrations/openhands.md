# OpenHands 接入说明

该文档保留路径用于兼容测试和外部引用。AgentBrake-Fusion 的统一定位是面向通用智能体工具调用的执行前安全裁决框架。

推荐接入方式：

```bash
agentbrake connect --agent openhands --repo . --mode full
agentbrake start --repo .
agentbrake doctor --repo . --agent openhands
```

OpenHands 可通过 OpenAI-compatible Gateway 和工具边界 adapter 接入 AgentBrake-Fusion，使工具候选动作在执行前进入多源证据融合裁决。
