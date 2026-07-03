# Codex CLI 接入说明

该文档保留路径用于兼容测试和外部引用。AgentBrake-Fusion 的统一定位是面向通用智能体工具调用的执行前安全裁决框架。

推荐接入方式：

```bash
agentbrake connect --agent codex --repo . --mode standard
agentbrake start --repo .
agentbrake doctor --repo . --agent codex
```

新增或调整智能体接入时，优先通过 YAML profile 和工具解析映射完成，不为单个智能体在核心裁决链路里写特殊分支。
