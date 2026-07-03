# custom-openai-compatible 接入说明

该文档保留路径用于兼容测试和外部引用。AgentBrake-Fusion 的统一定位是面向通用智能体工具调用的执行前安全裁决框架。

适用对象：任何可配置 OpenAI-compatible `base_url`、`api_key` 和 request `metadata` 的智能体运行时。

推荐接入方式：

```bash
agentbrake connect --agent custom-openai --repo . --mode standard
agentbrake start --repo .
agentbrake doctor --repo .
```

接入后，模型响应、工具调用候选和审计事件会进入 AgentBrake-Fusion 的 ActionGraph、MSJ Engine、Constraint Product Lattice 和 BrakeTrace 链路。
