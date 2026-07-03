# Agent-SafetyBench + AgentBrake-Fusion

这个目录用于把 AgentBrake-Fusion 插入 Agent-SafetyBench 的工具执行前。

核心插入点对应上游 `evaluation/eval.py` 中的：

```python
tool_call_result = env.call_tool(tool_name, deepcopy(arguments))
```

本适配层不修改上游文件，而是在 `agentbrake_runner.py` 中复刻评测循环，并替换为：

```text
model candidate tool call
  -> AgentBrake-Fusion ToolGate
  -> allow 才调用 env.call_tool(...)
  -> block / require_confirmation 返回安全工具结果
```

## 运行 deepseek-v4-flash 小样本

不要把 API key 写入源码或提交材料。只在当前 PowerShell 会话中设置：

```powershell
$env:DEEPSEEK_API_KEY="你的 key"
$env:DEEPSEEK_API_BASE="你的 OpenAI-compatible base URL"
python experiments/agent_safetybench/agentbrake_runner.py --model deepseek-v4-flash --limit 10
```

如果你的 DeepSeek 服务使用官方兼容地址，可以省略 `DEEPSEEK_API_BASE`，脚本默认使用：

```text
https://api.deepseek.com/v1
```

## 输出

默认输出目录：

```text
experiments/agent_safetybench/reports/deepseek_v4_flash/agentbrake_toolgate
```

主要文件：

- `gen_res.json`：带 AgentBrake ToolGate 结果的 Agent-SafetyBench 生成轨迹。
- `guard_trace.jsonl`：每一次候选工具调用的裁决记录。
- `summary.json`：核心统计指标。
- `summary.md`：论文写作可读摘要。

## 重要说明

Agent-SafetyBench 原始评分依赖 ShieldAgent 判断完整对话是否 safe / unsafe。
本适配层首先提供工具级执行前裁决指标，包括：

- Dangerous Action Blocking Rate
- Unsafe Tool Execution Rate
- Safe Action Pass Rate
- ToolGate decision distribution
- by-risk decision distribution

如需复现官方 safety score，可将 `gen_res.json` 作为上游 `score/eval_with_shield.py`
的输入格式基础，再接 ShieldAgent 评分。
