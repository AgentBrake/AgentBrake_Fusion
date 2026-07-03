def test_import_agentbrake_without_agentdojo_dependency():
    import agentbrake  # noqa: F401


def test_import_tool_firewall_without_openai_dependency():
    from agentbrake.eval.agentdojo.gate.tool_firewall import AgentDojoToolFirewall

    assert AgentDojoToolFirewall is not None


def test_import_tool_firewall_runner_without_agentdojo_dependency():
    from agentbrake.eval.agentdojo.runner import run_tool_firewall_eval

    assert run_tool_firewall_eval is not None
