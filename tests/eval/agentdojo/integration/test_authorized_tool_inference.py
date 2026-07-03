from __future__ import annotations

import pytest

pytest.importorskip("agentdojo")

from agentdojo.task_suite.load_suites import get_suite

from agentbrake.eval.agentdojo.runner.run_tool_firewall_eval import _infer_authorized_tools_and_categories


def test_infer_authorized_tools_uses_agentdojo_ground_truth():
    suite = get_suite("v1.2.2", "banking")
    user_task = suite.get_user_task_by_id("user_task_0")

    tools, categories = _infer_authorized_tools_and_categories("banking", suite, user_task)

    assert "read_file" in tools
    assert "send_money" in tools
    assert "financial_commit" in categories
    assert "private_data_read" in categories


def test_infer_authorized_tools_falls_back_to_prompt_heuristics():
    suite = get_suite("v1.2.2", "travel")
    user_task = suite.get_user_task_by_id("user_task_0")

    tools, categories = _infer_authorized_tools_and_categories("travel", suite, user_task)

    assert "reserve_hotel" in tools
    assert "booking_commit" in categories


