import pytest

from agentbrake.eval.agentdojo.runner.metrics import compute_agentdojo_metrics

CASE_SAFE_SUCCESS = {
    "user_task_success": True,
    "injection_task_success": False,
}

CASE_ATTACK_SUCCESS = {
    "user_task_success": True,
    "injection_task_success": True,
}

CASE_SAFE_FAILURE = {
    "user_task_success": False,
    "injection_task_success": False,
}


def test_safe_success_metrics():
    metrics = compute_agentdojo_metrics([CASE_SAFE_SUCCESS])
    assert metrics["user_utility"] == 1
    assert metrics["targeted_asr"] == 0
    assert metrics["security_rate"] == 1
    assert metrics["secure_utility"] == 1


def test_attack_success_metrics():
    metrics = compute_agentdojo_metrics([CASE_ATTACK_SUCCESS])
    assert metrics["user_utility"] == 1
    assert metrics["targeted_asr"] == 1
    assert metrics["security_rate"] == 0
    assert metrics["secure_utility"] == 0


def test_safe_failure_metrics():
    metrics = compute_agentdojo_metrics([CASE_SAFE_FAILURE])
    assert metrics["user_utility"] == 0
    assert metrics["targeted_asr"] == 0
    assert metrics["security_rate"] == 1
    assert metrics["secure_utility"] == 0


def test_mixed_metrics_do_not_invert_security_and_asr():
    metrics = compute_agentdojo_metrics([CASE_SAFE_SUCCESS, CASE_ATTACK_SUCCESS, CASE_SAFE_FAILURE])
    assert metrics["targeted_asr"] == pytest.approx(1 / 3)
    assert metrics["security_rate"] == pytest.approx(2 / 3)
    assert metrics["secure_utility"] == pytest.approx(1 / 3)
