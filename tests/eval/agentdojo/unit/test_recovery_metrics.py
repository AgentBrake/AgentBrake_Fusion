from agentbrake.eval.agentdojo.runner.metrics import compute_recovery_metrics


def test_recovery_success_rate_uses_only_blocked_cases():
    metrics = compute_recovery_metrics(
        [
            {"blocked_case": True, "final_user_task_success": True, "final_injection_task_success": False, "recovery_success": True},
            {"blocked_case": False, "final_user_task_success": False, "final_injection_task_success": False},
        ]
    )
    assert metrics["blocked_case_count"] == 1
    assert metrics["recovery_success_rate"] == 1


def test_no_blocked_cases_returns_null_recovery_metrics():
    metrics = compute_recovery_metrics([{"blocked_case": False}])
    assert metrics["post_block_user_success_rate"] is None
    assert metrics["recovery_success_rate"] is None


def test_repeated_block_rate_counts_retry_key_repeats():
    metrics = compute_recovery_metrics([{"blocked_case": True, "repeated_block_count": 2}])
    assert metrics["repeated_block_rate"] == 2


def test_confirmation_required_is_separate_from_block_count():
    metrics = compute_recovery_metrics([{"blocked_case": False, "confirmation_required_count": 1, "confirmation_executed_count": 0}])
    assert metrics["blocked_case_count"] == 0
    assert metrics["confirmation_case_count"] == 1
    assert metrics["confirmation_required_rate"] == 1


def test_executed_confirmation_counts_as_recovery_cohort():
    metrics = compute_recovery_metrics(
        [
            {
                "blocked_case": False,
                "confirmation_required_count": 1,
                "confirmation_executed_count": 1,
                "final_user_task_success": True,
                "final_injection_task_success": False,
            }
        ]
    )
    assert metrics["blocked_case_count"] == 0
    assert metrics["confirmation_case_count"] == 1
    assert metrics["confirmation_execute_rate"] == 1
    assert metrics["recovery_success_rate"] == 1
