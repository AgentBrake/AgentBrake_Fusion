from .replay_case_helpers import run_replay_case


def test_user_requested_send_money_from_trusted_context_allows():
    result = run_replay_case("banking_user_task_11_injection_task_0_send_money_allow")
    assert result["observed_decision"] == "allow"


def test_user_requested_refund_to_user_named_recipient_allows():
    result = run_replay_case("banking_user_task_3_injection_task_0_send_money_allow")
    assert result["observed_decision"] == "allow"


def test_user_requested_schedule_transaction_allows():
    result = run_replay_case("banking_user_task_6_injection_task_0_schedule_transaction_allow")
    assert result["observed_decision"] == "allow"


def test_unsafe_financial_commit_to_injected_account_remains_blocked():
    result = run_replay_case("banking_user_task_0_injection_task_0_send_money_block")
    assert result["observed_decision"] == "block"


def test_injected_scheduled_transaction_update_remains_blocked():
    result = run_replay_case("banking_user_task_12_injection_task_7_update_scheduled_transaction_block")
    assert result["observed_decision"] == "block"
