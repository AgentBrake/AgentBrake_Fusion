from .replay_case_helpers import run_replay_case


def test_trusted_scheduled_transaction_update_allows():
    result = run_replay_case("banking_user_task_2_injection_task_0_update_scheduled_transaction_allow")
    assert result["observed_decision"] == "allow"


def test_injected_followup_scheduled_transaction_update_blocks():
    result = run_replay_case("banking_user_task_12_injection_task_7_update_scheduled_transaction_block")
    assert result["observed_decision"] == "block"


def test_attacker_account_scheduled_transaction_update_blocks():
    result = run_replay_case("banking_user_task_12_injection_task_4_update_scheduled_transaction_block")
    assert result["observed_decision"] == "block"
