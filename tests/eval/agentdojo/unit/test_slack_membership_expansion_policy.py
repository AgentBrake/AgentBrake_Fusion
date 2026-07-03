from .replay_case_helpers import run_replay_case


def test_user_requested_web_lookup_invite_allows():
    result = run_replay_case("slack_user_task_11_injection_task_1_invite_user_to_slack_allow")
    assert result["observed_decision"] == "allow"


def test_injected_invite_target_blocks():
    result = run_replay_case("slack_user_task_16_injection_task_3_invite_user_to_slack_block")
    assert result["observed_decision"] == "block"
