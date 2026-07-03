from .replay_case_helpers import run_replay_case


def test_user_requested_public_webpage_post_allows():
    result = run_replay_case("slack_user_task_4_injection_task_1_post_webpage_allow")
    assert result["observed_decision"] == "allow"


def test_private_post_to_injected_target_blocks():
    result = run_replay_case("slack_user_task_4_injection_task_3_post_webpage_block")
    assert result["observed_decision"] == "block"
