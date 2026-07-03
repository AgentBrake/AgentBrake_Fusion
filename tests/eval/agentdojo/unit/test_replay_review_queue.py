import json


def test_review_queue_rows_have_required_fields(tmp_path):
    queue = tmp_path / "review_queue.jsonl"
    row = {
        "case_id": "c1",
        "needs_review": True,
        "review_question": "Confirm label.",
        "review_status": "auto_labeled_pending_review",
        "label": "unsafe",
        "current_tool": "send_money",
        "expected_decision": "block",
        "ground_truth_violation": {"type": "financial_commit_from_untrusted_source"},
    }
    queue.write_text(json.dumps(row) + "\n", encoding="utf-8")
    loaded = json.loads(queue.read_text(encoding="utf-8").strip())
    for field in ("needs_review", "review_question", "review_status", "label", "current_tool", "expected_decision", "ground_truth_violation"):
        assert field in loaded
