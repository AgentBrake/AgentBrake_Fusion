from agentbrake.gateway.session_identity import resolve_session_identity


def test_session_identity_prefers_agentbrake_run_id(tmp_path):
    identity = resolve_session_identity(
        request={"metadata": {"agentbrake_run_id": "run_explicit", "run_id": "run_compat"}},
        repo_root=tmp_path,
    )

    assert identity.run_id == "run_explicit"
    assert identity.source == "metadata.agentbrake_run_id"


def test_session_identity_uses_compatible_run_id(tmp_path):
    identity = resolve_session_identity(request={"metadata": {"run_id": "run_compat"}}, repo_root=tmp_path)

    assert identity.run_id == "run_compat"
    assert identity.source == "metadata.run_id"


def test_session_identity_derives_stable_run_id_from_conversation(tmp_path):
    first = resolve_session_identity(
        request={"request_id": "req_1", "metadata": {"conversation_id": "conv_1", "client_id": "client_a"}},
        repo_root=tmp_path,
    )
    second = resolve_session_identity(
        request={"request_id": "req_2", "metadata": {"conversation_id": "conv_1", "client_id": "client_a"}},
        repo_root=tmp_path,
    )

    assert first.run_id == second.run_id
    assert first.run_id.startswith("run_")
    assert first.source == "derived.conversation"


def test_session_identity_reads_http_header(tmp_path):
    identity = resolve_session_identity(
        request={"metadata": {"conversation_id": "conv_1"}},
        repo_root=tmp_path,
        headers={"X-AgentBrake-Fusion-Run-Id": "run_header"},
    )

    assert identity.run_id == "run_header"
    assert identity.source == "header.x-AgentBrake-Fusion-run-id"
