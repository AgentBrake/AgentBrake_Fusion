from __future__ import annotations

import pytest

from agentbrake.eval.agentdojo.compat.types import ablation_config_from_profile


def test_full_profile_enables_core_modules() -> None:
    cfg = ablation_config_from_profile("full")
    assert cfg.enable_provenance
    assert cfg.enable_task_contract
    assert cfg.enable_action_graph
    assert cfg.enable_suite_policy
    assert cfg.enable_recovery_guidance
    assert cfg.enable_generic_sink_policy


def test_rule_only_keeps_generic_sink_policy_only() -> None:
    cfg = ablation_config_from_profile("rule_only")
    assert not cfg.enable_provenance
    assert not cfg.enable_task_contract
    assert not cfg.enable_action_graph
    assert not cfg.enable_suite_policy
    assert not cfg.enable_recovery_guidance
    assert cfg.enable_generic_sink_policy


def test_no_binding_disables_provenance_and_task_contract() -> None:
    cfg = ablation_config_from_profile("no_binding")
    assert not cfg.enable_provenance
    assert not cfg.enable_task_contract
    assert cfg.enable_action_graph
    assert cfg.enable_suite_policy


def test_legacy_no_context_graph_disables_graph_facts() -> None:
    cfg = ablation_config_from_profile("legacy_no_context_graph")
    assert cfg.enable_provenance
    assert cfg.enable_task_contract
    assert not cfg.enable_action_graph


def test_no_context_graph_is_legacy_only() -> None:
    with pytest.raises(ValueError, match="legacy-only"):
        ablation_config_from_profile("no_context_graph")


def test_no_recovery_guidance_keeps_decision_modules() -> None:
    cfg = ablation_config_from_profile("no_recovery_guidance")
    assert cfg.enable_provenance
    assert cfg.enable_task_contract
    assert cfg.enable_action_graph
    assert cfg.enable_suite_policy
    assert not cfg.enable_recovery_guidance


def test_unknown_profile_raises_value_error() -> None:
    with pytest.raises(ValueError):
        ablation_config_from_profile("not_a_profile")
