from __future__ import annotations

import pytest

from agentbrake.eval.agentdojo.compat.types import ablation_config_from_profile


def test_actiongraph_profiles_target_edge_families() -> None:
    flat = ablation_config_from_profile("flatten_action_graph")
    assert flat.enable_action_graph
    assert not flat.enable_actiongraph_structure_edges
    assert not flat.enable_actiongraph_provenance_edges
    assert not flat.enable_actiongraph_dataflow_edges
    assert not flat.enable_actiongraph_history_edges

    provenance = ablation_config_from_profile("no_actiongraph_provenance_edges")
    assert provenance.enable_action_graph
    assert provenance.enable_actiongraph_structure_edges
    assert not provenance.enable_actiongraph_provenance_edges
    assert provenance.enable_actiongraph_dataflow_edges
    assert provenance.enable_actiongraph_history_edges

    dataflow = ablation_config_from_profile("no_actiongraph_dataflow_edges")
    assert dataflow.enable_actiongraph_provenance_edges
    assert not dataflow.enable_actiongraph_dataflow_edges

    history = ablation_config_from_profile("no_actiongraph_history_edges")
    assert history.enable_actiongraph_provenance_edges
    assert not history.enable_actiongraph_history_edges


def test_no_context_graph_is_not_active_actiongraph_profile() -> None:
    with pytest.raises(ValueError, match="legacy-only"):
        ablation_config_from_profile("no_context_graph")
