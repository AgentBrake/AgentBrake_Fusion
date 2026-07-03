from agentbrake.eval.agentdojo.evidence.taxonomy import AgentDojoToolTaxonomy


def test_taxonomy_groups_core_tools():
    tax = AgentDojoToolTaxonomy()
    assert tax.classify("send_money", suite="banking").group == "financial_commit"
    assert tax.classify("send_direct_message", suite="slack").group == "external_send"
    assert tax.classify("reserve_hotel", suite="travel").group == "booking_commit"
    assert tax.classify("delete_file", suite="workspace").group == "destructive_update"
    assert tax.classify("totally_new_mutating_tool").group == "unknown"


