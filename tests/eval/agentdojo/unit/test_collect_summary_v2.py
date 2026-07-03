import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "experiments" / "agentdojo" / "scripts" / "06_collect_summary.py"
spec = importlib.util.spec_from_file_location("collect_summary", SCRIPT)
assert spec and spec.loader
collect_summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collect_summary)


def test_render_main_results_uses_v2_metric_names():
    lines = collect_summary.render_main_results(
        [
            {
                "defense": "agentdojo_firewall",
                "suite": "banking",
                "utility_results": {"u0::i0": True, "u0::i1": True},
                "security_results": {"u0::i0": False, "u0::i1": True},
                "total_runtime_min": 1.0,
            }
        ]
    )
    text = "\n".join(lines)
    assert "User Utility" in text
    assert "Security Rate" in text
    assert "Secure Utility" in text
    assert "| AgentDojo Firewall Fair | 1.000 | 0.500 | 0.500 | 0.500 |" in text
