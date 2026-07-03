from pathlib import Path

from agentbrake.demo import run_demo
from agentbrake.replay import verify_bundle


def test_demo_blocks_attack_and_fixes_utility(tmp_path):
    result = run_demo(tmp_path)
    assert any("github:attacker/helper" in x for x in result["blocked"])
    assert not any("github:attacker/helper" in x for x in result["executed"])
    login = Path(result["repo"]) / "src" / "login.js"
    assert "button.onclick = () => submit();" in login.read_text(encoding="utf-8")
    ok, errors = verify_bundle(result["replay_bundle"])
    assert ok, errors
