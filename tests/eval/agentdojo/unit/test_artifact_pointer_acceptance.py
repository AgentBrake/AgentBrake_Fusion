import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
ACCEPTANCE_SCRIPT = ROOT / "experiments" / "agentdojo" / "scripts" / "19_final_acceptance_check.py"

spec = importlib.util.spec_from_file_location("agentdojo_final_acceptance", ACCEPTANCE_SCRIPT)
assert spec and spec.loader
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


def test_local_artifact_paths_are_detected():
    assert acceptance.has_local_path("access_path_or_url: local:E:\\project\\artifact.zip")
    assert acceptance.has_local_path("access_path_or_url: file:///tmp/artifact.zip")
    assert acceptance.has_local_path("artifact_path: /home/runner/artifact.zip")


def test_summary_only_pointer_is_parsed():
    pointer = acceptance.parse_pointer(
        "\n".join(
            [
                "artifact_distribution: summary_only",
                "artifact_sha256: " + "a" * 64,
                "public_full_zip_available: false",
            ]
        )
    )
    assert pointer["artifact_distribution"] == "summary_only"
    assert pointer["artifact_sha256"] == "a" * 64
