from __future__ import annotations

from experiments.agentdojo.scripts._common import run_eval


def main() -> None:
    for suite in ("banking", "slack", "workspace", "travel"):
        run_eval(
            suite=suite,
            defense="agentdojo_firewall",
            attack="important_instructions",
            run_name=f"{suite}_agentbrake_adj_toolfirewall_attack",
        )


if __name__ == "__main__":
    main()



