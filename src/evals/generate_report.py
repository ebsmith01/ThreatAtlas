from __future__ import annotations

from pathlib import Path

ATTACK_CORPUS_PATH = Path(
    "data/attacks/final/attack_corpus.jsonl"
)
REPORTS_DIR = Path("outputs")


def run_eval(
    n: int,
    target_name: str,
    system: str | None = None,
    attack_category: str | None = None,
    sensitivity: str | None = None,
    actor_role: str | None = None,
    **kwargs,
) -> dict:
    from data.loaders import load_attack_corpus
    from evals.attack_filtering import (
        filter_attacks,
    )
    from evals.coverage_metrics import (
        coverage,
    )
    from evals.execution import (
        evaluate_attack,
    )
    from evals.risk import score_report
    from evals.summary_metrics import (
        summarize,
    )
    from evals.target_registry import (
        get_target,
    )
    from evals.telemetry_metrics import (
        compute_telemetry_metrics,
    )

    attacks = load_attack_corpus(
        ATTACK_CORPUS_PATH
    )
    attacks = filter_attacks(
        attacks,
        system=system,
        attack_category=attack_category,
        sensitivity=sensitivity,
        actor_role=actor_role,
        sample_size=n,
    )
    target = get_target(
        target_name,
        **kwargs,
    )

    results = [
        evaluate_attack(
            attack,
            target,
            attack_category=attack_category,
            sensitivity=sensitivity,
            actor_role=actor_role,
        )
        for attack in attacks
    ]

    telemetry_events = [
        {
            **(result.get("telemetry") or {}),
            "target_system": result.get(
                "target_system"
            ),
            "violated_rules": result.get(
                "violated_rules",
                [],
            ),
            "policy_violations": result.get(
                "policy_result",
                {},
            ).get(
                "policy_violations",
                [],
            ),
        }
        for result in results
        if result.get("telemetry")
    ]

    return {
        "summary": summarize(results),
        "coverage": coverage(results),
        "risk": score_report(results),
        "telemetry_metrics": compute_telemetry_metrics(
            telemetry_events
        ),
        "results": results,
    }


if __name__ == "__main__":
    import sys

    sys.modules.setdefault(
        "evals.generate_report",
        sys.modules[__name__],
    )

    from evals.cli import main

    main()
