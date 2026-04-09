"""Quick ThreatAtlas demo run.

This script runs the built-in attack corpus against two example targets
(one vulnerable, one safer), prints summaries, calculates a simple risk score,
and writes JSON reports to the outputs/ directory.

Usage:
    python scripts/demo.py --sample 25 --profile balanced

Use a small sample for a fast smoke test; omit --sample to run the full corpus.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from evals.attack_eval import run_attack_eval
from evals.reporting import build_report, print_report_summary, save_report
from evals.risk import score_report
from targets.mock_safe_target import MockSafeTarget
from targets.mock_vulnerable_target import MockVulnerableTarget


def run_for_target(target, sample_size: int | None, profile: str, output_dir: Path):
    results = run_attack_eval(target=target, sample_size=sample_size)
    report = build_report(results)
    risk = score_report(results, profile=profile)

    print(f"\n=== {target.name} ===")
    print_report_summary(report)
    print(
        f"Risk: level={risk['risk_level']} score={risk['risk_score']} "
        f"profile={risk['profile']} critical_failures={risk['critical_failures']}"
    )

    output_path = output_dir / f"demo_{target.name}.json"
    save_report(report, output_path)
    print(f"Report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Run a ThreatAtlas demo")
    parser.add_argument(
        "--sample",
        type=int,
        default=None,
        help="Number of attack rows to evaluate (default: full corpus)",
    )
    parser.add_argument(
        "--profile",
        choices=["strict_security", "balanced", "high_utility"],
        default="balanced",
        help="Risk-weighting profile used for scoring",
    )
    args = parser.parse_args()

    output_dir = Path("outputs")
    output_dir.mkdir(parents=True, exist_ok=True)

    targets = [MockSafeTarget(), MockVulnerableTarget()]
    for target in targets:
        run_for_target(target, sample_size=args.sample, profile=args.profile, output_dir=output_dir)

    print("\nDone. Open the JSON files in outputs/ for full per-case detail.")


if __name__ == "__main__":
    main()
