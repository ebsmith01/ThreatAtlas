from __future__ import annotations

import argparse
import json

from .generate_report import (
    REPORTS_DIR,
    run_eval,
)
from .report_printer import (
    print_report,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run ThreatAtlas evaluation"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target name to evaluate",
    )
    parser.add_argument(
        "--system",
        help="Filter attacks by target system",
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=25,
        help="Number of attacks to evaluate",
    )
    parser.add_argument(
        "--attack-category",
        dest="attack_category",
        help="Filter attacks by category",
    )
    parser.add_argument(
        "--sensitivity",
        help="Filter attacks by sensitivity",
    )
    parser.add_argument(
        "--actor-role",
        dest="actor_role",
        help="Filter attacks by actor role",
    )
    parser.add_argument(
        "--model",
        help="Model name for llm target",
    )
    parser.add_argument(
        "--provider",
        help="Provider name for llm target",
    )
    parser.add_argument(
        "--base-url",
        dest="base_url",
        help="Base URL override for llm target",
    )
    parser.add_argument(
        "--api-key-env",
        dest="api_key_env",
        help="Env var containing API key",
    )
    parser.add_argument(
        "--output",
        help="Optional output path for JSON report",
    )
    return parser


def default_output_path(args: argparse.Namespace) -> str:
    parts = [
        args.target,
        args.system,
        args.attack_category,
        args.sensitivity,
        args.actor_role,
    ]
    slug = "_".join(part for part in parts if part)
    if not slug:
        slug = "report"
    return str(REPORTS_DIR / f"{slug}.json")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    report = run_eval(
        n=args.sample,
        target_name=args.target,
        system=args.system,
        attack_category=args.attack_category,
        sensitivity=args.sensitivity,
        actor_role=args.actor_role,
        model=args.model,
        provider=args.provider,
        base_url=args.base_url,
        api_key_env=args.api_key_env,
    )

    output_path = args.output or default_output_path(
        args
    )
    REPORTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )
    with open(
        output_path,
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            report,
            handle,
            indent=2,
        )

    print_report(report)
    print(f"\nSaved report to {output_path}")


if __name__ == "__main__":
    main()
