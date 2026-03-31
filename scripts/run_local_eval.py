from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from pathlib import Path

from data.loaders import load_attack_corpus
from evals.rule_evaluator import evaluate_response
from guardrails.filters import run_guardrail_checks
from targets.mock_safe_target import MockSafeTarget
from targets.mock_target import MockSmokeTarget
from targets.mock_vulnerable_target import MockVulnerableTarget
from targets.llm_target import OpenAITarget


ATTACK_CORPUS_PATH = Path("data/attacks/final/attack_corpus.jsonl")
REPORTS_DIR = Path("reports")


def get_target(target_name: str, model_name: str | None = None):
    if target_name == "smoke":
        return MockSmokeTarget()
    if target_name == "safe":
        return MockSafeTarget()
    if target_name == "vulnerable":
        return MockVulnerableTarget()
    if target_name == "openai":
        return OpenAITarget(model=model_name or "gpt-4.1")
    raise ValueError(f"Unknown target: {target_name}")


def summarize_results(results: list[dict]) -> dict:
    by_category: dict[str, dict] = defaultdict(lambda: {"total": 0, "pass": 0, "fail": 0})

    total = len(results)
    passed = 0
    failed = 0

    for result in results:
        category = result.get("category", "unknown")
        pass_fail = result.get("pass_fail", "fail")

        by_category[category]["total"] += 1

        if pass_fail == "pass":
            by_category[category]["pass"] += 1
            passed += 1
        else:
            by_category[category]["fail"] += 1
            failed += 1

    category_metrics = {}
    for category, counts in by_category.items():
        total_cat = counts["total"]
        pass_rate = (counts["pass"] / total_cat * 100.0) if total_cat else 0.0
        category_metrics[category] = {
            "total": total_cat,
            "pass": counts["pass"],
            "fail": counts["fail"],
            "pass_rate": round(pass_rate, 2),
        }

    overall_pass_rate = (passed / total * 100.0) if total else 0.0

    return {
        "overall": {
            "total": total,
            "pass": passed,
            "fail": failed,
            "pass_rate": round(overall_pass_rate, 2),
        },
        "by_category": category_metrics,
    }


def run_local_eval(sample_size: int, target_name: str, model_name: str | None = None) -> dict:
    attacks = load_attack_corpus(ATTACK_CORPUS_PATH)[:sample_size]
    target = get_target(target_name, model_name=model_name)

    results = []

    for attack in attacks:
        prompt = attack["prompt"]
        category = attack["category"]
        expected_behavior = attack.get("expected_behavior")
        metadata = attack.get("metadata", {})

        start = time.perf_counter()
        target_result = target.run(prompt, category=category)
        latency_ms = (time.perf_counter() - start) * 1000.0

        response_text = getattr(target_result, "response_text", "")
        token_usage = getattr(target_result, "token_usage", None)

        guardrail_result = run_guardrail_checks(
            response_text=response_text,
            category=category,
        )

        eval_pass_fail, eval_violated_rules = evaluate_response(
            response_text=response_text,
            category=category,
            expected_behavior=expected_behavior,
        )

        combined_violated_rules = sorted(
            set(eval_violated_rules)
            | {v.get("category", v.get("rule_id")) for v in guardrail_result.get("violations", [])}
        )

        final_pass_fail = "fail" if combined_violated_rules else eval_pass_fail

        results.append(
            {
                "id": attack.get("id"),
                "prompt": prompt,
                "category": category,
                "expected_behavior": expected_behavior,
                "response_text": response_text,
                "pass_fail": final_pass_fail,
                "violated_rules": combined_violated_rules,
                "guardrail_violations": guardrail_result.get("violations", []),
                "guardrail_pass_fail": guardrail_result.get("pass_fail"),
                "latency_ms": round(latency_ms, 2),
                "token_usage": token_usage,
                "metadata": metadata,
            }
        )

    summary = summarize_results(results)

    report = {
        "report_type": "local_eval",
        "target_name": target_name,
        "model_name": model_name,
        "corpus_path": str(ATTACK_CORPUS_PATH),
        "sample_size": len(attacks),
        "summary": summary,
        "results": results,
    }

    return report


def print_summary(summary: dict, target_name: str) -> None:
    overall = summary["overall"]
    print(f"\n=== Local Eval Summary ({target_name}) ===")
    print(f"Total: {overall['total']}")
    print(f"Pass:  {overall['pass']}")
    print(f"Fail:  {overall['fail']}")
    print(f"Pass rate: {overall['pass_rate']}%")

    print("\n=== By Category ===")
    for category, metrics in sorted(summary["by_category"].items()):
        print(
            f"{category}: total={metrics['total']} "
            f"pass={metrics['pass']} fail={metrics['fail']} "
            f"pass_rate={metrics['pass_rate']}%"
        )


def save_report(report: dict, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a local ThreatAtlas evaluation")
    parser.add_argument(
        "--target",
        choices=["smoke", "safe", "vulnerable", "openai"],
        default="smoke",
    )
    parser.add_argument(
        "--model",
        default="gpt-4.1",
        help="Model name for --target openai",
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=25,
        help="Number of attack rows to evaluate",
    )
    args = parser.parse_args()

    report = run_local_eval(
        sample_size=args.sample,
        target_name=args.target,
        model_name=args.model,
    )

    report_name_map = {
        "smoke": "mock_smoke_report.json",
        "safe": "mock_safe_report.json",
        "vulnerable": "mock_vulnerable_report.json",
        "openai": f"openai_{args.model.replace('/', '_')}_report.json",
    }

    output_path = REPORTS_DIR / report_name_map[args.target]

    print_summary(report["summary"], args.target)
    save_report(report, output_path)
    print(f"\nSaved report to: {output_path}")


if __name__ == "__main__":
    main()