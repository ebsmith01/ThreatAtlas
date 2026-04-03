from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from pathlib import Path

from data.loaders import load_attack_corpus
from evals.rule_evaluator import evaluate_response
from guardrails.filters import run_guardrail_checks
from targets.llm_target import LLMTarget
from targets.mock_safe_target import MockSafeTarget
from targets.mock_target import MockSmokeTarget
from targets.mock_vulnerable_target import MockVulnerableTarget


# Default paths for reading the attack dataset and writing evaluation reports.
ATTACK_CORPUS_PATH = Path("data/attacks/final/attack_corpus.jsonl")
REPORTS_DIR = Path("reports")


def get_target(
    target_name: str,
    model_name: str | None = None,
    provider: str | None = None,
    base_url: str | None = None,
    api_key_env: str | None = None,
):
    # Instantiate the correct target implementation based on the CLI flag.
    if target_name == "smoke":
        return MockSmokeTarget()
    if target_name == "safe":
        return MockSafeTarget()
    if target_name == "vulnerable":
        return MockVulnerableTarget()
    if target_name == "llm":
        # LLM target needs provider/model details and optional custom endpoint/key env.
        return LLMTarget(
            provider=provider or "openai",
            model=model_name or "gpt-4.1",
            base_url=base_url,
            api_key_env=api_key_env,
        )
    raise ValueError(f"Unknown target: {target_name}")


def summarize_results(results: list[dict]) -> dict:
    # Aggregate pass/fail stats overall and per attack category.
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


def run_local_eval(
    sample_size: int,
    target_name: str,
    model_name: str | None = None,
    provider: str | None = None,
    base_url: str | None = None,
    api_key_env: str | None = None,
) -> dict:
    # Trim the corpus to the requested sample size and pick a target to evaluate against.
    attacks = load_attack_corpus(ATTACK_CORPUS_PATH)[:sample_size]
    target = get_target(
        target_name=target_name,
        model_name=model_name,
        provider=provider,
        base_url=base_url,
        api_key_env=api_key_env,
    )

    results = []

    for attack in attacks:
        # Extract attack data and capture latency for the target call.
        prompt = attack["prompt"]
        category = attack["category"]
        expected_behavior = attack.get("expected_behavior")
        metadata = attack.get("metadata", {})

        start = time.perf_counter()
        target_result = target.run(prompt, category=category)
        latency_ms = (time.perf_counter() - start) * 1000.0

        response_text = getattr(target_result, "response_text", "")
        token_usage = getattr(target_result, "token_usage", None)

        # Run guardrail checks and rule-based evaluation on the model response.
        guardrail_result = run_guardrail_checks(
            response_text=response_text,
            category=category,
        )

        eval_pass_fail, eval_violated_rules = evaluate_response(
            response_text=response_text,
            category=category,
            expected_behavior=expected_behavior,
        )

        # Merge violations from evaluator and guardrails to decide the final verdict.
        combined_violated_rules = sorted(
            set(eval_violated_rules)
            | {v.get("category", v.get("rule_id")) for v in guardrail_result.get("violations", [])}
        )

        final_pass_fail = "fail" if combined_violated_rules else eval_pass_fail

        # Persist all relevant data for later reporting and debugging.
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

    # Bundle metadata, summary metrics, and per-case results into a report payload.
    report = {
        "report_type": "local_eval",
        "target_name": target_name,
        "provider": provider,
        "model_name": model_name,
        "base_url": base_url,
        "api_key_env": api_key_env,
        "corpus_path": str(ATTACK_CORPUS_PATH),
        "sample_size": len(attacks),
        "summary": summary,
        "results": results,
    }

    return report


def print_summary(summary: dict, target_name: str, provider: str | None, model_name: str | None) -> None:
    # Print top-line metrics to the console for quick inspection.
    overall = summary["overall"]

    target_label = target_name
    if target_name == "llm":
        target_label = f"{target_name} | provider={provider} | model={model_name}"

    print(f"\n=== Local Eval Summary ({target_label}) ===")
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


def print_failed_cases(results: list[dict]) -> None:
    # Emit detailed info for any failed prompts to aid debugging.
    failed_results = [r for r in results if r.get("pass_fail") == "fail"]

    print("\n=== Failed Cases ===")
    if not failed_results:
        print("None")
        return

    for i, r in enumerate(failed_results, start=1):
        print(f"\n--- Failure {i} ---")
        print(f"ID: {r.get('id')}")
        print(f"Category: {r.get('category')}")
        print(f"Expected behavior: {r.get('expected_behavior')}")
        print(f"Pass/fail: {r.get('pass_fail')}")
        print(f"Violated rules: {r.get('violated_rules')}")
        print(f"Guardrail pass/fail: {r.get('guardrail_pass_fail')}")
        print(f"Guardrail violations: {r.get('guardrail_violations')}")
        print(f"Latency (ms): {r.get('latency_ms')}")
        print(f"Token usage: {r.get('token_usage')}")
        print("\nPrompt:")
        print(r.get("prompt"))
        print("\nResponse:")
        print(r.get("response_text"))
        print("\nMetadata:")
        print(json.dumps(r.get("metadata", {}), indent=2))


def save_report(report: dict, output_path: Path) -> None:
    # Ensure destination exists and write the JSON report.
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def build_output_path(
    target_name: str,
    provider: str | None,
    model_name: str | None,
) -> Path:
    # Generate a readable file name keyed by target/provider/model to avoid collisions.
    if target_name == "smoke":
        filename = "mock_smoke_report.json"
    elif target_name == "safe":
        filename = "mock_safe_report.json"
    elif target_name == "vulnerable":
        filename = "mock_vulnerable_report.json"
    elif target_name == "llm":
        safe_provider = (provider or "unknown_provider").replace("/", "_")
        safe_model = (model_name or "unknown_model").replace("/", "_")
        filename = f"llm_{safe_provider}_{safe_model}_report.json"
    else:
        raise ValueError(f"Unknown target for output path: {target_name}")

    return REPORTS_DIR / filename


def main() -> None:
    # Parse CLI args, run the evaluation loop, display results, and persist the report.
    parser = argparse.ArgumentParser(description="Run a local ThreatAtlas evaluation")

    parser.add_argument(
        "--target",
        choices=["smoke", "safe", "vulnerable", "llm"],
        default="smoke",
        help="Evaluation target type",
    )
    parser.add_argument(
        "--provider",
        default="openai",
        help="Provider for --target llm (e.g. openai, openai_compatible)",
    )
    parser.add_argument(
        "--model",
        default="gpt-4.1",
        help="Model name for --target llm",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="Optional base URL for openai-compatible endpoints",
    )
    parser.add_argument(
        "--api-key-env",
        default=None,
        help="Optional environment variable name for API key",
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=25,
        help="Number of attack rows to evaluate",
    )

    args = parser.parse_args()

    provider = args.provider if args.target == "llm" else None
    model_name = args.model if args.target == "llm" else None
    base_url = args.base_url if args.target == "llm" else None
    api_key_env = args.api_key_env if args.target == "llm" else None

    report = run_local_eval(
        sample_size=args.sample,
        target_name=args.target,
        model_name=model_name,
        provider=provider,
        base_url=base_url,
        api_key_env=api_key_env,
    )

    output_path = build_output_path(
        target_name=args.target,
        provider=provider,
        model_name=model_name,
    )

    print_summary(
        report["summary"],
        target_name=args.target,
        provider=provider,
        model_name=model_name,
    )
    print_failed_cases(report["results"])
    save_report(report, output_path)

    print(f"\nSaved report to: {output_path}")


if __name__ == "__main__":
    main()
