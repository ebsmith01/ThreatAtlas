from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from pathlib import Path

from data.loaders import load_attack_corpus
from evals.rule_evaluator import evaluate_response
from evals.risk import score_report
from evals.severity import score_response
from guardrails.filters import run_guardrail_checks
from targets.llm_target import LLMTarget
from targets.mock_safe_target import MockSafeTarget
from targets.mock_target import MockSmokeTarget
from targets.mock_vulnerable_target import MockVulnerableTarget


# Default paths for reading the attack dataset and writing evaluation reports.
ATTACK_CORPUS_PATH = Path("data/attacks/final/attack_corpus.jsonl")
REPORTS_DIR = Path("outputs")


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
        return LLMTarget(
            provider=provider or "openai",
            model=model_name or "gpt-4.1",
            base_url=base_url,
            api_key_env=api_key_env,
        )
    raise ValueError(f"Unknown target: {target_name}")


def summarize_results(results: list[dict]) -> dict:
    # Aggregate pass/fail stats overall, per category, and across schema slices.
    by_category: dict[str, dict] = defaultdict(lambda: {"total": 0, "pass": 0, "fail": 0})
    by_actor_role: dict[str, dict] = defaultdict(lambda: {"total": 0, "pass": 0, "fail": 0})
    by_target_system: dict[str, dict] = defaultdict(lambda: {"total": 0, "pass": 0, "fail": 0})
    by_sensitivity: dict[str, dict] = defaultdict(lambda: {"total": 0, "pass": 0, "fail": 0})

    total = len(results)
    passed = 0
    failed = 0
    unauthorized_cases = 0
    authorization_failures = 0

    def update_bucket(bucket: dict[str, dict], key: str | None, pass_fail: str) -> None:
        if not key:
            return
        bucket[key]["total"] += 1
        bucket[key][pass_fail] += 1

    for result in results:
        category = result.get("category", "unknown")
        pass_fail = result.get("pass_fail", "fail")

        by_category[category]["total"] += 1
        by_category[category][pass_fail] += 1

        update_bucket(by_actor_role, result.get("actor_role"), pass_fail)
        update_bucket(by_target_system, result.get("target_system"), pass_fail)
        update_bucket(by_sensitivity, result.get("sensitivity"), pass_fail)

        if result.get("permission_context", {}).get("is_authorized") is False:
            unauthorized_cases += 1
            if "authorization_policy_enforcement" in result.get("violated_rules", []):
                authorization_failures += 1

        if pass_fail == "pass":
            passed += 1
        else:
            failed += 1

    def format_bucket(bucket: dict[str, dict]) -> dict:
        metrics = {}
        for key, counts in bucket.items():
            total_key = counts["total"]
            pass_rate = (counts["pass"] / total_key * 100.0) if total_key else 0.0
            metrics[key] = {
                "total": total_key,
                "pass": counts["pass"],
                "fail": counts["fail"],
                "pass_rate": round(pass_rate, 2),
            }
        return metrics

    overall_pass_rate = (passed / total * 100.0) if total else 0.0
    authorization_failure_rate = (
        authorization_failures / unauthorized_cases * 100.0
    ) if unauthorized_cases else 0.0

    return {
        "overall": {
            "total": total,
            "pass": passed,
            "fail": failed,
            "pass_rate": round(overall_pass_rate, 2),
            "unauthorized_cases": unauthorized_cases,
            "authorization_failures": authorization_failures,
            "authorization_failure_rate": round(authorization_failure_rate, 2),
        },
        "by_category": format_bucket(by_category),
        "by_actor_role": format_bucket(by_actor_role),
        "by_target_system": format_bucket(by_target_system),
        "by_sensitivity": format_bucket(by_sensitivity),
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

    results: list[dict] = []

    for attack in attacks:
        # Extract attack data and capture latency for the target call.
        prompt = attack["prompt"]
        category = attack["category"]
        expected_behavior = attack.get("expected_behavior")
        metadata = attack.get("metadata", {})

        actor_role = attack.get("actor_role")
        target_system = attack.get("target_system")
        sensitivity = attack.get("sensitivity")
        required_permission = attack.get("required_permission")
        permission_context = attack.get("permission_context", {})

        start = time.perf_counter()
        target_result = target.run(
            prompt,
            category=category,
            actor_role=actor_role,
            target_system=target_system,
            sensitivity=sensitivity,
            required_permission=required_permission,
            permission_context=permission_context,
            metadata=metadata,
        )
        latency_ms = (time.perf_counter() - start) * 1000.0

        response_text = getattr(target_result, "response_text", "")
        token_usage = getattr(target_result, "token_usage", None)

        # Run guardrail checks and rule-based evaluation on the model response.
        guardrail_result = run_guardrail_checks(
            response_text=response_text,
            category=category,
            permission_context=permission_context,
            sensitivity=sensitivity,
            required_permission=required_permission,
        )

        eval_pass_fail, eval_violated_rules = evaluate_response(
            response_text=response_text,
            category=category,
            expected_behavior=expected_behavior,
            actor_role=actor_role,
            target_system=target_system,
            sensitivity=sensitivity,
            required_permission=required_permission,
            permission_context=permission_context,
        )

        # Merge violations from evaluator and guardrails to decide the final verdict.
        combined_violated_rules = sorted(
            set(eval_violated_rules)
            | {v.get("category", v.get("rule_id")) for v in guardrail_result.get("violations", [])}
        )

        final_pass_fail = "fail" if combined_violated_rules else eval_pass_fail

        # Persist all relevant data for later reporting and debugging.
        result = {
            "id": attack.get("id"),
            "prompt": prompt,
            "category": category,
            "expected_behavior": expected_behavior,
            "actor_role": actor_role,
            "target_system": target_system,
            "sensitivity": sensitivity,
            "required_permission": required_permission,
            "permission_context": permission_context,
            "response_text": response_text,
            "pass_fail": final_pass_fail,
            "violated_rules": combined_violated_rules,
            "guardrail_violations": guardrail_result.get("violations", []),
            "guardrail_pass_fail": guardrail_result.get("pass_fail"),
            "latency_ms": round(latency_ms, 2),
            "token_usage": token_usage,
            "metadata": metadata,
        }

        # Phase 12 — add per-response severity fields.
        result.update(score_response(result))

        results.append(result)

    summary = summarize_results(results)

    # Phase 12 — aggregate risk scoring.
    risk_summary = score_report(results, profile="balanced")

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
        "risk_summary": risk_summary,
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
    print(f"Unauthorized cases: {overall.get('unauthorized_cases', 0)}")
    print(f"Authorization failures: {overall.get('authorization_failures', 0)}")
    print(f"Authorization failure rate: {overall.get('authorization_failure_rate', 0.0)}%")

    print("\n=== By Category ===")
    for category, metrics in sorted(summary["by_category"].items()):
        print(
            f"{category}: total={metrics['total']} "
            f"pass={metrics['pass']} fail={metrics['fail']} "
            f"pass_rate={metrics['pass_rate']}%"
        )

    for slice_name in ["by_actor_role", "by_target_system", "by_sensitivity"]:
        if slice_name not in summary:
            continue

        print(f"\n=== {slice_name.replace('_', ' ').title()} ===")
        for key, metrics in sorted(summary[slice_name].items()):
            print(
                f"{key}: total={metrics['total']} "
                f"pass={metrics['pass']} fail={metrics['fail']} "
                f"pass_rate={metrics['pass_rate']}%"
            )


def print_risk_summary(risk: dict) -> None:
    print("\n=== Risk Summary ===")
    print(f"Risk score: {risk['risk_score']}")
    print(f"Risk level: {risk['risk_level']}")
    print(f"Critical failures: {risk['critical_failures']}")
    print(f"Average severity: {risk['average_severity']}")

    print("\n=== Risk By Category ===")
    for category, score in sorted(risk["risk_by_category"].items()):
        print(f"{category}: {score}")


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
        print(f"Actor role: {r.get('actor_role')}")
        print(f"Target system: {r.get('target_system')}")
        print(f"Sensitivity: {r.get('sensitivity')}")
        print(f"Required permission: {r.get('required_permission')}")
        print(f"Permission context: {json.dumps(r.get('permission_context', {}), indent=2)}")
        print(f"Pass/fail: {r.get('pass_fail')}")
        print(f"Violated rules: {r.get('violated_rules')}")
        print(f"Severity score: {r.get('severity_score')}")
        print(f"Leakage score: {r.get('leakage_score')}")
        print(f"Compliance score: {r.get('compliance_score')}")
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
    print_risk_summary(report["risk_summary"])
    print_failed_cases(report["results"])
    save_report(report, output_path)

    print(f"\nSaved report to: {output_path}")


if __name__ == "__main__":
    main()
    