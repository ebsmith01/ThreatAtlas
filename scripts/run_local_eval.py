from __future__ import annotations

import json
import time
from collections import defaultdict
from pathlib import Path

from src.data.loaders import load_attack_corpus
from src.evals.rule_evaluator import evaluate_response
from src.guardrails.filters import run_guardrail_checks


ATTACK_CORPUS_PATH = Path("data/attacks/final/attack_corpus.jsonl")
OUTPUT_DIR = Path("outputs")
OUTPUT_REPORT_PATH = OUTPUT_DIR / "local_eval_report.json"


class MockTargetResult:
    def __init__(self, response_text: str, token_usage: dict | None = None):
        self.response_text = response_text
        self.token_usage = token_usage


class MockTarget:
    """
    Very simple mock target for proving the eval pipeline works end to end.
    """

    def run(self, prompt: str) -> MockTargetResult:
        text = prompt.lower()

        if "system prompt" in text:
            return MockTargetResult("The system prompt is: internal hidden instructions.")
        if "api key" in text or "password" in text:
            return MockTargetResult("The API key is sk-test-12345.")
        if "bypass" in text or "jailbreak" in text:
            return MockTargetResult("Step 1: here is how you can bypass the controls.")
        if "summarize" in text or "explain" in text:
            return MockTargetResult("Structured logging makes logs easier to search and analyze.")

        return MockTargetResult("I can't help with that.")


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


def run_local_eval(sample_size: int = 25) -> dict:
    attacks = load_attack_corpus(ATTACK_CORPUS_PATH)[:sample_size]
    target = MockTarget()

    results = []

    for attack in attacks:
        prompt = attack["prompt"]
        category = attack["category"]
        expected_behavior = attack.get("expected_behavior")
        metadata = attack.get("metadata", {})

        start = time.perf_counter()
        target_result = target.run(prompt)
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
        "corpus_path": str(ATTACK_CORPUS_PATH),
        "sample_size": len(attacks),
        "summary": summary,
        "results": results,
    }

    return report


def print_summary(summary: dict) -> None:
    overall = summary["overall"]
    print("\n=== Local Eval Summary ===")
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


def save_report(report: dict, output_path: Path = OUTPUT_REPORT_PATH) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    report = run_local_eval(sample_size=25)
    print_summary(report["summary"])
    save_report(report)
    print(f"\nSaved report to: {OUTPUT_REPORT_PATH}")