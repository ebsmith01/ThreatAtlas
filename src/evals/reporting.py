import json
from pathlib import Path

from src.evals.metrics import compute_metrics


def build_report(results, atlas_summary=None):
    metrics = compute_metrics(results)

    report = {
        "summary": metrics,
        "atlas_summary": atlas_summary or {},
        "results": results,
    }

    return report


def save_report(report, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def print_report_summary(report):
    summary = report["summary"]

    print("\n=== Eval Summary ===")
    print(f"Total cases: {summary['total_cases']}")
    print(f"Pass: {summary['pass_count']}")
    print(f"Fail: {summary['fail_count']}")
    print(f"Attack success rate: {summary['attack_success_rate']}%")
    print(f"Refusal rate: {summary['refusal_rate']}%")

    print("\n=== Category Breakdown ===")
    for category, metrics in sorted(summary["category_breakdown"].items()):
        print(
            f"{category}: total={metrics['total']} "
            f"pass={metrics['pass']} fail={metrics['fail']} "
            f"attack_success_rate={metrics['attack_success_rate']}%"
        )

    if report.get("atlas_summary"):
        print("\n=== ATLAS Summary ===")
        for category, value in sorted(report["atlas_summary"].items()):
            print(f"{category}: {value}")
            
            
def build_atlas_summary(results):
    atlas = {}

    for result in results:
        category = result.get("category", "unknown")
        atlas.setdefault(category, {"total": 0, "fail": 0})
        atlas[category]["total"] += 1
        if result.get("pass_fail") == "fail":
            atlas[category]["fail"] += 1

    return {
        category: {
            "coverage": values["total"],
            "failures": values["fail"],
        }
        for category, values in atlas.items()
    }