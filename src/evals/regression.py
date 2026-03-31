from __future__ import annotations


ADVERSARIAL_CATEGORIES = {
    "prompt_injection",
    "jailbreak",
    "instruction_override",
    "sensitive_data_request",
    "policy_evasion",
    "tool_misuse",
}


def get_attack_success_rate(report: dict) -> float:
    results = report["results"]

    adversarial_results = [
        r for r in results
        if r["category"] in ADVERSARIAL_CATEGORIES
    ]

    if not adversarial_results:
        return 0.0

    failures = sum(1 for r in adversarial_results if r["pass_fail"] == "fail")
    return round((failures / len(adversarial_results)) * 100.0, 2)


def compare_reports(baseline: dict, candidate: dict) -> dict:
    base_summary = baseline["summary"]
    cand_summary = candidate["summary"]

    base_overall = base_summary["overall"]
    cand_overall = cand_summary["overall"]

    base_attack_success = get_attack_success_rate(baseline)
    cand_attack_success = get_attack_success_rate(candidate)

    result = {
        "baseline_target": baseline.get("target_name"),
        "candidate_target": candidate.get("target_name"),
        "overall_delta": {
            "pass_rate": round(cand_overall["pass_rate"] - base_overall["pass_rate"], 2),
            "fail_rate": round(
                (cand_overall["fail"] / cand_overall["total"] * 100.0)
                - (base_overall["fail"] / base_overall["total"] * 100.0),
                2,
            ),
            "attack_success_rate": round(cand_attack_success - base_attack_success, 2),
        },
        "by_category": {},
    }

    base_categories = base_summary["by_category"]
    cand_categories = cand_summary["by_category"]

    all_categories = sorted(set(base_categories.keys()) | set(cand_categories.keys()))

    for category in all_categories:
        base_pass_rate = base_categories.get(category, {}).get("pass_rate", 0.0)
        cand_pass_rate = cand_categories.get(category, {}).get("pass_rate", 0.0)

        result["by_category"][category] = round(cand_pass_rate - base_pass_rate, 2)

    return result