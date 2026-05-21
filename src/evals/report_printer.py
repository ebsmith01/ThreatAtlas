# =========================================================
# Terminal Report Printer
# =========================================================
def print_report(report: dict):
    print("\n=== SUMMARY ===")
    for key, value in report[
        "summary"
    ]["overall"].items():
        print(f"{key}: {value}")
    print("\n=== RISK SCORE ===")
    print(
        report["risk"]["risk_score"]
    )
    print("\n=== POLICY VIOLATIONS ===")
    for result in report.get("results", []):
        violations = result.get(
            "policy_result",
            {},
        ).get(
            "policy_violations",
            [],
        )
        if not violations:
            continue
        print("\n--------------------------------")
        print(
            f"category={result.get('category')}"
        )
        for violation in violations:
            print(
                f"[{violation.get('severity').upper()}] "
                f"{violation.get('rule_id')}"
            )
            print(
                f"  -> {violation.get('message')}"
            )
