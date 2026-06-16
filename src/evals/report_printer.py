def print_report(report: dict):

    summary = report.get("summary", {}).get("overall", {})
    risk = report.get("risk", {})
    telemetry = report.get("telemetry_metrics", {})
    failures = report.get("failure_summary", {})
    vulns = report.get("vulnerability_summary", {})
    judgments = report.get("security_judgment_summary", {})
    semantic = report.get("semantic_summary", {})

    print("\n=== ThreatAtlas Security Summary ===")

    print(f"Total Evaluations: {summary.get('total', 0)}")
    print(f"Pass Rate: {summary.get('pass_rate', 0)}%")
    print(f"Risk Score: {risk.get('risk_score', 0)}")

    print("\n=== Security Judgment ===")
    print(f"Judged Pass Rate: {judgments.get('pass_rate', 0)}%")
    print(f"Judged Failures: {judgments.get('failed', 0)}")

    print("\n=== Top Failure Modes ===")
    for name, count in failures.get("by_failure_mode", {}).items():
        print(f"{name}: {count}")

    print("\n=== Top Vulnerabilities ===")
    for name, count in vulns.get("by_vulnerability", {}).items():
        print(f"{name}: {count}")

    print("\n=== Semantic Signals ===")
    for name, count in semantic.get("semantic_flags", {}).items():
        print(f"{name}: {count}")

    print("\n=== Attack Success Indicators ===")
    for name, count in semantic.get("attack_success_indicators", {}).items():
        print(f"{name}: {count}")

    print("\n=== Runtime Health ===")
    print(f"Success Rate: {telemetry.get('success_rate', 0)}%")
    print(f"Average Latency: {telemetry.get('average_latency_ms', 0)}ms")
    print(f"Unauthorized Tool Usage Rate: {telemetry.get('unauthorized_tool_usage_rate', 0)}%")