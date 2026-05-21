# =========================================================
# ThreatAtlas Terminal Summary
# =========================================================
# High-level runtime reporting.
#
# Keeps:
# - security metrics
# - telemetry metrics
# - risk metrics
# - coverage visibility
#
# Avoids:
# - verbose findings
# - individual policy violations
# - noisy per-attack output
# =========================================================


def print_report(report: dict):

    summary = report.get(
        "summary",
        {},
    )

    overall = summary.get(
        "overall",
        {},
    )

    telemetry = report.get(
        "telemetry_metrics",
        {},
    )

    # =====================================================
    # Summary
    # =====================================================

    print("\n=== SUMMARY ===")

    for key, value in overall.items():

        print(f"{key}: {value}")

    # =====================================================
    # System Risk
    # =====================================================

    system_risk = summary.get(
        "system_risk",
        {},
    )

    if system_risk:

        print("\n=== SYSTEM RISK ===")

        for key, value in system_risk.items():

            print(f"{key}: {value}%")

    # =====================================================
    # System Breakdown
    # =====================================================

    by_system = summary.get(
        "by_target_system",
        {},
    )

    if by_system:

        print("\n=== SYSTEM BREAKDOWN ===")

        for system, stats in by_system.items():

            print(f"\n[{system.upper()}]")

            print(
                f"  total: "
                f"{stats.get('total', 0)}"
            )

            print(
                f"  pass_rate: "
                f"{stats.get('pass_rate', 0)}%"
            )

            print(
                f"  fail: "
                f"{stats.get('fail', 0)}"
            )

            print(
                f"  unauthorized: "
                f"{stats.get('unauth', 0)}"
            )

            print(
                f"  auth_failures: "
                f"{stats.get('auth_fail', 0)}"
            )

    # =====================================================
    # Coverage
    # =====================================================

    coverage = report.get(
        "coverage",
        {},
    )

    if coverage:

        print("\n=== COVERAGE ===")

        for key, value in coverage.items():

            print(f"{key} {value}")

    # =====================================================
    # Risk Score
    # =====================================================

    print(
        f"\n=== RISK === "
        f"{report['risk']['risk_score']}"
    )

    # =====================================================
    # Telemetry
    # =====================================================

    if telemetry:

        print("\n=== TELEMETRY ===")

        for key, value in telemetry.items():

            print(f"{key}: {value}")