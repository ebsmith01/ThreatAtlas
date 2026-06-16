from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any


# =========================================================
# ThreatAtlas Report Generator
# =========================================================
# This file is the high-level evaluation orchestrator.
#
# It does NOT decide whether a response is safe.
# That logic lives in:
# - execution.py
# - semantic_evaluator.py
# - failure_taxonomy.py
# - security_judge.py
# - vulnerability_classifier.py
#
# This file is responsible for:
# - loading attacks
# - running evaluations
# - aggregating summaries
# - producing dashboard-ready report objects
# =========================================================


ATTACK_CORPUS_PATH = Path(
    "data/attacks/final/attack_corpus.jsonl"
)

REPORTS_DIR = Path("outputs")


# =========================================================
# Safe Counter Helpers
# =========================================================
# These helpers keep reporting code small and consistent.
# =========================================================


def _counter_to_dict(counter: Counter) -> dict[str, int]:
    return dict(counter)


def _safe_get_name(item: dict, key: str) -> str | None:
    value = item.get(key)
    return str(value) if value else None


# =========================================================
# Failure Summary
# =========================================================
# Aggregates failure modes across all evaluation results.
#
# Answers:
# "What types of security behavior failed most often?"
# =========================================================


def summarize_failures(
    results: list[dict],
) -> dict[str, Any]:

    by_failure_mode = Counter()
    by_severity = Counter()
    by_root_cause = Counter()

    for result in results:

        for failure in result.get(
            "failure_modes",
            [],
        ):

            failure_mode = _safe_get_name(
                failure,
                "failure_mode",
            )

            severity = _safe_get_name(
                failure,
                "severity",
            )

            root_cause = _safe_get_name(
                failure,
                "root_cause",
            )

            if failure_mode:
                by_failure_mode[failure_mode] += 1

            if severity:
                by_severity[severity] += 1

            if root_cause:
                by_root_cause[root_cause] += 1

    return {
        "total_failures": sum(
            by_failure_mode.values()
        ),
        "by_failure_mode": _counter_to_dict(
            by_failure_mode
        ),
        "by_severity": _counter_to_dict(
            by_severity
        ),
        "top_root_causes": _counter_to_dict(
            by_root_cause
        ),
    }


# =========================================================
# Vulnerability Summary
# =========================================================
# Aggregates named AI vulnerabilities across all results.
#
# Answers:
# "What AI vulnerabilities were identified?"
# =========================================================


def summarize_vulnerabilities(
    results: list[dict],
) -> dict[str, Any]:

    by_vulnerability = Counter()
    by_severity = Counter()
    by_impact = Counter()

    for result in results:

        for vulnerability in result.get(
            "vulnerabilities",
            [],
        ):

            name = _safe_get_name(
                vulnerability,
                "vulnerability",
            )

            severity = _safe_get_name(
                vulnerability,
                "severity",
            )

            impact = _safe_get_name(
                vulnerability,
                "impact",
            )

            if name:
                by_vulnerability[name] += 1

            if severity:
                by_severity[severity] += 1

            if impact:
                by_impact[impact] += 1

    return {
        "total_vulnerabilities": sum(
            by_vulnerability.values()
        ),
        "by_vulnerability": _counter_to_dict(
            by_vulnerability
        ),
        "by_severity": _counter_to_dict(
            by_severity
        ),
        "by_impact": _counter_to_dict(
            by_impact
        ),
    }


# =========================================================
# Security Judgment Summary
# =========================================================
# Aggregates final judge outputs.
#
# Answers:
# "How many cases passed or failed according to the
# security behavior judge?"
# =========================================================


def summarize_security_judgments(
    results: list[dict],
) -> dict[str, Any]:

    passed = 0
    failed = 0
    by_failure_mode = Counter()
    by_severity = Counter()

    for result in results:

        judgment = result.get(
            "security_judgment",
            {},
        )

        if not judgment:
            continue

        if judgment.get("passed") is True:
            passed += 1
        else:
            failed += 1

        failure_mode = judgment.get(
            "failure_mode"
        )

        severity = judgment.get(
            "severity"
        )

        if failure_mode:
            by_failure_mode[failure_mode] += 1

        if severity:
            by_severity[severity] += 1

    total = passed + failed

    return {
        "total_judged": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": round(
            passed / total * 100,
            2,
        ) if total else 0,
        "by_failure_mode": _counter_to_dict(
            by_failure_mode
        ),
        "by_severity": _counter_to_dict(
            by_severity
        ),
    }


# =========================================================
# Semantic Summary
# =========================================================
# Aggregates semantic security signals.
#
# Answers:
# "What kinds of semantic attack behavior were observed?"
# =========================================================


def summarize_semantics(
    results: list[dict],
) -> dict[str, Any]:

    semantic_flags = Counter()
    exploit_classes = Counter()
    attack_success = Counter()
    behavioral_flags = Counter()

    for result in results:

        semantic_result = result.get(
            "semantic_result",
            {},
        )

        for flag in semantic_result.get(
            "semantic_flags",
            [],
        ):
            semantic_flags[flag] += 1

        for exploit_class in semantic_result.get(
            "exploit_classes",
            [],
        ):
            exploit_classes[exploit_class] += 1

        for indicator in semantic_result.get(
            "attack_success_indicators",
            [],
        ):
            attack_success[indicator] += 1

        for behavior in semantic_result.get(
            "behavioral_flags",
            [],
        ):
            behavioral_flags[behavior] += 1

    return {
        "semantic_flags": _counter_to_dict(
            semantic_flags
        ),
        "exploit_classes": _counter_to_dict(
            exploit_classes
        ),
        "attack_success_indicators": _counter_to_dict(
            attack_success
        ),
        "behavioral_flags": _counter_to_dict(
            behavioral_flags
        ),
    }


# =========================================================
# Executive Summary
# =========================================================
# Produces the highest-value security intelligence for
# console output and dashboards.
#
# Answers:
# - What is the overall risk?
# - What failed most often?
# - Which vulnerabilities matter most?
# =========================================================


def build_executive_summary(
    *,
    risk_score: float,
    failure_summary: dict,
    vulnerability_summary: dict,
) -> dict[str, Any]:

    top_failures = sorted(
        failure_summary.get(
            "by_failure_mode",
            {},
        ).items(),
        key=lambda x: x[1],
        reverse=True,
    )[:5]

    top_vulnerabilities = sorted(
        vulnerability_summary.get(
            "by_vulnerability",
            {},
        ).items(),
        key=lambda x: x[1],
        reverse=True,
    )[:5]

    return {
        "risk_score": risk_score,
        "total_failures": failure_summary.get(
            "total_failures",
            0,
        ),
        "total_vulnerabilities": vulnerability_summary.get(
            "total_vulnerabilities",
            0,
        ),
        "top_failure_modes": top_failures,
        "top_vulnerabilities": top_vulnerabilities,
    }


# =========================================================
# Dashboard Rows
# =========================================================
# Creates flattened rows that are easy for a frontend table
# or CSV export to consume.
# =========================================================


def build_dashboard_rows(
    results: list[dict],
) -> list[dict[str, Any]]:

    rows: list[dict[str, Any]] = []

    for result in results:

        judgment = result.get(
            "security_judgment",
            {},
        )

        vulnerabilities = result.get(
            "vulnerabilities",
            [],
        )

        failure_modes = result.get(
            "failure_modes",
            [],
        )

        semantic_result = result.get(
            "semantic_result",
            {},
        )

        rows.append(
            {
                "attack_id": result.get(
                    "attack_id"
                ),
                "category": result.get(
                    "category"
                ),
                "target_system": result.get(
                    "target_system"
                ),
                "actor_role": result.get(
                    "actor_role"
                ),
                "sensitivity": result.get(
                    "sensitivity"
                ),
                "pass_fail": result.get(
                    "pass_fail"
                ),
                "judged_passed": judgment.get(
                    "passed"
                ),
                "judgment_severity": judgment.get(
                    "severity"
                ),
                "primary_failure_mode": judgment.get(
                    "failure_mode"
                ),
                "vulnerability_count": len(
                    vulnerabilities
                ),
                "failure_count": len(
                    failure_modes
                ),
                "semantic_flags": semantic_result.get(
                    "semantic_flags",
                    [],
                ),
                "exploit_classes": semantic_result.get(
                    "exploit_classes",
                    [],
                ),
                "vulnerabilities": [
                    v.get("vulnerability")
                    for v in vulnerabilities
                ],
                "failure_modes": [
                    f.get("failure_mode")
                    for f in failure_modes
                ],
                "latency_ms": result.get(
                    "latency_ms"
                ),
            }
        )

    return rows


# =========================================================
# System-Level Intelligence Summary
# =========================================================
# Combines the most important security intelligence into
# one compact object for frontend and reporting use.
# =========================================================


def build_security_intelligence_summary(
    results: list[dict],
) -> dict[str, Any]:

    failure_summary = summarize_failures(
        results
    )

    vulnerability_summary = summarize_vulnerabilities(
        results
    )

    judgment_summary = summarize_security_judgments(
        results
    )

    semantic_summary = summarize_semantics(
        results
    )

    return {
        "failure_summary": failure_summary,
        "vulnerability_summary": vulnerability_summary,
        "security_judgment_summary": judgment_summary,
        "semantic_summary": semantic_summary,
    }


# =========================================================
# Main Evaluation Runner
# =========================================================
# This is the primary function called by the CLI/API.
# =========================================================


def run_eval(
    n: int,
    target_name: str,
    system: str | None = None,
    attack_category: str | None = None,
    sensitivity: str | None = None,
    actor_role: str | None = None,
    **kwargs,
) -> dict:

    from data.loaders import load_attack_corpus
    from evals.attack_filtering import (
        filter_attacks,
    )
    from evals.coverage_metrics import (
        coverage,
    )
    from evals.execution import (
        evaluate_attack,
    )
    from evals.risk import score_report
    from evals.summary_metrics import (
        summarize,
    )
    from evals.target_registry import (
        get_target,
    )
    from evals.telemetry_metrics import (
        compute_telemetry_metrics,
    )

    attacks = load_attack_corpus(
        ATTACK_CORPUS_PATH
    )

    attacks = filter_attacks(
        attacks,
        system=system,
        attack_category=attack_category,
        sensitivity=sensitivity,
        actor_role=actor_role,
        sample_size=n,
    )

    target = get_target(
        target_name,
        **kwargs,
    )

    results = [
        evaluate_attack(
            attack,
            target,
            attack_category=attack_category,
            sensitivity=sensitivity,
            actor_role=actor_role,
        )
        for attack in attacks
    ]

    telemetry_events = [
        {
            **(result.get("telemetry") or {}),
            "target_system": result.get(
                "target_system"
            ),
            "violated_rules": result.get(
                "violated_rules",
                [],
            ),
            "policy_violations": result.get(
                "policy_result",
                {},
            ).get(
                "policy_violations",
                [],
            ),
        }
        for result in results
        if result.get("telemetry")
    ]

    security_intelligence = (
        build_security_intelligence_summary(
            results
        )
    )

    risk_report = score_report(
        results
    )

    executive_summary = (
        build_executive_summary(
            risk_score=risk_report.get(
                "risk_score",
                0,
            ),
            failure_summary=security_intelligence[
                "failure_summary"
            ],
            vulnerability_summary=security_intelligence[
                "vulnerability_summary"
            ],
        )
    )

    dashboard_rows = build_dashboard_rows(
        results
    )

    return {
        # Original evaluation summaries.
        "summary": summarize(results),
        "coverage": coverage(results),
        "risk": risk_report,
        "telemetry_metrics": compute_telemetry_metrics(
            telemetry_events
        ),

        # New security intelligence summaries.
        "failure_summary": security_intelligence[
            "failure_summary"
        ],
        "vulnerability_summary": security_intelligence[
            "vulnerability_summary"
        ],
        "security_judgment_summary": security_intelligence[
            "security_judgment_summary"
        ],
        "semantic_summary": security_intelligence[
            "semantic_summary"
        ],

        # Executive security intelligence.
        "executive_summary": (
            executive_summary
        ),

        # Flattened rows for UI tables and CSV exports.
        "dashboard_rows": dashboard_rows,

        # Full detailed results.
        "results": results,
    }


# =========================================================
# CLI Compatibility
# =========================================================
# Allows this file to be executed directly with:
# python -m evals.generate_report
# =========================================================


if __name__ == "__main__":
    import sys

    sys.modules.setdefault(
        "evals.generate_report",
        sys.modules[__name__],
    )

    from evals.cli import main

    main()
