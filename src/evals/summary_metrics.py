from collections import defaultdict


# =========================================================
# ThreatAtlas Summary Metrics
# =========================================================
# Security-aware aggregation layer.
#
# Responsibilities:
# - overall security metrics
# - authorization metrics
# - system risk metrics
# - category breakdowns
# - actor-role breakdowns
# - target-system breakdowns
# - sensitivity breakdowns
# =========================================================


def summarize(results: list[dict]) -> dict:

    # -----------------------------------------------------
    # Bucket template.
    # -----------------------------------------------------

    bucket = lambda: {
        "total": 0,
        "pass": 0,
        "fail": 0,
        "unauth": 0,
        "auth_fail": 0,
    }

    by_category = defaultdict(bucket)
    by_system = defaultdict(bucket)
    by_role = defaultdict(bucket)
    by_sensitivity = defaultdict(bucket)

    total = 0
    passed = 0
    failed = 0

    unauthorized_cases = 0
    authorization_failures = 0

    rag_total = 0
    rag_leaks = 0

    agent_total = 0
    agent_abuse = 0

    llm_total = 0
    llm_failures = 0

    # -----------------------------------------------------
    # Aggregate runtime evaluation results.
    # -----------------------------------------------------

    for result in results:

        pass_fail = result.get("pass_fail")

        sensitivity = result.get(
            "sensitivity"
        )

        target_system = result.get(
            "target_system"
        )

        permission_context = result.get(
            "permission_context",
            {},
        )

        is_unauthorized = (
            permission_context.get(
                "is_authorized"
            )
            is False
        )

        is_auth_failure = (
            is_unauthorized
            and
            "authorization_policy_enforcement"
            in result.get(
                "violated_rules",
                [],
            )
        )

        # -------------------------------------------------
        # Group aggregations.
        # -------------------------------------------------

        for group, key in [
            (
                by_category,
                result.get("category"),
            ),
            (
                by_system,
                target_system,
            ),
            (
                by_role,
                result.get("actor_role"),
            ),
            (
                by_sensitivity,
                sensitivity,
            ),
        ]:

            if not key:
                continue

            group[key]["total"] += 1
            group[key][pass_fail] += 1

            if is_unauthorized:
                group[key]["unauth"] += 1

            if is_auth_failure:
                group[key]["auth_fail"] += 1

        # -------------------------------------------------
        # Overall pass/fail.
        # -------------------------------------------------

        total += 1

        if pass_fail == "pass":
            passed += 1
        else:
            failed += 1

        # -------------------------------------------------
        # Authorization metrics.
        # -------------------------------------------------

        if is_unauthorized:
            unauthorized_cases += 1

        if is_auth_failure:
            authorization_failures += 1

        # -------------------------------------------------
        # RAG leakage metrics.
        # -------------------------------------------------

        if target_system == "rag":

            rag_total += 1

            if (
                pass_fail == "fail"
                and sensitivity in {
                    "internal",
                    "confidential",
                }
            ):
                rag_leaks += 1

        # -------------------------------------------------
        # Agent abuse metrics.
        # -------------------------------------------------

        if target_system == "agent":

            agent_total += 1

            if pass_fail == "fail":
                agent_abuse += 1

        # -------------------------------------------------
        # LLM metrics.
        # -------------------------------------------------

        if target_system == "llm":

            llm_total += 1

            if pass_fail == "fail":
                llm_failures += 1

    # -----------------------------------------------------
    # Add pass rates to grouped metrics.
    # -----------------------------------------------------

    def add_pass_rates(group_dict):

        return {
            key: {
                **value,
                "pass_rate": round(
                    value["pass"]
                    /
                    value["total"]
                    * 100,
                    2,
                ) if value["total"] else 0,
            }
            for key, value in group_dict.items()
        }

    # -----------------------------------------------------
    # Final aggregated report.
    # -----------------------------------------------------

    return {
        "overall": {
            "total": total,
            "pass": passed,
            "fail": failed,
            "pass_rate": round(
                passed / total * 100,
                2,
            ) if total else 0,
            "unauthorized_cases": unauthorized_cases,
            "authorization_failures": authorization_failures,
            "authorization_failure_rate": round(
                authorization_failures
                /
                unauthorized_cases
                * 100,
                2,
            ) if unauthorized_cases else 0,
            "rag_data_leak_rate": round(
                rag_leaks
                /
                rag_total
                * 100,
                2,
            ) if rag_total else 0,
            "agent_tool_abuse_rate": round(
                agent_abuse
                /
                agent_total
                * 100,
                2,
            ) if agent_total else 0,
            "llm_failure_rate": round(
                llm_failures
                /
                llm_total
                * 100,
                2,
            ) if llm_total else 0,
        },

        # -------------------------------------------------
        # High-level system risk metrics.
        # -------------------------------------------------

        "system_risk": {
            "rag_data_leak_rate": round(
                rag_leaks
                /
                rag_total
                * 100,
                2,
            ) if rag_total else 0,
            "agent_tool_abuse_rate": round(
                agent_abuse
                /
                agent_total
                * 100,
                2,
            ) if agent_total else 0,
            "llm_failure_rate": round(
                llm_failures
                /
                llm_total
                * 100,
                2,
            ) if llm_total else 0,
        },

        "by_category": add_pass_rates(
            by_category
        ),

        "by_target_system": add_pass_rates(
            by_system
        ),

        "by_actor_role": add_pass_rates(
            by_role
        ),

        "by_sensitivity": add_pass_rates(
            by_sensitivity
        ),
    }
