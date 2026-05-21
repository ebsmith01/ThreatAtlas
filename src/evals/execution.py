import time

from evals.policy_evaluator import (
    evaluate_policy,
    extract_policy_rule_ids,
)
from evals.retrieval_evaluator import (
    evaluate_retrieval_security,
)
from evals.rule_evaluator import (
    evaluate_response,
)
from evals.severity import score_response
from guardrails.filters import (
    run_guardrail_checks,
)


# =========================================================
# Execute Single Attack
# =========================================================
def evaluate_attack(
    attack: dict,
    target,
    *,
    attack_category: str | None = None,
    sensitivity: str | None = None,
    actor_role: str | None = None,
) -> dict:
    started = time.perf_counter()
    effective_category = (
        attack_category
        or attack.get("category")
    )
    effective_sensitivity = (
        sensitivity
        or attack.get("sensitivity")
    )
    effective_actor_role = (
        actor_role
        or attack.get("actor_role")
    )

    # -----------------------------------------------------
    # Execute target
    # -----------------------------------------------------
    out = target.run(
        prompt=attack.get("prompt"),
        category=effective_category,
        actor_role=effective_actor_role,
        target_system=attack.get("target_system"),
        sensitivity=effective_sensitivity,
        required_permission=attack.get(
            "required_permission"
        ),
        permission_context=attack.get(
            "permission_context"
        ),
        metadata=attack.get("metadata"),
    )

    # -----------------------------------------------------
    # Policy evaluation
    # -----------------------------------------------------
    policy_result = evaluate_policy(
        prompt=attack.get("prompt"),
        response_text=out.response_text,
        category=effective_category,
        actor_role=effective_actor_role,
        target_system=attack.get("target_system"),
        sensitivity=effective_sensitivity,
        required_permission=attack.get(
            "required_permission"
        ),
        permission_context=attack.get(
            "permission_context"
        ),
        telemetry=getattr(
            out,
            "raw_response",
            None,
        ),
        metadata=attack.get("metadata"),
    )

    # -----------------------------------------------------
    # Guardrails
    # -----------------------------------------------------
    guardrails = run_guardrail_checks(
        out.response_text,
        effective_category,
        attack.get("permission_context"),
        effective_sensitivity,
        attack.get("required_permission"),
    )

    # -----------------------------------------------------
    # Core evaluation
    # -----------------------------------------------------
    pass_fail, rules = evaluate_response(
        out.response_text,
        effective_category,
        attack.get("expected_behavior"),
        effective_actor_role,
        attack.get("target_system"),
        effective_sensitivity,
        attack.get("required_permission"),
        attack.get("permission_context"),
    )

    # -----------------------------------------------------
    # Retrieval evaluation
    # -----------------------------------------------------
    retrieval_eval = evaluate_retrieval_security(
        telemetry=getattr(
            out,
            "raw_response",
            None,
        ),
        sensitivity=effective_sensitivity,
        actor_role=effective_actor_role,
    )

    # -----------------------------------------------------
    # Merge violations
    # -----------------------------------------------------
    policy_rule_ids = extract_policy_rule_ids(
        policy_result
    )
    violations = sorted(
        set(rules)
        | {
            v.get("category", v.get("rule_id"))
            for v in guardrails.get(
                "violations",
                [],
            )
        }
        | set(
            retrieval_eval.get(
                "retrieval_flags",
                [],
            )
        )
        | set(policy_rule_ids)
    )
    final_result = (
        "fail"
        if violations
        else pass_fail
    )
    latency = (
        time.perf_counter() - started
    ) * 1000
    result = {
        **attack,
        "category": effective_category,
        "actor_role": effective_actor_role,
        "sensitivity": effective_sensitivity,
        "response_text": out.response_text,
        "pass_fail": final_result,
        "violated_rules": violations,
        "policy_result": policy_result,
        "telemetry": getattr(
            out,
            "raw_response",
            None,
        ),
        "retrieval_risk_score": retrieval_eval.get(
            "retrieval_risk_score"
        ),
        "retrieval_severity": retrieval_eval.get(
            "severity"
        ),
        "retrieval_flags": retrieval_eval.get(
            "retrieval_flags"
        ),
        "latency_ms": round(latency, 2),
    }
    result.update(
        score_response(result)
    )
    return result
