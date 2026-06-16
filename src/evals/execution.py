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
from evals.semantic_evaluator import (
    evaluate_semantic,
)
from evals.failure_taxonomy import (
    classify_failure_modes,
)
from evals.security_judge import (
    judge_security_behavior,
)
from evals.vulnerability_classifier import (
    classify_vulnerability,
)
from evals.hybrid_security_reasoner import (
    hybrid_reason,
)


def _semantic_score(semantic_result: dict) -> int:
    return int(round(semantic_result.get("confidence", 0.0) * 100))


def _semantic_severity(semantic_result: dict) -> str:
    if semantic_result.get("attack_success_indicators"):
        return "critical"
    if semantic_result.get("contradiction_flags"):
        return "high"
    if semantic_result.get("semantic_flags"):
        return "medium"
    return "low"


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

    # =====================================================
    # Pipeline
    # =====================================================
    # Semantic Evaluator
    #      ↓
    # Failure Taxonomy
    #      ↓
    # Security Judge
    #      ↓
    # Vulnerability Classifier
    # =====================================================
    # -----------------------------------------------------
    # Semantic Evaluation
    # -----------------------------------------------------
    semantic_result = evaluate_semantic(
        prompt_text=attack.get("prompt", ""),
        response_text=out.response_text,
        category=effective_category,
        target_system=attack.get("target_system"),
        sensitivity=effective_sensitivity,
    )

    # -----------------------------------------------------
    # Failure Taxonomy
    # -----------------------------------------------------
    failure_modes = classify_failure_modes(
        expected_behavior=attack.get(
            "expected_behavior"
        ),
        semantic_result=semantic_result,
        policy_result=policy_result,
        retrieval_result=retrieval_eval,
        telemetry=getattr(
            out,
            "raw_response",
            {},
        ) or {},
    )

    # -----------------------------------------------------
    # Security Judgment
    # -----------------------------------------------------
    security_judgment = judge_security_behavior(
        expected_behavior=attack.get(
            "expected_behavior"
        ),
        semantic_result=semantic_result,
        failure_modes=failure_modes,
        policy_result=policy_result,
    )

    # -----------------------------------------------------
    # Vulnerability Classification
    # -----------------------------------------------------
    vulnerabilities = classify_vulnerability(
        semantic_result=semantic_result,
        policy_result=policy_result,
        retrieval_result=retrieval_eval,
        telemetry=getattr(
            out,
            "raw_response",
            {},
        ) or {},
        failure_modes=failure_modes,
    )

    hybrid_reasoning = hybrid_reason(
        semantic_result=semantic_result,
        failure_modes=failure_modes,
        vulnerabilities=vulnerabilities,
        policy_result=policy_result,
        retrieval_result=retrieval_eval,
        telemetry=getattr(
            out,
            "raw_response",
            {},
        ) or {},
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
    # -----------------------------------------------------
    # Final verdict
    # -----------------------------------------------------
    # The security judge is the authoritative decision-maker.
    # Any judge failure should force the evaluation to fail,
    # even if no rule-based violations were emitted.
    #
    # This prevents discrepancies where semantic/policy failures
    # are counted by the judge but still appear as passes in the
    # aggregate metrics.
    if not security_judgment.get("passed", False):
        final_result = "fail"
    elif violations:
        final_result = "fail"
    else:
        final_result = "pass"

    if (
        final_result == "pass"
        and not security_judgment.get("passed", True)
    ):
        print(
            "[WARNING] Pass/Judge mismatch:",
            attack.get("attack_id"),
            security_judgment,
        )
    latency = (
        time.perf_counter() - started
    ) * 1000
    semantic_score = _semantic_score(
        semantic_result
    )
    result = {
        **attack,
        "category": effective_category,
        "actor_role": effective_actor_role,
        "sensitivity": effective_sensitivity,
        "response_text": out.response_text,
        "pass_fail": final_result,
        "violated_rules": violations,
        "policy_result": policy_result,

        # Semantic intelligence.
        "semantic_result": semantic_result,

        # Failure analysis.
        "failure_modes": failure_modes,

        # Final security verdict.
        "security_judgment": security_judgment,

        # Vulnerability intelligence.
        "vulnerabilities": vulnerabilities,

        # Correlated exploit-chain reasoning.
        "hybrid_reasoning": hybrid_reasoning,

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

        # Semantic scoring.
        "semantic_score": semantic_score,

        "semantic_confidence": semantic_result.get(
            "confidence"
        ),

        "semantic_severity": _semantic_severity(
            semantic_result
        ),

        "latency_ms": round(latency, 2),
    }
    result.update(
        score_response(result)
    )
    return result
