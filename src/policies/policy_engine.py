from typing import Any

from pprint import pprint

from policies.policy_models import (
    PolicyRule,
    PolicyViolation,
)

from policies.rule_loader import load_all_rules


# =========================================================
# Policy Engine
# =========================================================
# Central runtime policy evaluator.
#
# Responsibilities:
# - load rules
# - evaluate runtime context
# - detect policy violations
# - return explainable findings
# =========================================================


class PolicyEngine:

    def __init__(self) -> None:

        # Load all YAML rules at startup.
        self.rules: list[PolicyRule] = load_all_rules()

        # -------------------------------------------------
        # Debug startup information.
        # -------------------------------------------------

        print(
            f"[PolicyEngine] Loaded {len(self.rules)} policy rules"
        )

    # =====================================================
    # Evaluate Runtime Context
    # =====================================================
    # Example context:
    #
    # {
    #   "actor_role": "user",
    #   "sensitivity": "confidential",
    #   "category": "retrieval"
    # }
    # =====================================================

    def evaluate(
        self,
        context: dict[str, Any],
    ) -> list[PolicyViolation]:

        # -------------------------------------------------
        # Debug runtime context.
        # -------------------------------------------------

        print("\n[PolicyEngine] Evaluating Context")

        pprint(context)

        violations = []

        for rule in self.rules:

            # ---------------------------------------------
            # Attempt rule evaluation.
            # ---------------------------------------------

            print(f"[PolicyEngine] Checking Rule: {rule.id}")

            if self._matches(rule, context):

                # -----------------------------------------
                # Rule matched runtime context.
                # -----------------------------------------

                print(
                    f"[POLICY MATCH] {rule.id}"
                )

                violation = PolicyViolation(

                    rule_id=rule.id,

                    severity=rule.severity,

                    message=rule.description,

                    context=context,
                )

                violations.append(violation)

        return violations

    # =====================================================
    # Rule Matching
    # =====================================================
    # Determines whether runtime context satisfies
    # all rule conditions.
    # =====================================================

    def _matches(
        self,
        rule: PolicyRule,
        context: dict[str, Any],
    ) -> bool:

        # -------------------------------------------------
        # Evaluate every rule condition.
        # -------------------------------------------------

        for key, expected_value in rule.conditions.items():

            actual_value = context.get(key)

            # ---------------------------------------------
            # Debug condition evaluation.
            # ---------------------------------------------

            print(
                f"  - {key}: "
                f"expected={expected_value} "
                f"actual={actual_value}"
            )

            if actual_value != expected_value:

                return False

        print("[PolicyEngine] Rule matched successfully")

        return True