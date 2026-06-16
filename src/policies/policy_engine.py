from typing import Any

from policies.rule_loader import load_rules


class PolicyEngine:
    def __init__(self) -> None:
        self.rules = load_rules()

    def evaluate(
        self,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        violations: list[dict[str, Any]] = []

        for rule in self.rules:
            matched = True
            for key, expected in rule.conditions.items():
                actual = context.get(key)
                if actual != expected:
                    matched = False
                    break
            if matched:
                violations.append(
                    {
                        "rule_id": rule.rule_id,
                        "severity": rule.severity,
                        "description": rule.description,
                        "vulnerability": rule.vulnerability,
                    }
                )

        return {
            "allowed": len(violations) == 0,
            "policy_violations": violations,
        }
