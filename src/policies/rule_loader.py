from pathlib import Path

import yaml

from policies.policy_models import PolicyRule

RULES_DIR = Path(__file__).parent / "rules"


def load_rules() -> list[PolicyRule]:
    rules: list[PolicyRule] = []

    for path in sorted(RULES_DIR.glob("*.yaml")):
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        for item in data.get("rules", []):
            rules.append(
                PolicyRule(
                    rule_id=item["rule_id"],
                    description=item["description"],
                    severity=item["severity"],
                    conditions=item["conditions"],
                    vulnerability=item.get(
                        "vulnerability"
                    ),
                )
            )

    return rules
