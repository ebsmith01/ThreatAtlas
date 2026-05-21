from pathlib import Path
import yaml

from policies.policy_models import PolicyRule


# =========================================================
# Rule Loader
# =========================================================
# Loads YAML policy files into PolicyRule objects.
#
# Supports:
# - authorization rules
# - retrieval rules
# - prompt rules
# - behavioral rules
# =========================================================


# Base rules directory.
RULES_DIR = Path(__file__).parent / "rules"


# =========================================================
# Load YAML File
# =========================================================

def load_yaml_file(path: Path) -> list[dict]:

    with open(path, "r") as f:

        data = yaml.safe_load(f)

    return data or []


# =========================================================
# Convert YAML → PolicyRule objects
# =========================================================

def parse_rules(raw_rules: list[dict]) -> list[PolicyRule]:

    rules = []

    for r in raw_rules:

        rule = PolicyRule(

            id=r["id"],

            category=r["category"],

            severity=r["severity"],

            conditions=r.get("conditions", {}),

            action=r.get("action", "warn"),

            description=r.get("description", ""),
        )

        rules.append(rule)

    return rules


# =========================================================
# Load All Rules
# =========================================================
# Dynamically loads every YAML file in:
#
# src/policies/rules/
# =========================================================

def load_all_rules() -> list[PolicyRule]:

    all_rules = []

    yaml_files = RULES_DIR.glob("*.yaml")

    for file_path in yaml_files:

        raw_rules = load_yaml_file(file_path)

        parsed_rules = parse_rules(raw_rules)

        all_rules.extend(parsed_rules)

    return all_rules