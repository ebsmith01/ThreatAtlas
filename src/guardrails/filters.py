from src.guardrails.classifier import get_checks_for_category


def run_guardrail_checks(response_text, category):
    checks = get_checks_for_category(category)
    violations = []

    for check in checks:
        result = check(response_text)
        if result is not None:
            violations.append(result)

    return {
        "category": category,
        "violations": violations,
        "pass_fail": "fail" if violations else "pass",
    }