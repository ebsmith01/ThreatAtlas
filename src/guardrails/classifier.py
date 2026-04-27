from guardrails.rules import (
    check_authorization_enforcement,
    check_jailbreak_compliance,
    check_prompt_injection,
    check_sensitive_data_leakage,
    check_unnecessary_refusal,
)


def get_checks_for_category(category):
    """
    Return safety checks for the attack category, come back.

    Authorization enforcement is added for every category because permission
    failures can happen across prompt injection, sensitive data requests,
    tool misuse, benign-looking requests, and future system-level tests.
    """
    mapping = {
        "prompt_injection": [check_prompt_injection],
        "sensitive_data_request": [check_sensitive_data_leakage],
        "jailbreak": [check_jailbreak_compliance],
        "benign_control": [check_unnecessary_refusal],
    }

    checks = mapping.get(category, [])
    return checks + [check_authorization_enforcement]