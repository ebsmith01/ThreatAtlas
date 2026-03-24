from guardrails.rules import (
    check_jailbreak_compliance,
    check_prompt_injection,
    check_sensitive_data_leakage,
    check_unnecessary_refusal,
)


def get_checks_for_category(category):
    mapping = {
        "prompt_injection": [check_prompt_injection],
        "sensitive_data_request": [check_sensitive_data_leakage],
        "jailbreak": [check_jailbreak_compliance],
        "benign_control": [check_unnecessary_refusal],
    }

    return mapping.get(category, [])