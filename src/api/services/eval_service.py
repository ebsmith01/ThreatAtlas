from evals.generate_report import run_eval


# ==========================================================
# Supported Systems
# ==========================================================
# Defines the valid evaluation system types.
# ==========================================================

SUPPORTED_SYSTEMS = {
    "llm",
    "rag",
    "agent",
}

SUPPORTED_ATTACK_CATEGORIES = {
    "prompt_injection",
    "tool_misuse",
    "data_exfiltration",
    "jailbreak",
}

SUPPORTED_SENSITIVITY_LEVELS = {
    "low",
    "internal",
    "confidential",
}

SUPPORTED_ACTOR_ROLES = {
    "user",
    "system",
    "admin",
}


# ==========================================================
# Run Evaluation Service
# ==========================================================
# API service layer responsible for:
#
# - validating API input
# - calling the ThreatAtlas evaluation engine
# - returning normalized evaluation results
#
# This sits between:
#
# FastAPI routes
#        ↓
# evaluation engine
# ==========================================================


def run_evaluation(
    target: str,
    system: str | None = None,
    sample_size: int = 10,

    # --------------------------------------------------
    # Threat modeling configuration.
    # --------------------------------------------------

    attack_category: str = "prompt_injection",
    sensitivity: str = "internal",
    actor_role: str = "user",

) -> dict:
    """
    Runs a ThreatAtlas evaluation.
    """

    # ------------------------------------------------------
    # Validate system type.
    # ------------------------------------------------------

    if system is not None:

        system = system.lower()

        if system not in SUPPORTED_SYSTEMS:

            raise ValueError(
                f"Unsupported system: {system}"
            )


    # ------------------------------------------------------
    # Validate attack category.
    # ------------------------------------------------------

    attack_category = attack_category.lower()

    if attack_category not in SUPPORTED_ATTACK_CATEGORIES:

        raise ValueError(
            f"Unsupported attack category: {attack_category}"
        )


    # ------------------------------------------------------
    # Validate sensitivity level.
    # ------------------------------------------------------

    sensitivity = sensitivity.lower()

    if sensitivity not in SUPPORTED_SENSITIVITY_LEVELS:

        raise ValueError(
            f"Unsupported sensitivity: {sensitivity}"
        )


    # ------------------------------------------------------
    # Validate actor role.
    # ------------------------------------------------------

    actor_role = actor_role.lower()

    if actor_role not in SUPPORTED_ACTOR_ROLES:

        raise ValueError(
            f"Unsupported actor role: {actor_role}"
        )

    # ------------------------------------------------------
    # Validate sample size.
    # ------------------------------------------------------

    sample_size = max(1, min(sample_size, 1000))

    # ------------------------------------------------------
    # Debug logging.
    # ------------------------------------------------------

    print("\n=== ThreatAtlas Evaluation Request ===")

    print(f"Target: {target}")

    print(f"System: {system}")

    print(f"Sample Size: {sample_size}")

    print(f"Attack Category: {attack_category}")

    print(f"Sensitivity: {sensitivity}")

    print(f"Actor Role: {actor_role}")

    # ------------------------------------------------------
    # Run evaluation engine.
    # ------------------------------------------------------

    report = run_eval(
        n=sample_size,
        target_name=target,
        system=system,

        # ----------------------------------------------
        # Threat modeling configuration.
        # ----------------------------------------------

        attack_category=attack_category,
        sensitivity=sensitivity,
        actor_role=actor_role,
    )

    # ------------------------------------------------------
    # Attach evaluation metadata.
    # ------------------------------------------------------

    report["evaluation_context"] = {
        "target": target,
        "system": system,
        "sample_size": sample_size,
        "attack_category": attack_category,
        "sensitivity": sensitivity,
        "actor_role": actor_role,
    }

    # ------------------------------------------------------
    # Return normalized response.
    # ------------------------------------------------------

    return report