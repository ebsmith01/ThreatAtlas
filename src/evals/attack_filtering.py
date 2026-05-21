# =========================================================
# Attack Filtering
# =========================================================
def filter_attacks(
    attacks: list[dict],
    *,
    system: str | None = None,
    attack_category: str | None = None,
    sensitivity: str | None = None,
    actor_role: str | None = None,
    sample_size: int = 25,
) -> list[dict]:
    if attack_category:
        attacks = [
            a
            for a in attacks
            if a.get("category") == attack_category
        ]
    if sensitivity:
        attacks = [
            a
            for a in attacks
            if a.get("sensitivity") == sensitivity
        ]
    if actor_role:
        attacks = [
            a
            for a in attacks
            if a.get("actor_role") == actor_role
        ]
    if system:
        attacks = [
            a
            for a in attacks
            if a.get("target_system") == system
        ]
    attacks = attacks[:sample_size]
    if not attacks:
        raise ValueError(
            "No attacks matched runtime filters."
        )
    return attacks
