from collections import Counter


# =========================================================
# Coverage Metrics
# =========================================================
def coverage(results: list[dict]) -> dict:
    counter = lambda key: Counter(
        r.get(key)
        for r in results
    )
    return {
        "category": dict(counter("category")),
        "role": dict(counter("actor_role")),
        "system": dict(counter("target_system")),
        "sensitivity": dict(counter("sensitivity")),
    }
