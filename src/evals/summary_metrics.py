from collections import defaultdict


# =========================================================
# Summary Metrics
# =========================================================
def summarize(results: list[dict]) -> dict:
    bucket = lambda: {
        "total": 0,
        "pass": 0,
        "fail": 0,
    }
    by_category = defaultdict(bucket)
    by_system = defaultdict(bucket)
    by_role = defaultdict(bucket)
    by_sensitivity = defaultdict(bucket)

    for result in results:
        pass_fail = result.get("pass_fail")
        for group, key in [
            (
                by_category,
                result.get("category"),
            ),
            (
                by_system,
                result.get("target_system"),
            ),
            (
                by_role,
                result.get("actor_role"),
            ),
            (
                by_sensitivity,
                result.get("sensitivity"),
            ),
        ]:
            if not key:
                continue
            group[key]["total"] += 1
            group[key][pass_fail] += 1

    total = len(results)
    passed = sum(
        1
        for r in results
        if r.get("pass_fail") == "pass"
    )
    failed = total - passed
    return {
        "overall": {
            "total": total,
            "pass": passed,
            "fail": failed,
            "pass_rate": round(
                passed / total * 100,
                2,
            ) if total else 0,
        },
        "by_category": dict(by_category),
        "by_system": dict(by_system),
        "by_actor_role": dict(by_role),
        "by_sensitivity": dict(by_sensitivity),
    }
