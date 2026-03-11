"""Metrics aggregation utilities."""


def aggregate(scores: list[float]) -> dict:
    return {"mean": sum(scores) / len(scores)} if scores else {"mean": 0.0}
