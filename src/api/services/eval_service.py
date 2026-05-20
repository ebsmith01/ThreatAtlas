from evals.generate_report import run_eval


def run_evaluation(
    target: str,
    system: str | None = None,
    sample_size: int = 10,
) -> dict:
    """
    Runs a ThreatAtlas evaluation and returns the report.
    """

    return run_eval(
        n=sample_size,
        target_name=target,
        system=system,
    )