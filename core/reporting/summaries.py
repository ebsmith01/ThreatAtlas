"""Natural language summaries of evaluations."""


def summarize(findings: list[dict]) -> str:
    # TODO: add templated summarization
    return "; ".join(f.get("title", "finding") for f in findings)
