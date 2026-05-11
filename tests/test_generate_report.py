from evals.generate_report import run_eval


def test_report_contains_new_metrics():
    report = run_eval(
        n=5,
        target_name="safe",
    )

    overall = report["summary"]["overall"]

    assert "authorization_failure_rate" in overall
    assert "rag_data_leak_rate" in overall
    assert "agent_tool_abuse_rate" in overall
    assert "llm_failure_rate" in overall