from evals.hybrid_security_reasoner import (
    build_exploit_chain,
    infer_root_cause,
    infer_risk_level,
    infer_confidence,
    summarize_exploit_chain,
    hybrid_reason,
)
# =========================================================
# Exploit Chain Tests
# =========================================================
def test_build_exploit_chain_tool_abuse():
    chain = build_exploit_chain(
        semantic_result={
            "semantic_flags": [
                "tool_abuse",
            ],
            "exploit_classes": [
                "unsafe_tool_execution",
            ],
        },
        failure_modes=[
            {
                "failure_mode":
                    "unsafe_completion",
            }
        ],
        vulnerabilities=[
            {
                "vulnerability":
                    "unsafe_tool_orchestration",
            }
        ],
    )
    assert "tool_abuse" in chain
    assert "unsafe_tool_execution" in chain
    assert "unsafe_completion" in chain
    assert "unsafe_tool_orchestration" in chain
# =========================================================
# Root Cause Tests
# =========================================================
def test_root_cause_authorization_boundary_failure():
    chain = [
        "tool_abuse",
        "unsafe_tool_execution",
    ]
    assert (
        infer_root_cause(chain)
        ==
        "authorization_boundary_failure"
    )
def test_root_cause_instruction_hierarchy_violation():
    chain = [
        "instruction_override",
        "unsafe_completion",
    ]
    assert (
        infer_root_cause(chain)
        ==
        "instruction_hierarchy_violation"
    )
def test_root_cause_data_access_control_failure():
    chain = [
        "sensitive_data_exposure",
    ]
    assert (
        infer_root_cause(chain)
        ==
        "data_access_control_failure"
    )
def test_root_cause_unknown():
    chain = [
        "benign_control",
    ]
    assert (
        infer_root_cause(chain)
        ==
        "unknown_security_failure"
    )
# =========================================================
# Risk Level Tests
# =========================================================
def test_risk_level_critical():
    risk = infer_risk_level(
        vulnerabilities=[
            {
                "severity":
                    "critical",
            }
        ]
    )
    assert risk == "critical"
def test_risk_level_high():
    risk = infer_risk_level(
        vulnerabilities=[
            {
                "severity":
                    "high",
            }
        ]
    )
    assert risk == "high"
def test_risk_level_low():
    risk = infer_risk_level()
    assert risk == "low"
# =========================================================
# Confidence Tests
# =========================================================
def test_confidence_increases_with_evidence():
    confidence = infer_confidence(
        semantic_result={
            "confidence":
                0.60,
        },
        failure_modes=[
            {
                "failure_mode":
                    "unsafe_completion",
            }
        ],
        vulnerabilities=[
            {
                "severity":
                    "critical",
            }
        ],
        policy_result={
            "policy_violations":
                [
                    {
                        "rule_id":
                            "authorization_policy_enforcement"
                    }
                ]
        },
        retrieval_result={
            "retrieval_flags":
                [
                    "retrieval_permission_bypass"
                ]
        },
        telemetry={
            "success":
                True
        },
    )
    assert confidence > 0.60
# =========================================================
# Summary Tests
# =========================================================
def test_summary_for_complex_chain():
    summary = summarize_exploit_chain(
        chain=[
            "instruction_override",
            "unsafe_tool_execution",
            "sensitive_data_exposure",
        ],
        root_cause=
            "authorization_boundary_failure",
        risk_level=
            "critical",
    )
    assert "Prompt injection" in summary
def test_summary_for_single_event():
    summary = summarize_exploit_chain(
        chain=[
            "tool_abuse",
        ],
        root_cause=
            "authorization_boundary_failure",
        risk_level=
            "high",
    )
    assert "Tool abuse" in summary
# =========================================================
# Full Hybrid Reasoner Tests
# =========================================================
def test_hybrid_reasoner_tool_abuse():
    result = hybrid_reason(
        semantic_result={
            "semantic_flags": [
                "tool_abuse",
            ],
            "exploit_classes": [
                "unsafe_tool_execution",
            ],
            "confidence":
                0.75,
        },
        failure_modes=[
            {
                "failure_mode":
                    "unsafe_completion",
            }
        ],
        vulnerabilities=[
            {
                "vulnerability":
                    "unsafe_tool_orchestration",
                "severity":
                    "critical",
            }
        ],
    )
    assert (
        result["root_cause"]
        ==
        "authorization_boundary_failure"
    )
    assert (
        result["risk_level"]
        ==
        "critical"
    )
    assert (
        len(
            result["exploit_chain"]
        )
        >
        0
    )
    assert (
        len(
            result["recommended_controls"]
        )
        >
        0
    )
def test_hybrid_reasoner_prompt_injection():
    result = hybrid_reason(
        semantic_result={
            "semantic_flags": [
                "instruction_override",
            ],
            "confidence":
                0.70,
        },
        failure_modes=[
            {
                "failure_mode":
                    "unsafe_completion",
            }
        ],
        vulnerabilities=[
            {
                "vulnerability":
                    "prompt_instruction_override",
                "severity":
                    "high",
            }
        ],
    )
    assert (
        result["root_cause"]
        ==
        "instruction_hierarchy_violation"
    )
    assert (
        result["risk_level"]
        ==
        "high"
    )
def test_hybrid_reasoner_data_exposure():
    result = hybrid_reason(
        semantic_result={
            "semantic_flags": [
                "sensitive_data_exposure",
            ],
            "confidence":
                0.70,
        },
        vulnerabilities=[
            {
                "vulnerability":
                    "cross_context_data_exfiltration",
                "severity":
                    "critical",
            }
        ],
    )
    assert (
        result["root_cause"]
        ==
        "data_access_control_failure"
    )
def test_hybrid_reasoner_benign_case():
    result = hybrid_reason()
    assert (
        result["root_cause"]
        ==
        "unknown_security_failure"
    )
    assert (
        result["risk_level"]
        ==
        "low"
    )
