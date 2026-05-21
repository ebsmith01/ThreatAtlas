from __future__ import annotations

import argparse
import json
import time

from collections import Counter
from collections import defaultdict
from pathlib import Path

from data.loaders import load_attack_corpus

from evals.policy_evaluator import (
    evaluate_policy,
    extract_policy_rule_ids,
)

from evals.retrieval_evaluator import (
    evaluate_retrieval_security,
)

from evals.rule_evaluator import evaluate_response
from evals.risk import score_report
from evals.severity import score_response
from evals.telemetry_metrics import (
    compute_telemetry_metrics,
)

from guardrails.filters import run_guardrail_checks

from targets.llm_target import LLMTarget
from targets.mock_target import MockSmokeTarget
from targets.mock_safe_target import MockSafeTarget
from targets.mock_vulnerable_target import (
    MockVulnerableTarget,
)
from targets.mock_rag_target import MockRAGTarget
from targets.mock_agent_target import MockAgentTarget


# =========================================================
# ThreatAtlas
# =========================================================
# AI Vulnerability Intelligence Evaluation Pipeline
#
# Responsibilities:
# - load attacks
# - filter evaluation corpus
# - execute targets
# - evaluate policy violations
# - run guardrails
# - evaluate retrieval security
# - aggregate telemetry
# - generate vulnerability reports
# =========================================================


ATTACK_CORPUS_PATH = Path(
    "data/attacks/final/attack_corpus.jsonl"
)

REPORTS_DIR = Path("outputs")


# =========================================================
# Target Registry
# =========================================================
# Centralized target factory.
#
# Eventually this evolves into:
# - universal adapters
# - plugin registry
# - HTTP integrations
# - OpenAI integrations
# =========================================================


def get_target(
    name: str,
    model: str | None = None,
    provider: str | None = None,
    base_url: str | None = None,
    api_key_env: str | None = None,
):

    targets = {
        "smoke": MockSmokeTarget,
        "safe": MockSafeTarget,
        "vulnerable": MockVulnerableTarget,
    }

    if name in targets:
        return targets[name]()

    # -----------------------------------------------------
    # Agent Targets
    # -----------------------------------------------------

    if name == "agent_safe":
        return MockAgentTarget(
            vulnerable=False,
        )

    if name == "agent_vulnerable":
        return MockAgentTarget(
            vulnerable=True,
        )

    # -----------------------------------------------------
    # RAG Targets
    # -----------------------------------------------------

    if name == "rag_safe":
        return MockRAGTarget(
            vulnerable=False,
        )

    if name == "rag_vulnerable":
        return MockRAGTarget(
            vulnerable=True,
        )

    # -----------------------------------------------------
    # Real LLM Integration
    # -----------------------------------------------------

    if name == "llm":

        return LLMTarget(
            provider=provider or "openai",
            model=model or "gpt-4.1",
            base_url=base_url,
            api_key_env=api_key_env,
        )

    raise ValueError(f"Unknown target: {name}")


# =========================================================
# Attack Filtering
# =========================================================
# Applies runtime control-plane filters.
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


# =========================================================
# Single Evaluation Execution
# =========================================================
# Executes one attack against one target.
# =========================================================


def evaluate_attack(
    attack: dict,
    target,
    *,
    attack_category: str | None = None,
    sensitivity: str | None = None,
    actor_role: str | None = None,
) -> dict:

    started = time.perf_counter()

    # -----------------------------------------------------
    # Runtime Context
    # -----------------------------------------------------

    effective_category = (
        attack_category
        or attack.get("category")
    )

    effective_sensitivity = (
        sensitivity
        or attack.get("sensitivity")
    )

    effective_actor_role = (
        actor_role
        or attack.get("actor_role")
    )

    # -----------------------------------------------------
    # Execute Target
    # -----------------------------------------------------

    out = target.run(
        prompt=attack.get("prompt"),
        category=effective_category,
        actor_role=effective_actor_role,
        target_system=attack.get("target_system"),
        sensitivity=effective_sensitivity,
        required_permission=attack.get(
            "required_permission"
        ),
        permission_context=attack.get(
            "permission_context"
        ),
        metadata=attack.get("metadata"),
    )

    # -----------------------------------------------------
    # Centralized Policy Evaluation
    # -----------------------------------------------------

    policy_result = evaluate_policy(
        prompt=attack.get("prompt"),
        response_text=out.response_text,
        category=effective_category,
        actor_role=effective_actor_role,
        target_system=attack.get("target_system"),
        sensitivity=effective_sensitivity,
        required_permission=attack.get(
            "required_permission"
        ),
        permission_context=attack.get(
            "permission_context"
        ),
        telemetry=getattr(out, "raw_response", None),
        metadata=attack.get("metadata"),
    )

    # -----------------------------------------------------
    # Guardrails
    # -----------------------------------------------------

    guardrails = run_guardrail_checks(
        out.response_text,
        effective_category,
        attack.get("permission_context"),
        effective_sensitivity,
        attack.get("required_permission"),
    )

    # -----------------------------------------------------
    # Core Response Evaluation
    # -----------------------------------------------------

    pass_fail, rules = evaluate_response(
        out.response_text,
        effective_category,
        attack.get("expected_behavior"),
        effective_actor_role,
        attack.get("target_system"),
        effective_sensitivity,
        attack.get("required_permission"),
        attack.get("permission_context"),
    )

    # -----------------------------------------------------
    # Retrieval Security Evaluation
    # -----------------------------------------------------

    retrieval_eval = evaluate_retrieval_security(
        telemetry=getattr(out, "raw_response", None),
        sensitivity=effective_sensitivity,
        actor_role=effective_actor_role,
    )

    # -----------------------------------------------------
    # Merge Violations
    # -----------------------------------------------------

    policy_rule_ids = extract_policy_rule_ids(
        policy_result
    )

    violations = sorted(
        set(rules)
        |
        {
            v.get("category", v.get("rule_id"))
            for v in guardrails.get(
                "violations",
                [],
            )
        }
        |
        set(
            retrieval_eval.get(
                "retrieval_flags",
                [],
            )
        )
        |
        set(policy_rule_ids)
    )

    final_result = (
        "fail"
        if violations
        else pass_fail
    )

    latency = (
        time.perf_counter() - started
    ) * 1000

    result = {
        **attack,

        # Runtime context.
        "category": effective_category,
        "actor_role": effective_actor_role,
        "sensitivity": effective_sensitivity,

        # Response.
        "response_text": out.response_text,

        # Security result.
        "pass_fail": final_result,
        "violated_rules": violations,

        # Policy evaluation.
        "policy_result": policy_result,

        # Telemetry.
        "telemetry": getattr(
            out,
            "raw_response",
            None,
        ),

        # Retrieval analysis.
        "retrieval_risk_score": retrieval_eval.get(
            "retrieval_risk_score"
        ),
        "retrieval_severity": retrieval_eval.get(
            "severity"
        ),
        "retrieval_flags": retrieval_eval.get(
            "retrieval_flags"
        ),

        # Runtime performance.
        "latency_ms": round(latency, 2),
    }

    # -----------------------------------------------------
    # Severity Scoring
    # -----------------------------------------------------

    result.update(
        score_response(result)
    )

    return result


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


# =========================================================
# Main Evaluation Pipeline
# =========================================================


def run_eval(
    n: int,
    target_name: str,
    system: str | None = None,
    attack_category: str | None = None,
    sensitivity: str | None = None,
    actor_role: str | None = None,
    **kwargs,
):

    attacks = load_attack_corpus(
        ATTACK_CORPUS_PATH
    )

    attacks = filter_attacks(
        attacks,
        system=system,
        attack_category=attack_category,
        sensitivity=sensitivity,
        actor_role=actor_role,
        sample_size=n,
    )


    target = get_target(
        target_name,
        **kwargs,
    )

    results = []

    for attack in attacks:

        result = evaluate_attack(
            attack,
            target,
            attack_category=attack_category,
            sensitivity=sensitivity,
            actor_role=actor_role,
        )

        results.append(result)

    telemetry_events = [
        {
            **(r.get("telemetry") or {}),
            "target_system": r.get(
                "target_system"
            ),
            "violated_rules": r.get(
                "violated_rules",
                [],
            ),
            "policy_violations": r.get(
                "policy_result",
                {},
            ).get(
                "policy_violations",
                [],
            ),
        }
        for r in results
        if r.get("telemetry")
    ]

    telemetry_metrics = (
        compute_telemetry_metrics(
            telemetry_events
        )
    )

    return {
        "summary": summarize(results),
        "coverage": coverage(results),
        "risk": score_report(results),
        "telemetry_metrics": telemetry_metrics,
        "results": results,
    }


# =========================================================
# Report Printing
# =========================================================


def print_report(report: dict):
    overall = report[
        "summary"
    ]["overall"]

    print("\n=== ThreatAtlas Evaluation Summary ===")

    print(
        f"Total Evaluations: {overall.get('total')}"
    )

    print(
        f"Passed: {overall.get('pass')}"
    )

    print(
        f"Failed: {overall.get('fail')}"
    )

    print(
        f"Pass Rate: {overall.get('pass_rate')}%"
    )

    print(
        f"Risk Score: "
        f"{report['risk']['risk_score']}"
    )

    telemetry = report.get(
        "telemetry_metrics",
        {},
    )

    if telemetry:

        print(
            f"Average Latency: "
            f"{telemetry.get('average_latency_ms', 0)}ms"
        )

        print(
            f"Success Rate: "
            f"{telemetry.get('success_rate', 0)}%"
        )


# =========================================================
# CLI
# =========================================================


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--target",
        default="smoke",
    )

    parser.add_argument(
        "--model",
        default="gpt-4.1",
    )

    parser.add_argument(
        "--provider",
        default="openai",
    )

    parser.add_argument(
        "--sample",
        type=int,
        default=25,
    )

    parser.add_argument(
        "--system",
        choices=["llm", "rag", "agent"],
        default=None,
    )

    # -----------------------------------------------------
    # Runtime Threat Modeling Filters
    # -----------------------------------------------------

    parser.add_argument(
        "--attack-category",
        type=str,
        default=None,
    )

    parser.add_argument(
        "--sensitivity",
        type=str,
        default=None,
    )

    parser.add_argument(
        "--actor-role",
        type=str,
        default=None,
    )

    args = parser.parse_args()

    print("\n=== ThreatAtlas Evaluation ===")
    print(f"Target: {args.target}")
    print(f"System: {args.system}")
    print(f"Sample Size: {args.sample}")

    report = run_eval(
        n=args.sample,
        target_name=args.target,
        system=args.system,
        model=args.model,
        provider=args.provider,
        attack_category=args.attack_category,
        sensitivity=args.sensitivity,
        actor_role=args.actor_role,
    )

    print_report(report)

    REPORTS_DIR.mkdir(
        exist_ok=True,
    )

    output_path = (
        REPORTS_DIR
        /
        f"{args.target}_report.json"
    )

    json.dump(
        report,
        open(output_path, "w"),
        indent=2,
    )

    print(f"\nSaved: {output_path}")


if __name__ == "__main__":
    main()
