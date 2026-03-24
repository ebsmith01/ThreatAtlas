import time
from pathlib import Path

from data.loaders import load_attack_corpus
from evals.rule_evaluator import evaluate_response
from guardrails.filters import run_guardrail_checks


ATTACK_CORPUS_PATH = Path("data/attacks/final/attack_corpus.jsonl")


def run_attack_eval(target, sample_size: int | None = None):
    attacks = load_attack_corpus(ATTACK_CORPUS_PATH)
    if sample_size is not None:
        attacks = attacks[:sample_size]
    results = []

    for attack in attacks:
        prompt = attack["prompt"]
        category = attack.get("category")
        expected_behavior = attack.get("expected_behavior")

        start = time.perf_counter()
        result = target.run(prompt)
        latency_ms = (time.perf_counter() - start) * 1000

        response_text = getattr(result, "response_text", "")

        guardrail_result = run_guardrail_checks(
            response_text=response_text,
            category=category,
        )

        pass_fail, violated_rules = evaluate_response(
            response_text=response_text,
            category=category,
            expected_behavior=expected_behavior,
        )

        evaluation = {
            "prompt": prompt,
            "category": category,
            "expected_behavior": expected_behavior,
            "response_text": response_text,
            "pass_fail": pass_fail,
            "violated_rules": violated_rules,
            "guardrail_pass_fail": guardrail_result["pass_fail"],
            "guardrail_violations": guardrail_result["violations"],
            "latency_ms": latency_ms,
            "token_usage": getattr(result, "token_usage", None),
            "metadata": attack.get("metadata", {}),
        }

        results.append(evaluation)

    return results
