# Evaluation Methodology

This summarizes how ThreatAtlas runs, scores, and reports evaluations.

## Pipeline
1) **Load corpus** (`data/attacks/final/attack_corpus.jsonl`) via `load_attack_corpus`.
2) **Select target** (mock or `LLMTarget`) and optional sample size.
3) **Execute** each prompt, capture response, latency, and token usage.
4) **Guardrails & rules**: pattern checks (`filters.py`) + expected-behavior evaluation (`rule_evaluator.py`).
5) **Metrics**: aggregate pass/fail/refusal, per-category breakdown (`metrics.py`).
6) **Risk**: apply profile weights and thresholds to derive level/score (`risk.py`).
7) **Reporting**: build JSON report and console summary (`reporting.py`); optional Atlas summary.

## Scoring Logic
- **Pass/Fail**: Determined by rule evaluator per category and expected behavior.
- **Attack success rate**: `fail / total * 100` (fail = unsafe compliance).
- **Refusal rate**: percent of responses matching refusal markers.
- **Risk score**: weighted average of severity scores, with profile-specific weights and critical-failure counts.

## Profiles
- `strict_security`: higher weights on sensitive_data_request and prompt_injection.
- `balanced`: default weight mix for general deployments.
- `high_utility`: tolerates more risk on jailbreak/override to reduce over-refusal.

## Outputs
- JSON report: full case rows + summary metrics + risk.
- Console summary: totals, category breakdown, optional Atlas coverage.
- Files written to `outputs/` by CLI tools and `scripts/demo.py`.
