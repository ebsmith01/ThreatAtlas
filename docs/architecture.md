# Architecture

ThreatAtlas is a lightweight, script-first evaluation stack. Key layers:

- **Dataset layer** (`data/`, `src/data/loaders.py`): normalized attack corpus in JSONL, with source metadata preserved.
- **Targets** (`src/targets/`): pluggable evaluation surfaces. Includes mock safe/vulnerable targets and `LLMTarget` for OpenAI-compatible endpoints.
- **Evaluation engine** (`src/evals/attack_eval.py`): iterates corpus, invokes targets, records latency/usage, and runs guardrails & rule checks.
- **Guardrails & rules** (`src/guardrails/filters.py`, `src/evals/rule_evaluator.py`): string-pattern guardrails plus expected-behavior checks.
- **Scoring** (`src/evals/metrics.py`, `src/evals/risk.py`): aggregates pass/fail/refusal, computes attack success, and profile-weighted risk.
- **Reporting** (`src/evals/reporting.py`, `src/evals/generate_report.py`): builds JSON reports, prints summaries, and supports multi-run comparisons.
- **Interface** (`src/evals/cli.py`, `scripts/demo.py`): CLI entry points for local runs and quick demos; outputs live in `outputs/`.

Data flow
1) Load corpus → 2) call target → 3) guardrail & rule evaluation → 4) metrics/risk → 5) JSON report + console summary.
