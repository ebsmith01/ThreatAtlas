# Evaluation Plan

Objectives
- Measure attack success and refusal rates by category and model configuration.
- Quantify guardrail precision/recall and false-positive over-refusals.
- Produce decision-ready risk scores aligned to deployment profiles.

Scope & Targets
- Primary: LLM chat endpoints (OpenAI-compatible) via `LLMTarget`.
- Secondary: agent/tooling flows via `tool_misuse` cases (future expansion).
- Baseline controls: `MockSafeTarget`, `MockVulnerableTarget`.

Sampling Strategy
- Use full corpus for nightly runs; `--sample` flag for fast smoke tests.
- Maintain balanced category representation per target count in `dataset_design.md`.

Metrics Reported
- Pass/fail counts, attack success %, refusal %, latency, token usage (when available).
- Risk score and level from `src/evals/risk.py` with selectable profiles.
- Per-category guardrail violations and violated rules.

Cadence
- Smoke: on PRs with small samples.
- Nightly: full corpus on canonical models.
- Release: full corpus plus comparison against last release baselines.

See `docs/evaluation_methodology.md` for execution details and scoring formulas.
