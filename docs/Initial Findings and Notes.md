# ThreatAtlas — Testing Suite & Coverage Reference

## Overview

ThreatAtlas uses `pytest` to validate:

* evaluation pipelines
* guardrails
* authorization enforcement
* corpus loading
* reporting logic
* mock AI system behavior

Primary command:

```bash
pytest tests -v
```

Coverage command:

```bash
pytest --cov=src
```

---

# Current Test Suite

## 1. Loader & Schema Validation

Files:

* `tests/test_loader_schema.py`
* `tests/test_loaders.py`

Tests:

* attack corpus loads correctly
* JSONL parsing works
* required schema fields exist
* dataset structure is valid

Protects:

* corpus integrity
* ingestion pipeline
* schema consistency

---

## 2. Guardrail Tests

File:

* `tests/test_guardrails.py`

Tests:

* prompt injection detection
* sensitive data leakage detection
* benign prompt handling

Protects:

* core AI security detection logic
* policy enforcement behavior

---

## 3. Authorization Evaluation

File:

* `tests/test_authorization_eval.py`

Tests:

* unauthorized access detection
* permission-aware evaluation
* policy enforcement behavior

Protects:

* IAM simulation
* role/permission enforcement
* tool authorization checks

---

## 4. Mock Target Behavior

File:

* `tests/test_mock_targets.py`

Tests:

* safe target refuses unsafe requests
* vulnerable target leaks data
* smoke target behaves normally

Protects:

* target simulation behavior
* evaluation realism
* system-type testing

---

## 5. Report Generation

File:

* `tests/test_generate_report.py`

Tests:

* summary metric calculations
* authorization metrics
* system-level risk metrics
* coverage reporting

Protects:

* telemetry
* evaluation reporting
* risk summaries

---

## 6. End-to-End Evaluation Smoke Test

File:

* `tests/test_eval_smoke.py`

Tests:

* attack corpus execution
* target execution
* evaluator pipeline
* telemetry generation
* pass/fail classification
* multi-system attack handling

Protects:

* full ThreatAtlas evaluation flow

Pipeline tested:

```text
attack corpus
    ↓
target.run()
    ↓
run_attack_eval()
    ↓
guardrails
    ↓
rule evaluation
    ↓
telemetry + results
```

---

# Current Security Areas Covered

ThreatAtlas currently tests:

## Prompt Injection

* hidden instruction leakage
* system prompt exposure
* instruction override attempts

## Sensitive Data Leakage

* API key exposure
* confidential data leakage
* protected context disclosure

## Tool Misuse

* unauthorized tool access
* permission bypass behavior
* simulated CRM access

## Authorization Enforcement

* role-aware behavior
* permission-aware evaluation
* unauthorized action handling

## System Types

* LLM systems
* RAG systems
* Agent systems

---

# Current Coverage Snapshot

Initial coverage snapshot (5/6/26):

| File                                    | Coverage |
| --------------------------------------- | -------- |
| `src/evals/attack_eval.py`              | 96%      |
| `src/targets/base.py`                   | 92%      |
| `src/data/loaders.py`                   | 82%      |
| `src/evals/rule_evaluator.py`           | 63%      |
| `src/guardrails/filters.py`             | 62%      |
| `src/evals/generate_report.py`          | 51%      |
| `src/targets/mock_safe_target.py`       | 50%      |
| `src/targets/mock_target.py`            | 47%      |
| `src/targets/mock_vulnerable_target.py` | 33%      |
| `src/evals/severity.py`                 | 28%      |
| `src/evals/risk.py`                     | 15%      |
| `src/targets/llm_target.py`             | 19%      |
| TOTAL                                   | 24%      |

---

# Coverage Interpretation

Coverage columns:

| Column  | Meaning                              |
| ------- | ------------------------------------ |
| `Stmts` | executable lines/statements          |
| `Miss`  | statements not executed during tests |
| `Cover` | percentage of statements executed    |

Formula:

```text
coverage = executed_statements / total_statements * 100
```

---

# Current Strengths

Strongly tested areas:

* evaluation pipeline
* guardrails
* authorization logic
* corpus ingestion
* reporting metrics
* target simulation

These are the most important parts of ThreatAtlas right now.

---

# Current Weak Areas

Lower coverage areas:

* API layer
* corpus builder
* severity scoring
* risk scoring
* reporting helpers
* live LLM integrations

---

# Useful Commands

Run all tests:

```bash
pytest tests -v
```

Run coverage:

```bash
pytest --cov=src
```

Run one test file:

```bash
pytest tests/test_eval_smoke.py -v
```

Run one test:

```bash
pytest tests/test_guardrails.py::test_prompt_injection_violation -v
```

## Notes

On an initial 30-case evaluation against GPT-4.1, ThreatAtlas achieved a 93.33% overall pass rate, with prompt injection emerging as the clearest weak spot. The run also surfaced evaluation-rule gaps, especially around encoded instruction-following and system-prompt leakage classification.
