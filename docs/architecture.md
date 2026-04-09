# Architecture

Brief outline of services, core engine, and data layout for ThreatAtlas.

# Architecture

ThreatAtlas is designed as a modular, model-agnostic evaluation system for testing the safety, robustness, and reliability of LLM-based systems.

At a high level, the system follows a simple but powerful pipeline:

Corpus → Target → Evaluation → Risk Scoring → Reporting

---

## 1. Corpus Layer

The corpus layer defines **what is being tested**.

It consists of structured prompt datasets representing adversarial and control scenarios.

### Responsibilities
- Store canonical attack prompts
- Define evaluation categories
- Specify expected behavior
- Enable reproducible testing

### Data Format
Each entry includes:
- `prompt`
- `category`
- `expected_behavior`
- `metadata`

### Categories
- prompt_injection
- jailbreak
- instruction_override
- sensitive_data_request
- policy_evasion
- tool_misuse
- benign_control

### Key Files
- `data/attacks/final/attack_corpus.jsonl`

---

## 2. Target Layer

The target layer defines **what system is being tested**.

It abstracts away model-specific logic so all systems can be evaluated uniformly.

### Responsibilities
- Accept prompt input
- Return model response
- Standardize output format

### Target Types
- `mock_smoke_target` — basic sanity checks
- `mock_safe_target` — mostly compliant behavior
- `mock_vulnerable_target` — intentionally unsafe behavior
- `llm_target` — real model (OpenAI or compatible APIs)

### Interface Contract
All targets return:
- `response_text`
- optional `token_usage`

### Key Files
- `targets/llm_target.py`
- `targets/mock_*`

---

## 3. Evaluation Layer

The evaluation layer determines **whether a response is safe or unsafe**.

It combines rule-based evaluation with guardrail checks.

### Components

#### Rule Evaluator
- Category-specific logic
- Detects unsafe behaviors (e.g., jailbreak compliance)

#### Guardrails
- Detect obvious violations
- Independent safety checks (e.g., sensitive data leakage)

### Output
- `pass_fail`
- `violated_rules`
- `guardrail_violations`

### Key Files
- `evals/rule_evaluator.py`
- `guardrails/filters.py`

---

## 4. Risk & Severity Layer 

This layer determines **how dangerous failures are**.

It extends binary evaluation with quantitative scoring.

### Per-Response Metrics
- `severity_score`
- `leakage_score`
- `compliance_score`

### Run-Level Metrics
- `risk_score`
- `risk_level` (low / medium / high)
- `critical_failures`
- `risk_by_category`

### Profiles
- `strict_security`
- `balanced`
- `high_utility`

### Key Files
- `evals/severity.py`
- `evals/risk.py`

---

## 5. Reporting Layer

The reporting layer converts evaluation results into **structured outputs and insights**.

### Responsibilities
- Aggregate metrics
- Save JSON reports
- Surface failed cases
- Enable comparisons

### Outputs
- summary (pass rate, category breakdown)
- risk summary
- detailed results per prompt

### Key Files
- `evals/generate_report.py`

---

## 6. Comparison Layer 
The comparison layer enables **model and configuration comparison**.

### Capabilities
- Compare two evaluation runs
- Compute deltas for:
  - pass rate
  - attack success rate
  - refusal rate
  - risk score
  - category performance

### Use Cases
- regression testing
- model selection
- prompt/policy tuning

### Key Files
- `evals/compare_models.py`

---

## End-to-End Flow

1. Load attack corpus  
2. Select target (mock or real model)  
3. Run prompts through target  
4. Evaluate responses (rules + guardrails)  
5. Assign pass/fail and violated rules  
6. Compute per-response severity scores  
7. Aggregate into risk metrics  
8. Generate report  
9. Optionally compare against another run  

---

## Design Principles

### Model-Agnostic
Evaluation logic is decoupled from model implementation.

### Reproducible
Fixed corpus ensures consistent benchmarking.

### Explainable
All scoring and evaluation logic is transparent and rule-based.

### Modular
Each layer can be extended independently.

### Decision-Oriented
Outputs are designed to support deployment and safety decisions.

---
