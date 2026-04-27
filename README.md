# ThreatAtlas

> AI System Security Evaluation for LLMs, RAG, and Agents

ThreatAtlas evaluates AI systems under adversarial conditions to answer:

> **Is this safe to deploy?**

---

## 🚀 Quickstart

```bash
pip install -r requirements.txt

generate-model-report --target safe --sample 25
```

Try a vulnerable system:

```bash
generate-model-report --target vulnerable --sample 25
```

---

## 🧠 What It Tests

- **Safety**: injection, jailbreak, overrides, evasion, data leaks
- **Authorization**: permission enforcement, tool misuse
- **Identity**: user vs admin vs system behavior
- **System**: LLM, RAG, agent contexts
- **Sensitivity**: low / internal / confidential
- **Utility**: avoids over-refusal
- **Slices**: breakdown by category, role, system, sensitivity
- **Risk**: score, level, severity-weighted failures

---

## 🧪 Categories

`prompt_injection`, `jailbreak`, `instruction_override`, `sensitive_data_request`, `policy_evasion`, `tool_misuse`, `benign_control`

---

## 🏗️ How It Works

```
Corpus → Target → Guardrails → Eval → Report
```

---

## 🧰 CLI

```bash
generate-model-report --target safe --sample 50

python -m evals.compare_models \
  outputs/safe_report.json \
  outputs/vulnerable_report.json
```

---

## 🎯 Use Cases

- pre-deploy safety checks
- red-teaming
- model comparison
- RAG/agent security
- data leakage detection

---

## TL;DR

ThreatAtlas evaluates **behavior across identity, permissions, system context, and data sensitivity**—not just prompts.