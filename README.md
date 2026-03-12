# ThreatAtlas

ThreatAtlas is an LLM security evaluation lab for building, testing, and analyzing adversarial prompt corpora used to evaluate the safety, robustness, and reliability of LLM-based systems.

Instead of acting as a chatbot itself, ThreatAtlas is designed to help engineers and researchers answer a different question:

> Is this AI system safe enough to deploy?

ThreatAtlas focuses on adversarial prompt evaluation for LLM, RAG, and agent-style systems. It supports attack corpus construction, category balancing, validation, evaluation workflows, and reporting for common LLM security risks.

---

## What ThreatAtlas Does

ThreatAtlas builds and evaluates prompt corpora for testing AI systems against adversarial behaviors such as:

- prompt injection
- jailbreak attempts
- instruction override
- sensitive data extraction
- policy evasion
- unsafe tool misuse
- benign control prompts for baseline comparison

It is intended to support structured AI security testing rather than general question answering.

---

## Real-World Uses

ThreatAtlas can be used to support several practical AI security workflows.

### 1. LLM security testing
Test whether a model follows malicious instructions, reveals hidden prompts, leaks sensitive information, or violates expected behavior under adversarial input.

### 2. RAG system evaluation
Evaluate whether a retrieval-based system stays grounded, resists malicious context, and avoids hallucinating unsupported claims when exposed to adversarial prompts.

### 3. AI red-teaming
Run structured prompt suites across a model or application instead of relying on manual red-team testing alone.

### 4. Regression testing
Compare model or prompt-template changes over time and measure whether safety performance improves or degrades.

### 5. Corpus-driven evaluation research
Analyze attack distributions, category coverage, data quality, and benchmark design for adversarial AI testing.

---

## Current Attack Categories

ThreatAtlas currently supports the following evaluation categories:

- `prompt_injection`
- `jailbreak`
- `instruction_override`
- `sensitive_data_request`
- `policy_evasion`
- `tool_misuse`
- `benign_control`

These categories are used to build the final attack corpus and drive evaluation reporting.
