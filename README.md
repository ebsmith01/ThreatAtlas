# ThreatAtlas

ThreatAtlas is an LLM safety evaluation lab for adversarial robustness, alignment testing, content moderation, and risk-based decision making across LLM, RAG, and agent-based systems.

Instead of acting as a chatbot itself, ThreatAtlas is designed to answer the question:

> Is this AI system safe enough to deploy?

---

## What ThreatAtlas Does

ThreatAtlas evaluates AI systems by running structured prompt corpora against them and analyzing:

- how they behave under adversarial pressure
- whether they follow safety policies
- how severe their failures are
- how they compare to other models or configurations

It transforms raw model outputs into decision-ready safety insights.
---

## Real-World Uses

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

