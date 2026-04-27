
Dataset Design

Overview

ThreatAtlas uses a corpus-first evaluation design for testing LLM, RAG, and agent-based systems against adversarial prompt behavior.

The dataset is not just a collection of prompts — it is a security evaluation layer that encodes:
	•	attack behavior
	•	actor identity
	•	system target
	•	data sensitivity
	•	authorization context

This enables evaluation of both:
	•	model safety behavior (refusal, compliance, leakage)
	•	authorization policy behavior (who should be allowed to do what)

⸻

Design Goals

1. Shared schema across sources

Public datasets vary widely in structure and labeling. All rows are normalized into a single schema so downstream evaluation logic is consistent and source-agnostic.

2. Security-first representation

Each row encodes not just what is being asked, but:
	•	who is asking (actor_role)
	•	what system is targeted (target_system)
	•	what data is at risk (sensitivity)
	•	whether the action should be allowed (permission_context)

This transforms the dataset into a security testing framework, not just a prompt collection.

3. Category-based evaluation

Rows are mapped into a fixed internal taxonomy so evaluations reflect attack behavior, not dataset origin.

4. Global prompt deduplication

Prompts are deduplicated across all sources to prevent inflated counts and improve evaluation quality.

5. Controlled balancing

Each category is downsampled or backfilled to target sizes to ensure balanced evaluation coverage.

6. Explicit handling of sparsity

Synthetic backfills are used for underrepresented categories, with clear labeling to preserve transparency.

⸻

Canonical Attack Taxonomy

ThreatAtlas uses the following internal categories:
	•	prompt_injection
	•	jailbreak
	•	instruction_override
	•	sensitive_data_request
	•	policy_evasion
	•	tool_misuse
	•	benign_control

These categories are designed for practical adversarial testing, not strict alignment with any single dataset taxonomy.

⸻

Category Target Counts

{
  "prompt_injection": 12000,
  "jailbreak": 12000,
  "instruction_override": 8000,
  "sensitive_data_request": 8000,
  "policy_evasion": 5000,
  "tool_misuse": 5000,
  "benign_control": 10000
}


⸻

Category Definitions

prompt_injection
Attempts to override system instructions or manipulate model behavior.

jailbreak
Attempts to bypass safety constraints or refusal mechanisms.

instruction_override
Explicit attempts to replace higher-priority instructions (e.g. system prompts).

sensitive_data_request
Attempts to extract secrets, hidden prompts, credentials, or protected data.

policy_evasion
Uses encoding, obfuscation, or transformation to bypass safeguards.

tool_misuse
Attempts to trigger unsafe tool execution or access restricted systems.

benign_control
Non-adversarial prompts used to measure baseline behavior and over-refusal.

⸻

Source Datasets

The corpus is built from multiple Hugging Face datasets:
	•	neuralchemy/Prompt-injection-dataset
	•	wambosec/prompt-injections
	•	gabrielchua/system-prompt-leakage
	•	Antijection/prompt-injection-dataset-v1

Optional sources:
	•	allenai/wildjailbreak
	•	Mindgard/evaded-prompt-injection-and-jailbreak-samples

Each source is mapped into the internal taxonomy using source-specific heuristics.

⸻

Normalization Strategy

Each row is transformed into a unified schema via mapper functions.

Normalization includes:
	•	text cleaning
	•	category mapping
	•	benign/malicious classification
	•	tag normalization
	•	metadata preservation
	•	expected behavior assignment
	•	identity + permission modeling

⸻

Security-Aware Schema

Each normalized row follows this structure:

{
  "id": "...",
  "prompt": "...",

  "category": "...",
  "expected_behavior": "...",

  "actor_role": "user | admin | system",
  "target_system": "llm | rag | agent",
  "sensitivity": "low | internal | confidential",

  "required_permission": "...",
  "permission_context": {
    "is_authorized": true,
    "allowed_tools": ["..."]
  },

  "tags": [...],

  "source_dataset": "...",
  "source_split": "...",
  "original_category": "...",

  "is_benign": false,
  "metadata": {...}
}


⸻

Identity & Permission Modeling

ThreatAtlas introduces a lightweight IAM simulation layer:

Roles

Define what actions an actor is allowed to take.

Example:

roles:
  user:
    allowed_tools: ["search"]
  admin:
    allowed_tools: ["search", "crm_read"]

Permissions

Define the sensitivity of protected operations.

permissions:
  crm_read:
    sensitivity: "confidential"

Purpose

This enables evaluation of:
	•	unauthorized access attempts
	•	privilege escalation
	•	system impersonation
	•	agent/tool abuse

⸻

Evaluation Implications

With this schema, each row supports:

1. Safety Evaluation
	•	Did the model refuse when it should?
	•	Did it leak sensitive information?

2. Authorization Evaluation
	•	Should this actor be allowed to perform this action?
	•	Did the system enforce permission boundaries?

3. System-Level Testing
	•	Is the attack targeting LLM, RAG, or agent layers?
	•	Where do failures occur?

⸻

Validation

Validation ensures:
	•	required fields (prompt, category) exist
	•	categories match taxonomy
	•	identity and permission fields are populated
	•	synthetic rows are clearly labeled

⸻

Key Insight

ThreatAtlas is not just a dataset.

It is a security evaluation substrate that enables:
	•	model safety testing
	•	authorization testing
	•	system-level failure analysis

in a single, unified corpus.
