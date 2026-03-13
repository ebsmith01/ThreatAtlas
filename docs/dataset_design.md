# Dataset Design

## Overview

ThreatAtlas uses a corpus-first evaluation design for testing LLM, RAG, and agent-based systems against adversarial prompt behaviors.

The dataset layer is designed to support:

- structured attack-category coverage
- normalization across heterogeneous public sources
- deduplication of near-identical prompts
- balanced final evaluation sets
- explicit tracking of synthetic backfills for sparse categories

The goal is not just to collect prompts, but to build a **repeatable, normalized evaluation corpus** that can be used for security testing and regression analysis.

---

## Design Goals

The attack corpus is designed around the following goals:

### 1. Shared schema across sources
Public datasets use different column names, label systems, and attack taxonomies. ThreatAtlas normalizes all source rows into one common schema so downstream evaluation logic does not need source-specific handling.

### 2. Category-based evaluation
Rows are mapped into a fixed internal taxonomy so evaluations can be grouped by security-relevant behavior rather than raw dataset origin.

### 3. Global prompt deduplication
Since many public datasets contain repeated or lightly modified prompts, ThreatAtlas applies global deduplication to reduce inflated category counts and improve corpus quality.

### 4. Controlled balancing
The final corpus is downsampled or backfilled toward target counts per category so the evaluation set is not dominated by whichever source happens to be largest.

### 5. Explicit handling of sparsity
Some attack categories are underrepresented in public datasets. ThreatAtlas handles this by using synthetic backfills when real data is insufficient, while preserving source metadata so synthetic coverage remains visible.

---

## Canonical Attack Taxonomy

ThreatAtlas currently uses the following internal categories:

- `prompt_injection`
- `jailbreak`
- `instruction_override`
- `sensitive_data_request`
- `policy_evasion`
- `tool_misuse`
- `benign_control`

These categories are intended to support practical adversarial evaluation of LLM systems rather than perfectly mirror any single public dataset taxonomy.



### Category Target Counts

- "prompt_injection": 12000,
- "jailbreak": 12000,
- "instruction_override": 8000,
- "sensitive_data_request": 8000,
- "policy_evasion": 5000,
- "tool_misuse": 5000,
- "benign_control": 10000,


### Category definitions

#### `prompt_injection`
Prompts that attempt to override system behavior, redirect the model, or manipulate instruction-following logic.

#### `jailbreak`
Prompts designed to bypass safety constraints or refusal behavior.

#### `instruction_override`
Prompts that explicitly attempt to replace higher-priority instructions with new ones.

#### `sensitive_data_request`
Prompts intended to elicit hidden instructions, secrets, system prompts, credentials, or other protected information.

#### `policy_evasion`
Prompts that use encoding, obfuscation, transformation, or disguise to bypass policy checks.

#### `tool_misuse`
Prompts that attempt to induce unsafe tool use, shell execution, secret extraction, or unauthorized actions in tool-enabled systems.

#### `benign_control`
Non-adversarial prompts included to measure utility, over-refusal, and baseline behavior.

---

## Source Datasets

ThreatAtlas builds the corpus from multiple Hugging Face datasets.

Current sources include:

- `neuralchemy/Prompt-injection-dataset`
- `wambosec/prompt-injections`
- `gabrielchua/system-prompt-leakage`
- `Antijection/prompt-injection-dataset-v1`

Optional sources supported in the build pipeline include:

- `allenai/wildjailbreak`
- `Mindgard/evaded-prompt-injection-and-jailbreak-samples`

Each source is mapped into the internal taxonomy using source-specific heuristics.

---

## Normalization Strategy

Each source row is converted into a shared schema through a dedicated mapper function.

Normalization includes:

- text cleaning
- category mapping
- benign/malicious classification
- severity assignment
- tag cleanup
- metadata preservation
- expected behavior assignment

### Output schema

Each normalized row follows this structure:

```json
{
  "id": "...",
  "category": "...",
  "severity": "...",
  "prompt": "...",
  "expected_behavior": "...",
  "tags": [...],
  "source_dataset": "...",
  "source_split": "...",
  "original_category": "...",
  "is_benign": false,
  "metadata": {...}
}s