## Activation Probes & Constitutional Security Classifiers

### Core Idea

Instead of evaluating:

only the generated text

we evaluate:

the model's internal representations

during generation.

These internal representations are called:

hidden states

or:

activations

They contain latent semantic information about:

- intent
- compliance
- harmfulness
- jailbreak success
- deception
- unsafe reasoning
- retrieval manipulation

often BEFORE the model fully generates unsafe text.

### What Is an Activation Probe?

A probe is usually:

a small linear classifier

trained on hidden states.

Simplified pipeline:

```text
hidden states
-> linear classifier
-> harmful / harmless score
```

Most commonly:

- logistic regression
- linear layer
- shallow MLP

Very cheap computationally.

### Why This Matters for AI Security

Surface text detection is limited.

Example:

`"I cannot reveal secrets."`

looks safe.

But internally the model may already be:

- reasoning about credentials
- complying with unsafe instructions
- preparing unsafe continuation
- following a jailbreak trajectory

Activation probes can detect:

latent unsafe behavior

before it fully manifests.

### What ThreatAtlas Could Eventually Detect

#### 1. Prompt Injection Trajectories

Detect whether the model internally shifted from:

policy-following

to:

instruction override mode

even if the output still appears safe.

#### 2. Unsafe Compliance

Detect:

the model intends to comply

before explicit harmful text appears.

Example:

- hidden reasoning about passwords
- retrieval targeting sensitive documents
- preparing tool abuse actions

#### 3. Retrieval Exploit Semantics

Probe activations during:

RAG retrieval processing

to detect:

- retrieval poisoning
- instruction override via retrieved docs
- contextual hijacking
- semantic exfiltration intent

#### 4. Agentic Exploit Intent

Probe internal states during:

tool planning

to detect:

- privilege escalation
- destructive actions
- unsafe tool sequencing
- unauthorized access reasoning

before tools execute.

### Probe Architecture Inside ThreatAtlas

Future architecture:

```text
Prompt
-> LLM Forward Pass
-> Hidden States
-> Probe Classifiers
-> Semantic Risk Scores
-> Hybrid Security Reasoner
-> Final Exploit Intelligence
```

### Why Linear Probes Work

LLM hidden states already encode:

- semantics
- intent
- harmfulness
- topic
- reasoning direction

The probe simply:

extracts those signals

without retraining the whole model.

That's why probes are:

- fast
- lightweight
- scalable

### What You'd Need Technically

You need:

hidden-state access

which usually requires:

- local model hosting
- HuggingFace transformers
- open-weight models

Examples:

- Llama
- Mistral
- Gemma
- Qwen

NOT typical hosted chat APIs.

### Simplified Technical Example

```python
hidden_states = model(
    input_ids,
    output_hidden_states=True,
)
last_layer = hidden_states[-1]
probe_score = probe_classifier.predict(
    last_layer.mean(dim=1)
)
```

Where:

`probe_classifier`

might be:

- logistic regression
- linear layer
- sklearn classifier

### Ensemble Security Architecture

The strongest systems are:

multi-layer ensembles

Example ThreatAtlas future pipeline:

policy engine
+
semantic evaluator
+
activation probes
+
retrieval evaluator
+
telemetry analyzer
+
hybrid exploit reasoner

This creates:

constitutional-style AI security

instead of:

single-layer guardrails

### Why This Is Important Long-Term

Most AI security today relies on:

- regexes
- moderation endpoints
- jailbreak signatures
- static classifiers

Activation probing moves toward:

representation-level exploit intelligence

which is significantly more robust against:

- paraphrasing
- obfuscation
- indirect attacks
- latent harmful reasoning
- deceptive alignment

### ThreatAtlas Long-Term Vision

Eventually ThreatAtlas could evolve into:

real-time semantic exploit observability

where it detects:

- unsafe reasoning trajectories
- jailbreak activation patterns
- exploit chains
- latent malicious intent
- tool abuse planning
- retrieval compromise

directly from:

model cognition signals

rather than only surface outputs.

https://www.anthropic.com/research/sleeper-agents-training-deceptive-llms-that-persist-through-safety-training?utm_source=chatgpt.com

Anthropic Alignment Research

Anthropic Research Index￼

Especially:

* constitutional AI
* harmlessness evaluation
* jailbreak analysis
* deceptive alignment
