# Source Inventory

Current integrated public sources (Hugging Face):
- `neuralchemy/Prompt-injection-dataset` — mixed PI examples.
- `Antijection/prompt-injection-dataset-v1` — curated injections with labels.
- `wambosec/prompt-injections` — jailbreak-heavy corpus.
- `gabrielchua/system-prompt-leakage` — leakage-focused prompts.

Optional/queued:
- `allenai/wildjailbreak` — diverse jailbreaks; useful for robustness sweeps.
- `Mindgard/evaded-prompt-injection-and-jailbreak-samples` — obfuscated payloads.
- Private/internal corpora (placeholders).

Notes
- Licensing checked per dataset before inclusion; retain `source_dataset` metadata in normalized rows.
- Deduplication and category mapping occur in the build step to avoid source-specific handling downstream.
