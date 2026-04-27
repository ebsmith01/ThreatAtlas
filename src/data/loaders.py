import json
from pathlib import Path


def load_attack_corpus(path):
    path = Path(path)
    attacks = []

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            record = json.loads(line)

            # --- Required fields ---
            if "prompt" not in record:
                raise ValueError("Each row must have a 'prompt'")
            if "category" not in record:
                raise ValueError("Each row must have a 'category'")

            # --- New schema fields (optional but expected) ---
            attack = {
                "id": record.get("id"),
                "prompt": record["prompt"],
                "category": record["category"],
                "expected_behavior": record.get("expected_behavior"),

                # --- Identity / system modeling ---
                "actor_role": record.get("actor_role"),
                "target_system": record.get("target_system"),
                "sensitivity": record.get("sensitivity"),

                # --- Authorization modeling ---
                "required_permission": record.get("required_permission"),
                "permission_context": record.get("permission_context", {}),

                # --- Metadata ---
                "tags": record.get("tags", []),
                "source_dataset": record.get("source_dataset"),
                "source_split": record.get("source_split"),
                "original_category": record.get("original_category"),
                "is_benign": record.get("is_benign", False),
                "metadata": record.get("metadata", {}),
            }

            attacks.append(attack)

    return attacks