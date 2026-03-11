from pathlib import Path


def test_final_artifacts_exist():
    base = Path("data/attacks/final")
    required = [
        "attack_corpus.jsonl",
        "benign_control.jsonl",
        "instruction_override.jsonl",
        "jailbreak.jsonl",
        "policy_evasion.jsonl",
        "prompt_injection.jsonl",
        "sensitive_data_request.jsonl",
        "tool_misuse.jsonl",
        "manifest.json",
    ]
    for name in required:
        assert (base / name).exists()
