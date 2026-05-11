from data.loaders import load_attack_corpus


def test_attack_schema():
    attacks = load_attack_corpus("data/attacks/final/attack_corpus.jsonl")

    assert len(attacks) > 0

    row = attacks[0]

    required = [
        "prompt",
        "category",
        "actor_role",
        "target_system",
        "sensitivity",
    ]

    for field in required:
        assert field in row