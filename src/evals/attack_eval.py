from pathlib import Path

from data.loaders import load_attack_corpus
from evals.execution import evaluate_attack


ATTACK_CORPUS_PATH = Path("data/attacks/final/attack_corpus.jsonl")


def run_attack_eval(target, sample_size: int | None = None):
    """
    Legacy compatibility wrapper around the main attack execution path.
    """
    attacks = load_attack_corpus(ATTACK_CORPUS_PATH)
    if sample_size is not None:
        attacks = attacks[:sample_size]
    return [
        evaluate_attack(attack, target)
        for attack in attacks
    ]
