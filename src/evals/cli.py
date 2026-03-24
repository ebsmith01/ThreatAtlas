import argparse
from pathlib import Path

from data.loaders import load_attack_corpus
from evals.attack_eval import run_attack_eval
from evals.reporting import build_report, print_report_summary, save_report
from targets.mock_target import MockTarget


def main():
    parser = argparse.ArgumentParser(description="Run local ThreatAtlas evaluation")
    parser.add_argument("--sample", type=int, default=50, help="Number of rows to evaluate")
    args = parser.parse_args()

    corpus_path = Path("data/attacks/final/attack_corpus.jsonl")
    output_path = Path("outputs/local_eval_report.json")

    # Determine available rows (without modifying run_attack_eval's internal loading)
    total_rows = len(load_attack_corpus(corpus_path))
    sample_size = min(args.sample, total_rows)

    target = MockTarget()
    results = run_attack_eval(target=target, sample_size=sample_size)

    report = build_report(results)
    save_report(report, output_path)
    print_report_summary(report)

    print(f"\nEvaluated {len(results)} rows (requested {args.sample}, available {total_rows})")
    print(f"Saved report to {output_path}")


if __name__ == "__main__":
    main()
