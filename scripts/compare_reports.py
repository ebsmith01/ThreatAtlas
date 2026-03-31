from __future__ import annotations

import json
from pathlib import Path

from evals.regression import compare_reports


BASELINE_PATH = Path("reports/mock_vulnerable_report.json")
CANDIDATE_PATH = Path("reports/mock_safe_report.json")
OUTPUT_PATH = Path("reports/regression_report.json")


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


if __name__ == "__main__":
    baseline = load_json(BASELINE_PATH)
    candidate = load_json(CANDIDATE_PATH)

    regression = compare_reports(baseline, candidate)

    with OUTPUT_PATH.open("w", encoding="utf-8") as f:
        json.dump(regression, f, indent=2)

    print(json.dumps(regression, indent=2))
    print(f"\nSaved regression report to: {OUTPUT_PATH}")