# Run Commands

Quick command reference to exercise ThreatAtlas end-to-end.

## Setup
pip install -e .

generate-model-report --target safe --sample 25
generate-model-report --target vulnerable --sample 25


  compare-models \
  --run-a reports/mock_vulnerable_report.json \
  --run-b reports/mock_safe_report.json

generate-model-report \
  --target llm \
  --provider openai \
  --model gpt-4.1 \
  --sample 25

  compare-models \
  --run-a reports/mock_vulnerable_report.json \
  --run-b reports/mock_safe_report.json

