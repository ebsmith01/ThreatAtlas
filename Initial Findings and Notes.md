Initial Findings and Notes

On an initial 30-case evaluation against GPT-4.1, ThreatAtlas achieved a 93.33% overall pass rate, with prompt injection emerging as the clearest weak spot. The run also surfaced evaluation-rule gaps, especially around encoded instruction-following and system-prompt leakage classification.


generate-model-report --target safe --sample 25

generate-model-report \
  --target llm \
  --provider openai \
  --model gpt-4.1 \
  --sample 25

  compare-models \
  --run-a reports/mock_vulnerable_report.json \
  --run-b reports/mock_safe_report.json