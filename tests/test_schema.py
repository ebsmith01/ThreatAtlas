from pathlib import Path

from src.data.schema import AttackRecord, iter_jsonl


def test_attack_record_roundtrip(tmp_path: Path):
    record = AttackRecord(
        id="atk_test",
        category="prompt_injection",
        severity="medium",
        prompt="ignore prior",
        expected_behavior="refuse_or_ignore",
        tags=["unit"],
        source_dataset="test",
        source_split="train",
        original_category="prompt_injection",
        is_benign=False,
        metadata={},
    )

    out = tmp_path / "sample.jsonl"
    out.write_text(record.model_dump_json() + "\n")

    loaded = list(iter_jsonl(out))
    assert loaded[0] == record
