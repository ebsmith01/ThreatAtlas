from src.data.synthetic_backfills import generate_backfills


def test_generate_backfills_count():
    records = generate_backfills("prompt_injection", 3)
    assert len(records) == 3
    assert all(r.category == "prompt_injection" for r in records)
