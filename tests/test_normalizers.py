import pytest

import scripts.normalize_neuralchemy as neuralchemy


@pytest.mark.skip(reason="Normalization logic not implemented yet.")
def test_normalizer_placeholder():
    assert hasattr(neuralchemy, "main")
