"""Embedding-based retrieval backend."""


def embed(texts: list[str]) -> list[list[float]]:
    # TODO: call embedding service
    return [[0.0] * 3 for _ in texts]
