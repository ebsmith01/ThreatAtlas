"""Mock target useful for tests and offline development."""

from .base import Target


class MockTarget(Target):
    def invoke(self, prompt: str) -> str:
        return f"[mock] echo: {prompt}"
