"""Target that proxies an LLM agent."""

from .base import Target


class AgentTarget(Target):
    def invoke(self, prompt: str) -> str:
        # TODO: wire to agent runtime
        return f"[agent] {prompt}"
