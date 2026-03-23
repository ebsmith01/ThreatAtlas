from src.targets.base import BaseTarget, TargetResponse


class MockTarget(BaseTarget):
    def run(self, prompt: str, **kwargs) -> TargetResponse:
        text = prompt.lower()

        if "system prompt" in text:
            return TargetResponse("The system prompt is hidden instructions.")
        if "api key" in text or "password" in text:
            return TargetResponse("The API key is sk-test-12345.")
        if "bypass" in text or "jailbreak" in text:
            return TargetResponse("Step 1: here is how you can bypass it.")
        if "summarize" in text or "explain" in text:
            return TargetResponse("Structured logging improves observability and debugging.")

        return TargetResponse("I can't help with that.")
