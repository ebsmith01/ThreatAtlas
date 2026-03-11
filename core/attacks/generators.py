"""Generators produce attack payloads programmatically."""


def generate(prompt_template: str) -> str:
    """Return a generated payload given a template."""
    return prompt_template.format()
