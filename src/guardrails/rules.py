"""Simple rule stubs for request filtering."""

from __future__ import annotations


BLOCKLIST = ["whoami", "rm -rf", "password dump"]


def is_blocked(prompt: str) -> bool:
    text = prompt.lower()
    return any(token in text for token in BLOCKLIST)
