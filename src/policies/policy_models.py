from dataclasses import dataclass
from typing import Any


@dataclass
class PolicyRule:
    rule_id: str
    description: str
    severity: str
    conditions: dict[str, Any]
    vulnerability: str | None = None
