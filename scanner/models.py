"""Small data objects passed between the parser and rule engine."""

from dataclasses import dataclass
from typing import Any, Literal


@dataclass(frozen=True)
class Resource:
    logical_id: str
    resource_type: str
    properties: dict[str, Any]
    condition: str | None = None


@dataclass(frozen=True)
class Template:
    source: str
    resources: tuple[Resource, ...]


Status = Literal["PASS", "FAIL", "REVIEW"]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    status: Status
    severity: str
    resource_id: str
    path: str
    message: str
    recommendation: str
