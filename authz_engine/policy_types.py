"""Shared types used by policy functions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class Resource:
    """Target resource for an authorization request."""

    kind: str
    id: str
    attrs: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "attrs", dict(self.attrs))


@dataclass(frozen=True, slots=True)
class Decision:
    """Result returned by an individual policy function."""

    allowed: bool
    reason: str
    rule_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def is_not_applicable(self) -> bool:
        return self.allowed and self.reason.strip().lower() == "not applicable"

    @classmethod
    def not_applicable(
        cls,
        reason: str = "not applicable",
        rule_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> "Decision":
        return cls(True, reason, rule_id=rule_id, metadata=metadata or {})
