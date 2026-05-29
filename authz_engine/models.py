"""Core actor model for authorization decisions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class Actor:
    """The calling principal for an authorization request."""

    user_id: str
    roles: frozenset[str] = field(default_factory=frozenset)
    org: str | None = None
    attrs: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "roles", frozenset(self.roles))
        object.__setattr__(self, "attrs", dict(self.attrs))
