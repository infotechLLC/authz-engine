"""Deterministic policy evaluation engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from .models import Actor
from .policy_types import Decision, Resource

PolicyHandler = Callable[[Actor, str, Resource], Decision]


@dataclass(frozen=True, slots=True)
class Policy:
    """Named wrapper around a policy function."""

    name: str
    handler: PolicyHandler

    def evaluate(self, actor: Actor, action: str, resource: Resource) -> Decision:
        decision = self.handler(actor, action, resource)
        if not isinstance(decision, Decision):
            raise TypeError(f"Policy {self.name!r} returned {type(decision)!r}, expected Decision")
        if decision.rule_id is not None:
            return decision
        return Decision(
            allowed=decision.allowed,
            reason=decision.reason,
            rule_id=self.name,
            metadata=decision.metadata,
        )


@dataclass(frozen=True, slots=True)
class TraceStep:
    """Single step in an engine evaluation trace."""

    policy: str
    allowed: bool
    applicable: bool
    reason: str


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Final policy engine decision with explanation trace."""

    allowed: bool
    reason: str
    matched_policy: str | None
    trace: tuple[TraceStep, ...]

    def __bool__(self) -> bool:
        return self.allowed


class PolicyEngine:
    """Evaluate policies with first-deny-wins semantics."""

    def __init__(self, policies: Iterable[Policy], default_deny_reason: str = "no policy allowed request"):
        self._policies = tuple(policies)
        self._default_deny_reason = default_deny_reason

    @property
    def policies(self) -> tuple[Policy, ...]:
        return self._policies

    def decide(self, actor: Actor, action: str, resource: Resource) -> EvaluationResult:
        trace: list[TraceStep] = []
        first_allow: Decision | None = None

        for policy in self._policies:
            decision = policy.evaluate(actor, action, resource)
            applicable = not decision.is_not_applicable
            trace.append(
                TraceStep(
                    policy=policy.name,
                    allowed=decision.allowed,
                    applicable=applicable,
                    reason=decision.reason,
                )
            )

            if not applicable:
                continue

            if not decision.allowed:
                return EvaluationResult(
                    allowed=False,
                    reason=decision.reason,
                    matched_policy=decision.rule_id or policy.name,
                    trace=tuple(trace),
                )

            if first_allow is None:
                first_allow = decision

        if first_allow is not None:
            return EvaluationResult(
                allowed=True,
                reason=first_allow.reason,
                matched_policy=first_allow.rule_id,
                trace=tuple(trace),
            )

        return EvaluationResult(
            allowed=False,
            reason=self._default_deny_reason,
            matched_policy=None,
            trace=tuple(trace),
        )
