# authz-engine

Deterministic authorization engine with RBAC + ABAC and auditable decisions for systems that cannot afford ambiguity.

Why this exists

Authorization is not authentication.

Most systems implement authorization implicitly:

scattered if statements

role checks buried in handlers

inconsistent enforcement

no audit trail

no way to explain why a decision was made

This works until it doesn’t — and when it fails, it fails as a security incident.

authz-engine exists to make authorization:

explicit

deterministic

testable

auditable

If you need to explain access decisions to security teams, auditors, or incident responders, this is the missing layer.

What this is

A pure Python policy decision engine

Policies defined in code, not YAML

Deterministic evaluation (first-deny-wins)

Supports RBAC + ABAC

Framework-agnostic core

Designed for security-critical systems

This is a Policy Decision Point (PDP) you embed into your application.

What this is NOT

❌ Authentication (OAuth, SSO, IAM)

❌ User management

❌ Token issuance or validation

❌ A YAML / JSON policy interpreter

❌ A GUI-driven policy editor

If you want runtime-editable policies by non-engineers, this is the wrong tool — intentionally.

Core concepts

Authorization decisions are based on four concepts:

Actor – who is requesting access

Action – what they want to do

Resource – what they want to do it to

Decision – allow or deny, with a reason

Everything flows from this model.

Installation
pip install authz-engine


Python 3.10+ required.

Minimal example
from authz_engine.models import Actor
from authz_engine.policy_types import Resource, Decision
from authz_engine.policy_engine import Policy, PolicyEngine

def ticket_read(actor: Actor, action: str, resource: Resource) -> Decision:
    if action != "read" or resource.kind != "ticket":
        return Decision(True, "not applicable")

    if actor.roles.isdisjoint({"reader", "admin"}):
        return Decision(False, "role not permitted")

    if "admin" not in actor.roles and actor.org != resource.attrs.get("org"):
        return Decision(False, "org mismatch")

    return Decision(True, "ticket read permitted")

engine = PolicyEngine([
    Policy("ticket_read", ticket_read)
])

actor = Actor(
    user_id="u1",
    roles=frozenset({"reader"}),
    org="acme"
)

resource = Resource(
    kind="ticket",
    id="t1",
    attrs={"org": "acme"}
)

decision = engine.decide(actor, "read", resource)
print(decision)


This example demonstrates:

RBAC (role check)

ABAC (org attribute)

deterministic decisions

explicit reasoning

Policy conventions (important)
“Not applicable” rule

Policies must return allow when they do not apply:

return Decision(True, "not applicable")


Policies must deny explicitly when enforcing a rule.

This prevents accidental global denies and makes policy intent clear.

Decision model

Policies are evaluated in order

First deny wins

Allows are collected but not final

At least one explicit allow is required

This model is simple, predictable, and safe by default.

RBAC + ABAC

RBAC: roles such as admin, operator, approver

ABAC: attributes such as org, region, clearance, scope

The engine does not enforce semantics — you define the meaning in code.

This avoids leaky abstractions and hidden magic.

Audit logging (recommended)

The engine returns structured decisions.
You are expected to log them.

Recommended practice:

Log all denies

Sample allows

Never log raw tokens or secrets

Include correlation IDs

Example fields to log:

actor ID

roles

action

resource

decision

reason

This makes authorization decisions defensible during audits and incidents.

When NOT to use this

Do not use authz-engine if:

You need a full IAM or OAuth provider

You want policies editable by non-engineers at runtime

You don’t need auditability

Your authorization logic is trivial and unlikely to grow

This tool is optimized for clarity and correctness, not convenience.

Roadmap

v0.1 – Core policy engine (current)

v0.2 – Reference policy packs (SaaS multi-tenant, approval workflows)

v0.3 – Audit helper module (structured, sampled)

v0.4 – FastAPI integration reference repository

The core API is intentionally small and stable.

Security

If you discover a security issue, do not open a public issue.

Please report privately via GitHub Security Advisories or contact the maintainers directly.

License

Apache License 2.0

Final note

Authorization bugs are not feature bugs — they are trust failures.

This project exists to make authorization boring, explicit, and explainable.
