from authz_engine.models import Actor
from authz_engine.policy_engine import Policy, PolicyEngine
from authz_engine.policy_types import Decision, Resource


def test_explicit_allow_is_required() -> None:
    engine = PolicyEngine(
        [
            Policy("ticket_read", lambda actor, action, resource: Decision.not_applicable()),
        ]
    )

    result = engine.decide(
        Actor(user_id="u1", roles=frozenset({"reader"}), org="acme"),
        "read",
        Resource(kind="ticket", id="t1", attrs={"org": "acme"}),
    )

    assert not result.allowed
    assert result.reason == "no policy allowed request"


def test_first_deny_wins() -> None:
    def allow_reader(actor: Actor, action: str, resource: Resource) -> Decision:
        if action != "read":
            return Decision.not_applicable()
        if "reader" in actor.roles:
            return Decision(True, "reader can read")
        return Decision.not_applicable()

    def deny_cross_org(actor: Actor, action: str, resource: Resource) -> Decision:
        if action != "read":
            return Decision.not_applicable()
        if actor.org != resource.attrs.get("org"):
            return Decision(False, "org mismatch")
        return Decision(True, "org matches")

    engine = PolicyEngine([Policy("allow_reader", allow_reader), Policy("deny_cross_org", deny_cross_org)])
    result = engine.decide(
        Actor(user_id="u1", roles=frozenset({"reader"}), org="acme"),
        "read",
        Resource(kind="ticket", id="t1", attrs={"org": "other"}),
    )

    assert not result.allowed
    assert result.matched_policy == "deny_cross_org"
    assert [step.policy for step in result.trace] == ["allow_reader", "deny_cross_org"]


def test_matching_allow_succeeds_when_no_deny_applies() -> None:
    def ticket_read(actor: Actor, action: str, resource: Resource) -> Decision:
        if action != "read" or resource.kind != "ticket":
            return Decision.not_applicable()
        if actor.roles.isdisjoint({"reader", "admin"}):
            return Decision(False, "role not permitted")
        if "admin" not in actor.roles and actor.org != resource.attrs.get("org"):
            return Decision(False, "org mismatch")
        return Decision(True, "ticket read permitted")

    engine = PolicyEngine([Policy("ticket_read", ticket_read)])
    result = engine.decide(
        Actor(user_id="u1", roles=frozenset({"reader"}), org="acme"),
        "read",
        Resource(kind="ticket", id="t1", attrs={"org": "acme"}),
    )

    assert result.allowed
    assert result.matched_policy == "ticket_read"
    assert result.reason == "ticket read permitted"


def test_policy_return_type_is_enforced() -> None:
    engine = PolicyEngine([Policy("bad", lambda actor, action, resource: True)])

    try:
        engine.decide(Actor(user_id="u1"), "read", Resource(kind="ticket", id="t1"))
    except TypeError as exc:
        assert "expected Decision" in str(exc)
    else:
        raise AssertionError("TypeError was not raised")
