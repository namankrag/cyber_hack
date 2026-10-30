"""Policy Enforcement Point (PEP) — make the check unavoidable.

The HTTP `/v1/check` endpoint is a Policy *Decision* Point (PDP): it returns a
verdict but cannot stop a caller who ignores it. That's advisory by nature.

This module provides the *enforcement* point: a wrapper that puts the policy
check directly in the tool's execution path, so the tool literally cannot run
unless AgentShield allowed it. There is no "please comply" — a blocked call
raises before the tool body executes.

Use it to wrap real tool callables:

    guarded = guard(shield, "send_email", send_email)
    guarded(to=..., body=...)        # raises PolicyViolation unless ALLOW

or as a decorator:

    @enforced(shield, "send_email")
    def send_email(to: str, body: str = "") -> str: ...

Provenance is resolved from trusted state (contextvars / token), never from
the call arguments — see provenance.py.
"""
from __future__ import annotations

import functools
from typing import Any, Callable

from .engine_factory import AgentShield
from .models import Decision, EnforcementResult, ToolCall
from .provenance import resolve


class PolicyViolation(Exception):
    """Raised when a tool call is not ALLOWED. Carries the full result."""

    def __init__(self, result: EnforcementResult) -> None:
        self.result = result
        super().__init__(result.headline())


def guard(
    shield: AgentShield,
    tool_name: str,
    fn: Callable[..., Any],
    *,
    context_arg: str | None = "context",
) -> Callable[..., Any]:
    """Wrap `fn` so every call is enforced before the body runs.

    `context_arg` names a kwarg (if present) whose value is the untrusted
    content the detectors should scan; it is still forwarded to `fn`.
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        context = str(kwargs.get(context_arg, "")) if context_arg else ""
        call = ToolCall(
            tool_name=tool_name,
            arguments={k: v for k, v in kwargs.items() if k != context_arg},
            source=resolve(),            # trusted state only; defaults UNTRUSTED
            context=context,
            metadata={"pep": "in_process"},
        )
        result = shield.check(call)
        if result.decision is not Decision.ALLOW:
            raise PolicyViolation(result)
        return fn(*args, **kwargs)

    wrapper.__agentshield_guarded__ = True  # type: ignore[attr-defined]
    return wrapper


def enforced(shield: AgentShield, tool_name: str, **kw):
    """Decorator form of `guard`."""
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        return guard(shield, tool_name, fn, **kw)
    return deco
