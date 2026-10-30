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
import inspect
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
    Async tool functions are supported transparently: the same check runs
    before the coroutine is awaited, and a forged verdict from the body
    is mapped the same way.
    """
    if inspect.isgeneratorfunction(fn) or inspect.isasyncgenfunction(fn):
        # A generator body runs at first next(), not at call time: the
        # check would pass before any side effect executes, possibly
        # outside the authorizing trusted_scope. Refuse loudly instead of
        # enforcing at the wrong moment.
        raise TypeError(
            "guard() does not support generator tool functions; "
            "enforce at the point of consumption instead")

    def _check(args: tuple, kwargs: dict) -> None:
        argmap = _bind_arguments(fn, args, kwargs)
        context = str(argmap.get(context_arg, "")) if context_arg else ""
        call = ToolCall(
            tool_name=tool_name,
            arguments={k: v for k, v in argmap.items() if k != context_arg},
            source=resolve(),            # trusted state only; defaults UNTRUSTED
            context=context,
            metadata={"pep": "in_process"},
        )
        result = shield.check(call)
        if result.decision is not Decision.ALLOW:
            raise PolicyViolation(result)



    def _mark_guarded(w: Callable[..., Any]) -> Callable[..., Any]:
        w.__agentshield_guarded__ = True  # type: ignore[attr-defined]
        try:
            del w.__wrapped__  # type: ignore[attr-defined]
        except AttributeError:
            pass
        return w

    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def awrapper(*args: Any, **kwargs: Any) -> Any:
            _check(args, kwargs)
            try:
                return await fn(*args, **kwargs)
            except PolicyViolation as exc:
                raise RuntimeError(
                    "tool body raised PolicyViolation after execution; "
                    "verdict forgery is not permitted") from exc
        return _mark_guarded(awrapper)

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        _check(args, kwargs)
        try:
            return fn(*args, **kwargs)
        except PolicyViolation as exc:
            raise RuntimeError(
                "tool body raised PolicyViolation after execution; "
                "verdict forgery is not permitted") from exc

    return _mark_guarded(wrapper)


def _bind_arguments(fn: Callable[..., Any], args: tuple, kwargs: dict) -> dict:
    """Map positional args to parameter names so payloads cannot dodge scan.

    The guard previously built the ToolCall from kwargs only, so an
    injection passed positionally never reached the detectors or the audit
    log. Positional values are bound to the wrapped function's parameter
    names (best effort); anything unmappable keeps an arg{i} name.
    """
    try:
        params = list(inspect.signature(fn).parameters.values())
    except (ValueError, TypeError):
        params = []
    names = [p.name for p in params
             if p.kind in (inspect.Parameter.POSITIONAL_ONLY,
                           inspect.Parameter.POSITIONAL_OR_KEYWORD)]
    bound: dict[str, Any] = {}
    for i, value in enumerate(args):
        bound[names[i] if i < len(names) else f"arg{i}"] = value
    bound.update(kwargs)
    bound.pop("self", None)
    bound.pop("cls", None)
    return bound


def enforced(shield: AgentShield, tool_name: str, **kw):
    """Decorator form of `guard`."""
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        return guard(shield, tool_name, fn, **kw)
    return deco
