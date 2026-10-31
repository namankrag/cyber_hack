"""AgentShield as a real MCP gateway (protocol-layer enforcement).

This is the upscale that matters most for "secure the agent, not just the
prompt": instead of trusting the agent to call our HTTP endpoint, we sit
*inside the Model Context Protocol* as server middleware. Every single
`tools/call` the agent makes passes through AgentShield before the tool runs —
at the transport layer, below the model, where an injected instruction cannot
talk its way past the check.

It integrates the official MCP Python SDK (`modelcontextprotocol/python-sdk`,
imported as `mcp`). The SDK provides the server, the protocol, and the
middleware hook; AgentShield provides the decision brain (the same
PolicyEngine the HTTP gateway and the demo use — one enforcement core, three
front doors).

Provenance note: MCP does not itself carry "did the user ask for this, or did
a document?". Provenance must be supplied by the harness wrapping the agent —
it is established *outside* the model, which is the whole point. Callers tag a
tool call by adding an `_agentshield` object to its arguments, where any
source above `untrusted` must be backed by a valid HMAC token (see
provenance.py and mint_token):

    {"to": "...", "_agentshield": {"source": "user", "token": "<hmac>",
                                   "session_id": "<session>",
                                   "context": "<doc>",
                                   "trace_id": "<trace>",
                                   "parent_id": "<parent>"}}

The middleware strips that tag before the real tool sees the arguments. An
asserted source with no valid token resolves to UNTRUSTED (fail-closed), so a
tag placed by the agent or by injected content cannot elevate trust.

DROP-IN PROXY: point the gateway at any MCP server speaking stdio and it
fronts that upstream — tools are listed from the upstream at startup and every
upstream `tools/call` passes through the same EnforcementMiddleware (tag
strip, manifest verify, shield.check, audit). Configure with:

    AGENTSHIELD_UPSTREAM_CMD="python examples/upstream_demo_server.py"
    AGENTSHIELD_UPSTREAM_ARGS="--extra-flag"   # optional, appended

so adoption is "change one line in your MCP client config": point the client
at the gateway instead of the upstream directly. With no upstream configured
the gateway falls back to the built-in DEMO tools below (unchanged).

INDIRECT-INJECTION DEFENSE (MCP responses as untrusted data): an MCP tool
response is itself untrusted content that re-enters the agent context, so after
an ALLOWed call the middleware inspects the response (ingestion.py): hidden /
obfuscated instructions (CSS-hidden, HTML comments, zero-width, base64) are
STRIPPED before the client sees them, and the (untrusted) response is recorded
on the call's session. A later egress call in the same session is then caught
as exfiltration by the engine's deterministic guard. Supply a `session_id` in
the provenance tag to enable the cross-call activity link.
"""
from __future__ import annotations

import asyncio
import atexit
import concurrent.futures
import dataclasses
import os
import re
import shlex
import threading
from typing import Any

import mcp.types as mcp_types
from mcp.server.mcpserver import MCPServer

from ..activity import SessionContext
from ..engine_factory import AgentShield
from ..ingestion import Channel, Provenance
from ..models import Decision, EnforcementResult, PolicyReason, ToolCall
from ..policy.manifest import ToolManifest
from . import input_too_large
from ..provenance import resolve

_TAG = "_agentshield"

#: Max characters of a tool response inspected for hidden/injected content.
_RESPONSE_SCAN_CAP = 20000
#: Max concurrent sessions tracked for recent-activity (LRU-evicted).
_SESSION_CAP = 500


def _looks_html(text: str) -> bool:
    return "<" in text and ">" in text and bool(re.search(r"<[A-Za-z/!]", text))

#: Env var holding the upstream MCP server command (shlex-split). Unset or
#: blank means "no upstream": the gateway serves the built-in demo tools.
UPSTREAM_CMD_ENV = "AGENTSHIELD_UPSTREAM_CMD"
#: Env var holding extra upstream args, appended after the command (shlex-split).
UPSTREAM_ARGS_ENV = "AGENTSHIELD_UPSTREAM_ARGS"
#: Env var bounding one upstream round-trip (list or call), in seconds.
UPSTREAM_TIMEOUT_ENV = "AGENTSHIELD_UPSTREAM_TIMEOUT_S"
#: Startup + per-call budget when the env var is absent or malformed.
DEFAULT_UPSTREAM_TIMEOUT_S = 30.0


def _deny(shield: AgentShield, call: ToolCall, rule: str,
          detail: str) -> mcp_types.CallToolResult:
    """Audit a DENY and render it as an inspectable MCP error result."""
    shield.audit.record(EnforcementResult(
        call=call, decision=Decision.DENY,
        reasons=[PolicyReason(rule=rule, decision=Decision.DENY,
                              detail=detail)],
        fail_closed=True))
    return mcp_types.CallToolResult(
        content=[mcp_types.TextContent(
            type="text",
            text=(f"DENIED by AgentShield.\nTool: {call.tool_name}\n"
                  f"Decision: deny (fail-closed)\nReasons:\n  - [{rule}] {detail}"))],
        is_error=True,
    )


def upstream_command_from_env(env: Any = None) -> list[str] | None:
    """Upstream stdio command from AGENTSHIELD_UPSTREAM_CMD (+ _ARGS).

    Returns None when unconfigured (gateway uses demo tools). shlex-split so
    quoted program paths with spaces work on both POSIX and Windows.
    """
    src = os.environ if env is None else env
    raw = (src.get(UPSTREAM_CMD_ENV) or "").strip()
    if not raw:
        return None
    posix = os.name != "nt"
    cmd = [_strip_quotes(t) for t in shlex.split(raw, posix=posix)]
    extra = (src.get(UPSTREAM_ARGS_ENV) or "").strip()
    if extra:
        cmd.extend(_strip_quotes(t) for t in shlex.split(extra, posix=posix))
    return cmd or None


def _strip_quotes(token: str) -> str:
    """Drop one layer of surrounding quotes (Windows keeps them literally)."""
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    return token


def upstream_timeout_from_env(env: Any = None) -> float:
    """Per-upstream-round-trip budget in seconds (floor 0.5s)."""
    src = os.environ if env is None else env
    try:
        return max(0.5, float(src.get(UPSTREAM_TIMEOUT_ENV, "")
                              or DEFAULT_UPSTREAM_TIMEOUT_S))
    except ValueError:
        return DEFAULT_UPSTREAM_TIMEOUT_S


class UpstreamError(Exception):
    """The upstream MCP server is unreachable or misbehaving."""


class UpstreamProxy:
    """Persistent stdio connection to one arbitrary upstream MCP server.

    The subprocess is spawned once (from config) and driven from a dedicated
    background thread running its own asyncio loop, so sync callers (FastAPI
    workers, SDK tool threads) and async callers alike can use it: every
    method blocks with a timeout and raises UpstreamError on failure.

    Upstream failures are fail-closed by the caller (the middleware audits a
    DENY and the proxy tool raises), never silently downgraded to demo tools.
    """

    def __init__(self, cmd: list[str], timeout_s: float = 30.0,
                 cwd: str | None = None,
                 env: dict[str, str] | None = None) -> None:
        if not cmd:
            raise UpstreamError("empty upstream command")
        self._cmd = list(cmd)
        self._timeout_s = float(timeout_s)
        self._cwd = cwd
        self._extra_env = dict(env) if env else None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()
        self._open_error: BaseException | None = None
        self._session: Any = None
        self._stack: Any = None
        self._closed = False
        self._thread = threading.Thread(
            target=self._thread_main, name="agentshield-upstream",
            daemon=True)
        self._thread.start()
        if not self._ready.wait(self._timeout_s + 5.0):
            raise UpstreamError(
                f"upstream did not start in time: {' '.join(self._cmd)}")
        if self._open_error is not None:
            raise UpstreamError(
                f"cannot reach upstream {' '.join(self._cmd)}: "
                f"{self._open_error}") from self._open_error
        atexit.register(self.close)

    # -- background thread ---------------------------------------------
    def _thread_main(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            loop.run_until_complete(self._open())
        except BaseException as exc:  # fail fast: __init__ re-raises loudly
            self._open_error = exc
        finally:
            self._ready.set()
        if self._open_error is None:
            loop.run_forever()
            try:
                loop.run_until_complete(self._aclose())
            except BaseException:
                pass
        loop.close()

    async def _open(self) -> None:
        from contextlib import AsyncExitStack

        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        params = StdioServerParameters(
            command=self._cmd[0], args=self._cmd[1:],
            cwd=self._cwd, env=self._extra_env)
        stack = AsyncExitStack()
        self._stack = stack
        try:
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(
                ClientSession(read, write))
            await session.initialize()
        except BaseException:
            try:
                await stack.aclose()
            except BaseException:
                pass
            self._stack = None
            raise
        self._session = session

    async def _aclose(self) -> None:
        stack = self._stack
        self._session, self._stack = None, None
        try:
            if stack is not None:
                await stack.aclose()
        except BaseException:
            pass

    # -- sync façade (any thread) ---------------------------------------
    def _submit(self, coro_factory, what: str):
        """Run a session coroutine on the proxy loop with a timeout."""
        loop = self._loop
        if self._closed or loop is None or not loop.is_running():
            raise UpstreamError(f"upstream is closed ({what})")
        coro = coro_factory()
        try:
            fut = asyncio.run_coroutine_threadsafe(coro, loop)
        except RuntimeError as exc:
            coro.close()
            raise UpstreamError(
                f"upstream not accepting calls ({what}): {exc}") from exc
        try:
            return fut.result(timeout=self._timeout_s)
        except concurrent.futures.TimeoutError as exc:
            raise UpstreamError(
                f"upstream timed out after {self._timeout_s}s "
                f"({what})") from exc
        except UpstreamError:
            raise
        except Exception as exc:
            raise UpstreamError(
                f"upstream call failed ({what}): {exc}") from exc

    def list_tools(self) -> list[Any]:
        """Upstream tool list (SDK Tool objects). Raises UpstreamError."""
        res = self._submit(lambda: self._session.list_tools(), "tools/list")
        return list(res.tools or [])

    def call_tool(self, name: str, arguments: dict | None) -> str:
        """Forward one call; returns upstream text (error text passes through).

        Transport/protocol failures raise UpstreamError (fail-closed). An
        upstream tool's own domain error (is_error result) is NOT a gateway
        failure: its text passes through transparently.
        """
        res = self._submit(
            lambda: self._session.call_tool(str(name), dict(arguments or {})),
            f"tools/call {name}")
        texts = []
        for block in res.content or []:
            text = getattr(block, "text", None)
            texts.append(text if isinstance(text, str)
                         else f"<{type(block).__name__} non-text content omitted>")
        body = "\n".join(texts).strip()
        if getattr(res, "is_error", False):
            return f"Upstream tool {name!r} reported an error:\n{body}"
        return body

    def close(self) -> None:
        """Stop the loop and reap the upstream subprocess (idempotent)."""
        if self._closed:
            return
        self._closed = True
        loop, thread = self._loop, self._thread
        try:
            if loop is not None and loop.is_running():
                loop.call_soon_threadsafe(loop.stop)
        except RuntimeError:
            pass
        if (thread is not None and thread.is_alive()
                and threading.current_thread() is not thread):
            thread.join(timeout=10.0)


# -- proxy tool synthesis -----------------------------------------------
#: Marker embedded in the fail-closed error a proxy tool raises when the
#: upstream dies. The SDK converts tool exceptions to is_error *results*
#: inside call_next, so the middleware detects an upstream failure by this
#: marker in the result text (single source of truth, same module).
_UPSTREAM_FAILURE_MARKER = "[upstream_error]"


def _result_text(res: Any) -> str:
    """Best-effort text of a tool result (for failure classification).

    The middleware layer sees raw JSON-RPC dicts
    ({"content": [{"text": ...}], "isError": ...}); object forms are
    accepted too so unit callers are not coupled to the transport shape.
    """
    content = res.get("content") if isinstance(res, dict) else getattr(res, "content", None)
    parts = []
    for block in content or []:
        if isinstance(block, dict):
            text = block.get("text")
        else:
            text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
    return "\n".join(parts)


def _result_is_error(res: Any) -> bool:
    """True when a tool result (dict or object) carries is_error."""
    if isinstance(res, dict):
        return bool(res.get("isError") or res.get("is_error"))
    return bool(getattr(res, "is_error", False))


def _replace_result_text(res: Any, new_text: str) -> Any:
    """Return `res` with its text (and any result-wrapped structured content)
    replaced by `new_text`, preserving the shape the MCP SDK expects.

    Used to neutralize a poisoned tool response: the hidden instructions are
    stripped from BOTH the text blocks and the structured content so they can't
    survive in either channel. Tools with richer structured output are
    fail-safely collapsed to this sanitized text (documented limit).
    """
    if isinstance(res, dict):
        out = dict(res)
        out["content"] = [{"type": "text", "text": new_text}]
        sc = out.get("structuredContent")
        if isinstance(sc, dict):
            out["structuredContent"] = ({**sc, "result": new_text}
                                        if "result" in sc else {"result": new_text})
        return out
    try:
        res.content = [mcp_types.TextContent(type="text", text=new_text)]
        sc = getattr(res, "structured_content", None)
        if isinstance(sc, dict):
            res.structured_content = ({**sc, "result": new_text}
                                      if "result" in sc else {"result": new_text})
        return res
    except Exception:
        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text=new_text)],
            structured_content={"result": new_text},
            is_error=_result_is_error(res))
_JSON_TO_PY = {
    "string": "str", "integer": "int", "number": "float",
    "boolean": "bool", "array": "list", "object": "dict",
}


def _proxy_param_decls(input_schema: dict) -> tuple[str, list[tuple[str, str]]]:
    """Signature source + [(json_name, py_name)] for an upstream schema.

    Unknown/complex JSON types fall back to Any (validated but unconverted).
    `_agentshield` is reserved for the provenance tag and never forwarded.
    """
    import keyword

    schema = input_schema if isinstance(input_schema, dict) else {}
    props = schema.get("properties") or {}
    if not isinstance(props, dict):
        props = {}
    required = schema.get("required") or []
    required = set(required) if isinstance(required, list) else set()
    used: set[str] = set()
    decls: list[str] = []
    mapping: list[tuple[str, str]] = []
    for raw in props:
        base = re.sub(r"\W", "_", str(raw)) or "arg"
        if re.match(r"^\d", base):
            base = "_" + base
        if keyword.iskeyword(base) or base == "_agentshield":
            base += "_"
        name = base
        i = 2
        while name in used:
            name = f"{base}_{i}"
            i += 1
        used.add(name)
        mapping.append((str(raw), name))
        detail = props.get(raw) or {}
        pytype = (_JSON_TO_PY.get(detail.get("type"), "Any")
                  if isinstance(detail, dict) else "Any")
        if str(raw) in required:
            decls.append(f"{name}: {pytype}")
        else:
            decls.append(f"{name}: {pytype} = None")
    return ", ".join(decls), mapping


def _forward_upstream_call(tool_name: str, proxy: UpstreamProxy,
                           arguments: dict) -> str:
    """Forward one ALLOWED call; upstream failure raises fail-closed."""
    from mcp.server.mcpserver.exceptions import ToolError

    clean = {k: v for k, v in (arguments or {}).items()
             if v is not None and k != _TAG}
    try:
        return proxy.call_tool(tool_name, clean)
    except UpstreamError as exc:
        raise ToolError(
            f"DENIED by AgentShield.\nTool: {tool_name}\n"
            f"Decision: deny (fail-closed)\n"
            f"Reasons:\n  - [upstream_error] upstream MCP server failed: {exc}"
        ) from exc


def _make_proxy_fn(tool_name: str, description: str,
                   input_schema: dict, proxy: UpstreamProxy):
    """Build a gateway tool function mirroring an upstream input schema.

    The synthesized signature carries the upstream types so `list_tools`
    advertises the real schema and the SDK validates arguments before the
    forward. Optional args default to None and are dropped when unset, so
    upstream defaults apply.
    """
    sig_src, mapping = _proxy_param_decls(input_schema)
    keys = "{" + ", ".join(f"{raw!r}: {py}" for raw, py in mapping) + "}"
    fn_name = re.sub(r"\W", "_", f"proxy_{tool_name}") or "proxy_tool"
    src = (
        f"def {fn_name}({sig_src}) -> str:\n"
        f"    return _forward(_TOOL_NAME, _PROXY, {keys})\n"
    )
    namespace: dict[str, Any] = {"_forward": _forward_upstream_call,
                                 "_TOOL_NAME": tool_name, "_PROXY": proxy}
    exec(compile(src, f"<agentshield-proxy:{tool_name}>", "exec"), namespace)
    fn = namespace[fn_name]
    fn.__doc__ = description or f"Proxied upstream tool {tool_name}."
    return fn


class EnforcementMiddleware:
    """MCP ServerMiddleware: `(ctx, call_next) -> result`.

    Intercepts `tools/call`, runs AgentShield, and:
      * ALLOW            -> forwards to the real tool (call_next)
      * DENY             -> short-circuits with an error result (tool never runs)
      * REQUIRE_APPROVAL -> short-circuits, held for a human (tool never runs)

    Two tripwires run before the policy engine: the signed tool manifest
    (live description+schema vs. the startup signature — catches
    rug-pull/tool-poisoning) and provenance resolution (replay/expiry/
    session-checked). Every denial is written to the audit log.

    A tool that fails AFTER an ALLOW verdict is fail-closed too: the
    client sees an error result and a DENY is audited (`upstream_error`
    for proxied tools, `tool_error` otherwise).
    """

    def __init__(self, shield: AgentShield,
                 manifest: ToolManifest | None = None,
                 tool_lookup=None,
                 proxied_tools: Any = None) -> None:
        self.shield = shield
        self.manifest = manifest
        # Callable mapping a tool name to its live registered tool object
        # (or None). Injected by build_gateway so tests can snapshot first.
        self._tool_lookup = tool_lookup
        # Names of tools forwarded to an upstream server (fail-closed set).
        self._proxied_tools = frozenset(proxied_tools or ())
        # Per-session recent-activity memory, keyed by the tag's session_id.
        # Lets the gate connect a poisoned MCP response to a later egress in
        # the same session (the indirect-injection exfiltration sequence).
        self._sessions: dict[str, SessionContext] = {}

    def _get_session(self, session_id) -> SessionContext | None:
        if not session_id or not isinstance(session_id, str):
            return None
        sess = self._sessions.get(session_id)
        if sess is None:
            if len(self._sessions) >= _SESSION_CAP:
                self._sessions.pop(next(iter(self._sessions)), None)  # LRU-ish
            sess = SessionContext(session_id=session_id)
            self._sessions[session_id] = sess
        return sess

    def _inspect_response(self, tool_name: str, res, session):
        """Treat an MCP tool response as UNTRUSTED data: inspect it for hidden/
        obfuscated injected instructions before it re-enters the agent context.

        When hidden content is found, the response is neutralized — only the
        visible text (hidden stripped, provenance-banner'd) is returned, so the
        injected instructions never reach the model. The event is audited, and
        (if a session is tracked) recorded so a later egress in the same
        session is seen as exfiltration.
        """
        text = _result_text(res)
        if not text:
            return res
        ct = "html" if _looks_html(text) else "text"
        ingested = self.shield.ingest(
            text[:_RESPONSE_SCAN_CAP],
            Provenance(Channel.MCP_RESPONSE, origin=str(tool_name)),
            content_type=ct, session=session)
        if not ingested.has_hidden_content:
            return res
        self.shield.audit.record(EnforcementResult(
            call=ToolCall(tool_name=tool_name, source=ingested.trust,
                          metadata={"transport": "mcp", "phase": "response"}),
            decision=Decision.ALLOW,
            reasons=[PolicyReason(
                rule="mcp_response_sanitized", decision=Decision.ALLOW,
                detail=(f"Hidden/obfuscated content stripped from "
                        f"'{tool_name}' response: "
                        f"{', '.join(r for r, _ in ingested.hidden_segments[:3])}."))],
            detections=ingested.detections, fail_closed=False))
        return _replace_result_text(res, ingested.agent_text())

    def _audit_downstream_failure(self, call: ToolCall,
                                  exc: Exception) -> None:
        """Audit a crash on the way out of an ALLOW verdict (fail-closed)."""
        rule = ("upstream_error"
                if call.tool_name in self._proxied_tools
                else "tool_error")
        self.shield.audit.record(EnforcementResult(
            call=call, decision=Decision.DENY,
            reasons=[PolicyReason(
                rule=rule, decision=Decision.DENY,
                detail=(f"{call.tool_name} failed after ALLOW: "
                        f"{type(exc).__name__}: {exc}"))],
            fail_closed=True))

    async def __call__(self, ctx, call_next):  # noqa: ANN001 - SDK-typed context
        if ctx.method != "tools/call" or not ctx.params:
            return await call_next(ctx)

        name = ctx.params.get("name")
        arguments = dict(ctx.params.get("arguments") or {})

        # Pull the provenance tag out of the arguments so the real tool never
        # sees it. The tag's asserted source is only honored if it carries a
        # valid HMAC token minted from the harness secret — otherwise the call
        # resolves to UNTRUSTED. The agent (and any injected content) can place
        # a tag in the arguments, but cannot forge the token.
        tag = arguments.pop(_TAG, {}) or {}
        if not isinstance(tag, dict):
            tag = {}
        source = resolve(tag.get("source"), tag.get("token"),
                         session_id=tag.get("session_id"))
        # Recent-activity memory for this session (if the harness supplied an
        # id): makes the exfil-after-poisoned-response guard work across calls.
        session = self._get_session(tag.get("session_id"))
        trace_id = tag.get("trace_id")
        parent_id = tag.get("parent_id")
        context = str(tag.get("context", ""))
        if input_too_large(context, arguments):
            return mcp_types.CallToolResult(
                content=[mcp_types.TextContent(
                    type="text",
                    text="DENIED by AgentShield.\nTool: (input too large)\nDecision: deny\n" "Reasons:\n  - [input_too_large] call input exceeds the 256KB edge budget.")],
                is_error=True,
            )

        if not isinstance(name, str) or not name.strip():
            # Audit the rejection: this branch returns before shield.check,
            # so without an explicit record the probe would be invisible.
            denied_call = ToolCall(tool_name="(missing name)",
                                   arguments=arguments, source=source,
                                   context=context,
                                   metadata={"transport": "mcp"})
            self.shield.audit.record(EnforcementResult(
                call=denied_call, decision=Decision.DENY,
                reasons=[PolicyReason(rule="invalid_tool",
                                      decision=Decision.DENY,
                                      detail="missing or blank tool name")],
                fail_closed=True))
            return mcp_types.CallToolResult(
                content=[mcp_types.TextContent(
                    type="text",
                    text="DENIED by AgentShield.\nTool: (missing name)\nDecision: deny\n"
                         "Reasons:\n  - [invalid_tool] missing or blank tool name.")],
                is_error=True,
            )
        call = ToolCall(
            tool_name=str(name),
            arguments=arguments,
            source=source,
            trace_id=trace_id if isinstance(trace_id, str) else None,
            parent_id=parent_id if isinstance(parent_id, str) else None,
            context=context,
            metadata={"transport": "mcp"},
        )
        # Signed tool manifest: the live tool's description+schema must
        # still match the startup signature. A mismatch means the tool was
        # redefined after registration (rug-pull / tool-poisoning) — DENY
        # before the policy engine even sees the call.
        if self.manifest is not None and self._tool_lookup is not None:
            try:
                live = self._tool_lookup(str(name))
            except Exception:
                live = None
            if live is not None:
                ok, why = self.manifest.verify_tool(
                    str(name), getattr(live, "description", "") or "",
                    getattr(live, "parameters", None) or {})
                if not ok:
                    return _deny(self.shield, call,
                                 "tool_manifest_mismatch", why)
        result = self.shield.check(call, session=session)

        if result.decision is Decision.ALLOW:
            # Forward with the sanitized arguments (tag removed).
            clean_params = dict(ctx.params)
            clean_params["arguments"] = arguments
            try:
                res = await call_next(
                    dataclasses.replace(ctx, params=clean_params))
            except Exception as exc:
                # A crash on the way out (transport/middleware bug — tool
                # failures normally surface as is_error results, below).
                self._audit_downstream_failure(call, exc)
                raise
            # Tool failures surface as is_error *results*: the SDK converts
            # them inside the handler, so there is no exception to catch
            # here. An upstream failure after ALLOW is fail-closed — audit
            # the DENY so the trail stays complete. The proxy tool marks its
            # fail-closed error with _UPSTREAM_FAILURE_MARKER; an upstream
            # tool's own domain error (or an argument-validation error) has
            # no marker and passes through as ordinary tool output.
            if (call.tool_name in self._proxied_tools
                    and _result_is_error(res)
                    and _UPSTREAM_FAILURE_MARKER in _result_text(res)):
                self.shield.audit.record(EnforcementResult(
                    call=call, decision=Decision.DENY,
                    reasons=[PolicyReason(
                        rule="upstream_error", decision=Decision.DENY,
                        detail=(f"{call.tool_name} failed after ALLOW: "
                                f"{_result_text(res)}"))],
                    fail_closed=True))
            # Inspect the tool RESPONSE as untrusted data: strip hidden
            # injected instructions before they re-enter the agent context,
            # and record the (untrusted) ingest so a later egress in this
            # session is caught as exfiltration.
            return self._inspect_response(call.tool_name, res, session)

        # Blocked: return a structured, inspectable error result. The agent
        # receives the verdict and the reasons — not a silent failure.
        reasons = "\n".join(f"  - [{r.rule}] {r.detail}" for r in result.reasons)
        verb = ("DENIED by AgentShield"
                if result.decision is Decision.DENY
                else "HELD FOR HUMAN APPROVAL by AgentShield")
        text = (f"{verb}.\n"
                f"Tool: {name}\n"
                f"Decision: {result.decision.value}"
                f"{' (fail-closed)' if result.fail_closed else ''}\n"
                f"Reasons:\n{reasons}")
        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text=text)],
            is_error=True,
        )


def _build_demo_gateway(shield: AgentShield) -> MCPServer:
    """Gateway serving the 5 built-in demo tools (no upstream configured)."""
    server = MCPServer(
        name="AgentShield-Gateway",
        instructions="All tool calls are enforced by AgentShield policy.",
    )
    # Register our enforcement as the OUTERMOST middleware so it runs before
    # the tool lookup/handler for every request.
    # NOTE: demo tools are registered below first; the manifest snapshot is
    # taken after registration and handed to the middleware, so any later
    # redefinition (rug-pull/tool-poisoning) trips verification.

    @server.tool(description="Search the public web (low sensitivity).")
    def search_web(query: str) -> str:
        return f"[mock] top results for: {query}"

    @server.tool(description="Read an internal document (low sensitivity).")
    def read_document(doc_id: str) -> str:
        return f"[mock] contents of {doc_id}"

    @server.tool(description="Search the local UNTRUSTED retrieval corpus (low sensitivity).")
    def read_rag_docs(query: str) -> str:
        from ..rag.tools import read_rag_docs as _read_rag_docs

        return _read_rag_docs(query)

    @server.tool(description="Send an email (HIGH sensitivity, approval-gated).")
    def send_email(to: str, body: str = "") -> str:
        return f"[mock] email sent to {to}"

    @server.tool(description="Query the customer database (HIGH sensitivity).")
    def read_customer_db(query: str) -> str:
        return f"[mock] rows for: {query}"

    # Snapshot live tool identities AFTER registration: description+schema
    # signed with the harness secret. The middleware re-verifies on every
    # call; without a secret the manifest is unsigned and verification is
    # skipped but flagged (insecure dev mode).
    manifest = ToolManifest.from_tools(
        {t.name: {"description": t.description or "",
                  "schema": t.parameters or {}}
         for t in server._tool_manager.list_tools()})
    server.middleware.insert(
        0, EnforcementMiddleware(shield, manifest=manifest,
                                 tool_lookup=_live_tool_lookup(server)))
    return server


def _build_proxy_gateway(shield: AgentShield, cmd: list[str],
                         timeout_s: float | None) -> MCPServer:
    """Gateway fronting an arbitrary upstream MCP server over stdio.

    Spawns the upstream, lists its tools, and registers one forwarding tool
    per upstream tool. A broken/unreachable upstream raises UpstreamError
    (loud, fail-closed) — it NEVER silently falls back to demo tools.
    """
    timeout = (upstream_timeout_from_env() if timeout_s is None
               else max(0.5, float(timeout_s)))
    proxy = UpstreamProxy(cmd, timeout_s=timeout)
    try:
        upstream_tools = proxy.list_tools()
    except UpstreamError:
        proxy.close()
        raise
    server = MCPServer(
        name="AgentShield-Gateway",
        instructions=("AgentShield-protected proxy: every tool call is "
                      "enforced by AgentShield policy before reaching upstream."),
    )
    for info in upstream_tools:
        schema = getattr(info, "input_schema", None)
        if schema is None:
            schema = getattr(info, "inputSchema", None)
        if not isinstance(schema, dict):
            schema = {}
        fn = _make_proxy_fn(info.name, info.description or "", schema, proxy)
        server.add_tool(fn, name=info.name,
                        description=info.description or "")
    manifest = ToolManifest.from_tools(
        {t.name: {"description": t.description or "",
                  "schema": t.parameters or {}}
         for t in server._tool_manager.list_tools()})
    server.middleware.insert(
        0, EnforcementMiddleware(
            shield, manifest=manifest,
            tool_lookup=_live_tool_lookup(server),
            proxied_tools={t.name for t in server._tool_manager.list_tools()}))
    # Lifecycle handle: tests, demos, and operators reap the upstream
    # subprocess via close_gateway_proxy(server) (also atexit-guarded).
    server._agentshield_upstream = proxy  # noqa: SLF001 - owned handle
    return server


def build_gateway(shield: AgentShield | None = None,
                  upstream_cmd: list[str] | None = None,
                  upstream_timeout_s: float | None = None) -> MCPServer:
    """Build an MCP server with AgentShield enforcement.

    Upstream mode (drop-in proxy): pass ``upstream_cmd`` explicitly or set
    AGENTSHIELD_UPSTREAM_CMD (+ optional AGENTSHIELD_UPSTREAM_ARGS). The demo
    tools are intentionally "dangerous" so the enforcement is visible.
    In production you'd point at your real upstream MCP server — the
    middleware governs all tools identically.
    """
    shield = shield or AgentShield()
    cmd = (list(upstream_cmd) if upstream_cmd is not None
           else upstream_command_from_env())
    if cmd:
        return _build_proxy_gateway(shield, cmd, upstream_timeout_s)
    return _build_demo_gateway(shield)


def close_gateway_proxy(server: MCPServer) -> bool:
    """Reap the upstream subprocess behind a proxy gateway (idempotent).

    Returns True when a proxy was attached, False for demo-mode gateways.
    """
    proxy = getattr(server, "_agentshield_upstream", None)
    if proxy is None:
        return False
    proxy.close()
    return True


def _live_tool_lookup(server):
    """Return a name -> live-tool callable for manifest verification."""
    def _lookup(name: str):
        try:
            return server._tool_manager.get_tool(name)
        except Exception:
            return None
    return _lookup


# Entry point:  python -m agentshield.gateway.mcp_gateway   (stdio transport)
if __name__ == "__main__":  # pragma: no cover
    build_gateway().run()
