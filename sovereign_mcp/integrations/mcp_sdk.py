"""Drop-in protection for servers built on the official MCP Python SDK.

Supports **SDK 1.x and 2.x**. That matters: the published servers people
actually run - `mcp-server-git`, `mcp-server-fetch` and the rest - pin `mcp`
1.x, where `MCPServer` and the whole `Extension` API do not exist. An adapter
written against 2.x alone protects almost nothing in the wild.

**Protect any existing server** - yours or someone else's, either SDK line::

    from sovereign_mcp.integrations import protect

    protect(server)

`protect()` is the general entry point. It wraps the registered `tools/call`
handler, which every flavour of server shares: the low-level `Server`, 1.x
`FastMCP`, and 2.x `MCPServer`.

**Create a new protected server**::

    from sovereign_mcp.integrations import sovereign_server

    mcp = sovereign_server("my-server")     # FastMCP on 1.x, MCPServer on 2.x

    @mcp.tool()
    def read_file(path: str) -> str:
        ...

Two-phase by design. Input-side checks (registration, integrity, input schema,
injection, sanitization, value constraints, permissions) run BEFORE the tool
executes, so a malicious call to `delete_file` is stopped rather than merely
reported. Output-side layers (A, anti-patterns, B, PII, content safety, C
consensus, D) run on the result.

Requires the official SDK: pip install mcp
"""

import asyncio
import inspect
import logging

from sovereign_mcp.tool_registry import ToolRegistry
from sovereign_mcp.output_gate import OutputGate

logger = logging.getLogger(__name__)

try:
    from mcp import types
    from mcp.server.lowlevel import Server as LowLevelServer
    from mcp.types import CallToolResult, TextContent
except ImportError as exc:  # pragma: no cover - exercised by the import test
    raise ImportError(
        "sovereign_mcp.integrations.mcp_sdk needs the official MCP SDK.\n"
        "    pip install mcp\n"
        "The rest of sovereign_mcp works without it."
    ) from exc

# The high-level class was renamed between SDK lines, and the Extension API is
# 2.x-only. Probe rather than assume: which one is installed depends on which
# server packages the user has, and `mcp-server-git` pins 1.x.
try:                                          # SDK 2.x
    from mcp.server import MCPServer
except ImportError:                           # pragma: no cover
    MCPServer = None

try:                                          # SDK 1.x
    from mcp.server.fastmcp import FastMCP
except ImportError:                           # pragma: no cover
    FastMCP = None

try:                                          # SDK 2.x only
    from mcp.server.extension import Extension
except ImportError:                           # pragma: no cover
    Extension = None

#: Every high-level wrapper class available in this installation.
_HIGH_LEVEL = tuple(c for c in (MCPServer, FastMCP) if c is not None)

#: Attributes under which a high-level server keeps its low-level Server.
#: `_lowlevel_server` on 2.x MCPServer, `_mcp_server` on 1.x FastMCP.
_LOWLEVEL_ATTRS = ("_lowlevel_server", "_mcp_server")


class GateDeclined(Exception):
    """Raised when on_decline='raise'. Carries the GateResult as `.result`."""

    def __init__(self, result):
        self.result = result
        super().__init__("[{}] {}".format(result.layer, result.reason))


#: What the model sees when a call is declined. Deliberately names the layer
#: and reason: a silent empty result teaches an agent to retry, while a
#: specific reason lets it correct course or stop.
_DECLINE_TEMPLATE = (
    "BLOCKED by SovereignShield ({layer}): {reason}\n"
    "This tool call was not executed. Do not retry it unchanged."
)

#: JSON Schema spells these differently from sovereign-mcp's frozen field map.
_CONSTRAINT_ALIASES = {
    "minimum": "min",
    "maximum": "max",
    "minLength": "min_length",
    "maxLength": "max_length",
    "minItems": "min_length",
    "maxItems": "max_length",
}
_PASSTHROUGH_KEYS = ("type", "enum", "pattern", "items")


def _to_frozen_schema(json_schema):
    """Translate JSON Schema into the flat field map sovereign-mcp freezes.

    MCP tools describe parameters as standard JSON Schema::

        {"type": "object",
         "properties": {"path": {"type": "string", "maxLength": 260}},
         "required": ["path"]}

    sovereign-mcp freezes a flat map instead, and names its numeric and length
    constraints `min`/`max`/`min_length`/`max_length`::

        {"path": {"type": "string", "max_length": 260, "required": True}}

    Without this translation every parameter of every real MCP tool reads as
    "unknown parameter" and the gate rejects legitimate traffic - which is how
    this function came to exist.

    A field whose type cannot be expressed (an `anyOf` union, a `$ref`) is kept
    with no type constraint: the parameter stays known, so the call is not
    rejected, and the remaining layers still inspect it.
    """
    if not isinstance(json_schema, dict):
        return {}
    properties = json_schema.get("properties")
    if not isinstance(properties, dict):
        # No `properties` key: already a flat map, or an open schema.
        return {} if "type" in json_schema else dict(json_schema)

    required = set(json_schema.get("required") or ())
    frozen = {}
    for field, spec in properties.items():
        if not isinstance(spec, dict):
            frozen[field] = {}
            continue
        definition = {k: spec[k] for k in _PASSTHROUGH_KEYS if k in spec}
        for source, target in _CONSTRAINT_ALIASES.items():
            if source in spec:
                definition[target] = spec[source]
        if field in required:
            definition["required"] = True
        frozen[field] = definition
    return frozen


def _schema_of(tool, which):
    """Read a tool's input/output schema across SDK naming conventions.

    1.x spells them `inputSchema`/`outputSchema`; 2.x uses `input_schema`/
    `output_schema`.
    """
    for attr in ("{}_schema".format(which), "{}Schema".format(which)):
        value = getattr(tool, attr, None)
        if value is not None:
            return value
    return None


def _as_dict(result):
    """Coerce a tools/call result into the dict the gate verifies.

    Prefers structured content. Falls back to the concatenated text blocks so
    the deception, PII and content-safety layers still see something real.
    """
    # Low-level handlers return ServerResult wrapping a CallToolResult.
    result = getattr(result, "root", result)
    for attr in ("structured_content", "structuredContent"):
        structured = getattr(result, attr, None)
        if isinstance(structured, dict):
            return structured
    blocks = getattr(result, "content", None) or []
    if not isinstance(blocks, (list, tuple)):
        blocks = [blocks]
    text = "\n".join(
        b.text for b in blocks if getattr(b, "type", None) == "text"
    )
    return {"text": text}


def _lowlevel_of(server):
    """The low-level Server underneath, whichever wrapper the caller used."""
    for attr in _LOWLEVEL_ATTRS:
        low = getattr(server, attr, None)
        if low is not None:
            return low
    return server


async def _discover_tools(server):
    """Return the tool definitions a server exposes, at any API level.

    A high-level wrapper offers `list_tools()` directly. A low-level `Server`
    only has whatever handler its `@server.list_tools()` decorator registered,
    so ask that handler - the same source of truth a client would query.
    """
    if _HIGH_LEVEL and isinstance(server, _HIGH_LEVEL):
        tools = server.list_tools()
        if inspect.isawaitable(tools):
            tools = await tools
        return list(tools)

    low = _lowlevel_of(server)
    handler = low.request_handlers.get(types.ListToolsRequest)
    if handler is None:
        raise RuntimeError(
            "This server registers no tools/list handler, so there are no tool "
            "definitions to freeze. Register your tools before protecting it."
        )
    result = await handler(types.ListToolsRequest(method="tools/list"))
    return list(getattr(result, "root", result).tools)


#: The `tools/call` method name, as 2.x keys its handler registry.
_CALL_TOOL_METHOD = "tools/call"


def _find_call_tool_handler(low):
    """Locate the registered tools/call handler across both SDK lines.

    The two lines store and shape handlers differently, and the difference is
    not cosmetic:

    * 1.x - `Server.request_handlers` is a public dict keyed by request *type*,
      and a handler takes the whole request: `handler(req)`.
    * 2.x - `Server._request_handlers` is keyed by method *string* and holds a
      `HandlerEntry(params_type, handler)`, where a handler takes
      `(ctx, params)`. Registration goes through the public
      `add_request_handler` / `get_request_handler`.

    Returns `(line, handler, params_type)` with `line` either "1.x" or "2.x",
    or None when no handler is registered.
    """
    getter = getattr(low, "get_request_handler", None)
    if callable(getter):
        entry = getter(_CALL_TOOL_METHOD)
        if entry is None:
            return None
        return ("2.x", entry.handler, entry.params_type)

    handlers = getattr(low, "request_handlers", None)
    if handlers is None:
        return None
    original = handlers.get(types.CallToolRequest)
    if original is None:
        return None
    return ("1.x", original, None)


async def invoke_tool(server, name, arguments):
    """Drive a tools/call straight through a server's handler.

    Returns `(blocked, text)`: whether the result was an error, and its text.
    This is the same entry point a client request reaches, so it exercises
    whatever protection is installed - without a transport, a client session
    or an event loop of its own. Intended for tests, demos and policy dry-runs
    rather than production traffic.

    Handles the 1.x/2.x handler differences so callers do not have to.
    """
    low = _lowlevel_of(server)
    if not hasattr(low, "request_handlers") and not hasattr(
            low, "get_request_handler"):
        raise TypeError(
            "protect() expects an MCP server; got {} with no request_handlers."
            .format(type(server).__name__))
    found = _find_call_tool_handler(low)
    if found is None:
        raise RuntimeError("server has no tools/call handler")
    line, handler, _ = found
    if line == "2.x":
        params = types.CallToolRequestParams(name=name, arguments=arguments)
        result = await handler(None, params)
    else:
        result = await handler(types.CallToolRequest(
            method=_CALL_TOOL_METHOD,
            params=types.CallToolRequestParams(name=name, arguments=arguments),
        ))
    root = getattr(result, "root", result)
    blocked = bool(getattr(root, "isError", None)
                   or getattr(root, "is_error", None))
    text = " ".join(getattr(b, "text", "") for b in (root.content or []))
    return blocked, text


def _decline_blocks(gate_result):
    return [TextContent(
        type="text",
        text=_DECLINE_TEMPLATE.format(
            layer=gate_result.layer, reason=gate_result.reason),
    )]


class _Verifier:
    """The verification core shared by every entry point.

    Both `SovereignGate` (the 2.x extension) and `protect()` (the handler
    wrapper) run this one implementation. That is deliberate: two copies of a
    security check drift, and the drifted copy is always the deployed one.
    """

    def __init__(self, gate=None, risk_level="HIGH", verify_output=True,
                 on_decline="block", pii_policy="warn"):
        if on_decline not in ("block", "raise", "log"):
            raise ValueError(
                "on_decline must be 'block', 'raise' or 'log', got {!r}".format(
                    on_decline)
            )
        self._gate = gate
        self._risk_level = risk_level
        self._verify_output = verify_output
        self._on_decline = on_decline
        self._pii_policy = pii_policy
        self._server = None
        self._frozen = gate is not None
        self._lock = asyncio.Lock()

    def bind(self, server):
        self._server = server
        return server

    async def ensure_frozen(self):
        if self._frozen:
            return
        async with self._lock:
            if self._frozen:
                return
            if self._server is None:
                # Fail loudly rather than waving calls through. A gate that
                # quietly allowed everything would be indistinguishable from
                # a working one.
                raise RuntimeError(
                    "The SovereignShield gate was never bound to a server, so "
                    "it has no tool definitions to verify against. Use "
                    "sovereign_server(...) or protect(server)."
                )
            self._gate = await self._build_gate(self._server)
            self._frozen = True

    async def _build_gate(self, server):
        registry = ToolRegistry()
        tools = await _discover_tools(server)
        for tool in tools:
            registry.register_tool(
                name=tool.name,
                description=tool.description or "",
                input_schema=_to_frozen_schema(_schema_of(tool, "input")),
                # MCP tools need not declare an output schema; an open object
                # keeps Layer A quiet rather than failing every result.
                output_schema=_to_frozen_schema(_schema_of(tool, "output")),
                risk_level=self._risk_level,
            )
        frozen = registry.freeze()
        logger.info(
            "SovereignShield froze %d tool definition(s): %s",
            len(tools), ", ".join(t.name for t in tools) or "(none)",
        )
        return OutputGate(frozen, pii_policy=self._pii_policy)

    async def before(self, name, args):
        """A GateResult to decline with, or None to let the call proceed."""
        await self.ensure_frozen()
        result = await asyncio.to_thread(
            self._gate.verify_call, name, input_params=args
        )
        return None if result.accepted else self._note(result, name)

    async def after(self, name, args, call_result):
        """A GateResult to decline with, or None to let the result through."""
        if not self._verify_output:
            return None
        result = await asyncio.to_thread(
            self._gate.verify, name, _as_dict(call_result), input_params=args
        )
        return None if result.accepted else self._note(result, name)

    def _note(self, gate_result, tool_name):
        logger.warning(
            "SovereignShield declined %s at layer %s: %s",
            tool_name, gate_result.layer, gate_result.reason,
        )
        if self._on_decline == "raise":
            raise GateDeclined(gate_result)
        if self._on_decline == "log":
            return None
        return gate_result


# --------------------------------------------------------------------------
# Entry point 1 - protect an existing server. Works on every SDK line.
# --------------------------------------------------------------------------

def protect(server, *, gate=None, risk_level="HIGH", verify_output=True,
            on_decline="block", pii_policy="warn"):
    """Protect a server that already exists, whichever API built it.

    Works on the low-level `Server` - the API most published MCP servers use,
    including `mcp-server-git` and `mcp-server-fetch` - and on 1.x `FastMCP`
    and 2.x `MCPServer`, by wrapping the `tools/call` handler they all share::

        from sovereign_mcp.integrations import protect

        protect(server)

    `pii_policy` defaults to "warn" here, not "block". This wraps tools you
    may not have written, and plenty of them return personal data as their
    normal output - `git log` carries author emails in every entry. Blocking
    those would make the gate unusable on real servers. Pass
    `pii_policy="block"` when your tools should never emit PII.

    Returns the same server, wrapped in place. Idempotent: protecting an
    already-protected server logs and leaves it alone rather than stacking a
    second gate.
    """
    low = _lowlevel_of(server)
    if not hasattr(low, "request_handlers") and not hasattr(
            low, "get_request_handler"):
        raise TypeError(
            "protect() expects an MCP server; got {} with no request_handlers."
            .format(type(server).__name__))
    found = _find_call_tool_handler(low)
    if found is None:
        raise RuntimeError(
            "This server registers no tools/call handler, so there is nothing "
            "to protect. Register your tools before calling protect()."
        )
    line, original, params_type = found
    # Two ways a server can already be gated: this function wrapped its
    # handler, or (on 2.x) sovereign_server installed the extension - whose
    # composed handler carries no marker of ours. Checking the server itself
    # catches both, so protecting twice cannot stack two gates.
    if (getattr(original, "_sovereign_protected", False)
            or getattr(server, "sovereign_gate", None) is not None):
        logger.info("SovereignShield: server already protected; leaving it alone.")
        return server

    verifier = _Verifier(gate, risk_level, verify_output, on_decline, pii_policy)
    verifier.bind(server)

    def _blocked(gate_result, wrap):
        result = CallToolResult(
            content=_decline_blocks(gate_result), is_error=True)
        return types.ServerResult(result) if wrap else result

    if line == "2.x":
        async def guarded(ctx, params):
            name = params.name
            args = dict(params.arguments or {})
            declined = await verifier.before(name, args)
            if declined is not None:
                return _blocked(declined, wrap=False)
            result = await original(ctx, params)
            declined = await verifier.after(name, args, result)
            if declined is not None:
                return _blocked(declined, wrap=False)
            return result
    else:
        async def guarded(req):
            name = req.params.name
            args = dict(req.params.arguments or {})
            declined = await verifier.before(name, args)
            if declined is not None:
                return _blocked(declined, wrap=True)
            result = await original(req)
            declined = await verifier.after(name, args, result)
            if declined is not None:
                return _blocked(declined, wrap=True)
            return result

    guarded._sovereign_protected = True
    guarded._sovereign_verifier = verifier
    if line == "2.x":
        low.add_request_handler(_CALL_TOOL_METHOD, params_type, guarded)
    else:
        low.request_handlers[types.CallToolRequest] = guarded
    server.sovereign_gate = verifier
    return server


# --------------------------------------------------------------------------
# Entry point 2 - the SDK 2.x extension, for servers you are creating
# --------------------------------------------------------------------------

if Extension is not None:

    class SovereignGate(Extension):
        """An MCP SDK 2.x extension that runs the verification chain.

        Args:
            gate: A pre-built OutputGate. Supply this when you want consensus,
                an audit log, identity checks, or any other configured layer.
                When omitted, a deterministic-only gate is built from the tools
                the server has registered.
            risk_level: Risk assigned to tools discovered from the server.
                "HIGH" (the default) means Layer C consensus runs when a
                verifier is configured; "LOW" skips it.
            verify_output: Also verify the tool's result after it runs. On by
                default. Set False for pre-execution checks only.
            on_decline: "block" (default) returns an error result to the
                caller; "raise" raises GateDeclined; "log" records and allows -
                use only to measure what a policy *would* block.

        The freeze happens on the first tool call, not at construction, because
        the SDK fixes extensions at construction time while `@mcp.tool()`
        decorators run afterwards. By the first call every decorator has run,
        so that is the earliest honest moment to freeze.

        Only available on SDK 2.x. On 1.x use `protect()`.
        """

        identifier = "dev.sovereignshield/gate"

        def __init__(self, gate=None, risk_level="HIGH", verify_output=True,
                     on_decline="block", pii_policy="warn"):
            self._verifier = _Verifier(
                gate, risk_level, verify_output, on_decline, pii_policy)

        def bind(self, server):
            """Attach to the server whose tools should be frozen.

            `sovereign_server()` does this for you. Call it yourself only when
            you construct MCPServer directly::

                gate = SovereignGate()
                mcp = MCPServer("my-server", extensions=[gate])
                gate.bind(mcp)
            """
            if MCPServer is not None and not isinstance(server, MCPServer):
                raise TypeError(
                    "Expected an MCPServer, got {}. For any other server, use "
                    "protect(server).".format(type(server).__name__))
            return self._verifier.bind(server)

        async def intercept_tool_call(self, params, ctx, call_next):
            name = params.name
            args = dict(params.arguments or {})

            declined = await self._verifier.before(name, args)
            if declined is not None:
                return CallToolResult(
                    content=_decline_blocks(declined), is_error=True)

            result = await call_next(ctx)

            declined = await self._verifier.after(name, args, result)
            if declined is not None:
                return CallToolResult(
                    content=_decline_blocks(declined), is_error=True)
            return result

        async def _ensure_frozen(self):
            """Freeze now rather than on the first call. Mainly for tests."""
            await self._verifier.ensure_frozen()

else:  # pragma: no cover - depends on which SDK line is installed

    class SovereignGate:
        """Unavailable: the Extension API arrived in MCP SDK 2.x."""

        def __init__(self, *args, **kwargs):
            raise RuntimeError(
                "SovereignGate needs the MCP SDK 2.x Extension API, which this "
                "installation does not have. Use protect(server) instead - it "
                "works on every SDK line."
            )


def sovereign_server(name=None, *, gate=None, risk_level="HIGH",
                     verify_output=True, on_decline="block",
                     pii_policy="warn", **kwargs):
    """Create a new protected server, using whichever SDK is installed.

    A drop-in replacement for `MCPServer(...)` (2.x) or `FastMCP(...)` (1.x) -
    every other argument is passed straight through::

        mcp = sovereign_server("my-server")

    Returns the server. Reach the gate through `mcp.sovereign_gate`.
    """
    if MCPServer is not None:
        sentinel = SovereignGate(
            gate=gate, risk_level=risk_level, verify_output=verify_output,
            on_decline=on_decline, pii_policy=pii_policy,
        )
        extensions = list(kwargs.pop("extensions", None) or ())
        extensions.append(sentinel)
        server = MCPServer(name, extensions=extensions, **kwargs)
        sentinel.bind(server)
        server.sovereign_gate = sentinel
        return server

    if FastMCP is not None:
        # 1.x has no Extension API, so wrap the handler instead. FastMCP
        # registers its tools/call handler at construction, so this is safe
        # before any @mcp.tool() has run - the freeze is lazy either way.
        server = FastMCP(name, **kwargs)
        return protect(server, gate=gate, risk_level=risk_level,
                       verify_output=verify_output, on_decline=on_decline,
                       pii_policy=pii_policy)

    raise RuntimeError(  # pragma: no cover
        "No high-level MCP server class found. Install a supported SDK: "
        "pip install mcp"
    )
