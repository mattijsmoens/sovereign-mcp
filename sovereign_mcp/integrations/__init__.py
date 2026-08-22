"""Adapters that connect sovereign-mcp to real MCP server frameworks.

Each adapter lives in its own module and imports its framework lazily, so
`import sovereign_mcp` never requires a framework you do not use.

Currently available:
    mcp_sdk — the official MCP Python SDK (`pip install mcp`), version 2.x.
"""

__all__ = [
    "SovereignGate",
    "sovereign_server",
    "protect",
    "invoke_tool",
    "GateDeclined",
]


def __getattr__(name):
    # Lazy re-export so `from sovereign_mcp.integrations import SovereignGate`
    # works without making `mcp` a hard dependency of the package.
    if name in __all__:
        from sovereign_mcp.integrations import mcp_sdk
        return getattr(mcp_sdk, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
