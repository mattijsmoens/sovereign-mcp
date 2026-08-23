"""Moved to its own package.

`sovereign-mcp-audit` is now published separately, under Apache 2.0 rather than
the Business Source License, with the MCP SDK as a real dependency instead of an
optional extra. It shares no code with this library and uses none of its
patented technology, so there was no reason for it to be licensed like one.

    pip install sovereign-mcp-audit

This module remains so that an existing entry point says where the tool went
rather than disappearing. It will be removed in a future release.
"""

import sys

MESSAGE = """
sovereign-mcp-audit has moved to its own package.

    pip install sovereign-mcp-audit

It is Apache 2.0 now, and the MCP SDK comes with it rather than being an
optional extra, so the command works straight after installing.

  https://github.com/mattijsmoens/sovereign-mcp-audit
"""


def main(argv=None):
    sys.stderr.write(MESSAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main())
