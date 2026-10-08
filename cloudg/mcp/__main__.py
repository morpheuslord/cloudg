"""Entry point for ``python -m cloudg.mcp``, the cloudg MCP command line.

The commands live in :mod:`cloudg.mcp.cli`. ``python -m cloudg.mcp serve``
starts a stdio MCP server; ``--help`` lists the other commands.
"""

from cloudg.mcp.cli import main

if __name__ == "__main__":
    main()
