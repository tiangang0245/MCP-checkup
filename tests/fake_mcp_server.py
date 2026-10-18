"""A minimal MCP stdio server used only by the test suite.

Serves whatever tool list the JSON file in argv[1] contains. Nothing here talks
to the network or to a third-party package: v0.4's handshake is tested against
this file and nothing else.
"""

import json
import sys


def main() -> int:
    with open(sys.argv[1], encoding="utf-8") as fh:
        tools = json.load(fh)
    out = sys.stdout
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        method, mid = msg.get("method"), msg.get("id")
        if method == "initialize":
            json.dump({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-mcp", "version": "0"}}}, out)
        elif method == "tools/list":
            json.dump({"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}}, out)
        else:
            continue
        out.write("\n")
        out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
