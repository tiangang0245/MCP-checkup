"""Package names an MCP server is legitimately expected to come from.

Used only for near-miss (typosquat) matching against names the user actually
typed - never for network lookups, so the tool stays offline.
"""

OFFICIAL_PACKAGES = (
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-time",
    "@modelcontextprotocol/server-git",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-google-drive",
    "@modelcontextprotocol/server-google-maps",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-pdf",
    "@modelcontextprotocol/server-redshift",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-playwright",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-sequentialthinking",
    "@modelcontextprotocol/server-aws-kb-retrieval",
)

# names that look like the official scope but are not in the list above
OFFICIAL_SCOPE = "@modelcontextprotocol/"
