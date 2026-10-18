"""Canonical JSON + a stable fingerprint for tool-definition snapshots.

An RFC 8785 (JCS) subset: keys are sorted by Unicode code point, no insignificant
whitespace, UTF-8 output. The one deviation from the spec is key ordering for
astral-plane characters (code-point order, not UTF-16 code-unit order); it does
not change ordering for the ASCII / BMP keys that appear in MCP tool schemas.
"""

from __future__ import annotations

import hashlib
import json


def canonical(obj) -> str:
    if isinstance(obj, dict):
        items = ",".join(json.dumps(str(k), ensure_ascii=False) + ":" + canonical(obj[k])
                         for k in sorted(obj, key=str))
        return "{" + items + "}"
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(canonical(v) for v in obj) + "]"
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def fingerprint(obj) -> str:
    return "sha256:" + hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()
