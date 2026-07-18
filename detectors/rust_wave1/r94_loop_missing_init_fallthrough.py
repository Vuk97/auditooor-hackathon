"""
r94_loop_missing_init_fallthrough.py

Flags fns that use a framework-default helper when a custom
per-protocol implementation exists in the same module but is never
set/registered in the module's init / keeper wiring.

Source: Solodit #54967 (Code4rena MANTRA — resolver not init'd in keeper).
Class: missing-init-fallthrough (both).

Heuristic:
  1. Source file defines a custom struct `XResolver` / `XConverter` /
     `XOracle` / `XHandler`.
  2. An `init` / `New*Keeper` / `DefaultConfig` fn exists in source.
  3. That init fn does NOT reference the custom name (assignment or
     registration).
  4. Elsewhere the custom name IS referenced (so it's not dead code).
"""

from __future__ import annotations
import re
from _util import (
    source_nocomment,
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_CUSTOM_STRUCT_RE = re.compile(r"pub\s+struct\s+(\w+(Resolver|Converter|Oracle|Handler|Strategy))\b")
_INIT_FN_RE = re.compile(
    r"pub\s+fn\s+(new\w*|init\w*|default_config|default_\w+_keeper)\s*\(",
    re.IGNORECASE,
)


def run(tree, source: bytes, filepath: str):
    hits = []
    src_nc = source_nocomment(source)

    custom_structs = list(_CUSTOM_STRUCT_RE.finditer(src_nc))
    if not custom_structs:
        return hits

    for cm in custom_structs:
        name = cm.group(1)
        # Must be referenced elsewhere (not dead code)
        if src_nc.count(name) < 2:
            continue

        # Check each init fn
        for im in _INIT_FN_RE.finditer(src_nc):
            fn_start = im.end()
            # Find end of this fn by brace matching (approximate: next pub fn or end)
            next_pub = src_nc.find("pub fn ", fn_start)
            fn_end = next_pub if next_pub != -1 else len(src_nc)
            init_body = src_nc[fn_start:fn_end]
            if name not in init_body:
                # Init doesn't set this custom helper
                prefix = src_nc[:im.start()]
                line = prefix.count("\n") + 1
                hits.append({
                    "severity": "medium",
                    "line": line,
                    "col": 0,
                    "snippet": im.group(0)[:80],
                    "message": (
                        f"fn `{im.group(1)}` is an init / keeper-wiring site. "
                        f"Custom helper `{name}` is defined in this module "
                        f"but never assigned/registered in init. Framework "
                        f"default wins at runtime — behavior drift. See "
                        f"Solodit #54967 (MANTRA)."
                    ),
                })
                break  # one hit per custom struct
    return hits
