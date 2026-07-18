"""
r94_loop_indexer_finalize_dos.py

Flags indexer fns that parse a block and can RETURN AN ERROR (or panic)
based on malformed tx contents, thereby preventing block indexing.

Source: Solodit #55305 (Code4rena Initia minievm).
Class: indexer-finalize-dos (both).

Heuristic:
  1. Fn name matches /listen_?finalize_?block|index_?block|process_?block|on_?finalize/.
  2. Body iterates block.txs / txs_in_block and calls something that
     can error: `parse`, `decode`, `unmarshal`, `try_from`.
  3. Body does NOT wrap the per-tx call in a `match`/`if let Ok`/
     `.unwrap_or` / error-swallow.
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, text_of, line_col, snippet_of, is_pub, body_text_nocomment, IDENT,
)

_FN_NAME_RE = re.compile(r"(?i)(listen_?finalize_?block|index_?block|process_?block|on_?finalize|finalize_?hook)")
_ITER_RE = re.compile(fr"\.txs|txs_in_block|block\.transactions|for\s+\w+\s+in\s+{IDENT}txs")
_ERR_CALL_RE = re.compile(r"\.parse\s*\(|\.decode\s*\(|\.unmarshal\s*\(|try_from\s*\(|\?\s*[;,\)]")
_SWALLOW_RE = re.compile(
    r"match\s+\w+\s*\{[^}]*Err\s*\(\s*_\s*\)\s*=>\s*(continue|skip)|"
    r"if\s+let\s+Ok\s*\(|\.unwrap_or\s*\(|\.unwrap_or_else\s*\(|"
    r"\.or_else\s*\(|\.ok\s*\(\s*\)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _ITER_RE.search(body_nc):
            continue
        if not _ERR_CALL_RE.search(body_nc):
            continue
        if _SWALLOW_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` iterates block transactions and calls "
                f"parse/decode/unmarshal/try_from with error propagation "
                f"(? or direct return) and no per-tx error swallow. "
                f"A crafted tx can halt block indexing (DoS). See "
                f"Solodit #55305 (Initia minievm)."
            ),
        })
    return hits
