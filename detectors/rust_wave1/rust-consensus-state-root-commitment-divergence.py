"""
rust-consensus-state-root-commitment-divergence.py

Flags consensus or block-finalization functions that compute a local
state root, but commit or return an externally supplied header/proposal
root without first checking equality against the local root.

Recall class: consensus/state-root divergence across Rust node code
such as zebra, near, and cosmos-Rust style block executors.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    line_col,
    snippet_of,
)


_FN_NAME_RE = re.compile(
    r"(finali[sz]e|execute|apply|commit|import|process|validate)_?"
    r"(block|chunk|state|root|app|header)?"
    r"|(state_?root|app_?hash|commit_?root)",
    re.IGNORECASE,
)

_LOCAL_ROOT_DECL_RE = re.compile(
    r"\b(?:let\s+(?:mut\s+)?)?"
    r"(?P<local>(?:computed|local|recomputed|expected|actual|new)_?"
    r"(?:state_?root|app_?hash|root_?hash|root))\b"
    r"\s*(?::[^=;]+)?="
    r"[^;{]*(?:compute|calculate|calc|derive|recompute|apply|execute|hash|merkle)"
    r"[^;]*;",
    re.IGNORECASE | re.DOTALL,
)

_EXTERNAL_ROOT_RE = re.compile(
    r"\b(?P<external>"
    r"(?:block|header|proposal|candidate|chunk|commit|receipt|trusted|remote|"
    r"incoming|advertised|expected)"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)*"
    r"\s*\.\s*(?:state_?root|app_?hash|root_?hash|root)"
    r")\b",
    re.IGNORECASE,
)

_COMMIT_SINK_PREFIX_RE = re.compile(
    r"(?:commit|store|set|write|save|persist|insert|update|return|Ok)\s*"
    r"(?:[A-Za-z0-9_:.\s]*\()?[^;\n]{0,160}",
    re.IGNORECASE,
)


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _has_root_equality_guard(body_text: str, local: str, external: str) -> bool:
    compact = _compact(body_text)
    local_c = _compact(local)
    external_c = _compact(external)

    guard_shapes = (
        f"{local_c}!={external_c}",
        f"{external_c}!={local_c}",
        f"{local_c}=={external_c}",
        f"{external_c}=={local_c}",
        f"assert_eq!({local_c},{external_c}",
        f"assert_eq!({external_c},{local_c}",
        f"ensure!({local_c}=={external_c}",
        f"ensure!({external_c}=={local_c}",
        f"debug_assert_eq!({local_c},{external_c}",
        f"debug_assert_eq!({external_c},{local_c}",
    )
    return any(shape in compact for shape in guard_shapes)


def _external_reaches_commit_sink(body_text: str, external: str) -> bool:
    external_c = _compact(external)
    for match in _COMMIT_SINK_PREFIX_RE.finditer(body_text):
        window = body_text[match.start(): match.end()]
        if external_c in _compact(window):
            return True

    tail = body_text.rsplit(";", 2)[-1]
    return external_c in _compact(tail)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn in function_items(root):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue

        body_nc = body_text_nocomment(body, source)
        local_match = _LOCAL_ROOT_DECL_RE.search(body_nc)
        if local_match is None:
            continue
        local_root = local_match.group("local")

        external_match = _EXTERNAL_ROOT_RE.search(body_nc)
        if external_match is None:
            continue
        external_root = external_match.group("external")

        if _has_root_equality_guard(body_nc, local_root, external_root):
            continue
        if not _external_reaches_commit_sink(body_nc, external_root):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"fn `{name}` computes `{local_root}` but commits or returns "
                f"external `{external_root}` without an equality guard. "
                "Consensus finalizers must bind committed state roots to "
                "the locally executed root to avoid state-root divergence."
            ),
        })
    return hits
