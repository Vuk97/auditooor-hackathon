"""
rust_shielded_secret_in_log.py

Flags logging macro calls (trace!/debug!/info!/warn!/error!/println!) that
use the tracing `?` or `%` debug/display format specifier on a shielded-secret
identifier: nullifier, note_commitment, commitment, spending_key, spend_key,
viewing_key, ivk, ovk, fvk, value_balance, memo.

Shape (class-invariant):
  - A macro_invocation whose macro name is one of the log macros.
  - The macro token-tree text contains `?<secret>` or `%<secret>` where
    <secret> matches the shielded-secret pattern (word boundary enforced).
  - The same macro call text does NOT contain a guard: redact / truncate /
    .hash() / sanitize / mask.
  - The enclosing function is not under #[test] / #[cfg(test)].

Real zebra surface confirmed:
  zebra-state/src/service/check/nullifier.rs:173  trace!(?nullifier, ...)
  zebra-state/src/service/check/nullifier.rs:219  trace!(?nullifier, ...)
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
    text_of,
    walk_no_nested_fn,
)

# ---------------------------------------------------------------------------
# Log macro names we care about
# ---------------------------------------------------------------------------
_LOG_MACRO_RE = re.compile(
    r"^(?:trace|debug|info|warn|error|println)$"
)

# ---------------------------------------------------------------------------
# Shielded-secret identifier pattern.
# Matches the identifier portion immediately after `?` or `%` in a tracing
# macro argument, e.g.  ?nullifier   ?note_commitment   %spending_key
# ---------------------------------------------------------------------------
_SECRET_NAMES_RE = re.compile(
    r"[?%](?:"
    r"nullifier"
    r"|note_commitment"
    r"|note_cmx"
    r"|commitment"
    r"|spending_key"
    r"|spend_key"
    r"|viewing_key"
    r"|ivk"
    r"|ovk"
    r"|fvk"
    r"|value_balance"
    r"|memo"
    r")\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Guard / cap patterns: if ANY of these appear inside the macro call text
# the call is considered safe (value is already redacted / hashed / masked).
# ---------------------------------------------------------------------------
_GUARD_PATTERNS = [
    re.compile(r"\bredact\b", re.IGNORECASE),
    re.compile(r"\btruncate\b", re.IGNORECASE),
    re.compile(r"\.hash\s*\(\s*\)"),
    re.compile(r"\bsanitize\b", re.IGNORECASE),
    re.compile(r"\bmask\b", re.IGNORECASE),
    re.compile(r"\bHidden\b"),
    re.compile(r"\bPrivate\b"),
]


def _macro_name(macro_node, source: bytes) -> str:
    """Return the bare macro name for a macro_invocation node."""
    # tree-sitter-rust: macro_invocation -> identifier (or scoped_identifier) `!` token_tree
    for c in macro_node.children:
        if c.type == "identifier":
            return text_of(c, source)
        if c.type == "scoped_identifier":
            # e.g. tracing::trace  – take the last segment
            idents = [x for x in c.children if x.type == "identifier"]
            if idents:
                return text_of(idents[-1], source)
    return ""


def _has_guard(macro_text: str) -> bool:
    return any(p.search(macro_text) for p in _GUARD_PATTERNS)


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)

        for node in walk_no_nested_fn(body):
            if node.type != "macro_invocation":
                continue

            macro_name = _macro_name(node, source)
            if not _LOG_MACRO_RE.match(macro_name):
                continue

            macro_text = text_of(node, source)

            # Must contain ?<secret> or %<secret>
            m = _SECRET_NAMES_RE.search(macro_text)
            if m is None:
                continue

            # Skip if a guard/cap is present in the same macro call
            if _has_guard(macro_text):
                continue

            line, col = line_col(node)
            secret_token = m.group(0)  # e.g. "?nullifier"
            hits.append({
                "severity": "low",
                "line": line,
                "col": col,
                "snippet": snippet_of(node, source),
                "message": (
                    f"fn `{name}`: logging macro emits shielded-secret value "
                    f"`{secret_token}` via Debug/Display format specifier. "
                    "Nullifiers, note commitments, spending/viewing keys, "
                    "value balances, and memos are privacy-sensitive ZCash "
                    "protocol data — emitting them to a log sink (even at "
                    "TRACE level) can leak transaction graph information to "
                    "any party with access to node logs. Wrap the value with "
                    "a redacting Display adapter or remove the field from the "
                    "log call."
                ),
            })

    return hits
