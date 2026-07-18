"""
anchor_signer_check_missing_on_authority.py

Anchor / Solana class: handler function takes an `authority: Signer<'info>`
or `authority: AccountInfo<'info>` parameter but never verifies the key or
the signer flag.

Heuristic:
  1. Function body references a field named `authority` / `admin` / `owner`
     / `payer`.
  2. Function body or the handler's context struct's attribute set does
     NOT contain any of:
         `is_signer`, `.key()` comparison, `require_keys_eq!`,
         `has_one = authority`, `signer = authority`, `#[account(signer)]`,
         `Signer<`.
  3. The same file declares a `Ctx<'info>` struct that carries an
     `authority` field with NO `Signer<` / `#[account(signer)]`.

Implementation: we text-search for `authority : AccountInfo<'info>` on
struct fields (the risky form) AND flag any handler whose body doesn't
verify it.

Fixtures test against text patterns — we don't need real anchor compile.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, line_col, snippet_of,
    in_test_cfg,
)


_AUTHORITY_NAMES = ("authority", "admin", "owner", "payer")

_VERIFY_PATTERNS = (
    r"\.is_signer\b",
    r"require_keys_eq!\s*\(",
    r"has_one\s*=",
    r"signer\s*=",
    r"#\[\s*account\s*\([^)]*signer",
    r"assert_keys_eq!\s*\(",
    r"Signer\s*<",
)


_ANCHOR_MARKER_RE = re.compile(
    r"(#\[derive\(Accounts\)\]|AccountInfo\s*<|Signer\s*<|"
    r"anchor_lang::|use\s+anchor_lang)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    text = source.decode("utf-8", errors="replace")
    # Only run on files that look like Anchor programs.
    if not _ANCHOR_MARKER_RE.search(text):
        return hits
    # Look for struct fields declared as `authority: AccountInfo<'info>`
    # (risky — not Signer<>)
    risky_field_re = re.compile(
        r"\b(authority|admin|owner|payer)\s*:\s*AccountInfo\s*<"
    )
    field_hits = list(risky_field_re.finditer(text))
    if not field_hits:
        # No risky struct field — still scan handlers that take Signer but
        # don't check keys
        pass

    # Scan functions
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)
        # Must reference authority identifier
        if not any(re.search(r"\b" + a + r"\b", body_text)
                   for a in _AUTHORITY_NAMES):
            continue
        # Must have at least one state mutation / signer-gated action
        if ".set(" not in body_text and "mutate" not in body_text and \
                "transfer" not in body_text and "token::" not in body_text:
            continue
        # Verified?
        if any(re.search(p, body_text) for p in _VERIFY_PATTERNS):
            continue
        # Also skip if the same file has the struct field declared as
        # `Signer<'info>` (positive safety signal).  Cross-check using text.
        if re.search(r"(authority|admin|owner|payer)\s*:\s*Signer\s*<",
                     text):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source, 200),
            "message": (
                f"fn `{name}` acts on `authority` / `admin` / `owner` "
                f"without verifying `is_signer` / `require_keys_eq!` / "
                f"`Signer<'info>` type — account substitution open."
            ),
        })
    return hits
