"""
admin_origin_or_role_guard_missing.py

Flags Rust privileged mutation handlers that write admin/config/upgrade
state without an origin, signer, owner, or role guard.

Target shapes:
  - Substrate dispatchables like set_config, set_admin, force_upgrade, or
    pause that write StorageValue/StorageMap state but omit ensure_root,
    ensure_signed, or a configured origin check.
  - Anchor handlers that update ctx.accounts.config/admin/authority state
    while the Context struct does not constrain the authority with Signer,
    has_one, constraint, or an explicit signer/account check.

This is broader than the existing Soroban require_auth and narrow Anchor
authority-field detectors. It targets same-class admin-bypass misses where
the privileged write is expressed as Rust storage mutation or Anchor account
field assignment rather than a Soroban contractimpl storage set.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
    source_nocomment,
    text_of,
)


_PRIVILEGED_NAME_RE = re.compile(
    r"(^|_)(set|update|force|grant|revoke|transfer|claim|become|"
    r"assume|rotate|change|upgrade|migrate|pause|unpause|sudo)"
    r"(_|$).*(admin|owner|role|config|authority|governance|governor|"
    r"operator|oracle|fee|treasury|upgrade|pause|code)|"
    r"^(set_config|update_config|set_admin|set_owner|grant_role|"
    r"revoke_role|upgrade|force_upgrade|set_code|set_params|set_fee|"
    r"set_oracle|set_treasury|set_authority|set_operator|pause|unpause)$",
    re.IGNORECASE,
)

_PRIVILEGED_BODY_RE = re.compile(
    r"(?i)\b(admin|owner|role|config|authority|governance|governor|"
    r"operator|oracle|fee|treasury|upgrade|pause|paused|code_hash|"
    r"runtime_code|params)\b"
)

_STATE_WRITE_RE = re.compile(
    r"(?x)"
    r"(?:"
    r"::\s*(?:put|insert|mutate|try_mutate|remove|kill)\s*\(|"
    r"\.\s*(?:put|insert|mutate|try_mutate|set|remove)\s*\(|"
    r"\bctx\s*\.\s*accounts\s*\.\s*\w+\s*\.\s*\w+\s*=|"
    r"\bself\s*\.\s*\w+\s*=|"
    r"\b\w+\s*\.\s*(?:admin|owner|role|config|authority|governance|"
    r"operator|oracle|fee|treasury|paused|code_hash|params)\s*="
    r")"
)

_GUARD_RE = re.compile(
    r"(?x)"
    r"(?:"
    r"ensure_root\s*\(|"
    r"ensure_signed\s*\(|"
    r"ensure_origin\s*\(|"
    r"RawOrigin\s*::\s*Root|"
    r"AdminOrigin\s*::\s*ensure_origin|"
    r"GovernanceOrigin\s*::\s*ensure_origin|"
    r"RootOrigin\s*::\s*ensure_origin|"
    r"SignedBy\s*<|"
    r"EnsureRoot\s*<|"
    r"ensure!\s*\([^;]*(?:admin|owner|authority|governance|operator|"
    r"role|is_root|has_role)|"
    r"assert(?:_eq|!)?\s*!\s*\([^;]*(?:admin|owner|authority|"
    r"governance|operator|role)|"
    r"\b(?:only|check|require|assert)_(?:admin|owner|governance|"
    r"authority|operator|role)\s*\(|"
    r"\.require_auth\s*\(|"
    r"\bhas_role\s*\(|"
    r"\.contains\s*\([^;]*(?:caller|who|sender|authority|admin)|"
    r"\.is_signer\b|"
    r"require_keys_eq!\s*\(|"
    r"assert_keys_eq!\s*\(|"
    r"\.owner\s*==|"
    r"\.key\s*\(\s*\)\s*=="
    r")"
)

_ANCHOR_MARKER_RE = re.compile(
    r"(anchor_lang::|use\s+anchor_lang|Context\s*<|AccountInfo\s*<|"
    r"Signer\s*<|#\[\s*derive\s*\(\s*Accounts\s*\)\s*\])"
)

_SUBSTRATE_MARKER_RE = re.compile(
    r"(frame_support|#\[\s*pallet::call\s*\]|OriginFor\s*<|"
    r"DispatchResult|StorageValue\s*<|StorageMap\s*<|ensure_root\s*\(|"
    r"ensure_signed\s*\()"
)

_ANCHOR_SAFE_RE = re.compile(
    r"(?x)"
    r"(?:"
    r"Signer\s*<|"
    r"has_one\s*=|"
    r"constraint\s*=|"
    r"\#\[\s*account\s*\([^)]*signer|"
    r"require_keys_eq!\s*\(|"
    r"assert_keys_eq!\s*\(|"
    r"\.is_signer\b|"
    r"\.owner\s*==|"
    r"\.key\s*\(\s*\)\s*=="
    r")"
)


def _signature_text(fn, source: bytes) -> str:
    full = text_of(fn, source)
    return full.split("{", 1)[0]


def _extract_braced_body(text: str, open_pos: int) -> str:
    depth = 0
    start = None
    for idx in range(open_pos, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
            if depth == 1:
                start = idx + 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                return text[start:idx]
    return ""


def _anchor_context_names(signature: str) -> list[str]:
    names = re.findall(r"Context\s*<\s*([A-Za-z_][A-Za-z0-9_]*)\s*>", signature)
    names.extend(
        match.group(2)
        for match in re.finditer(
            r"\b(ctx|context|accounts)\s*:\s*(?:&\s*)?([A-Za-z_][A-Za-z0-9_]*)",
            signature,
        )
    )
    return names


def _anchor_context_has_guard(signature: str, source_text: str) -> bool:
    for ctx_name in _anchor_context_names(signature):
        struct_match = re.search(r"\bstruct\s+" + re.escape(ctx_name) + r"\b", source_text)
        if not struct_match:
            continue
        open_pos = source_text.find("{", struct_match.end())
        if open_pos == -1:
            continue
        struct_body = _extract_braced_body(source_text, open_pos)
        if _ANCHOR_SAFE_RE.search(struct_body):
            return True
    return False


def _looks_privileged(name: str, body_text: str) -> bool:
    return bool(_PRIVILEGED_NAME_RE.search(name) or _PRIVILEGED_BODY_RE.search(body_text))


def _has_state_write(body_text: str) -> bool:
    return bool(_STATE_WRITE_RE.search(body_text))


def _has_guard(fn, body_text: str, source: bytes, source_text: str) -> bool:
    if _GUARD_RE.search(body_text):
        return True
    signature = _signature_text(fn, source)
    if _ANCHOR_MARKER_RE.search(source_text) and _anchor_context_has_guard(signature, source_text):
        return True
    return False


def _supported_surface(source_text: str) -> bool:
    return bool(_SUBSTRATE_MARKER_RE.search(source_text) or _ANCHOR_MARKER_RE.search(source_text))


def run(tree, source: bytes, filepath: str):
    hits = []
    source_text = source_nocomment(source)
    if not _supported_surface(source_text):
        return hits

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        body_nc = body_text_nocomment(body, source)
        if not _looks_privileged(name, body_nc):
            continue
        if not _has_state_write(body_nc):
            continue
        if _has_guard(fn, body_nc, source, source_text):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source, 220),
            "message": (
                f"pub fn `{name}` performs a privileged admin/config/"
                f"upgrade mutation without an origin, signer, owner, or "
                f"role guard. Add ensure_root/ensure_signed plus a role "
                f"check, or constrain the Anchor authority account."
            ),
        })

    return hits
