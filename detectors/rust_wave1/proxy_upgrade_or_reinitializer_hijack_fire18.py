"""
proxy_upgrade_or_reinitializer_hijack_fire18.py

Fire18 Rust recall lift for proxy-hijack class misses.

Flags proxy, upgrade, migration, baseline, or initializer state that can be
captured by the wrong actor, left unset after an upgrade, or initialized in a
per-user namespace without binding it to the current global baseline.

Detector hits are candidate evidence only. Filing work still needs R40, R76,
and R80 proof discipline.
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


_UPGRADE_CONTEXT_RE = re.compile(
    r"(?i)("
    r"proxy|upgrade|upgradable|implementation|impl_hash|code_hash|"
    r"runtime_code|delegate_target|initializer|reinitializer|migrate|"
    r"migration|baseline|checkpoint|accumulator|amount_claimed"
    r")"
)

_UPGRADE_FN_NAME_RE = re.compile(
    r"(?i)("
    r"^(?:init|initialize|setup|instantiate|configure|deploy|create|"
    r"upgrade|migrate|reinitialize)"
    r"|(?:proxy|upgrade|implementation|admin|owner|baseline|checkpoint|"
    r"migration|reinitializer|position)"
    r")"
)

_SELF_ADMIN_PROXY_NEW_RE = re.compile(
    r"(?is)\b(?:TransparentUpgradeableProxy|TransparentProxy|"
    r"UpgradeableProxy|Proxy)\s*::\s*new\s*\("
    r"[^;]{0,420},\s*"
    r"(?:address\s*\(\s*this\s*\)|address_of\s*\(\s*self\s*\)|"
    r"address_of\s*\(\s*Self\s*\)|self\s*\.\s*addr|"
    r"env\s*\.\s*current_contract_address\s*\(\s*\)|"
    r"env\s*\.\s*invoker\s*\(\s*\)|caller\s*\(\s*\)|"
    r"msg_sender\s*\(\s*\)|ctx\s*\.\s*accounts\s*\.\s*"
    r"(?:deployer|factory|payer|signer)\s*\.\s*key\s*\(\s*\)|"
    r"(?:deployer|factory|payer|caller|signer))"
)

_SENSITIVE_UPGRADE_WRITE_RE = re.compile(
    r"(?is)(?P<lhs>"
    r"(?:self|state|proxy_state|config|storage|ctx\s*\.\s*accounts\s*"
    r"\.\s*[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"[A-Za-z0-9_]*"
    r"(?:admin|owner|implementation|upgrade_authority|upgrade_admin|"
    r"proxy_admin|delegate_target|code_hash|impl_hash|baseline|"
    r"checkpoint)"
    r"[A-Za-z0-9_]*"
    r")\s*=\s*(?P<rhs>[^;\n]+)"
    r"|"
    r"\b(?P<map>[A-Za-z_][A-Za-z0-9_]*"
    r"(?:admin|owner|implementation|upgrade|proxy|baseline|checkpoint)"
    r"[A-Za-z0-9_]*)\s*\.\s*(?:insert|set)\s*\("
)

_WRONG_ACTOR_RHS_RE = re.compile(
    r"(?is)\b("
    r"env\s*\.\s*invoker\s*\(\s*\)|caller\s*\(\s*\)|msg_sender\s*\(\s*\)|"
    r"ctx\s*\.\s*accounts\s*\.\s*(?:deployer|factory|payer|caller|"
    r"signer|initializer)\s*\.\s*key\s*\(\s*\)|"
    r"\b(?:deployer|factory|payer|caller|signer|initializer)\b|"
    r"Default\s*::\s*default\s*\(\s*\)|Pubkey\s*::\s*default\s*\(\s*\)|"
    r"None|0(?:u\d+)?"
    r")"
)

_AUTH_GUARD_RE = re.compile(
    r"(?is)("
    r"\.require_auth(?:_for_args)?\s*\(|"
    r"require_(?:admin|owner|governance|authority|operator)\s*\(|"
    r"ensure_(?:admin|owner|governance|authority|operator|root)\s*\(|"
    r"check_(?:admin|owner|governance|authority|operator)\s*\(|"
    r"only_(?:admin|owner|governance|authority|operator)|"
    r"has_role\s*\(|require_keys_eq!\s*\(|assert_keys_eq!\s*\(|"
    r"ensure!\s*\([^;]{0,360}(?:caller|sender|signer|authority|who|"
    r"admin|owner)[^;]{0,360}(?:==|!=|has_role|contains|is_admin|"
    r"is_owner)"
    r")"
)

_ONCE_GUARD_RE = re.compile(
    r"(?is)("
    r"initialized\s*==\s*false|!\s*[A-Za-z_][A-Za-z0-9_\.]*initialized|"
    r"AlreadyInitialized|NotInitialized|init_once|once_cell|set_once|"
    r"reinitializer\s*\(\s*\d+\s*\)|initialize_v?\d+|"
    r"version\s*(?:<|==)\s*\d+|migration_version\s*(?:<|==)\s*\d+"
    r")"
)

_CONFIGURED_AUTHORITY_RE = re.compile(
    r"(?i)\b("
    r"configured_(?:admin|owner|authority|implementation)|"
    r"expected_(?:admin|owner|authority|implementation)|"
    r"trusted_(?:admin|owner|authority)|governance_(?:admin|owner)|"
    r"multisig_(?:admin|owner)|proxy_admin_arg|admin_authority|"
    r"owner_authority|upgrade_authority_input"
    r")\b"
)

_GLOBAL_ACC_RE = re.compile(
    r"(?i)\b("
    r"amount_claimable_per_share|reward_per_token_stored|global_index|"
    r"current_index|accumulator|baseline_index|checkpoint_index"
    r")\b"
)

_POSITION_WRITE_RE = re.compile(
    r"(?is)("
    r"positions?\s*\.\s*insert\s*\(|positions?\s*\[[^\]]+\]\s*=|"
    r"Position\s*\{|new_position\s*=\s*Position"
    r")"
)

_BASELINE_ZERO_RE = re.compile(
    r"(?is)\b("
    r"amount_claimed|baseline|checkpoint|reward_debt|user_index"
    r")\s*:\s*(?:0|Default\s*::\s*default\s*\(\s*\)|None)\b"
)

_BASELINE_FROM_GLOBAL_RE = re.compile(
    r"(?is)\b("
    r"amount_claimed|baseline|checkpoint|reward_debt|user_index"
    r")\s*:\s*[^,;{}]*(?:amount_claimable_per_share|reward_per_token_stored|"
    r"global_index|current_index|accumulator|baseline_index|checkpoint_index)"
    r"|"
    r"\.(?:amount_claimed|baseline|checkpoint|reward_debt|user_index)\s*="
    r"[^;]*(?:amount_claimable_per_share|reward_per_token_stored|"
    r"global_index|current_index|accumulator|baseline_index|checkpoint_index)"
)

_MIGRATION_MARKER_RE = re.compile(
    r"(?i)(//\s*(?:moved|migrated|was|previously)\s+(?:from|in)|"
    r"///\s*(?:moved|migrated|was|previously)\s+(?:from|in)|"
    r"#\s*\[\s*doc\s*=\s*\"\s*(?:moved|migrated|was|previously)\s+"
    r"(?:from|in))"
)

_REINITIALIZER_RE = re.compile(
    r"(?is)\b("
    r"reinitializer\s*\(\s*\d+\s*\)|fn\s+(?:reinitialize|"
    r"initialize_v\d+|initialize_v_\d+|initialize_v\d+_migration|"
    r"migrate_init|migrate_v\d+)\s*\("
    r")"
)


def _safe_upgrade_write(body_text: str, rhs: str) -> bool:
    if not _AUTH_GUARD_RE.search(body_text):
        return False
    if not (_ONCE_GUARD_RE.search(body_text) or _CONFIGURED_AUTHORITY_RE.search(rhs)):
        return False
    if _WRONG_ACTOR_RHS_RE.search(rhs):
        return False
    return True


def _migration_marker_hit(raw_source: str) -> dict | None:
    marker = _MIGRATION_MARKER_RE.search(raw_source)
    if not marker:
        return None
    if _REINITIALIZER_RE.search(raw_source):
        return None

    line = raw_source.count("\n", 0, marker.start()) + 1
    return {
        "severity": "high",
        "line": line,
        "col": 0,
        "snippet": " ".join(raw_source[marker.start():marker.start() + 220].split()),
        "message": (
            "Migration marker says upgrade storage moved from another module, "
            "but no reinitializer or versioned migration initializer exists. "
            "The migrated proxy or implementation state can remain default."
        ),
    }


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    raw_source = source.decode("utf-8", errors="ignore")
    source_text = source_nocomment(source)

    migration_hit = _migration_marker_hit(raw_source)
    if migration_hit is not None:
        hits.append(migration_hit)

    if not _UPGRADE_CONTEXT_RE.search(source_text):
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
        full_text = text_of(fn, source)
        body_nc = body_text_nocomment(body, source)
        fn_context = f"{name}\n{full_text}"
        if not _UPGRADE_CONTEXT_RE.search(fn_context):
            continue

        line, col = line_col(fn)

        if _SELF_ADMIN_PROXY_NEW_RE.search(body_nc):
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source, 220),
                "message": (
                    f"pub fn `{name}` creates an upgradeable proxy with the "
                    "factory, caller, or current contract as admin. The "
                    "proxy admin can be hijacked or made unable to upgrade."
                ),
            })
            continue

        if _GLOBAL_ACC_RE.search(full_text) and _POSITION_WRITE_RE.search(body_nc):
            has_baseline_zero = bool(_BASELINE_ZERO_RE.search(body_nc))
            has_global_baseline = bool(_BASELINE_FROM_GLOBAL_RE.search(body_nc))
            if has_baseline_zero or not has_global_baseline:
                hits.append({
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source, 220),
                    "message": (
                        f"pub fn `{name}` creates per-user baseline state "
                        "while a global accumulator is in scope, but the new "
                        "position is not bound to the current global baseline. "
                        "A user can capture a context-free baseline."
                    ),
                })
                continue

        if not _UPGRADE_FN_NAME_RE.search(name):
            continue

        write = _SENSITIVE_UPGRADE_WRITE_RE.search(body_nc)
        if not write:
            continue

        rhs = write.groupdict().get("rhs") or ""
        if _safe_upgrade_write(body_nc, rhs):
            continue

        if _WRONG_ACTOR_RHS_RE.search(rhs):
            reason = "writes authority from caller, deployer, self, or default state"
        elif not _AUTH_GUARD_RE.search(body_nc):
            reason = "writes upgrade or initializer state without an owner/admin guard"
        elif not _ONCE_GUARD_RE.search(body_nc):
            reason = "writes initializer state without once-only or versioned state"
        else:
            reason = "writes upgrade state without a configured authority binding"

        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source, 220),
            "message": (
                f"pub fn `{name}` {reason}. Durable proxy, implementation, "
                "admin, owner, or initializer state can be captured or "
                "reinitialized by the wrong actor."
            ),
        })

    return hits
