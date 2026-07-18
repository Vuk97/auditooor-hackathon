"""
rust_proxy_init_owner_hijack_missing_admin_binding.py

Flags Rust proxy or component initialization paths that bind the proxy owner,
admin, or upgrade authority to the deployer, payer, caller, or a default value
instead of an explicit configured authority.

This is intentionally narrower than the generic initialize frontrun detectors:
the source must look proxy/component/upgrade-like and the assignment must write
an admin-like field from an ambient actor or default. A safe path that uses a
configured, expected, governance, or multisig admin binding is suppressed.
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
)


_INIT_PROXY_NAME_RE = re.compile(
    r"(?i)(?:"
    r"(?:initialize|init|setup|instantiate|deploy|create|configure)"
    r"[A-Za-z0-9_]*(?:proxy|component|upgrade|implementation)|"
    r"(?:proxy|component|upgrade)[A-Za-z0-9_]*(?:initialize|init|setup)"
    r")"
)

_PROXY_CONTEXT_RE = re.compile(
    r"(?i)\b(?:"
    r"ProxyState|Upgradeable|TransparentProxy|UpgradeableProxy|"
    r"implementation|implementation_hash|implementation_key|"
    r"upgrade_authority|upgrade_admin|proxy_admin|component_admin|"
    r"component_owner|delegate_target|runtime_code_hash|code_hash|"
    r"impl_hash|upgrade"
    r")\b"
)

_BAD_ADMIN_BINDING_RE = re.compile(
    r"(?P<lhs>"
    r"(?:ctx\s*\.\s*accounts\s*\.\s*)?"
    r"[A-Za-z_][A-Za-z0-9_\.]*"
    r"\s*\.\s*"
    r"(?:admin|owner|upgrade_authority|upgrade_admin|proxy_admin|"
    r"component_admin|component_owner|authority)"
    r")"
    r"\s*=\s*"
    r"(?P<rhs>"
    r"ctx\s*\.\s*accounts\s*\.\s*"
    r"(?:deployer|payer|initializer|creator|caller|signer)"
    r"\s*\.\s*key\s*\(\s*\)|"
    r"(?:deployer|payer|initializer|creator|caller|signer)"
    r"(?:\s*\.\s*key\s*\(\s*\))?|"
    r"env\s*\.\s*invoker\s*\(\s*\)|"
    r"caller\s*\(\s*\)|"
    r"msg_sender\s*\(\s*\)|"
    r"Default\s*::\s*default\s*\(\s*\)|"
    r"Pubkey\s*::\s*default\s*\(\s*\)|"
    r"[A-Za-z_][A-Za-z0-9_:]*\s*::\s*default\s*\(\s*\)|"
    r"None|0(?:u\d+)?"
    r")",
    re.DOTALL,
)

_CONFIGURED_ADMIN_BINDING_RE = re.compile(
    r"(?i)\b(?:"
    r"configured_admin|expected_admin|trusted_admin|governance_admin|"
    r"multisig_admin|root_admin|initial_admin|proxy_admin_arg|"
    r"admin_authority|owner_authority|upgrade_authority_input"
    r")\b|"
    r"require_keys_eq!\s*\(|"
    r"assert_keys_eq!\s*\(|"
    r"ensure!\s*\([^;]*(?:configured|expected|trusted|governance|"
    r"multisig|admin_authority|upgrade_authority)",
    re.DOTALL,
)


def _looks_like_proxy_init(name: str, body_text: str, source_text: str) -> bool:
    if _INIT_PROXY_NAME_RE.search(name):
        return True
    if not re.search(r"(?i)^(initialize|init|setup|instantiate)$", name):
        return False
    return bool(_PROXY_CONTEXT_RE.search(body_text) or _PROXY_CONTEXT_RE.search(source_text))


def _has_configured_admin_binding(body_text: str) -> bool:
    return bool(_CONFIGURED_ADMIN_BINDING_RE.search(body_text))


def run(tree, source: bytes, filepath: str):
    hits = []
    source_text = source_nocomment(source)
    if not _PROXY_CONTEXT_RE.search(source_text):
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
        if not _looks_like_proxy_init(name, body_nc, source_text):
            continue
        if _has_configured_admin_binding(body_nc):
            continue

        match = _BAD_ADMIN_BINDING_RE.search(body_nc)
        if not match:
            continue

        line, col = line_col(fn)
        lhs = " ".join(match.group("lhs").split())
        rhs = " ".join(match.group("rhs").split())
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source, 220),
            "message": (
                f"pub fn `{name}` initializes proxy/component authority "
                f"`{lhs}` from `{rhs}` instead of a configured admin. "
                f"An attacker-controlled deployer/caller can become the "
                f"upgrade authority; pass and verify an explicit admin "
                f"binding."
            ),
        })

    return hits
