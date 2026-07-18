"""
rust_proxy_user_controlled_delegate_target.py

Flags Rust proxy or proxy-like authority routes where a public function lets
an attacker seize execution authority:

1. caller-supplied implementation, code hash, or delegate target is stored or
   invoked without an admin gate or implementation allowlist;
2. caller-supplied external client address is used as the execution counterparty
   without an asset allowlist;
3. first caller initializes bridge or route authority without authorization;
4. non-upgradeable ownership is used in a proxy or Initializable context.

This encodes the proxy-hijack primitive, not a fixture string: attacker input
becomes the execution authority for later proxy dispatch.
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


_PROXY_CONTEXT_RE = re.compile(
    r"(?i)\b(?:"
    r"ProxyState|Upgradeable|UpgradeableProxy|TransparentProxy|"
    r"proxy|implementation|implementation_hash|delegate_target|"
    r"runtime_code_hash|code_hash|upgrade_authority|upgrade_admin|"
    r"program_id|invoke_signed|delegate_call|call_contract"
    r")\b"
)

_ENTRY_NAME_RE = re.compile(
    r"(?i)(?:"
    r"initialize|init|setup|instantiate|deploy|create|configure|upgrade|"
    r"set_implementation|set_delegate|set_code_hash|execute|dispatch|"
    r"fallback|proxy_call|delegate_call"
    r")"
)

_TARGET_PARAM_RE = re.compile(
    r"\b(?P<name>"
    r"(?:new_)?(?:implementation|implementation_hash|impl_hash|"
    r"delegate_target|target_program|target_contract|target|program_id|"
    r"runtime_code_hash|code_hash|logic)"
    r")\s*:",
    re.IGNORECASE,
)

_ADDR_PARAM_RE = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?:&\s*)?Address\b"
)

_CONTROLLED_STORE_TEMPLATE = (
    r"(?is)\b[A-Za-z_][A-Za-z0-9_\.]*\s*\.\s*"
    r"(?:implementation|implementation_hash|impl_hash|delegate_target|"
    r"target_program|runtime_code_hash|code_hash|program_id|logic)"
    r"\s*=\s*{param}\b"
)

_CONTROLLED_EXEC_TEMPLATE = (
    r"(?is)(?:"
    r"program_id\s*:\s*{param}\b|"
    r"(?:invoke|invoke_signed|delegate_call|call_contract|wasm_execute)"
    r"\s*\([^;{{}}]{{0,260}}{param}\b"
    r")"
)

_ADMIN_OR_IMPL_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"require_keys_eq!\s*\(|assert_keys_eq!\s*\(|"
    r"require_admin\s*\(|require_owner\s*\(|only_owner|only_admin|"
    r"ensure_?(?:owner|admin|governance|governor)\s*\(|"
    r"has_role\s*\(|is_admin\s*\(|is_owner\s*\(|"
    r"configured_admin|expected_admin|governance_admin|multisig_admin|"
    r"implementation_registry|impl_registry|approved_impl|"
    r"approved_implementation|trusted_implementation|allowed_implementation|"
    r"known_code_hash|expected_implementation|verify_code_hash|"
    r"is_approved_implementation|is_allowed_implementation|"
    r"approved_implementations\s*\.\s*contains|"
    r"allowed_implementations\s*\.\s*contains|"
    r"trusted_implementations\s*\.\s*contains|"
    r"allowed_code_hashes\s*\.\s*contains|"
    r"approved_code_hashes\s*\.\s*contains"
    r")"
)

_CLIENT_PATTERNS = [
    r"TokenClient\s*::\s*new\s*\(",
    r"token\s*::\s*Client\s*::\s*new\s*\(",
    r"sep41\s*::\s*Client\s*::\s*new\s*\(",
    r"StellarAssetClient\s*::\s*new\s*\(",
]

_CLIENT_EFFECT_RE = re.compile(
    r"(?is)\.(?:transfer|transfer_from|burn|mint|burn_from)\s*\("
)

_DEPOSIT_LIKE_FN_RE = re.compile(r"(?i)(?:deposit|stake|supply|wrap)")

_INFLOW_TO_CONTRACT_RE = re.compile(
    r"(?is)\.(?:transfer|transfer_from)\s*\([^;{}]{0,180}"
    r"current_contract_address\s*\("
)

_ASSET_VALIDATION_RE = re.compile(
    r"(?is)(?:"
    r"assert_allowed_token|validate_asset|is_listed|get_reserve|"
    r"asset_registry|require_listed|check_reserve|has_reserve|"
    r"whitelist|allowlist|approved_asset|approved_token"
    r")"
)

_ROUTE_CONTEXT_RE = re.compile(
    r"(?i)\b(?:bridge|gateway|route|path|chain|lane|remote|peer|"
    r"trusted_remote|registry|config)\b"
)

_ROUTE_WRITE_RE = re.compile(
    r"(?is)(?:"
    r"(?:\b\w+\s*\.\s*)?\w*(?:rout|gateway|chain|peer|remote|registry|config)\w*"
    r"\s*\.\s*(?:insert|set|push)\s*\(|"
    r"self\s*\.\s*\w*(?:rout|gateway|chain|peer|remote|registry|"
    r"config|owner|admin|authority)\w*\s*="
    r")"
)

_ROUTE_AUTH_RE = re.compile(
    r"(?is)(?:"
    r"\.require_auth\s*\(|require_auth\s*\(|require_admin\s*\(|"
    r"require_owner\s*\(|ensure_?(?:owner|admin|governance|governor|"
    r"factory|deployer)\s*\(|assert_?(?:owner|admin)\s*\(|"
    r"check_?(?:owner|admin|role)\s*\(|has_role\s*\(|"
    r"only_?(?:owner|admin|governance|governor|factory|deployer)"
    r")"
)

_ROUTE_FIRST_WRITE_RE = re.compile(
    r"(?is)(?:"
    r"contains_key\s*\(|\.has\s*\(|\.get\s*\([^;{}]{0,160}\)\s*"
    r"\.\s*is_(?:none|some)\s*\(|is_empty\s*\(|len\s*\(\s*\)\s*==\s*0|"
    r"already_(?:initialized|registered)|route_exists|not_registered|"
    r"initialized|registered|created"
    r")"
)

_SOURCE_CHAIN_RE = re.compile(
    r"(?i)\b(?:source|src|origin|from)[a-z0-9_]*(?:chain|domain|id)[a-z0-9_]*\b"
)

_DEST_CHAIN_RE = re.compile(
    r"(?i)\b(?:destination|dest|dst|remote|target|to)[a-z0-9_]*"
    r"(?:chain|domain|id)[a-z0-9_]*\b"
)

_SAME_CHAIN_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"assert_ne!\s*\(\s*[^,;{}]*(?:source|src|origin|from)[^,;{}]*,\s*"
    r"[^,;{}]*(?:destination|dest|dst|remote|target|to)|"
    r"SameChain|InvalidSameChain|same_chain"
    r")"
)

_OWNABLE_NON_UPGRADEABLE_RE = re.compile(
    r'import\s+["\'][^"\']*openzeppelin[^"\']*/access/Ownable\.sol["\']|'
    r'use\s+openzeppelin::access::ownable::Ownable\b|'
    r"import\s+\{\s*Ownable\s*\}\s+from"
)

_UPGRADEABLE_CONTEXT_RE = re.compile(
    r"Initializable|UUPSUpgradeable|TransparentUpgradeableProxy|"
    r"fn\s+initialize\s*\(|ContextUpgradeable"
)

_OWNABLE_UPGRADEABLE_RE = re.compile(
    r"OwnableUpgradeable|Ownable2StepUpgradeable"
)


def _target_param_names(fn_text: str) -> list[str]:
    names: list[str] = []
    for match in _TARGET_PARAM_RE.finditer(fn_text):
        name = match.group("name")
        if name not in names:
            names.append(name)
    return names


def _address_param_names(fn_text: str) -> list[str]:
    names: list[str] = []
    for match in _ADDR_PARAM_RE.finditer(fn_text):
        name = match.group("name")
        if name not in names:
            names.append(name)
    return names


def _target_flows_to_store_or_exec(body_text: str, param: str) -> str | None:
    escaped = re.escape(param)
    if re.search(_CONTROLLED_STORE_TEMPLATE.format(param=escaped), body_text):
        return "stored as proxy implementation or delegate target"
    if re.search(_CONTROLLED_EXEC_TEMPLATE.format(param=escaped), body_text):
        return "used as proxy execution target"
    return None


def _client_target_flow(name: str, body_text: str, param: str) -> str | None:
    if not _DEPOSIT_LIKE_FN_RE.search(name):
        return None
    if _ASSET_VALIDATION_RE.search(body_text):
        return None
    if not _CLIENT_EFFECT_RE.search(body_text):
        return None
    if not _INFLOW_TO_CONTRACT_RE.search(body_text):
        return None
    for pattern in _CLIENT_PATTERNS:
        if re.search(pattern + r"[^;{}]{0,180}&?" + re.escape(param) + r"\b", body_text):
            return "uses caller-controlled external client as execution counterparty"
    return None


def _route_initializer_flow(fn_text: str, body_text: str) -> str | None:
    if not _ROUTE_CONTEXT_RE.search(fn_text):
        return None
    if not _ROUTE_WRITE_RE.search(body_text):
        return None
    if _ROUTE_AUTH_RE.search(body_text):
        return None

    has_source_dest = bool(_SOURCE_CHAIN_RE.search(fn_text) and _DEST_CHAIN_RE.search(fn_text))
    missing_same_chain_guard = has_source_dest and not _SAME_CHAIN_GUARD_RE.search(body_text)
    first_write_only = bool(_ROUTE_FIRST_WRITE_RE.search(body_text))
    if missing_same_chain_guard or first_write_only:
        return "lets the first caller claim bridge or proxy route authority"
    return None


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    source_text = source_nocomment(source)
    if (
        _OWNABLE_NON_UPGRADEABLE_RE.search(source_text)
        and _UPGRADEABLE_CONTEXT_RE.search(source_text)
        and not _OWNABLE_UPGRADEABLE_RE.search(source_text)
    ):
        hits.append({
            "severity": "high",
            "line": 1,
            "col": 0,
            "snippet": source_text[:200],
            "message": (
                "Upgradeable or proxy-like Rust source imports non-upgradeable "
                "Ownable. The proxy initialization path can lose or misbind "
                "owner authority; use an upgrade-safe owner initializer."
            ),
        })

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        fn_text = text_of(fn, source)
        body_nc = body_text_nocomment(body, source)

        flow: str | None = None
        param_for_message = ""

        if (
            (_ENTRY_NAME_RE.search(name) or _PROXY_CONTEXT_RE.search(body_nc))
            and not _ADMIN_OR_IMPL_GUARD_RE.search(body_nc)
        ):
            for param in _target_param_names(fn_text):
                flow = _target_flows_to_store_or_exec(body_nc, param)
                if flow is not None:
                    param_for_message = param
                    break

        if flow is None:
            for param in _address_param_names(fn_text):
                flow = _client_target_flow(name, body_nc, param)
                if flow is not None:
                    param_for_message = param
                    break

        if flow is None and _ENTRY_NAME_RE.search(name):
            flow = _route_initializer_flow(fn_text, body_nc)
            if flow is not None:
                param_for_message = "route configuration"

        if flow is None:
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source, 240),
            "message": (
                f"pub fn `{name}` accepts caller-supplied `{param_for_message}` "
                f"and {flow} without an admin gate or implementation allowlist. "
                f"An attacker can seize proxy execution authority."
            ),
        })
        continue

    return hits
