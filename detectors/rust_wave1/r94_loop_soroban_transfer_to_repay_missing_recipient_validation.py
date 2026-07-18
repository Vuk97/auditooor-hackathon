"""
r94_loop_soroban_transfer_to_repay_missing_recipient_validation.py

Flags Soroban-style `transfer_to(...)` or `repay(on_behalf_of, ...)`
flows that pass a recipient-like `Address` argument into the value sink
without validating that the address is nonzero, not the current
contract, and not otherwise restricted.

Confirmed source anchor:
- solodit-spec:drafts_rust_soroban:missing-recipient-validation:93e5bde0d21c

This detector stays intentionally narrow:
- Rust / Soroban only (`#[contractimpl]` pub fns)
- only recipient-like `Address` params
- only `transfer_to(...)` and `repay(...)` sink shapes
- suppressed when the body checks zero/self, whitelist, or auth on the
  recipient parameter
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    functions_in_contractimpl,
    is_pub,
    line_col,
    snippet_of,
    text_of,
)


_RECIPIENT_PARAM_RE = re.compile(
    r"\b(to|recipient|receiver|beneficiary|dst|on_behalf_of)\s*:\s*&?\s*Address\b"
)

_VALIDATION_TEMPLATE = (
    r"\b{param}\b\s*(?:==|!=)\s*Address::(?:zero|default)\s*\(|"
    r"Address::(?:zero|default)\s*\([^)]*\)\s*(?:==|!=)\s*\b{param}\b|"
    r"\b{param}\b\s*(?:==|!=)\s*{ident}current_contract_address\s*\(\s*\)|"
    r"{ident}current_contract_address\s*\(\s*\)\s*(?:==|!=)\s*\b{param}\b|"
    r"\b{param}\b\s*\.\s*require_auth\s*\(|"
    r"require_auth_for_args\s*\([^)]*\b{param}\b|"
    r"is_whitelisted\s*\([^)]*\b{param}\b|"
    r"whitelist\.(?:contains|get)\s*\([^)]*\b{param}\b|"
    r"allowed_recipients?\.(?:contains|get)\s*\([^)]*\b{param}\b"
)


def _recipient_params(fn_node, source: bytes) -> list[str]:
    names: list[str] = []
    for child in fn_node.children:
        if child.type != "parameters":
            continue
        for param in child.children:
            if param.type != "parameter":
                continue
            ptext = text_of(param, source)
            match = _RECIPIENT_PARAM_RE.search(ptext)
            if not match:
                continue
            names.append(match.group(1))
    return names


def _sink_uses_param(body_nc: str, param: str) -> bool:
    patterns = [
        rf"\btransfer_to\s*\([^)]*\b{re.escape(param)}\b[^)]*\)",
        rf"\brepay\s*\([^)]*\b{re.escape(param)}\b[^)]*\)",
    ]
    return any(re.search(pattern, body_nc) for pattern in patterns)


def _has_validation(body_nc: str, param: str) -> bool:
    pattern = _VALIDATION_TEMPLATE.format(param=re.escape(param), ident=r"[\w\.]*")
    return re.search(pattern, body_nc) is not None


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        params = _recipient_params(fn, source)
        if not params:
            continue
        body_nc = body_text_nocomment(body, source)
        for param in params:
            if not _sink_uses_param(body_nc, param):
                continue
            if _has_validation(body_nc, param):
                continue
            name = fn_name(fn, source)
            line, col = line_col(fn)
            hits.append(
                {
                    "severity": "low",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source)[:200],
                    "message": (
                        f"pub fn `{name}` passes recipient-like Address "
                        f"`{param}` into `transfer_to(...)` or `repay(...)` "
                        f"without zero/self/whitelist-or-auth validation "
                        f"(missing-recipient-validation, Soroban). "
                        f"See Halborn 7.20 / Solodit rust_soroban anchor."
                    ),
                }
            )
    return hits
