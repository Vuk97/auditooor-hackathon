"""
r94_loop_soroban_recipient_domain_validation_missing.py

Flags narrow Soroban recipient-domain validation gaps on public
`#[contractimpl]` entrypoints named `withdraw_to`, `repay_for`,
`transfer_to`, or `repay` when they accept a recipient-like `Address`
parameter and do not perform any zero / self / auth check on it.

Scope is intentionally tight:
- Rust / Soroban only
- pub fns inside `#[contractimpl]`
- function names limited to withdraw_to / repay_for / transfer_to / repay
- recipient-like Address params only
- suppression only for obvious zero/self/auth checks on that param
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


_TARGET_FN_RE = re.compile(r"^(withdraw_to|repay_for|transfer_to|repay)$")
_RECIPIENT_PARAM_RE = re.compile(
    r"\b(to|recipient|receiver|beneficiary|dst|on_behalf_of)\s*:\s*&?\s*Address\b"
)
_STRING_RE = re.compile(
    r"(?s)b?r#*\".*?\"#*|b?\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'"
)
_TRIVIAL_ALIAS_RE = re.compile(
    r"\blet\s+(?:mut\s+)?(?P<alias>[A-Za-z_]\w*)\s*(?::[^=;]+)?="
    r"\s*&?\s*(?P<src>[A-Za-z_]\w*)(?:\s*\.\s*clone\s*\(\s*\))?\s*;"
)
_BOOL_ALIAS_RE = re.compile(
    r"\blet\s+(?:mut\s+)?(?P<alias>[A-Za-z_]\w*)\s*(?::[^=;]+)?="
    r"\s*(?P<expr>[^;]+);"
)

_COND_TEMPLATE = (
    r"\b{name}\b\s*(?:==|!=)\s*Address::(?:zero|default)\s*\([^)]*\)|"
    r"Address::(?:zero|default)\s*\([^)]*\)\s*(?:==|!=)\s*\b{name}\b|"
    r"\b{name}\b\s*(?:==|!=)\s*{ident}current_contract_address\s*\(\s*\)|"
    r"{ident}current_contract_address\s*\(\s*\)\s*(?:==|!=)\s*\b{name}\b|"
    r"is_whitelisted\s*\([^)]*\b{name}\b|"
    r"whitelist\s*(?:\(\s*\))?\.(?:contains|get)\s*\([^)]*\b{name}\b|"
    r"allowed_recipients?\s*(?:\(\s*\))?\.(?:contains|get)\s*\([^)]*\b{name}\b"
)
_GUARD_PREFIXES = (
    r"if\s*!?\s*\(?\s*",
    r"assert(?:_eq|_ne)?!\s*\([^)]*",
    r"(?:require|ensure)!\s*\([^)]*",
)


def _blank_preserve_newlines(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_string_literals(src: str) -> str:
    return _STRING_RE.sub(_blank_preserve_newlines, src)


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
            if match:
                names.append(match.group(1))
    return names


def _trivial_aliases(body_nc: str, param: str) -> list[str]:
    names = {param}
    changed = True
    while changed:
        changed = False
        for match in _TRIVIAL_ALIAS_RE.finditer(body_nc):
            src = match.group("src")
            alias = match.group("alias")
            if src not in names or alias in names:
                continue
            names.add(alias)
            changed = True
    return sorted(names)


def _validation_expr_re(name: str) -> re.Pattern[str]:
    cond = _COND_TEMPLATE.format(name=re.escape(name), ident=r"[\w\.]*")
    return re.compile(cond)


def _bool_aliases(body_nc: str, names: list[str]) -> list[str]:
    aliases: set[str] = set()
    changed = True
    while changed:
        changed = False
        for match in _BOOL_ALIAS_RE.finditer(body_nc):
            alias = match.group("alias")
            expr = match.group("expr")
            if alias in aliases or alias in names:
                continue
            if any(_validation_expr_re(name).search(expr) for name in names) or any(
                re.search(rf"\b{re.escape(src)}\b", expr) for src in aliases
            ):
                aliases.add(alias)
                changed = True
    return sorted(aliases)


def _bool_alias_guarded(body_nc: str, aliases: list[str]) -> bool:
    if not aliases:
        return False
    alias_pat = "|".join(re.escape(alias) for alias in aliases)
    return re.search(
        rf"\bif\s*!?\s*\(?\s*\b(?:{alias_pat})\b|"
        rf"\bassert(?:_eq|_ne)?!\s*\([^)]*\b(?:{alias_pat})\b|"
        rf"\b(?:require|ensure)!\s*\([^)]*\b(?:{alias_pat})\b",
        body_nc,
    ) is not None


def _has_validation(body_nc: str, names: list[str]) -> bool:
    auth_names = "|".join(re.escape(name) for name in names)
    if re.search(
        rf"\b(?:{auth_names})\b\s*\.\s*require_auth\s*\(|"
        rf"require_auth_for_args\s*\([^)]*\b(?:{auth_names})\b",
        body_nc,
    ):
        return True

    for name in names:
        cond = _validation_expr_re(name).pattern
        for prefix in _GUARD_PREFIXES:
            if re.search(prefix + cond, body_nc):
                return True

    if _bool_alias_guarded(body_nc, _bool_aliases(body_nc, names)):
        return True
    return False


def _sink_uses_param(body_nc: str, names: list[str]) -> bool:
    escaped = "|".join(re.escape(name) for name in names)
    return re.search(
        rf"\b(?:transfer_to|repay|token_send|credit_repay)\s*\([^)]*\b(?:{escaped})\b",
        body_nc,
    ) is not None


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _TARGET_FN_RE.fullmatch(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        params = _recipient_params(fn, source)
        if not params:
            continue
        body_nc = _strip_string_literals(body_text_nocomment(body, source))
        for param in params:
            names = _trivial_aliases(body_nc, param)
            if not _sink_uses_param(body_nc, names):
                continue
            if _has_validation(body_nc, names):
                continue
            line, col = line_col(fn)
            hits.append(
                {
                    "severity": "low",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source)[:200],
                    "message": (
                        f"pub fn `{name}` accepts recipient-like Address `{param}` "
                        f"without zero/self/auth validation "
                        f"(Soroban recipient-domain validation missing)."
                    ),
                }
            )
    return hits
