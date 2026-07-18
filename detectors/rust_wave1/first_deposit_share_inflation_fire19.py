"""
first_deposit_share_inflation_fire19.py

Rust same-class lift for first-depositor-inflation recall gaps.

Flags ERC4626-like or share-vault code where an empty-supply deposit path,
donatable asset denominator, preview/convert rounding mismatch, or zero-share
mint path can inflate the share price for later users. The detector stays
quiet when the source has explicit virtual assets/shares, dead shares, or
minimum-share checks.
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


_ENTRYPOINT_RE = re.compile(
    r"(?i)^(deposit|deposit_to|mint|mint_shares|stake|join|join_pool|"
    r"add_liquidity|wrap|subscribe)$"
)

_SAFE_MITIGATION_RE = re.compile(
    r"(?i)(VIRTUAL_(?:SHARES|ASSETS)|virtual_(?:shares|assets)|"
    r"DEAD_SHARES|dead_shares|INITIAL_DEAD_SHARES|MIN_LIQUIDITY|"
    r"MINIMUM_LIQUIDITY|MIN_SHARES|MINIMUM_SHARES|min_shares_out|"
    r"initial_shares|burn_dead_shares|lock_minimum|seed_liquidity)"
)

_SAFE_MIN_SHARE_GUARD_RE = re.compile(
    r"(?i)(ensure!|require!|assert!|if)\s*\([^;\n]{0,220}"
    r"(?:shares|share_amount)[^;\n]{0,80}(?:>=|>|<)"
    r"[^;\n]{0,80}(?:MIN_|minimum|min_)"
)

_SHARE_TOTAL_RE = re.compile(r"(?i)(total_shares|total_supply|share_supply|supply)")
_ASSET_TOTAL_RE = re.compile(r"(?i)(total_assets|asset_balance|managed_assets|assets)")
_SHARE_FORMULA_RE = re.compile(
    r"(?is)("
    r"(?:assets|amount|deposit_amount|share_amount|shares)\s*"
    r"(?:\.checked_mul\s*\([^;]{0,120}(?:total_supply|total_shares|share_supply|supply)"
    r"|[*]\s*(?:self\.)?(?:total_supply|total_shares|share_supply|supply))"
    r"[^;]{0,260}"
    r"(?:\.checked_div\s*\([^;]{0,120}(?:total_assets|asset_balance|managed_assets)"
    r"|/\s*(?:self\.)?(?:total_assets|asset_balance|managed_assets))"
    r")"
)

_ZERO_SHARE_MINT_RE = re.compile(
    r"(?is)(let\s+(?:mut\s+)?(?:shares|share_amount)[^=;\n]*="
    r"[^;]{0,300}(?:/|checked_div)[^;]{0,220};)"
)

_DONATION_SURFACE_RE = re.compile(
    r"(?i)(donat|external_balance|balance_of\s*\([^)]*(?:self|contract|vault|address)|"
    r"current_contract_address|actual_assets|asset_balance)"
)

_EMPTY_BRANCH_RE = re.compile(
    r"(?is)if\s+[^{}]{0,180}(?:total_assets|total_shares|total_supply|"
    r"share_supply|supply)[^{}]{0,120}(?:==\s*0|is_zero\s*\(\s*\))"
    r"[^{}]{0,80}\{(?P<branch>[^{}]{0,260})\}"
)

_DANGEROUS_EMPTY_BRANCH_RE = re.compile(
    r"(?i)(max\s*\(|checked_add|saturating_add|div_ceil|ceil|round_up|"
    r"\+\s*1|\b1\s*\+|,\s*1\s*\)|return\s+0\b|\b0\s*;)"
)

_ROUND_UP_RE = re.compile(
    r"(?is)(div_ceil|ceil|round_up|checked_add\s*\([^)]*(?:saturating_sub\s*\(\s*1\s*\)|-\s*1)|"
    r"\+\s*(?:self\.)?(?:total_assets|total_shares|total_supply)[^;\n]{0,80}-\s*1)"
)

_ROUND_DOWN_RE = re.compile(r"(?is)(checked_div\s*\(|/)")


def _mitigated(module_text: str, body_text: str = "") -> bool:
    haystack = f"{module_text}\n{body_text}"
    return bool(
        _SAFE_MITIGATION_RE.search(haystack)
        or _SAFE_MIN_SHARE_GUARD_RE.search(haystack)
    )


def _collect_functions(tree, source: bytes):
    out = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        out.append(
            {
                "node": fn,
                "name": fn_name(fn, source),
                "body": body_text_nocomment(body, source),
                "pub": is_pub(fn, source),
            }
        )
    return out


def _body_by_name(functions: list[dict], wanted: str) -> str:
    for item in functions:
        if item["name"].lower() == wanted:
            return item["body"]
    return ""


def _item_by_name(functions: list[dict], wanted: str) -> dict | None:
    for item in functions:
        if item["name"].lower() == wanted:
            return item
    return None


def _entrypoint_formula_reason(name: str, body: str, module_text: str) -> str | None:
    if not _ENTRYPOINT_RE.search(name):
        return None
    if _mitigated(module_text, body):
        return None
    if not (_SHARE_TOTAL_RE.search(body) and _ASSET_TOTAL_RE.search(body)):
        return None
    if _SHARE_FORMULA_RE.search(body):
        if _DONATION_SURFACE_RE.search(body) or _EMPTY_BRANCH_RE.search(body):
            return "empty-supply share formula uses donatable assets without virtual shares"
        return "share formula can round to zero without virtual share protection"
    if _ZERO_SHARE_MINT_RE.search(body):
        return "share mint amount can round to zero before accounting"
    return None


def _branch_is_plain_passthrough(branch: str) -> bool:
    cleaned = " ".join(branch.replace(";", " ").split())
    return cleaned in {"shares", "return shares", "assets", "return assets", "amount", "return amount"}


def _first_branch_asymmetry(functions: list[dict], module_text: str) -> tuple[dict, str] | None:
    if _mitigated(module_text):
        return None

    deposit = _body_by_name(functions, "deposit")
    mint = _body_by_name(functions, "mint")
    preview = _item_by_name(functions, "preview_mint")
    if not (deposit and mint and preview):
        return None
    if "convert_to_shares" not in deposit or "preview_mint" not in mint:
        return None

    for match in _EMPTY_BRANCH_RE.finditer(preview["body"]):
        branch = match.group("branch")
        if _branch_is_plain_passthrough(branch):
            continue
        if _DANGEROUS_EMPTY_BRANCH_RE.search(branch):
            return preview, "mint preview has asymmetric empty-supply branch"
    return None


def _preview_convert_rounding_mismatch(
    functions: list[dict], module_text: str
) -> tuple[dict, str] | None:
    if _mitigated(module_text):
        return None

    preview_deposit = _item_by_name(functions, "preview_deposit")
    convert_to_shares = _item_by_name(functions, "convert_to_shares")
    if preview_deposit and convert_to_shares:
        if (
            _ROUND_UP_RE.search(preview_deposit["body"])
            and _ROUND_DOWN_RE.search(convert_to_shares["body"])
            and not _ROUND_UP_RE.search(convert_to_shares["body"])
        ):
            return (
                preview_deposit,
                "preview_deposit rounds up while convert_to_shares rounds down",
            )

    preview_mint = _item_by_name(functions, "preview_mint")
    convert_to_assets = _item_by_name(functions, "convert_to_assets")
    if preview_mint and convert_to_assets:
        if (
            "preview_mint" in preview_mint["name"].lower()
            and _ROUND_DOWN_RE.search(preview_mint["body"])
            and not _ROUND_UP_RE.search(preview_mint["body"])
            and _ROUND_UP_RE.search(convert_to_assets["body"])
        ):
            return (
                preview_mint,
                "preview_mint rounds down while convert_to_assets rounds up",
            )

    return None


def _hit(filepath: str, item: dict, reason: str, source: bytes) -> dict:
    line, col = line_col(item["node"])
    return {
        "severity": "medium",
        "line": line,
        "col": col,
        "snippet": snippet_of(item["node"], source, 200),
        "message": (
            f"{filepath}: first-depositor-inflation candidate in fn "
            f"`{item['name']}`: {reason}. Require virtual assets/shares, "
            "dead shares, minimum-share guards, or consistent preview/convert "
            "rounding before accepting deposits or minting shares."
        ),
    }


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    module_text = source_nocomment(source)
    functions = _collect_functions(tree, source)

    for item in functions:
        if not item["pub"]:
            continue
        reason = _entrypoint_formula_reason(item["name"], item["body"], module_text)
        if reason is not None:
            hits.append(_hit(filepath, item, reason, source))

    asymmetry = _first_branch_asymmetry(functions, module_text)
    if asymmetry is not None:
        item, reason = asymmetry
        hits.append(_hit(filepath, item, reason, source))

    rounding = _preview_convert_rounding_mismatch(functions, module_text)
    if rounding is not None:
        item, reason = rounding
        hits.append(_hit(filepath, item, reason, source))

    return hits
