"""
double_subtraction_accounting_fire10.py

Flags Rust accounting entrypoints that debit the same balance, debt, share,
reserve, or liquidity sink twice in one public function without first deriving
a single checked combined delta.

This is intentionally narrower than r94_loop_double_subtraction_accounting:
it looks for repeated accounting sink mutations, not just repeated subtraction
syntax.
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
)


_ACCOUNTING_WORD_RE = re.compile(
    r"(?i)(balances?|debts?|shares?|reserves?|liquidity|collateral|"
    r"assets?|supply|principal|borrow|stake|position|vault)"
)

_FN_CONTEXT_RE = re.compile(
    r"(?i)(withdraw|redeem|burn|repay|borrow|liquidat|settle|claim|"
    r"slash|unstake|exit|remove_liquidity|debit)"
)

_DIRECT_DEBIT_RE = re.compile(
    r"(?P<target>\b(?:self|state|pool|vault|market|ledger|position|account)"
    r"\s*\.\s*[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\])?)"
    r"\s*-=\s*(?P<amount>[^;\n]+);",
    re.MULTILINE,
)

_MAP_DEBIT_RE = re.compile(
    r"(?P<target>\b(?:self|state|pool|vault|market|ledger|position|account)"
    r"\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*\.\s*(?:insert|set)\s*\("
    r"(?P<body>[\s\S]{0,420}?(?:\s-\s|\.checked_sub\s*\(|\.saturating_sub\s*\()"
    r"[\s\S]{0,420}?)\)\s*;",
    re.MULTILINE,
)

_BURN_OR_DEBIT_CALL_RE = re.compile(
    r"\b(?:self|state|pool|vault|market|ledger)\s*\.\s*"
    r"(?P<method>(?:burn|debit|slash|remove|withdraw|reduce)_"
    r"[A-Za-z0-9_]*(?:balance|debt|share|reserve|liquidity|collateral|asset)"
    r"[A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)

_CHECKED_ADD_ASSIGN_RE = re.compile(
    r"\blet\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*[^;]{0,260}\.checked_add\s*\(",
    re.MULTILINE,
)


def _normalise_target(target: str) -> str:
    return re.sub(r"\s+", "", target)


def _has_accounting_context(name: str, body: str) -> bool:
    return bool(_FN_CONTEXT_RE.search(name) or _ACCOUNTING_WORD_RE.search(body))


def _has_single_checked_delta(body: str) -> bool:
    for match in _CHECKED_ADD_ASSIGN_RE.finditer(body):
        var = match.group("var")
        if not _ACCOUNTING_WORD_RE.search(var):
            # "total_delta" and "net_debit" are common safe names even when
            # they do not repeat a concrete ledger noun.
            if not re.search(r"(?i)(delta|debit|burn|withdraw|repay|amount)", var):
                continue
        tail = body[match.end() : match.end() + 1200]
        if re.search(
            rf"(?:checked_sub|saturating_sub)\s*\(\s*{re.escape(var)}\b|"
            rf"-\s*{re.escape(var)}\b|"
            rf"\b(?:burn|debit|slash|withdraw|remove)_[A-Za-z0-9_]*"
            rf"\s*\([^;)]*\b{re.escape(var)}\b",
            tail,
        ):
            return True
    return False


def _collect_debits(body: str) -> list[tuple[int, str, str]]:
    debits: list[tuple[int, str, str]] = []

    for match in _DIRECT_DEBIT_RE.finditer(body):
        target = _normalise_target(match.group("target"))
        amount = match.group("amount")
        if not _ACCOUNTING_WORD_RE.search(target + " " + amount):
            continue
        debits.append((match.start(), target, match.group(0)))

    for match in _MAP_DEBIT_RE.finditer(body):
        target = _normalise_target(match.group("target"))
        if not _ACCOUNTING_WORD_RE.search(target + " " + match.group("body")):
            continue
        debits.append((match.start(), target, match.group(0)))

    for match in _BURN_OR_DEBIT_CALL_RE.finditer(body):
        method = match.group("method")
        if not _ACCOUNTING_WORD_RE.search(method):
            continue
        debits.append((match.start(), f"method:{method}", match.group(0)))

    return sorted(debits, key=lambda item: item[0])


def _first_repeated_sink(
    debits: list[tuple[int, str, str]]
) -> tuple[str, tuple[int, str, str], tuple[int, str, str]] | None:
    seen: dict[str, tuple[int, str, str]] = {}
    for debit in debits:
        _pos, target, _text = debit
        prev = seen.get(target)
        if prev is not None:
            return target, prev, debit
        seen[target] = debit
    return None


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue

        body_nc = body_text_nocomment(body, source)
        if not _has_accounting_context(name, body_nc):
            continue
        if _has_single_checked_delta(body_nc):
            continue

        repeated = _first_repeated_sink(_collect_debits(body_nc))
        if repeated is None:
            continue

        target, _first, _second = repeated
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:220],
            "message": (
                f"pub fn `{name}` debits accounting sink `{target}` more "
                "than once without a single checked combined delta. Independent "
                "subtractions or burns can double-charge a balance, debt, "
                "share, reserve, or liquidity ledger."
            ),
        })
    return hits
