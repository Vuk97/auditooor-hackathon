"""
gas_price_zero_unchecked.py - Cosmos/Go gas-price divisor without zero guard.

Flags Go functions that divide or modulo by a gas-price-shaped identifier
(`gasPrice`, `GasPrice`, `gas_fee`, etc.) without an in-body zero guard.

Corpus evidence: reference/findings_go.jsonl includes
solodit-55256-seda-gasprice-zero-divbyzero-halt, where a permissionless
request with gasPrice=0 panicked the tally path and could halt validators.
"""

from __future__ import annotations

import re


GAS_PRICE_NAME = r"(?:gas_?[Pp]rice|GasPrice|gas_?[Ff]ee|GasFee)"
GAS_PRICE_DIVISION = re.compile(
    r"(?P<num>[A-Za-z_][\w\.\[\]]*|\([^)]+\))"
    r"\s*(?P<op>/|%)\s*"
    r"(?P<div>(?:[A-Za-z_][\w]*\.)*" + GAS_PRICE_NAME + r")\b"
)
GAS_PRICE_ZERO_GUARD = re.compile(
    r"(?:[A-Za-z_][\w]*\.)*" + GAS_PRICE_NAME
    + r"\s*(?:==|!=|<=|>=|<|>)\s*"
    + r"(?:0|big\.NewInt\s*\(\s*0\s*\)|sdk\.ZeroInt\s*\(\s*\))"
    + r"|(?:[A-Za-z_][\w]*\.)*"
    + GAS_PRICE_NAME
    + r"\.IsZero\s*\("
    + r"|\bIsZero\s*\(\s*(?:[A-Za-z_][\w]*\.)*"
    + GAS_PRICE_NAME
    + r"\s*\)"
    + r"|(?:[A-Za-z_][\w]*\.)*"
    + GAS_PRICE_NAME
    + r"\.Sign\s*\(\s*\)\s*(?:==|!=|<=|>=|<|>)"
)


def _blank_comment(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank_comment, src)
    return re.sub(r"/\*.*?\*/", _blank_comment, src, flags=re.S)


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        body = engine.fn_body(fn)
        if body is None:
            continue

        body_text = engine.text(body)
        body_no_comments = _strip_comments(body_text)
        match = GAS_PRICE_DIVISION.search(body_no_comments)
        if not match:
            continue
        if GAS_PRICE_ZERO_GUARD.search(body_no_comments):
            continue

        line_offset = body_text[: match.start()].count("\n")
        snippet = body_text.splitlines()[line_offset].strip()

        hits.append(
            {
                "severity": "high",
                "line": engine.line(body) + line_offset,
                "col": 0,
                "snippet": snippet[:160],
                "message": (
                    "Go/Cosmos function divides or mods by "
                    f"`{match.group('div')}` without an in-body zero guard "
                    "(solodit-55256 SEDA gasPrice=0 chain-halt class)."
                ),
            }
        )
    return hits
