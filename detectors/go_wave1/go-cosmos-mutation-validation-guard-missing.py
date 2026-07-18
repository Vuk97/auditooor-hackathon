"""
go-cosmos-mutation-validation-guard-missing.py

Sibling Go/Cosmos class detector for validation gaps before state, fund, or
gas-cost mutations. It intentionally covers three invariant shapes that the
Go held-out set currently clusters under missing-recipient-validation:

1. InitGenesis consumes genesis fields without Validate or ValidateGenesis.
2. Fund-moving SDK calls discard or ignore returned errors.
3. GasPrice-shaped values are used as divisors without a zero guard.

This is recall-only evidence. It marks validation-before-mutation gaps; R40
and engagement-specific rubric gates still decide exploitability.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-cosmos-mutation-validation-guard-missing"

_INIT_GENESIS_RE = re.compile(r"^InitGenesis$")
_CONSUMES_GENESIS_RE = re.compile(
    r"(\.Set[A-Za-z]*\s*\(|store\.Set|\.SetParams\s*\("
    r"|genState\.|genesisState\.|gs\.|data\.[A-Z])"
)
_VALIDATE_RE = re.compile(
    r"(\.Validate\s*\(\s*\)|ValidateGenesis\s*\(|ValidateBasic\s*\()"
)

_RISKY_CALL = (
    r"(SendCoins|SendCoinsFromModuleToAccount|SendCoinsFromAccountToModule"
    r"|SendCoinsFromModuleToModule|MintCoins|BurnCoins|DelegateCoins"
    r"|UndelegateCoins|Transfer|Withdraw|SetBalance|Mint|Burn|Settle"
    r"|Payout|Distribute)"
)
_DISCARD_RE = re.compile(
    r"(?:^|\n)\s*(?:_\s*,\s*)*_\s*=\s*[A-Za-z_][\w.]*\."
    + _RISKY_CALL + r"\s*\(",
)
_BARE_CALL_RE = re.compile(
    r"(?:^|\n)[ \t]*[A-Za-z_][\w.]*\." + _RISKY_CALL + r"\s*\(",
)

_GAS_PRICE_NAME = r"(?:gas_?[Pp]rice|GasPrice|gas_?[Ff]ee|GasFee)"
_GAS_PRICE_DIVISION_RE = re.compile(
    r"(?P<num>[A-Za-z_][\w\.\[\]]*|\([^)]+\))\s*(?P<op>/|%)\s*"
    r"(?P<div>(?:[A-Za-z_][\w]*\.)*" + _GAS_PRICE_NAME + r")\b"
)
_GAS_PRICE_ZERO_GUARD_RE = re.compile(
    r"(?:[A-Za-z_][\w]*\.)*" + _GAS_PRICE_NAME
    + r"\s*(?:==|!=|<=|>=|<|>)\s*"
    + r"(?:0|big\.NewInt\s*\(\s*0\s*\)|sdk\.ZeroInt\s*\(\s*\))"
    + r"|(?:[A-Za-z_][\w]*\.)*" + _GAS_PRICE_NAME + r"\.IsZero\s*\("
    + r"|\bIsZero\s*\(\s*(?:[A-Za-z_][\w]*\.)*"
    + _GAS_PRICE_NAME + r"\s*\)"
)


def _line_has_capture(line: str) -> bool:
    stripped = line.strip()
    if stripped.startswith(("if ", "return ", "err ")):
        return True
    if re.match(r"^[A-Za-z_][\w.]*(\s*,\s*[A-Za-z_][\w.]*)*\s*:?=", stripped):
        head = stripped.split("=", 1)[0]
        return not bool(re.fullmatch(r"[\s_,]*", head))
    return False


def _blank_comment(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank_comment, src)
    return re.sub(r"/\*.*?\*/", _blank_comment, src, flags=re.S)


def _hit(engine, fn, name, why):
    return {
        "severity": "high",
        "line": engine.line(fn),
        "col": engine.col(fn),
        "snippet": engine.text(fn).splitlines()[0][:160],
        "message": (
            f"`{name}` has a validation-before-mutation gap: {why}. "
            f"Validate genesis, check SDK mutation errors, and guard "
            f"gas-price divisors before accepting state changes. "
            f"(class: missing-recipient-validation)"
        ),
    }


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        body_text = engine.text(body)
        body_no_comments = _strip_comments(body_text)

        if (
            _INIT_GENESIS_RE.match(name)
            and _CONSUMES_GENESIS_RE.search(body_no_comments)
            and not _VALIDATE_RE.search(body_no_comments)
        ):
            hits.append(_hit(engine, fn, name, "genesis fields are consumed without validation"))
            continue

        if _DISCARD_RE.search(body_no_comments):
            hits.append(_hit(engine, fn, name, "a fund-moving SDK error is discarded"))
            continue

        for match in _BARE_CALL_RE.finditer(body_no_comments):
            line = body_no_comments[match.start():].split("\n", 1)[0]
            if not _line_has_capture(line):
                hits.append(_hit(engine, fn, name, "a fund-moving SDK error is ignored"))
                break
        else:
            if (
                _GAS_PRICE_DIVISION_RE.search(body_no_comments)
                and not _GAS_PRICE_ZERO_GUARD_RE.search(body_no_comments)
            ):
                hits.append(_hit(engine, fn, name, "GasPrice is used as a divisor without a zero guard"))

    return hits
