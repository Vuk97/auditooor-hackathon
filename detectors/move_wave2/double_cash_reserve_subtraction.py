"""
double-subtraction-of-cash-reserve-bypasses-max-deposit-limit.

Bug class: arithmetic / accounting
Language:  move (Sui)
Source:    solodit-2026-04-cycle20-move / Sherlock CurrentSUI
Source URL: https://solodit.cyfrin.io/issues/m-2-double-subtraction-of-cash_reserve-in-deposit_limit_breached-allows-bypassing-the-maximum-deposit-limit-sherlock-currentsui-contest-march-2026-git

Semantic anchor:
  `deposit_limit_breached` subtracts `cash_reserve` TWICE from the
  deposit-limit comparison expression.  This understates the used
  capacity, allowing attackers to deposit past the intended maximum.

Detection strategy:
  Flag Move deposit-limit check functions where:
    1. A variable named `cash_reserve` (or similar) appears MORE THAN
       ONCE on the same side of a subtraction expression in the limit
       computation.
    2. No comment or intentional double-subtraction idiom is present.

  Proxy signal: `cash_reserve` appears at least twice as a subtracted
  operand within the same arithmetic expression or within the same
  limit-check assertion.

M14-trap note:
  Bug class is "double subtraction of the same reserve variable in
  capacity check" — predicate counts occurrences of the variable in
  the limiting expression, not fixture shape.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_LIMIT_FN_RE = re.compile(
    r"fun\s+(deposit_limit_breached|check_deposit_limit|"
    r"is_over_limit|over_deposit_cap|deposit_cap_exceeded)\s*[(<]",
    re.IGNORECASE,
)

# cash_reserve (or synonym) subtracted; count occurrences
_CASH_RESERVE_RE = re.compile(
    r"\b(?:cash_reserve|reserve_amount|liquidity_reserve|"
    r"available_reserve)\b",
    re.IGNORECASE,
)

# Tolerance: intentional double-adjustment comment would make us skip
_INTENTIONAL_COMMENT_RE = re.compile(
    r"(?:intentional|by design|double.subtract.*ok)",
    re.IGNORECASE,
)


def _line_at(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _extract_fn_body(source: str, fn_start: int) -> str:
    idx = source.find("{", fn_start)
    if idx == -1:
        return ""
    depth = 0
    for i in range(idx, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[fn_start:i + 1]
    return source[fn_start:]


_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def _strip_comments(s: str) -> str:
    return _LINE_COMMENT_RE.sub("", s)


def scan_text(source: str, filepath: str = "<memory>") -> list[dict]:
    hits: list[dict] = []
    for m in _LIMIT_FN_RE.finditer(source):
        raw_body = _extract_fn_body(source, m.start())
        if _INTENTIONAL_COMMENT_RE.search(raw_body):
            continue
        body = _strip_comments(raw_body)
        occurrences = len(_CASH_RESERVE_RE.findall(body))
        if occurrences >= 2:
            line = _line_at(source, m.start())
            fn_name = m.group(1)
            hits.append({
                "severity": "medium",
                "filepath": filepath,
                "line": line,
                "function": fn_name,
                "message": (
                    f"`{fn_name}` references `cash_reserve` {occurrences} times "
                    "in the deposit-limit computation. Double-subtraction understates "
                    "used capacity, allowing deposits beyond the maximum limit."
                ),
            })
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path))


def run_text(source: str, filepath: str) -> list[dict]:
    return scan_text(source, filepath)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect double cash_reserve subtraction in Move deposit limit checks."
    )
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    hits: list[dict] = []
    for p in args.paths:
        if p.is_dir():
            for f in sorted(p.rglob("*.move")):
                hits.extend(scan_file(f))
        elif p.suffix == ".move":
            hits.extend(scan_file(p))
    if args.json:
        print(json.dumps(hits, indent=2))
    else:
        for h in hits:
            print(f"{h['filepath']}:{h['line']}: {h['severity']}: {h['message']}")
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
