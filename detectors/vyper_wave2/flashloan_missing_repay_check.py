"""
incorrect-flashloan-integration-virtualpool — missing repay-with-fee check.

Bug class: flashloan / reentrancy
Language:  vyper
Source:    solodit-2026-04-cycle32-vyper / Quantstamp Yield Basis
Source URL: https://solodit.cyfrin.io/issues/incorrect-flashloan-integration-quantstamp-yield-basis-markdown

Semantic anchor:
  The VirtualPool (or equivalent flash-loan integration) does not verify
  that the loaned amount PLUS fee has been repaid by the callback.  The
  reentrant call path is also incorrectly wired — an attacker can drain
  the pool by not repaying the fee.

Detection strategy:
  Flag Vyper contracts where:
    1. A flashloan / flash_loan function is defined.
    2. After the callback invocation there is no explicit check that
       `balance_after >= balance_before + fee` (or equivalent repayment
       check using `assert`, `require`, or a subtraction-then-compare).

  Proxy signal: `flash_loan` function calls a callback but the post-
  callback repayment assertion is absent or incomplete.

M14-trap note:
  Bug class is "flashloan callback without fee-repayment assertion" —
  predicate checks for ABSENT repayment guard after callback, not
  fixture shape.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_FLASHLOAN_FN_RE = re.compile(
    r"def\s+(flash_?loan|flashLoan|borrow|flash_borrow)\s*\(",
    re.IGNORECASE,
)

# Callback invocation inside flash loan body
_CALLBACK_RE = re.compile(
    r"(?:IFlashLoanReceiver|flash_loan_callback|on_flash_loan|"
    r"receiver\.flash|callback\s*\(|execute\s*\()",
    re.IGNORECASE,
)

# Repayment assertion (the fix)
# Covers: assert balance_after >= X, assert balanceOf(...) >= X, balance_after - balance_before, etc.
_REPAY_CHECK_RE = re.compile(
    r"(?:"
    r"assert\b[^,\n]*\bbalance\w*\s*>="  # assert <balance_expr> >=
    r"|assert\b[^,\n]*\.balanceOf\b"     # assert <contract>.balanceOf(...)
    r"|balance_after\s*-\s*balance_before"
    r"|amount_repaid\s*>="
    r"|repaid\s*==\s*amount"
    r")",
    re.IGNORECASE,
)


def _line_at(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _extract_fn_body(source: str, fn_start: int) -> str:
    lines = source[fn_start:].split("\n")
    if not lines:
        return ""
    base_indent = len(lines[0]) - len(lines[0].lstrip())
    body_lines: list[str] = [lines[0]]
    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "":
            body_lines.append(line)
            continue
        curr_indent = len(line) - len(line.lstrip())
        if curr_indent <= base_indent and stripped:
            break
        body_lines.append(line)
    return "\n".join(body_lines)


def scan_text(source: str, filepath: str = "<memory>") -> list[dict]:
    hits: list[dict] = []
    for m in _FLASHLOAN_FN_RE.finditer(source):
        body = _extract_fn_body(source, m.start())
        has_callback = bool(_CALLBACK_RE.search(body))
        has_repay_check = bool(_REPAY_CHECK_RE.search(body))
        if has_callback and not has_repay_check:
            line = _line_at(source, m.start())
            fn_name = m.group(1)
            hits.append({
                "severity": "high",
                "filepath": filepath,
                "line": line,
                "function": fn_name,
                "message": (
                    f"`{fn_name}` invokes a flash-loan callback but does not assert "
                    "that the loan amount plus fee has been repaid after the callback. "
                    "An attacker can avoid repaying the fee, draining the pool."
                ),
            })
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path))


def run_text(source: str, filepath: str) -> list[dict]:
    return scan_text(source, filepath)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect missing repayment assertion in Vyper flash-loan functions."
    )
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    hits: list[dict] = []
    for p in args.paths:
        if p.is_dir():
            for f in sorted(p.rglob("*.vy")):
                hits.extend(scan_file(f))
        elif p.suffix in (".vy", ".vyper"):
            hits.extend(scan_file(p))
    if args.json:
        print(json.dumps(hits, indent=2))
    else:
        for h in hits:
            print(f"{h['filepath']}:{h['line']}: {h['severity']}: {h['message']}")
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
