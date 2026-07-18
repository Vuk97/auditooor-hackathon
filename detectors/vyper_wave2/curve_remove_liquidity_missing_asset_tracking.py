"""
tokens-from-curve-remove-liquidity-not-added-to-assets-list-when-min-amounts-0.

Bug class: dex-integration / asset-tracking
Language:  vyper
Source:    solodit-2026-04-cycle32-vyper / Sherlock Sentiment
Source URL: https://solodit.cyfrin.io/issues/h-7-tokens-received-from-curves-remove_liquidity-should-be-added-to-the-assets-list-even-if-_min_amounts-are-set-to-0-sherlock-sentiment-sentiment-git

Semantic anchor:
  When `remove_liquidity` is called with ALL min_amounts set to zero,
  the integration's `canRemoveLiquidity` / asset-tracking helper only
  records tokens where `min_amount > 0`.  The Curve pool still returns
  ALL tokens, but the account/portfolio tracker drops the zero-min-
  amount tokens entirely — resulting in untracked balances.

Detection strategy:
  Flag Vyper contracts where:
    1. A call to `remove_liquidity` (Curve) is present.
    2. The code only adds tokens to an assets list / account tracker
       when the corresponding min_amount is > 0 (conditional that
       gates asset registration on min_amount != 0 or > 0).
    3. There is no fallback that registers the received tokens
       unconditionally after the call.

  Proxy signal: `if min_amounts[i] > 0:` or equivalent guard
  surrounds the asset-list update inside a remove_liquidity context
  without an else branch that also registers the asset.

M14-trap note:
  Bug class is "asset tracking conditional on caller-supplied min-amount
  guard" — predicate checks for a conditional asset registration inside
  a remove_liquidity scope, not for fixture-shape characteristics.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_REMOVE_LIQ_RE = re.compile(r"\bremove_liquidity\b", re.IGNORECASE)

# Conditional guard on min_amount for asset registration
_MIN_AMOUNT_GUARD_RE = re.compile(
    r"if\s+\w*min_amount\w*\s*(?:\[\w+\])?\s*(?:>|!=|==)\s*0",
    re.IGNORECASE,
)

# Asset-list update patterns (the thing being conditionally gated)
_ASSET_UPDATE_RE = re.compile(
    r"(?:assets\.append|addToAssets|_add_asset|token_in\.append|"
    r"assets_list\.append|tokensIn\.append|self\.assets)\b",
    re.IGNORECASE,
)

# Unconditional fallback after the remove call (the fix pattern)
_UNCONDITIONAL_ASSET_RE = re.compile(
    r"(?:for\s+\w+\s+in\s+\w+\s*:\s*\n\s*\w+\.append|"
    r"assets\s*=\s*received_tokens)",
    re.IGNORECASE,
)

_FN_RE = re.compile(
    r"def\s+(\w+)\s*\(",
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
    if not _REMOVE_LIQ_RE.search(source):
        return []

    hits: list[dict] = []
    for m in _FN_RE.finditer(source):
        body = _extract_fn_body(source, m.start())
        if not _REMOVE_LIQ_RE.search(body):
            continue
        has_guard = bool(_MIN_AMOUNT_GUARD_RE.search(body))
        has_asset_update = bool(_ASSET_UPDATE_RE.search(body))
        has_unconditional = bool(_UNCONDITIONAL_ASSET_RE.search(body))
        if has_guard and has_asset_update and not has_unconditional:
            line = _line_at(source, m.start())
            fn_name = m.group(1)
            hits.append({
                "severity": "high",
                "filepath": filepath,
                "line": line,
                "function": fn_name,
                "message": (
                    f"`{fn_name}` calls `remove_liquidity` but only adds received "
                    "tokens to the asset tracker when `min_amount > 0`. Tokens with "
                    "zero min_amount are silently dropped from tracking even though "
                    "Curve returns them — account balances become under-reported."
                ),
            })
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path))


def run_text(source: str, filepath: str) -> list[dict]:
    return scan_text(source, filepath)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect asset-tracking bug in Curve remove_liquidity zero-min-amounts."
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
