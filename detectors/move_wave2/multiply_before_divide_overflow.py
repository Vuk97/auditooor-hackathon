"""
multiply-before-divide-overflow-in-update-pool-reward-manager-freezes-lending.

Bug class: arithmetic / overflow
Language:  move (Sui / Aptos)
Source:    solodit-2026-04-cycle20-move / Sherlock CurrentSUI
Source URL: https://solodit.cyfrin.io/issues/h-2-multiply-before-divide-overflow-in-update_pool_reward_manager-permanently-freezes-all-lending-operations-for-affected-cointype-sherlock-currentsui-contest-march-2026-git

Semantic anchor:
  In `update_pool_reward_manager` (or similar reward accumulation
  functions) the code computes `(reward * precision) / divisor` where
  both `reward` and `precision` are large u128/u64 values.  The
  intermediate product `reward * precision` overflows u128 before
  the division can bring it back into range.  Once the arithmetic
  panics, all lending operations for that CoinType are permanently frozen.

Detection strategy:
  Flag Move source where:
    1. A reward/accumulator update function contains a multiply expression
       whose operands include a precision constant AND a reward/amount
       variable — both potentially large.
    2. The multiply is followed by a divide (not preceded), i.e. the
       division does NOT reduce the value before multiplication.
    3. No `checked_mul` / `safe_mul` / intermediate cast-to-u256 is present.

  Proxy signal: pattern `<ident> * <precision_const>` inside an update
  function where neither operand is first divided/scaled down.

M14-trap note:
  Bug class is "intermediate multiplication overflow before division" —
  the predicate checks for the structural order (mul then div, without
  an intermediate down-scale), not fixture shape.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

# Move function definition
_FN_RE = re.compile(
    r"(?:public\s+)?(?:entry\s+)?fun\s+(update_pool_reward_manager|"
    r"update_reward|accrue_interest|update_index|accumulate_reward|"
    r"update_pool_reward|calc_reward_per_share)\s*[(<]",
    re.IGNORECASE,
)

# Multiply with a precision/scaling constant BEFORE divide
# Vulnerable: (reward * PRECISION) / denom   — intermediate may overflow
_MUL_BEFORE_DIV_RE = re.compile(
    r"\b\w+\s*\*\s*(?:PRECISION|precision|1_000_000_000|1000000000|"
    r"1_000_000|E9|E18|RAY|WAD|BASE)\b",
    re.IGNORECASE,
)

# Safe patterns: using checked_mul, (a as u256), or dividing first
_SAFE_MUL_RE = re.compile(
    r"(?:checked_mul|safe_mul|mul_div|as\s+u256|as\s+u128\b.*as\s+u256|"
    r"\/\s*\w+\s*\*)",  # divide-then-multiply order
    re.IGNORECASE,
)


def _line_at(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _extract_fn_body(source: str, fn_start: int) -> str:
    """Extract Move function body by brace-counting."""
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


def scan_text(source: str, filepath: str = "<memory>") -> list[dict]:
    hits: list[dict] = []
    for m in _FN_RE.finditer(source):
        body = _extract_fn_body(source, m.start())
        if not _MUL_BEFORE_DIV_RE.search(body):
            continue
        if _SAFE_MUL_RE.search(body):
            continue
        line = _line_at(source, m.start())
        fn_name = m.group(1)
        hits.append({
            "severity": "high",
            "filepath": filepath,
            "line": line,
            "function": fn_name,
            "message": (
                f"`{fn_name}` performs multiply-before-divide with a large precision "
                "constant without overflow protection. The intermediate product may "
                "overflow u128, permanently freezing lending operations."
            ),
        })
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path))


def run_text(source: str, filepath: str) -> list[dict]:
    return scan_text(source, filepath)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect multiply-before-divide overflow in Move reward managers."
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
