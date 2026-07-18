"""
amount-claimable-per-share-accounting-broken — stale global accumulator vs per-user baseline.

Bug class: arithmetic / accounting
Language:  vyper
Source:    solodit-2026-04-cycle32-vyper / Sherlock Fair Funding (Alchemix)
Source URL: https://solodit.cyfrin.io/issues/h-1-amount_claimable_per_share-accounting-is-broken-and-will-result-in-vault-insolvency-sherlock-fair-funding-fair-funding-by-alchemix-unstoppable-git

Semantic anchor:
  Vyper vaults that maintain a per-share global accumulator (e.g.
  `amount_claimable_per_share`) must also snapshot the per-position
  baseline at deposit time.  If a new deposit is processed while the
  accumulator is non-zero but the position's snapshot (e.g.
  `amount_claimed`) is left at zero, every existing share's accrued
  claim is silently credited against the new deposit — ultimately
  insolvency.

Detection strategy:
  Scan vyper source for:
    1. A global per-share accumulator variable (claimable_per_share,
       reward_per_share, yield_per_share, …).
    2. A deposit / mint / add_collateral function that writes a NEW
       position mapping without also setting a per-position baseline
       (amount_claimed, reward_debt, snapshot_per_share, …) in the
       same block.

  Positive fixture: deposit function missing the baseline assignment.
  Negative fixture: deposit function explicitly sets the baseline.

M14-trap note:
  The predicate looks for ABSENT baseline assignment inside the deposit
  body; this encodes the bug class semantics (stale-accumulator-at-
  deposit), not the fixture shape.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

# ── Semantic patterns ──────────────────────────────────────────────────────────

# Global accumulator: names with per_share / per_token / per_unit
_ACCUMULATOR_DECL_RE = re.compile(
    r"(?:amount_claimable_per_share|reward_per_share|yield_per_share|"
    r"acc_per_share|claimable_per_share|reward_per_token|"
    r"debt_per_share)\b",
    re.IGNORECASE,
)

# Deposit / mint entry points in vyper
_DEPOSIT_FN_RE = re.compile(
    r"^@(?:external|public)\b[^\n]*\n(?:[^\n]*\n)*?def\s+"
    r"(?:deposit|mint|add_collateral|add_position|open_position|stake)"
    r"\s*\(",
    re.MULTILINE | re.IGNORECASE,
)

# Per-position baseline assignment (the fix pattern)
_BASELINE_ASSIGN_RE = re.compile(
    r"(?:amount_claimed|reward_debt|snapshot_per_share|"
    r"claimable_snapshot|position_snapshot|last_per_share|"
    r"user_reward_per_token_paid)\s*(?:\[[^\]]+\])?\s*=",
    re.IGNORECASE,
)

# ── Line-number helper ─────────────────────────────────────────────────────────

def _line_at(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _extract_fn_body(source: str, fn_start: int) -> tuple[str, int]:
    """Extract the body of a vyper function by matching indentation."""
    lines = source[fn_start:].split("\n")
    if not lines:
        return "", fn_start
    # find indentation of the `def` line
    def_line = lines[0]
    base_indent = len(def_line) - len(def_line.lstrip())
    body_lines: list[str] = [lines[0]]
    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "":
            body_lines.append(line)
            continue
        current_indent = len(line) - len(line.lstrip())
        if current_indent <= base_indent and stripped:
            break
        body_lines.append(line)
    return "\n".join(body_lines), fn_start


# ── Scanner ───────────────────────────────────────────────────────────────────

# Simplified: match on the `def` line directly, not the decorator.
_DEPOSIT_DEF_RE = re.compile(
    r"^def\s+(deposit|mint|add_collateral|add_position|open_position|stake)\s*\(",
    re.MULTILINE | re.IGNORECASE,
)


def _extract_vyper_fn_body(source: str, def_start: int) -> str:
    """Extract vyper function body starting from the `def` line."""
    lines = source[def_start:].split("\n")
    if not lines:
        return ""
    # Skip the `def ...` line itself; body starts after the colon
    body_lines: list[str] = [lines[0]]
    # Body lines have indent > 0 (vyper uses 4-space indent conventionally)
    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "" or stripped.startswith("#"):
            body_lines.append(line)
            continue
        # A non-indented, non-empty line starts a new function/decorator
        if line and not line[0].isspace():
            break
        body_lines.append(line)
    return "\n".join(body_lines)


_LINE_COMMENT_RE = re.compile(r"#[^\n]*")


def _strip_comments(s: str) -> str:
    return _LINE_COMMENT_RE.sub("", s)


def scan_text(source: str, filepath: str = "<memory>") -> list[dict]:
    # Only interesting if contract uses a per-share accumulator
    if not _ACCUMULATOR_DECL_RE.search(source):
        return []

    hits: list[dict] = []
    for m in _DEPOSIT_DEF_RE.finditer(source):
        fn_body = _strip_comments(_extract_vyper_fn_body(source, m.start()))
        fn_name = m.group(1)
        # Bug: deposit body does NOT contain a per-position baseline assignment
        if not _BASELINE_ASSIGN_RE.search(fn_body):
            line = _line_at(source, m.start())
            hits.append({
                "severity": "high",
                "filepath": filepath,
                "line": line,
                "function": fn_name,
                "message": (
                    f"`{fn_name}` in `{filepath}` writes a new position while a "
                    "per-share accumulator is present, but does not initialize the "
                    "per-position baseline (amount_claimed / reward_debt / snapshot). "
                    "Stale global-accumulator vs per-user baseline leads to vault insolvency."
                ),
            })
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path))


def run_text(source: str, filepath: str) -> list[dict]:
    return scan_text(source, filepath)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect stale per-share accumulator at deposit in Vyper vaults."
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
