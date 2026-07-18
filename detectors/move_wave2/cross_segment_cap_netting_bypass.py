"""
cross-segment-limiter-netting-failure-lets-attacker-grief-daily-caps.

Bug class: miscellaneous / accounting scope
Language:  move (Sui)
Source:    solodit-2026-04-cycle20-move / Sherlock CurrentSUI
Source URL: https://solodit.cyfrin.io/issues/m-1-cross-segment-limiter-netting-failure-lets-attackers-grief-daily-borrow-and-withdraw-caps-sherlock-currentsui-contest-march-2026-git

Semantic anchor:
  Daily borrow/withdraw caps are enforced per-segment per-user but
  netting across segments is not enforced at the global level.  An
  attacker zig-zags between segments — borrowing in segment A, repaying,
  borrowing in segment B, etc. — to repeatedly consume the per-segment
  cap while the global daily cap is never triggered.

Detection strategy:
  Flag Move borrow/withdraw functions where:
    1. A per-segment daily-cap check is enforced (segment-scoped
       `daily_borrow` / `segment_cap`).
    2. There is NO global daily-cap check that accounts for net cross-
       segment usage (global_daily_borrow / total_daily_limit / net_cap).

  Proxy signal: function checks `segment.daily_borrow <= segment.cap`
  but does NOT check a global aggregation of all segments.

M14-trap note:
  Bug class is "per-segment cap enforced but global netting absent" —
  predicate checks for the ABSENCE of a cross-segment aggregate check,
  not fixture shape.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_BORROW_FN_RE = re.compile(
    r"fun\s+(borrow|withdraw|request_borrow|cross_borrow|"
    r"multi_segment_borrow)\s*[(<]",
    re.IGNORECASE,
)

# Per-segment cap check
_SEGMENT_CAP_RE = re.compile(
    r"\b(?:segment(?:_cap|\.cap|\.daily)|per_segment|daily_segment|"
    r"segment_limit|segment\.borrow)\b",
    re.IGNORECASE,
)

# Global / aggregate cap check (the fix)
_GLOBAL_CAP_RE = re.compile(
    r"(?:global_daily|total_daily|net_daily|aggregate_cap|"
    r"cross_segment_cap|global_cap|total_borrow_cap|global_limit|"
    r"Protocol\b[^;{]*(?:cap|limit|borrow))",
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


def scan_text(source: str, filepath: str = "<memory>") -> list[dict]:
    hits: list[dict] = []
    for m in _BORROW_FN_RE.finditer(source):
        body = _extract_fn_body(source, m.start())
        has_segment_cap = bool(_SEGMENT_CAP_RE.search(body))
        has_global_cap = bool(_GLOBAL_CAP_RE.search(body))
        if has_segment_cap and not has_global_cap:
            line = _line_at(source, m.start())
            fn_name = m.group(1)
            hits.append({
                "severity": "medium",
                "filepath": filepath,
                "line": line,
                "function": fn_name,
                "message": (
                    f"`{fn_name}` enforces per-segment daily caps but has no global "
                    "cross-segment netting check. An attacker can grief daily borrow/"
                    "withdraw caps by zig-zagging between segments."
                ),
            })
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path))


def run_text(source: str, filepath: str) -> list[dict]:
    return scan_text(source, filepath)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect missing cross-segment netting in Move daily cap enforcement."
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
