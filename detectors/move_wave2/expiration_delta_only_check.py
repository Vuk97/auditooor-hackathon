"""
user-can-bypass-max-expiration-in-extend-expiration-path.

Bug class: input-validation / bound-check
Language:  move (Aptos/Initia)
Source:    solodit-2026-04-cycle20-move / Code4rena Initia
Source URL: https://solodit.cyfrin.io/issues/h-03-user-can-bypass-max_expiration-when-extend-expiration-code4rena-initia-initia-git

Semantic anchor:
  `extend_expiration` validates only the DELTA (extension amount) against
  MAX_EXPIRATION, not the resulting SUM `current_expiry + delta`.  A user
  can call the function repeatedly with small deltas that each pass the
  check individually, incrementally extending the expiration far beyond
  the cap.

Detection strategy:
  Flag Move `extend_expiration` functions where:
    1. There is an assertion/check on `delta` or `extension` against
       `MAX_EXPIRATION` or `max_expiry`.
    2. There is NO assertion on `current_expiry + delta` against the cap.

  Proxy signal: `assert!(delta <= MAX_EXPIRATION)` or `assert!(extension < max)`
  without a companion `assert!(current + delta <= MAX_EXPIRATION)`.

M14-trap note:
  Bug class is "delta-only bound check misses cumulative result" —
  predicate checks the STRUCTURE of the assertion (what is bounded),
  not fixture shape.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_EXTEND_FN_RE = re.compile(
    r"fun\s+(extend_expiration|extend_lock|extend_duration|"
    r"increase_expiry|renew_lock)\s*[(<]",
    re.IGNORECASE,
)

# Delta-only check: assert delta <= MAX (without the sum)
_DELTA_ONLY_CHECK_RE = re.compile(
    r"assert!\s*\(\s*\w*(?:delta|extension|duration|amount)\w*\s*<=?\s*"
    r"\w*(?:MAX_EXPIRATION|max_expiry|max_lock|MAX_LOCK)\w*",
    re.IGNORECASE,
)

# Correct cumulative check: current + delta <= MAX
_CUMULATIVE_CHECK_RE = re.compile(
    r"assert!\s*\([^)]*(?:\+)[^)]*(?:MAX_EXPIRATION|max_expiry|max_lock|MAX_LOCK)",
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
    for m in _EXTEND_FN_RE.finditer(source):
        body = _extract_fn_body(source, m.start())
        has_delta_check = bool(_DELTA_ONLY_CHECK_RE.search(body))
        has_cumulative = bool(_CUMULATIVE_CHECK_RE.search(body))
        if has_delta_check and not has_cumulative:
            line = _line_at(source, m.start())
            fn_name = m.group(1)
            hits.append({
                "severity": "high",
                "filepath": filepath,
                "line": line,
                "function": fn_name,
                "message": (
                    f"`{fn_name}` validates only the extension delta against "
                    "MAX_EXPIRATION, not the resulting sum (current + delta). "
                    "Users can bypass the cap by calling with many small deltas."
                ),
            })
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path))


def run_text(source: str, filepath: str) -> list[dict]:
    return scan_text(source, filepath)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect delta-only expiration bound check in Move extend functions."
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
