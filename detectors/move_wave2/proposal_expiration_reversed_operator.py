"""
proposal-expiration-logic-uses-reversed-comparison-operator.

Bug class: access-control / logic-error
Language:  move (Aptos/Initia)
Source:    solodit-2026-04-cycle20-move / Code4rena Initia
Source URL: https://solodit.cyfrin.io/issues/m-03-the-proposal-expiration-logic-is-incorrect-code4rena-initia-initia-git

Semantic anchor:
  `is_proposal_expired` uses a reversed `<` / `>` in the expiration
  check.  A proposal that should be alive is marked expired (governance
  locked out) and vice versa (expired proposals accepted as valid).

Detection strategy:
  Flag Move functions named `is_proposal_expired` / `proposal_expired` /
  `check_expiry` whose comparison against an expiration timestamp uses
  the WRONG direction compared to what "expired" means.

  A proposal is expired when `now >= expiry` — i.e. the check should be
  `now >= proposal.expiry` or `proposal.expiry <= now`.  The buggy form
  is `proposal.expiry >= now` or `now <= proposal.expiry` (reversed).

  Proxy signal: the expiry-check function contains `expiry >= now` or
  `now <= expiry` rather than `now >= expiry`.

M14-trap note:
  Bug class is "reversed comparison operator in expiry predicate" —
  the predicate checks the DIRECTION of the comparison, not fixture
  shape. False-positive risk is acknowledged for non-expiry comparisons.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_EXPIRY_FN_RE = re.compile(
    r"fun\s+(is_proposal_expired|proposal_expired|check_expiry|"
    r"is_expired|has_expired)\s*[(<]",
    re.IGNORECASE,
)

# Reversed comparison: expiry is GREATER than or equal to now (wrong direction)
# Buggy: expiry >= now   or   now <= expiry
_REVERSED_EXPIRY_RE = re.compile(
    r"(?:"
    r"\w*expir\w*\s*>=\s*\w*(?:now|timestamp|clock|time)\w*"
    r"|"
    r"\w*(?:now|timestamp|clock|time)\w*\s*<=\s*\w*expir\w*"
    r")",
    re.IGNORECASE,
)

# Correct direction: now >= expiry  or  expiry <= now
_CORRECT_EXPIRY_RE = re.compile(
    r"(?:"
    r"\w*(?:now|timestamp|clock|time)\w*\s*>=\s*\w*expir\w*"
    r"|"
    r"\w*expir\w*\s*<=\s*\w*(?:now|timestamp|clock|time)\w*"
    r")",
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
    for m in _EXPIRY_FN_RE.finditer(source):
        body = _strip_comments(_extract_fn_body(source, m.start()))
        has_reversed = bool(_REVERSED_EXPIRY_RE.search(body))
        has_correct = bool(_CORRECT_EXPIRY_RE.search(body))
        # Flag if reversed comparison present and correct comparison absent
        if has_reversed and not has_correct:
            line = _line_at(source, m.start())
            fn_name = m.group(1)
            hits.append({
                "severity": "medium",
                "filepath": filepath,
                "line": line,
                "function": fn_name,
                "message": (
                    f"`{fn_name}` uses a reversed comparison operator for expiry "
                    "(`expiry >= now` instead of `now >= expiry`). Proposals are "
                    "marked expired when active and vice versa."
                ),
            })
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path))


def run_text(source: str, filepath: str) -> list[dict]:
    return scan_text(source, filepath)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect reversed comparison operator in Move proposal expiry checks."
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
