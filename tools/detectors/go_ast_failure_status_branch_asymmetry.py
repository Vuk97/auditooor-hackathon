#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


SCHEMA = "auditooor.go_ast_failure_status_branch_asymmetry.v1"

STATUS_WRITE_RE = re.compile(
    r"\b("
    r"SetStatus[A-Za-z_]*|"
    r"UpdateStatus[A-Za-z_]*|"
    r"StatusFor[A-Za-z_]*|"
    r"MarkAs[A-Za-z_]*|"
    r"SetState[A-Za-z_]*"
    r")\s*\("
)

STATUS_ASSIGN_RE = re.compile(
    r"(?i)\b(?:[\w\.]*status)\s*(?:=|:=)\s*[^=]"
)

SUCCESS_LITERAL_RE = re.compile(
    r"(?i)(StatusSuccess|StatusOK|StatusCompleted|StatusFilled|StatusFinal|Success|Completed|Filled)"
)

FAILURE_LITERAL_RE = re.compile(
    r"(?i)(StatusFailed|StatusRejected|StatusError|StatusCancelled|StatusCanceled|Failed|Rejected|Errored|Cancelled|Canceled|Blocked)"
)

IF_ERR_RE = re.compile(
    r"^\s*if\s+(?:err|[a-zA-Z_][\w]*)\s*(?:!=|==)\s*nil\s*\{?\s*$"
)
IF_ERR_INLINE_RE = re.compile(
    r"^\s*if\s+(?:[\w\.]+\s*[:=]=?\s*[^\;]+;\s*)?(?:err|[a-zA-Z_][\w]*)\s*(?:!=|==)\s*nil\s*\{"
)

ELSE_RE = re.compile(r"^\s*\}\s*else\s*(?:\{|if\b)")

FUNC_DECL_RE = re.compile(
    r"^\s*func\s+(?:\((?P<recv>[^)]*)\)\s+)?(?P<name>[A-Za-z_][\w]*)\s*\("
)

COMMENT_LINE_RE = re.compile(r"^\s*(//|/\*|\*)")


@dataclass
class Candidate:
    file: str
    line: int
    function: str
    snippet: str
    severity_hint: str


def _strip_strings_and_comments(line: str) -> str:
    out = []
    i = 0
    in_str = None
    while i < len(line):
        c = line[i]
        if in_str:
            if c == "\\" and i + 1 < len(line):
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ('"', "'", "`"):
            in_str = c
            i += 1
            continue
        if c == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        out.append(c)
        i += 1
    return "".join(out)


def _iter_funcs(lines: List[str]):
    i = 0
    n = len(lines)
    while i < n:
        m = FUNC_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group("name")
        depth = 0
        body_start = -1
        opened = False
        j = i
        while j < n:
            stripped = _strip_strings_and_comments(lines[j])
            for ch in stripped:
                if ch == "{":
                    if not opened:
                        opened = True
                        body_start = j
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if opened and depth == 0:
                        yield name, i, body_start, j
                        i = j + 1
                        break
            else:
                j += 1
                continue
            break
        else:
            return


def _block_end(lines: List[str], start: int) -> int:
    """Given line index where '{' opens, return index of matching '}'."""
    depth = 0
    n = len(lines)
    # find first '{' from start
    j = start
    opened = False
    while j < n:
        stripped = _strip_strings_and_comments(lines[j])
        for ch in stripped:
            if ch == "{":
                opened = True
                depth += 1
            elif ch == "}":
                depth -= 1
                if opened and depth == 0:
                    return j
        j += 1
    return n - 1


def _scan_block_for_status(lines: List[str], start: int, end: int) -> Tuple[bool, bool, bool]:
    """Return (has_status_write, has_success_literal, has_failure_literal) inside lines[start..end]."""
    write = succ = fail = False
    for k in range(start, end + 1):
        raw = lines[k]
        if COMMENT_LINE_RE.match(raw):
            continue
        stripped = _strip_strings_and_comments(raw)
        if STATUS_WRITE_RE.search(stripped) or STATUS_ASSIGN_RE.search(stripped):
            write = True
        if SUCCESS_LITERAL_RE.search(stripped):
            succ = True
        if FAILURE_LITERAL_RE.search(stripped):
            fail = True
    return write, succ, fail


def _classify_branch(write: bool, succ: bool, fail: bool) -> str:
    if not write:
        return "none"
    if fail and not succ:
        return "failure"
    if succ and not fail:
        return "success"
    if succ and fail:
        return "mixed"
    return "write_only"


def scan_file(path: Path) -> List[Candidate]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return []
    lines = text.splitlines()
    out: List[Candidate] = []
    for name, decl_line, body_start, body_end in _iter_funcs(lines):
        k = body_start + 1
        while k < body_end:
            raw = lines[k]
            stripped = _strip_strings_and_comments(raw)
            is_if_err = bool(IF_ERR_RE.match(stripped) or IF_ERR_INLINE_RE.match(stripped))
            if not is_if_err:
                k += 1
                continue
            # find opening brace and block
            then_open = k
            if "{" not in stripped:
                # look for following line containing '{'
                if k + 1 < body_end and "{" in _strip_strings_and_comments(lines[k + 1]):
                    then_open = k + 1
                else:
                    k += 1
                    continue
            then_end = _block_end(lines, then_open)
            # check for else
            else_open = -1
            else_end = -1
            after = then_end + 1
            if after < body_end:
                tail = _strip_strings_and_comments(lines[then_end])
                # else is usually on same line as the closing }
                if "else" in tail and "{" in tail:
                    else_open = then_end
                    else_end = _block_end(lines, then_end + 1) if "{" not in tail.split("else", 1)[1] else _block_end(lines, then_end)
                elif after < body_end and ELSE_RE.match(_strip_strings_and_comments(lines[after])):
                    else_open = after
                    else_end = _block_end(lines, after)
            if else_open < 0:
                k = then_end + 1
                continue
            t_write, t_succ, t_fail = _scan_block_for_status(lines, then_open + 1, then_end - 1)
            e_write, e_succ, e_fail = _scan_block_for_status(lines, else_open + 1, else_end - 1)
            t_kind = _classify_branch(t_write, t_succ, t_fail)
            e_kind = _classify_branch(e_write, e_succ, e_fail)
            # asymmetry: one branch writes status (esp. success-like), the other doesn't write at all.
            asymmetric = False
            if t_write and not e_write:
                asymmetric = True
                offending = then_open + 1
            elif e_write and not t_write:
                asymmetric = True
                offending = else_open + 1
            else:
                asymmetric = False
                offending = k + 1
            # Tighter signal: if the writing branch has a success-like literal and the other has none.
            if asymmetric:
                if (t_write and t_succ and not e_write) or (e_write and e_succ and not t_write):
                    sev = "HIGH"
                else:
                    sev = "MEDIUM"
                snippet = lines[k].strip()
                out.append(
                    Candidate(
                        file=str(path),
                        line=k + 1,
                        function=name,
                        snippet=snippet[:240],
                        severity_hint=sev,
                    )
                )
            k = (else_end if else_end > 0 else then_end) + 1
    return out


def walk_repo(root: Path) -> Iterable[Path]:
    for p in root.rglob("*.go"):
        parts = set(p.parts)
        if "vendor" in parts or "testdata" in parts:
            continue
        if p.name.endswith("_test.go"):
            continue
        if p.name.endswith(".pb.go") or p.name.endswith(".pb.gw.go"):
            continue
        yield p


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Go AST detector: failure-branch state-update asymmetry")
    ap.add_argument("repo", type=Path)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--threshold", type=int, default=0)
    args = ap.parse_args(argv)

    root = args.repo
    if not root.exists():
        print(f"error: {root} does not exist", file=sys.stderr)
        return 2

    candidates: List[Candidate] = []
    if root.is_file() and root.suffix == ".go":
        candidates.extend(scan_file(root))
    else:
        for p in walk_repo(root):
            candidates.extend(scan_file(p))

    payload = {
        "schema": SCHEMA,
        "root": str(root),
        "count": len(candidates),
        "candidates": [asdict(c) for c in candidates],
    }
    text = json.dumps(payload, indent=2)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    else:
        print(text)
    if args.threshold and len(candidates) < args.threshold:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
