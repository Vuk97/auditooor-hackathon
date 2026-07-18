#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


SCHEMA = "auditooor.sql_handler_missing_perform.v1"

SQL_SUFFIXES = {".sql", ".psql", ".pgsql", ".plpgsql"}

# Match the start of a CREATE [OR REPLACE] FUNCTION declaration. The
# dollar-quoted body delimiter is captured so we can match the matching close.
FUNC_DECL_RE = re.compile(
    r"CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+"
    r"(?:[A-Za-z_][\w]*\s*\.\s*)?(?P<name>[A-Za-z_][\w]*)\s*\(",
    re.IGNORECASE,
)

# Dollar-quote tag, e.g. $$, $BODY$, $function$
DOLLAR_TAG_RE = re.compile(r"\$([A-Za-z_][\w]*)?\$")

# A SELECT-expression-statement candidate: a line whose first non-whitespace
# token is SELECT and which calls an identifier-shaped function. We do NOT
# match SELECT INTO ..., SELECT ... INTO ..., assignment via :=, RETURNING,
# WITH-CTEs, or sub-expression usages on subsequent lines (the assignment
# check looks at the full statement up to the terminating semicolon).
SELECT_CALL_RE = re.compile(
    r"^\s*SELECT\s+"
    r"(?P<callee>[A-Za-z_][\w]*)\s*\(",
    re.IGNORECASE,
)

# Tokens that indicate the SELECT result is captured / not discarded. If any
# of these appear in the same statement (up to the next ';' that's not inside
# parens) the line is NOT a missing-PERFORM candidate.
ASSIGN_TOKENS_RE = re.compile(
    r"\bINTO\b|\bRETURNING\b|:=",
    re.IGNORECASE,
)

# If a SELECT statement contains FROM / WHERE / JOIN / GROUP BY / HAVING /
# ORDER BY / LIMIT / OFFSET / UNION, the call is acting as a sub-expression
# in a query — treating it as a missing-PERFORM is too noisy. We skip.
QUERY_CONTEXT_RE = re.compile(
    r"\bFROM\b|\bWHERE\b|\bJOIN\b|\bGROUP\s+BY\b|\bHAVING\b|"
    r"\bORDER\s+BY\b|\bLIMIT\b|\bOFFSET\b|\bUNION\b",
    re.IGNORECASE,
)

# Side-effect prefix heuristic. If callee name starts with one of these,
# emit MEDIUM severity_hint (still advisory); else LOW.
SIDE_EFFECT_PREFIX_RE = re.compile(
    r"^(update|insert|delete|set|mark|create|record|log|emit|notify)_",
    re.IGNORECASE,
)


@dataclass
class Candidate:
    file: str
    line: int
    function_caller: str
    function_called: str
    snippet: str
    severity_hint: str


def _strip_sql_comments(text: str) -> str:
    """
    Remove -- line comments and /* */ block comments. Preserve line count so
    1-based line numbers from the original text remain valid when matched
    line-by-line on the stripped output.
    """
    # block comments — replace with same-length whitespace per character,
    # preserving newlines so line indices remain stable.
    def _blank(m: re.Match[str]) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in m.group(0))

    text = re.sub(r"/\*.*?\*/", _blank, text, flags=re.DOTALL)
    # line comments
    out_lines: List[str] = []
    for line in text.splitlines():
        i = line.find("--")
        if i >= 0:
            line = line[:i]
        out_lines.append(line)
    return "\n".join(out_lines)


def _find_dollar_quoted_bodies(
    text: str,
) -> List[Tuple[int, int, str]]:
    """
    Find PL/pgSQL function bodies as (body_start_offset, body_end_offset,
    function_name). body_start_offset is the character offset AFTER the
    opening dollar tag, body_end_offset is the offset BEFORE the closing tag.
    Bodies are matched only when a CREATE [OR REPLACE] FUNCTION declaration
    precedes the opening tag.
    """
    bodies: List[Tuple[int, int, str]] = []
    pos = 0
    while pos < len(text):
        decl = FUNC_DECL_RE.search(text, pos)
        if not decl:
            break
        func_name = decl.group("name")
        # find first dollar-tag after the declaration
        tag = DOLLAR_TAG_RE.search(text, decl.end())
        if not tag:
            pos = decl.end()
            continue
        open_tag = tag.group(0)
        body_start = tag.end()
        # find matching close tag (same exact tag string)
        close = text.find(open_tag, body_start)
        if close < 0:
            pos = body_start
            continue
        bodies.append((body_start, close, func_name))
        pos = close + len(open_tag)
    return bodies


def _line_of(offset: int, line_starts: List[int]) -> int:
    """Return 1-based line number for a character offset."""
    # binary search
    lo, hi = 0, len(line_starts) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if line_starts[mid] <= offset:
            lo = mid + 1
        else:
            hi = mid - 1
    return hi + 1  # convert to 1-based


def _compute_line_starts(text: str) -> List[int]:
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _statement_end(text: str, start: int, body_end: int) -> int:
    """
    Find the offset of the terminating ';' for a statement beginning at
    `start`. Skips semicolons inside parentheses. Bounded by body_end.
    """
    depth = 0
    i = start
    in_str = None
    while i < body_end:
        ch = text[i]
        if in_str:
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch == "'" or ch == '"':
            in_str = ch
            i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == ";" and depth == 0:
            return i
        i += 1
    return body_end


def _scan_body(
    text: str,
    body_start: int,
    body_end: int,
    func_name: str,
    file_path: Path,
    line_starts: List[int],
) -> List[Candidate]:
    """Scan one function body and emit candidates."""
    out: List[Candidate] = []
    body = text[body_start:body_end]
    # iterate over lines of the body
    body_line_starts: List[int] = [0]
    for i, ch in enumerate(body):
        if ch == "\n":
            body_line_starts.append(i + 1)
    for local_line_idx, local_offset in enumerate(body_line_starts):
        # end of this line within the body
        if local_line_idx + 1 < len(body_line_starts):
            line_end_local = body_line_starts[local_line_idx + 1] - 1
        else:
            line_end_local = len(body)
        line_text = body[local_offset:line_end_local]
        m = SELECT_CALL_RE.match(line_text)
        if not m:
            continue
        callee = m.group("callee")
        # ignore obvious read-only built-ins / control-flow tokens that
        # share the SELECT-call shape
        if callee.upper() in {
            "EXISTS",
            "CASE",
            "COALESCE",
            "NULLIF",
            "GREATEST",
            "LEAST",
            "ARRAY",
            "ROW",
        }:
            continue
        # locate the terminating ';' of this statement, bounded by body
        stmt_start_global = body_start + local_offset
        stmt_end_global = _statement_end(text, stmt_start_global, body_end)
        stmt_text = text[stmt_start_global:stmt_end_global]
        # if the statement assigns / captures the result → not a candidate
        if ASSIGN_TOKENS_RE.search(stmt_text):
            continue
        # if the statement looks like a query (FROM/WHERE/JOIN/...), skip:
        # the SELECT-call is then a column-expression of a real query, not
        # a discarded side-effect.
        if QUERY_CONTEXT_RE.search(stmt_text):
            continue
        severity = (
            "MEDIUM" if SIDE_EFFECT_PREFIX_RE.match(callee) else "LOW"
        )
        snippet = line_text.strip()[:240]
        line_no = _line_of(stmt_start_global, line_starts)
        out.append(
            Candidate(
                file=str(file_path),
                line=line_no,
                function_caller=func_name,
                function_called=callee,
                snippet=snippet,
                severity_hint=severity,
            )
        )
    return out


def scan_file(path: Path) -> List[Candidate]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return []
    text = _strip_sql_comments(raw)
    line_starts = _compute_line_starts(text)
    bodies = _find_dollar_quoted_bodies(text)
    out: List[Candidate] = []
    for body_start, body_end, func_name in bodies:
        out.extend(
            _scan_body(text, body_start, body_end, func_name, path, line_starts)
        )
    return out


def walk_repo(root: Path) -> Iterable[Path]:
    skip_dirs = {
        ".git",
        "node_modules",
        "vendor",
        "__pycache__",
        "target",
        "out",
        "dist",
        "build",
        "coverage",
    }
    if root.is_file():
        if root.suffix.lower() in SQL_SUFFIXES:
            yield root
        return
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in SQL_SUFFIXES:
            continue
        parts = set(p.parts)
        if parts & skip_dirs:
            continue
        yield p


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="PL/pgSQL detector: SELECT-helper without PERFORM (side-effect drop)",
    )
    ap.add_argument("repo", type=Path, help="repo root or .sql file to scan")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument(
        "--threshold",
        type=int,
        default=0,
        help="min candidates to exit 1 (0 = always exit 0)",
    )
    args = ap.parse_args(argv)

    root = args.repo
    if not root.exists():
        print(f"error: {root} does not exist", file=sys.stderr)
        return 2

    candidates: List[Candidate] = []
    for p in walk_repo(root):
        candidates.extend(scan_file(p))

    payload = {
        "schema": SCHEMA,
        "root": str(root),
        "count": len(candidates),
        "candidates": [asdict(c) for c in candidates],
    }
    out_text = json.dumps(payload, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(out_text, encoding="utf-8")
    else:
        print(out_text)
    if args.threshold and len(candidates) < args.threshold:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
