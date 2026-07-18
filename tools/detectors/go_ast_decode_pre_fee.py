#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Optional


SCHEMA = "auditooor.go_ast_decode_pre_fee.v1"

UNMARSHAL_RE = re.compile(
    r"\b("
    r"proto\.Unmarshal|"
    r"[A-Za-z_][\w]*\.Unmarshal\b|"
    r"[A-Za-z_][\w]*\.UnmarshalAny\b|"
    r"[A-Za-z_][\w]*\.UnmarshalBinary\b|"
    r"[A-Za-z_][\w]*\.UnmarshalJSON\b|"
    r"codec\.UnmarshalAny\b|"
    r"NewProtoCodec\([^\)]*\)\.Unmarshal[A-Za-z_]*\b|"
    r"\bUnmarshalAny\("
    r")"
)

FEE_GUARD_RE = re.compile(
    r"(?i)(fee|gas|deduct|charge|rate.?limit|throttle|priority|gasconsumed|consumegas|gascost|consume_gas)"
)

HANDLER_HINT_RE = re.compile(
    r"(?i)(decode|unmarshal|handle|server|ante|preprocess|extract|process)"
)

MSGSERVER_TYPE_RE = re.compile(
    r"(?i)(MsgServer|Handler|Keeper|Server|AnteHandler|Decorator)$"
)

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
    # crude: drop // comments and quoted strings to reduce regex false hits
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
        if c == '"' or c == "'" or c == "`":
            in_str = c
            i += 1
            continue
        if c == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        out.append(c)
        i += 1
    return "".join(out)


def _iter_funcs(lines: List[str]):
    """
    Yield (func_name, start_line_idx, body_start_idx, body_end_idx, recv).
    body indices are 0-based line numbers spanning the brace-balanced body.
    """
    i = 0
    n = len(lines)
    while i < n:
        m = FUNC_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group("name")
        recv = m.group("recv") or ""
        # find opening brace; may be same line or later
        depth = 0
        body_start = -1
        j = i
        opened = False
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
                        yield name, i, body_start, j, recv
                        i = j + 1
                        break
            else:
                j += 1
                continue
            break
        else:
            return


def _is_exported(name: str) -> bool:
    return bool(name) and name[0].isupper()


def _is_msgserver_method(recv: str) -> bool:
    if not recv:
        return False
    # recv like "k Keeper" or "ms msgServer"
    parts = recv.split()
    if not parts:
        return False
    tname = parts[-1].lstrip("*")
    return bool(MSGSERVER_TYPE_RE.search(tname))


def scan_file(path: Path) -> List[Candidate]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return []
    lines = text.splitlines()
    out: List[Candidate] = []
    for name, decl_line, body_start, body_end, recv in _iter_funcs(lines):
        if not (_is_exported(name) or _is_msgserver_method(recv)):
            continue
        # scan body lines [body_start+1 .. body_end-1]
        unmarshal_idx = -1
        for k in range(body_start + 1, body_end):
            raw = lines[k]
            if COMMENT_LINE_RE.match(raw):
                continue
            stripped = _strip_strings_and_comments(raw)
            if UNMARSHAL_RE.search(stripped):
                unmarshal_idx = k
                break
        if unmarshal_idx < 0:
            continue
        # scan preceding body lines for fee guard
        has_guard = False
        for k in range(body_start + 1, unmarshal_idx):
            raw = lines[k]
            if COMMENT_LINE_RE.match(raw):
                continue
            stripped = _strip_strings_and_comments(raw)
            if FEE_GUARD_RE.search(stripped):
                has_guard = True
                break
        if has_guard:
            continue
        snippet = lines[unmarshal_idx].strip()
        sev = "HIGH" if HANDLER_HINT_RE.search(name) else "MEDIUM"
        out.append(
            Candidate(
                file=str(path),
                line=unmarshal_idx + 1,
                function=name,
                snippet=snippet[:240],
                severity_hint=sev,
            )
        )
    return out


def walk_repo(root: Path) -> Iterable[Path]:
    for p in root.rglob("*.go"):
        # skip vendor/testdata/_test.go/generated .pb.go to lower noise
        parts = set(p.parts)
        if "vendor" in parts or "testdata" in parts:
            continue
        if p.name.endswith("_test.go"):
            continue
        if p.name.endswith(".pb.go") or p.name.endswith(".pb.gw.go"):
            continue
        yield p


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Go AST detector: decode-before-fee-guard CPU exhaustion")
    ap.add_argument("repo", type=Path, help="repo root to scan")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--threshold", type=int, default=0, help="min candidates to exit 1")
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
    out_text = json.dumps(payload, indent=2)
    if args.out:
        args.out.write_text(out_text, encoding="utf-8")
    else:
        print(out_text)
    if args.threshold and len(candidates) < args.threshold:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
