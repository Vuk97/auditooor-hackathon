#!/usr/bin/env python3
"""Go detector for unconditional cap growth from an external amount.

Source-backed lift:
  Solodit #63344, tier-2 public archive, reports Solidity `PortalCCIP._setNewCap`
  unconditionally setting a new cap to `max(cap, totalSupply) + amount`.

RELATED TOOLS:
  - tools/tests/test_dos_cap_flag_or_estimation_oneway_exhaustion.py covers a
    Solidity fixture family for sticky DoS flags and raw gas caps.
  - tools/rust-host-length-cast-unbounded-alloc-scan.py covers Rust allocation
    growth from untrusted lengths.
  - This detector fills the Go-specific gap for cap or limit setters that add
    a message/request amount without a headroom guard.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional


SCHEMA = "auditooor.go_ast_dos_cap_unbounded_input_growth_fire7.v1"
SOURCE_RECORD_ID = "solodit:63344:m-01-unnecessary-cap-inflation-and-unbounded-cap-growth"

FUNC_DECL_RE = re.compile(
    r"^\s*func\s+(?:\((?P<recv>[^)]*)\)\s+)?(?P<name>[A-Za-z_]\w*)\s*\("
)

CAP_CONTEXT_RE = re.compile(
    r"(cap|limit|quota|max|ceiling|headroom|allowance|debtLimit|supplyCap|mintCap)",
    re.IGNORECASE,
)
SUPPLY_CONTEXT_RE = re.compile(
    r"(supply|totalSupply|total|outstanding|minted|issued|utilized|used|debt|usage)",
    re.IGNORECASE,
)
AMOUNT_SOURCE_RE = re.compile(
    r"\b(?:(?:msg|req|request|payload|input|packet|message)\."
    r"[A-Za-z_]\w*(?:Amount|Amt|Size|Qty|Quantity|Limit|Cap|Value|Delta)"
    r"|(?:amount|amt|size|qty|quantity|delta|value|mintAmount|burnAmount"
    r"|inputAmount|messageAmount|requestedAmount|limitDelta|capDelta))\b",
    re.IGNORECASE,
)
CAP_WRITE_RE = re.compile(
    r"\b(?P<name>SetNewCap|SetCap|SetSupplyCap|SetMintCap|SetDebtLimit"
    r"|SetLimit|UpdateCap|UpdateLimit|IncreaseCap|IncreaseLimit"
    r"|SetMax|SetQuota|setNewCap|setCap|setLimit)\s*\(",
    re.IGNORECASE,
)
CAP_ASSIGN_RE = re.compile(
    r"\b[A-Za-z_]\w*\.(?:Cap|Limit|SupplyCap|MintCap|DebtLimit|Max|Quota)\s*"
    r"(?:=|\+=)\s*(?P<rhs>[^;\n]+)",
    re.IGNORECASE,
)
ASSIGN_RE = re.compile(r"\b(?P<lhs>[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<rhs>[^;\n]+)")
HEADROOM_GUARD_RE = re.compile(
    r"(Ensure|Validate|Check|Assert|Has|Needs|Can)[A-Za-z_]*(Cap|Limit|Headroom|Quota)"
    r"|(?:remaining|headroom|available|room)\s*(?:>=|>|<=|<|==|!=)\s*[^;\n]*"
    r"(?:amount|amt|msg\.[A-Za-z_]\w*Amount|req\.[A-Za-z_]\w*Amount)"
    r"|(?:cap|limit|quota)\s*-\s*(?:supply|totalSupply|used|usage|debt)"
    r"\s*(?:>=|>)\s*[^;\n]*(?:amount|amt|msg\.[A-Za-z_]\w*Amount|req\.[A-Za-z_]\w*Amount)"
    r"|(?:supply|totalSupply|used|usage|debt)\s*\+\s*"
    r"(?:amount|amt|msg\.[A-Za-z_]\w*Amount|req\.[A-Za-z_]\w*Amount)"
    r"\s*(?:<=|<)\s*(?:cap|limit|quota)",
    re.IGNORECASE,
)


@dataclass
class Candidate:
    file: str
    line: int
    function: str
    snippet: str
    severity_hint: str
    source_record_id: str
    reason: str


def _strip_strings_and_comments(line: str) -> str:
    out: list[str] = []
    i = 0
    in_str: str | None = None
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


def _iter_funcs(lines: list[str]):
    i = 0
    n = len(lines)
    while i < n:
        match = FUNC_DECL_RE.match(lines[i])
        if not match:
            i += 1
            continue
        name = match.group("name")
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


def _split_call_args(call_text: str) -> list[str]:
    start = call_text.find("(")
    end = call_text.rfind(")")
    if start < 0 or end <= start:
        return []
    args_text = call_text[start + 1 : end]
    args: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in args_text:
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth > 0:
            depth -= 1
    if current or args_text.strip():
        args.append("".join(current).strip())
    return args


def _call_spans(body_lines: list[str], first_line: int) -> list[tuple[str, int]]:
    spans: list[tuple[str, int]] = []
    current: list[str] = []
    current_line = first_line
    depth = 0
    for offset, raw in enumerate(body_lines):
        line_no = first_line + offset
        line = _strip_strings_and_comments(raw)
        if current:
            current.append(line)
            depth += line.count("(") - line.count(")")
            if depth <= 0:
                spans.append(("\n".join(current), current_line))
                current = []
            continue
        if not CAP_WRITE_RE.search(line):
            continue
        current = [line]
        current_line = line_no
        depth = line.count("(") - line.count(")")
        if depth <= 0:
            spans.append((line, line_no))
            current = []
    return spans


def _find_aliases(body_text: str) -> tuple[set[str], set[str], set[str]]:
    cap_terms = {"cap", "currentCap", "supplyCap", "limit", "currentLimit"}
    supply_terms = {"supply", "totalSupply", "used", "usage", "debt", "total"}
    amount_terms = {"amount", "amt", "delta", "value", "size", "qty"}

    for match in AMOUNT_SOURCE_RE.finditer(body_text):
        amount_terms.add(match.group(0))

    changed = True
    while changed:
        changed = False
        for line in body_text.splitlines():
            match = ASSIGN_RE.search(line)
            if not match:
                continue
            lhs = match.group("lhs")
            rhs = match.group("rhs")
            if CAP_CONTEXT_RE.search(lhs) or _mentions(rhs, cap_terms):
                if lhs not in cap_terms:
                    cap_terms.add(lhs)
                    changed = True
            if SUPPLY_CONTEXT_RE.search(lhs) or _mentions(rhs, supply_terms):
                if lhs not in supply_terms:
                    supply_terms.add(lhs)
                    changed = True
            if AMOUNT_SOURCE_RE.search(rhs) or _mentions(rhs, amount_terms):
                if lhs not in amount_terms:
                    amount_terms.add(lhs)
                    changed = True
    return cap_terms, supply_terms, amount_terms


def _mentions(expr: str, terms: set[str]) -> bool:
    for term in terms:
        if "." in term or "(" in term or "[" in term:
            if term in expr:
                return True
            continue
        if re.search(rf"\b{re.escape(term)}\b", expr):
            return True
    return False


def _has_headroom_guard(body_text: str) -> bool:
    for line in body_text.splitlines():
        if HEADROOM_GUARD_RE.search(line):
            return True
    return False


def _risky_expr(expr: str, cap_terms: set[str], supply_terms: set[str], amount_terms: set[str]) -> bool:
    if "+" not in expr:
        return False
    if not _mentions(expr, amount_terms):
        return False
    return _mentions(expr, cap_terms) or _mentions(expr, supply_terms) or CAP_CONTEXT_RE.search(expr)


def _find_risky_cap_write(
    body_lines: list[str],
    first_line: int,
    cap_terms: set[str],
    supply_terms: set[str],
    amount_terms: set[str],
) -> tuple[int, str] | None:
    for call_text, line_no in _call_spans(body_lines, first_line):
        args = _split_call_args(call_text)
        if any(_risky_expr(arg, cap_terms, supply_terms, amount_terms) for arg in args):
            return line_no, call_text.splitlines()[0].strip()[:240]

    for offset, raw in enumerate(body_lines):
        line = _strip_strings_and_comments(raw)
        match = CAP_ASSIGN_RE.search(line)
        if not match:
            continue
        rhs = match.group("rhs")
        if _risky_expr(rhs, cap_terms, supply_terms, amount_terms) or "+=" in line:
            return first_line + offset, raw.strip()[:240]
    return None


def scan_file(path: Path) -> list[Candidate]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return []
    lines = text.splitlines()
    out: list[Candidate] = []
    for name, decl_line, body_start, body_end in _iter_funcs(lines):
        fn_text = "\n".join(lines[decl_line : body_end + 1])
        body_lines = lines[body_start + 1 : body_end]
        body_text = "\n".join(_strip_strings_and_comments(line) for line in body_lines)
        if not CAP_CONTEXT_RE.search(fn_text):
            continue
        if not SUPPLY_CONTEXT_RE.search(fn_text):
            continue
        if not AMOUNT_SOURCE_RE.search(fn_text):
            continue
        if _has_headroom_guard(body_text):
            continue

        cap_terms, supply_terms, amount_terms = _find_aliases(body_text)
        risky = _find_risky_cap_write(body_lines, body_start + 2, cap_terms, supply_terms, amount_terms)
        if risky is None:
            continue
        line_no, snippet = risky
        out.append(
            Candidate(
                file=str(path),
                line=line_no,
                function=name,
                snippet=snippet,
                severity_hint="MEDIUM",
                source_record_id=SOURCE_RECORD_ID,
                reason=(
                    "cap or limit write adds an external amount to current cap, "
                    "supply, or usage without a headroom guard"
                ),
            )
        )
    return out


def walk_repo(root: Path) -> Iterable[Path]:
    for p in root.rglob("*.go"):
        parts = set(p.parts)
        if "vendor" in parts or "testdata" in parts or ".auditooor" in parts:
            continue
        if p.name.endswith("_test.go"):
            continue
        if p.name.endswith(".pb.go") or p.name.endswith(".pb.gw.go"):
            continue
        yield p


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Go detector: unconditional cap growth from external input"
    )
    ap.add_argument("repo", type=Path, help="repo root or Go file to scan")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--threshold", type=int, default=0, help="min candidates to exit 1")
    args = ap.parse_args(argv)

    root = args.repo
    if not root.exists():
        print(f"error: {root} does not exist", file=sys.stderr)
        return 2

    candidates: list[Candidate] = []
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
