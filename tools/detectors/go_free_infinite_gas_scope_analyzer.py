#!/usr/bin/env python3
"""D7 — FreeInfiniteGasDecorator scope analyzer.

In a cosmos-sdk app's `app/ante.go` or `app/ante/*.go`, identify ante
decorators that switch the gas meter to a free / infinite meter
(`SetGasMeter(NewFreeInfiniteGasMeter())` / `WithGasMeter(InfiniteGasMeter(...))`
/ etc). Within each such decorator, extract the gating predicate that
decides which messages receive free gas (e.g.
`if isClobMsg(msg) || IsSingleAppInjectedMsg(tx.GetMsgs())`) and the
msg-type tokens referenced from it. Emit a decision matrix:
msg-type-token → free-gas | metered.

CLI:
    python3 tools/detectors/go_free_infinite_gas_scope_analyzer.py <repo-path> [--out report.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional


SCHEMA = "auditooor.go_free_infinite_gas_scope_analyzer.v1"

FILE_NAME_RE = re.compile(r"(?i)ante.*\.go$|.*ante\.go$")
# Match files inside an */ante/ or */app/ante/ directory regardless of filename.
ANTE_DIR_RE = re.compile(r"(?i)(^|/)(app/)?ante(/|$)")

FUNC_DECL_RE = re.compile(
    r"^\s*func\s+(?:\((?P<recv>[^)]*)\)\s+)?(?P<name>[A-Za-z_][\w]*)\s*\("
)

# Free / infinite gas-meter switch shapes.
FREE_GAS_RE = re.compile(
    r"(?i)\b("
    r"(?:Set|Switch|With)GasMeter\s*\(\s*[^)]*InfiniteGas[A-Za-z_]*|"
    r"NewFreeInfiniteGasMeter\s*\(|"
    r"NewInfiniteGasMeter\s*\(|"
    r"FreeInfiniteGasMeter|"
    r"freeInfiniteGasDecorator"
    r")"
)

# Predicate token capture — msg-type references inside the decorator.
MSG_TYPE_RE = re.compile(r"\b(Msg[A-Z][A-Za-z0-9_]*|is[A-Z][A-Za-z0-9_]*Msg|Is[A-Z][A-Za-z0-9_]*Msg)\b")

# Gating predicates ("is*Msg" helpers and ClobMsg / AppInjected hints).
GATE_HINT_RE = re.compile(
    r"(?i)(isClob|IsClobMsg|IsSingleAppInjected|hasClobMsg|isOffChain|isInjected|isAppInjected)"
)

IF_RE = re.compile(r"^\s*if\s+(?P<cond>.+?)\s*\{\s*$")

SKIP_DIRS = {".git", "vendor", "node_modules", "build", ".cache"}


@dataclass
class Decorator:
    file: str
    decorator: str
    func_line: int
    gas_switch_line: int
    gas_switch_snippet: str
    gating_predicate: Optional[str]
    gating_predicate_line: Optional[int]
    msg_type_tokens: List[str] = field(default_factory=list)
    decision_matrix: Dict[str, str] = field(default_factory=dict)
    severity_hint: str = "INFO"


def _iter_go_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*.go"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name.endswith("_test.go"):
            continue
        if FILE_NAME_RE.search(path.name) or ANTE_DIR_RE.search(str(path.as_posix())):
            yield path


def _split_functions(lines: List[str]):
    funcs = []
    current = None
    brace = 0
    started = False
    for idx, line in enumerate(lines, start=1):
        m = FUNC_DECL_RE.match(line)
        if m and current is None:
            current = {"name": m.group("name"), "start": idx, "lines": []}
            brace = line.count("{") - line.count("}")
            started = "{" in line
            current["lines"].append(line)
            if started and brace == 0:
                current["end"] = idx
                funcs.append(current)
                current = None
                started = False
            continue
        if current is not None:
            current["lines"].append(line)
            brace += line.count("{") - line.count("}")
            if not started and "{" in line:
                started = True
            if started and brace <= 0:
                current["end"] = idx
                funcs.append(current)
                current = None
                started = False
                brace = 0
    return funcs


def _find_gating_predicate(body_lines: List[str], gas_offset: int):
    """Walk upward from the gas-switch line, find the nearest enclosing `if` statement.
    Returns (predicate_text, line_offset_within_body) or (None, None).
    """
    for offset in range(gas_offset - 1, -1, -1):
        line = body_lines[offset]
        m = IF_RE.match(line)
        if m:
            cond = m.group("cond")
            if GATE_HINT_RE.search(cond) or MSG_TYPE_RE.search(cond):
                return cond, offset
        # Stop walking too far back — function-scoped.
        if FUNC_DECL_RE.match(line):
            break
    return None, None


def _scan_file(path: Path) -> List[Decorator]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = text.splitlines()
    out: List[Decorator] = []
    funcs = _split_functions(lines)
    for fn in funcs:
        body = fn["lines"]
        for off, raw in enumerate(body):
            if not FREE_GAS_RE.search(raw):
                continue
            # Skip declarations (func / type / var) — we want runtime call
            # sites where the gas meter is actually swapped, not the helper
            # constructor's own declaration line.
            stripped = raw.lstrip()
            if FUNC_DECL_RE.match(raw):
                continue
            if stripped.startswith(("type ", "var ", "// ")):
                continue
            # Heuristic floor: a real call site has either an assignment or
            # an internal call expression that isn't the constructor decl.
            if "=" not in raw and "(" not in raw:
                continue
            gating_pred, gating_off = _find_gating_predicate(body, off)
            gating_pred_line = (fn["start"] + gating_off) if gating_off is not None else None
            tokens: List[str] = []
            if gating_pred:
                tokens = sorted(set(MSG_TYPE_RE.findall(gating_pred)))
            # Decision matrix: each token gets free-gas; unmatched messages
            # default to metered. We only emit the free-gas rows (positive
            # classifications) since unmatched tokens are unbounded.
            matrix = {t: "free-gas" for t in tokens}
            # Severity hint: HIGH if predicate references "ClobMsg" or
            # "AppInjected" (broad-scope free gas → DoS surface);
            # else MEDIUM if predicate is present; else INFO.
            severity = "INFO"
            if gating_pred:
                severity = "MEDIUM"
                if GATE_HINT_RE.search(gating_pred):
                    severity = "HIGH"
            out.append(
                Decorator(
                    file=str(path),
                    decorator=fn["name"],
                    func_line=fn["start"],
                    gas_switch_line=fn["start"] + off,
                    gas_switch_snippet=raw.strip()[:240],
                    gating_predicate=(gating_pred.strip() if gating_pred else None),
                    gating_predicate_line=gating_pred_line,
                    msg_type_tokens=tokens,
                    decision_matrix=matrix,
                    severity_hint=severity,
                )
            )
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="D7 FreeInfiniteGasDecorator scope analyzer"
    )
    ap.add_argument("root", help="repo root to scan")
    ap.add_argument("--out", help="write JSON to this path")
    args = ap.parse_args(argv)

    root = Path(args.root)
    if not root.exists():
        print(json.dumps({"schema": SCHEMA, "error": "root does not exist", "root": str(root)}))
        return 2

    decorators: List[Decorator] = []
    for f in _iter_go_files(root):
        decorators.extend(_scan_file(f))

    payload = {
        "schema": SCHEMA,
        "root": str(root),
        "count": len(decorators),
        "decorators": [asdict(d) for d in decorators],
    }
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
