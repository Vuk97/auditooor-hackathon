#!/usr/bin/env python3
"""D4 — InsuranceFund payment ordering invariant sentinel.

Detects: in a cosmos-sdk LIQUIDATION_PATH (typically `process_single_match.go`
or any `*liquidation*.go`), the insurance-fund transfer
(`bankKeeper.SendCoins(insuranceFund, ...)` / `*.TransferInsuranceFundPayments`
/ similar) MUST precede `subaccountKeeper.UpdateSubaccounts(...)`. If
UpdateSubaccounts is called earlier in the same function body than the
insurance-fund send, the invariant is inverted and we flag.

CLI:
    python3 tools/detectors/go_insurance_fund_ordering_sentinel.py <repo-path> [--out report.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Optional


SCHEMA = "auditooor.go_insurance_fund_ordering_sentinel.v1"

FILE_NAME_RE = re.compile(r"(?i)(process.*match.*\.go$|.*liquidation.*\.go$)")

FUNC_DECL_RE = re.compile(
    r"^\s*func\s+(?:\((?P<recv>[^)]*)\)\s+)?(?P<name>[A-Za-z_][\w]*)\s*\("
)

# Insurance-fund transfer call shapes:
#   bk.SendCoins(... insuranceFund ...)   /   bankKeeper.SendCoins(insuranceFund, ...)
#   *.TransferInsuranceFundPayments(...)
#   *.SendCoinsFromAccountToModule(... insuranceFund ...) / ModuleToModule
IF_TRANSFER_RE = re.compile(
    r"(?i)\b("
    r"[A-Za-z_][\w]*\.TransferInsuranceFundPayments\s*\(|"
    r"[A-Za-z_][\w]*\.PayInsuranceFund\s*\(|"
    r"[A-Za-z_][\w]*\.SendCoins[A-Za-z]*\s*\([^\)]*insurance[A-Za-z]*|"
    r"[A-Za-z_][\w]*\.SendCoins[A-Za-z]*\s*\([^\)]*InsuranceFund"
    r")"
)

UPDATE_SUBACCOUNTS_RE = re.compile(
    r"\b[A-Za-z_][\w]*\.UpdateSubaccounts[A-Za-z]*\s*\("
)

LIQUIDATION_HINT_RE = re.compile(
    r"(?i)(liquidation|liquidate|persistLiquidationMatch|liquidator)"
)

SKIP_DIRS = {".git", "vendor", "node_modules", "build", ".cache"}


@dataclass
class Sentinel:
    file: str
    func: str
    func_line: int
    if_transfer_line: Optional[int]
    if_transfer_snippet: Optional[str]
    update_subaccounts_line: Optional[int]
    update_subaccounts_snippet: Optional[str]
    pattern: str
    severity_hint: str
    evidence: str


def _iter_go_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*.go"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name.endswith("_test.go"):
            continue
        if not FILE_NAME_RE.search(path.name):
            continue
        yield path


def _split_functions(lines: List[str]):
    """Yield (name, start_lineno_1based, end_lineno_1based, body_lines)."""
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


def _scan_file(path: Path) -> List[Sentinel]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = text.splitlines()
    out: List[Sentinel] = []
    for fn in _split_functions(lines):
        body = "\n".join(fn["lines"])
        if not LIQUIDATION_HINT_RE.search(body) and not LIQUIDATION_HINT_RE.search(fn["name"]):
            continue
        if_lines: List[tuple[int, str]] = []
        us_lines: List[tuple[int, str]] = []
        for offset, raw in enumerate(fn["lines"]):
            absolute = fn["start"] + offset
            if IF_TRANSFER_RE.search(raw):
                if_lines.append((absolute, raw.strip()))
            if UPDATE_SUBACCOUNTS_RE.search(raw):
                us_lines.append((absolute, raw.strip()))
        if not if_lines or not us_lines:
            continue
        first_if = min(l for l, _ in if_lines)
        first_us = min(l for l, _ in us_lines)
        if first_us < first_if:
            us_pair = next(p for p in us_lines if p[0] == first_us)
            if_pair = next(p for p in if_lines if p[0] == first_if)
            out.append(
                Sentinel(
                    file=str(path),
                    func=fn["name"],
                    func_line=fn["start"],
                    if_transfer_line=if_pair[0],
                    if_transfer_snippet=if_pair[1][:240],
                    update_subaccounts_line=us_pair[0],
                    update_subaccounts_snippet=us_pair[1][:240],
                    pattern="ORDER_INVERTED",
                    severity_hint="HIGH",
                    evidence=(
                        f"UpdateSubaccounts at line {us_pair[0]} precedes "
                        f"insurance-fund transfer at line {if_pair[0]} in {fn['name']}"
                    ),
                )
            )
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="D4 InsuranceFund payment ordering sentinel")
    ap.add_argument("root", help="repo root to scan")
    ap.add_argument("--out", help="write JSON to this path")
    args = ap.parse_args(argv)

    root = Path(args.root)
    if not root.exists():
        print(json.dumps({"schema": SCHEMA, "error": "root does not exist", "root": str(root)}))
        return 2

    sentinels: List[Sentinel] = []
    for f in _iter_go_files(root):
        sentinels.extend(_scan_file(f))

    payload = {
        "schema": SCHEMA,
        "root": str(root),
        "count": len(sentinels),
        "sentinels": [asdict(s) for s in sentinels],
    }
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
