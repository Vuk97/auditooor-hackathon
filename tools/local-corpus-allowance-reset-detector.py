#!/usr/bin/env python3
"""Detect the local-corpus Curve/USDT hanging allowance shape.

This is intentionally narrow. It looks for Solidity Curve swap helpers that
approve a pool for a non-zero amount and do not clear the allowance in the same
function. The first packet source is Hexens 1inch ONI-12.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SCHEMA = "auditooor.local_corpus.allowance_reset_detector.v1"

FUNCTION_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)[^{;]*\{",
    re.S,
)

CURVE_CONTEXT_RE = re.compile(
    r"\b(curve|curfe|Curve|CURVE|coins\s*\(|exchange\s*\(|pool)\b"
)

POOL_APPROVE_RE = re.compile(
    r"(\.approve\s*\(\s*pool\s*,\s*(?!0\b)[^)]+\)|"
    r"\bsafeApprove\s*\([^,]+,\s*pool\s*,\s*(?!0\b)[^)]+\)|"
    r"\bapprove\s*\(\s*pool\s*,\s*(?!0\b)[^)]+\)|"
    r"0x095ea7b3[0-9a-fA-F]*.*?mstore\s*\(\s*add\s*\(\s*ptr\s*,\s*0x04\s*\)\s*,\s*pool\s*\).*?"
    r"mstore\s*\(\s*add\s*\(\s*ptr\s*,\s*0x24\s*\)\s*,\s*(?!0\b)[A-Za-z_][A-Za-z0-9_]*\s*\).*?"
    r"safeERC20\s*\([^)]*\))",
    re.S,
)

RESET_RE = re.compile(
    r"(\.approve\s*\(\s*pool\s*,\s*0\s*\)|"
    r"\bsafeApprove\s*\([^,]+,\s*pool\s*,\s*0\s*\)|"
    r"\bforceApprove\s*\([^)]*pool[^)]*\)|"
    r"mstore\s*\(\s*add\s*\(\s*ptr\s*,\s*0x24\s*\)\s*,\s*0\s*\).*?"
    r"safeERC20\s*\([^)]*\))",
    re.S,
)


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    function: str
    packet_id: str
    title: str
    message: str


def solidity_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_file() and path.suffix == ".sol":
            yield path
        elif path.is_dir():
            yield from sorted(path.rglob("*.sol"))


def find_matching_brace(source: str, open_index: int) -> int:
    depth = 0
    i = open_index
    while i < len(source):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(source)


def functions(source: str) -> Iterable[tuple[str, int, str]]:
    for match in FUNCTION_RE.finditer(source):
        open_index = source.find("{", match.start())
        if open_index == -1:
            continue
        end = find_matching_brace(source, open_index)
        yield match.group("name"), match.start(), source[match.start():end]


def is_curve_helper(name: str, body: str) -> bool:
    lower_name = name.lower()
    if "curfe" in lower_name or "curve" in lower_name:
        return True
    return bool(CURVE_CONTEXT_RE.search(body) and "pool" in body)


def detect_source(source: str, path: str) -> list[Hit]:
    hits: list[Hit] = []
    for name, start, body in functions(source):
        if not is_curve_helper(name, body):
            continue
        approve = POOL_APPROVE_RE.search(body)
        if approve is None:
            continue
        tail_after_approve = body[approve.end():]
        if RESET_RE.search(tail_after_approve):
            continue
        hits.append(
            Hit(
                path=path,
                line=source.count("\n", 0, start) + 1,
                function=name,
                packet_id="LCCR-PKT-001",
                title="Unoswap Curve USDT hanging allowance DoS",
                message=(
                    "Curve-like helper approves `pool` for a non-zero amount "
                    "without clearing the allowance afterward; USDT-style "
                    "tokens can revert later approvals when a hanging "
                    "allowance remains."
                ),
            )
        )
    return hits


def scan_paths(paths: Iterable[Path]) -> list[Hit]:
    hits: list[Hit] = []
    for path in solidity_files(paths):
        try:
            source = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            source = path.read_text(encoding="latin-1")
        hits.extend(detect_source(source, str(path)))
    return hits


def build_payload(hits: list[Hit]) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "selected_packet": "LCCR-PKT-001",
        "detector": "local-corpus-curve-usdt-hanging-allowance",
        "hit_count": len(hits),
        "hits": [asdict(hit) for hit in hits],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="Solidity file or directory to scan")
    args = parser.parse_args(argv)
    payload = build_payload(scan_paths(args.paths))
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if payload["hit_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
