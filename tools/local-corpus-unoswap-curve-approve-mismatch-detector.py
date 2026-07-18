#!/usr/bin/env python3
"""Detect the local-corpus Unoswap Curve token/spender approval mismatch.

This scanner is intentionally narrow. It looks for the Hexens INOCT-4 shape:
`_unoswap` pulls the caller's declared input token into the router, then calls a
Curve helper without passing that token; the Curve helper derives `fromToken`
from a caller-selected pool and approves that pool for `amount`.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SCHEMA = "auditooor.local_corpus.unoswap_curve_approve_mismatch_detector.v1"

FUNCTION_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)[^{;]*\{",
    re.S,
)

ROUTER_PULL_RE = re.compile(
    r"("
    r"\bsafeTransferFromUniversal\s*\(\s*msg\.sender\s*,\s*address\s*\(\s*this\s*\)\s*,\s*amount\b|"
    r"\btransferFrom\s*\(\s*msg\.sender\s*,\s*address\s*\(\s*this\s*\)\s*,\s*amount\b"
    r")",
    re.S,
)

CURVE_BRANCH_RE = re.compile(r"\bProtocol(?:Lib)?\s*\.\s*Protocol\s*\.\s*Curve\b|\bProtocol\s*\.\s*Curve\b|\bcurve\b", re.I)

CURFE_CALL_RE = re.compile(r"\b(?P<callee>_[A-Za-z0-9_]*(?:curfe|curve)[A-Za-z0-9_]*)\s*\((?P<args>[^;{}]*)\)", re.I | re.S)

POOL_FROM_DEX_RE = re.compile(
    r"("
    r"\bpool\b[\s\S]{0,220}\bdex\b|"
    r"\bdex\b[\s\S]{0,220}\bpool\b|"
    r"\baddress\s+pool\s*=\s*[^;]*dex\b|"
    r"\blet\s+pool\s*:=[\s\S]{0,120}\bdex\b"
    r")",
    re.S,
)

POOL_TOKEN_DERIVATION_RE = re.compile(
    r"("
    r"\b(?:address\s+)?(?P<var1>fromToken|srcToken|tokenIn|inputToken)\b\s*=[^;]*(?:coins\s*\(|pool)|"
    r"\blet\s+(?P<var2>fromToken|srcToken|tokenIn|inputToken)\s*:=[\s\S]{0,260}(?:coins\s*\(|pool)"
    r")",
    re.S,
)

APPROVE_DERIVED_TOKEN_RE = re.compile(
    r"("
    r"\basmApprove\s*\(\s*(?:fromToken|srcToken|tokenIn|inputToken)\s*,\s*pool\s*,\s*amount\b|"
    r"\b(?:approve|safeApprove|forceApprove)\s*\(\s*(?:fromToken|srcToken|tokenIn|inputToken)\s*,\s*pool\s*,\s*amount\b|"
    r"\bIERC20\s*\(\s*(?:fromToken|srcToken|tokenIn|inputToken)\s*\)\s*\.\s*(?:approve|safeApprove)\s*\(\s*pool\s*,\s*amount\b"
    r")",
    re.S,
)


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    unoswap_function: str
    curve_function: str
    packet_id: str
    title: str
    message: str


@dataclass(frozen=True)
class FunctionBlock:
    name: str
    start: int
    body: str


# r36-rebuttal: bugfix-inventory-claude-20260610
_TEST_SUFFIXES = (".t.sol", ".s.sol", ".test.sol")
_TEST_DIR_SEGMENTS = {"test", "tests", "script"}


def _is_test_file(p: Path) -> bool:
    """Return True for test/script fixtures that should not be scanned."""
    name_lower = p.name.lower()
    if any(name_lower.endswith(sfx) for sfx in _TEST_SUFFIXES):
        return True
    parts_lower = {seg.lower() for seg in p.parts}
    return bool(parts_lower & _TEST_DIR_SEGMENTS)


def solidity_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_file() and path.suffix == ".sol" and not _is_test_file(path):
            yield path
        elif path.is_dir():
            yield from sorted(p for p in path.rglob("*.sol") if not _is_test_file(p))


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


def functions(source: str) -> Iterable[FunctionBlock]:
    for match in FUNCTION_RE.finditer(source):
        open_index = source.find("{", match.start())
        if open_index == -1:
            continue
        end = find_matching_brace(source, open_index)
        yield FunctionBlock(match.group("name"), match.start(), source[match.start():end])


def _call_args_without_comments(args: str) -> str:
    args = re.sub(r"//.*?$|/\*[\s\S]*?\*/", "", args, flags=re.M)
    return re.sub(r"\s+", "", args)


def _unoswap_curve_calls_without_token(fn: FunctionBlock) -> list[str]:
    if "unoswap" not in fn.name.lower():
        return []
    if ROUTER_PULL_RE.search(fn.body) is None:
        return []
    if CURVE_BRANCH_RE.search(fn.body) is None:
        return []

    callees: list[str] = []
    for match in CURFE_CALL_RE.finditer(fn.body):
        args = _call_args_without_comments(match.group("args"))
        if "token" in args.lower() or "fromtoken" in args.lower():
            continue
        callees.append(match.group("callee"))
    return callees


def _curve_helper_approves_pool_derived_token(fn: FunctionBlock) -> bool:
    lower_name = fn.name.lower()
    if "curfe" not in lower_name and "curve" not in lower_name:
        return False
    if POOL_FROM_DEX_RE.search(fn.body) is None:
        return False
    if POOL_TOKEN_DERIVATION_RE.search(fn.body) is None:
        return False
    if APPROVE_DERIVED_TOKEN_RE.search(fn.body) is None:
        return False
    return True


def detect_source(source: str, path: str) -> list[Hit]:
    blocks = list(functions(source))
    curve_helpers = {fn.name: fn for fn in blocks if _curve_helper_approves_pool_derived_token(fn)}
    if not curve_helpers:
        return []

    hits: list[Hit] = []
    seen: set[tuple[str, str]] = set()
    for fn in blocks:
        for callee in _unoswap_curve_calls_without_token(fn):
            curve_fn = curve_helpers.get(callee)
            if curve_fn is None:
                continue
            key = (fn.name, curve_fn.name)
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                Hit(
                    path=path,
                    line=source.count("\n", 0, curve_fn.start) + 1,
                    unoswap_function=fn.name,
                    curve_function=curve_fn.name,
                    packet_id="LCCR-PKT-013",
                    title="Unoswap approves mismatched token/spender during Curve path",
                    message=(
                        "Unoswap pulls the user-declared token into the router, "
                        "then calls a Curve helper without passing that token; "
                        "the helper derives fromToken from a caller-selected pool "
                        "and approves that pool for amount."
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
        "selected_packet": "LCCR-PKT-013",
        "detector": "local-corpus-unoswap-curve-approve-mismatch",
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
