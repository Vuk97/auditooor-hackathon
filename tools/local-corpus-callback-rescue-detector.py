#!/usr/bin/env python3
"""Detect permissionless swap callbacks that rescue router-held funds.

This scanner is intentionally narrow. It looks for Solidity swap callbacks
that can be called directly and transfer tokens from the callback contract to
`msg.sender` / `caller()` without proving the caller is the pool. The source
packet is Hexens 1inch INOCT-2.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SCHEMA = "auditooor.local_corpus.callback_rescue_detector.v1"

FUNCTION_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)[^{;]*\{",
    re.S,
)

PUBLIC_OR_EXTERNAL_RE = re.compile(r"\b(?:external|public)\b")

AUTH_GUARD_RE = re.compile(
    r"("
    r"\bverifyCallback\b|"
    r"\bCallbackValidation\b|"
    r"\bPoolAddress\b|"
    r"\bcomputeAddress\b|"
    r"\bonlyPool\b|"
    r"\b_verifyPool\b|"
    r"\brequire\s*\([^;]*(?:msg\.sender|caller\s*\(\s*\))\s*==|"
    r"\brequire\s*\([^;]*==\s*(?:msg\.sender|caller\s*\(\s*\))|"
    r"\bif\s*\([^;]*(?:msg\.sender|caller\s*\(\s*\))\s*!=|"
    r"\bif\s*\([^;]*!=\s*(?:msg\.sender|caller\s*\(\s*\))|"
    r"iszero\s*\(\s*eq\s*\(\s*caller\s*\(\s*\)\s*,|"
    r"iszero\s*\(\s*eq\s*\([^)]*,\s*caller\s*\(\s*\)\s*\)"
    r")",
    re.S,
)

CALLER_TRANSFER_RE = re.compile(
    r"("
    r"\.\s*(?:safeTransfer|uniTransfer|transfer)\s*\(\s*(?:payable\s*\(\s*)?msg\.sender\b|"
    r"\b(?:safeTransfer|uniTransfer|transfer)\s*\(\s*[^,;]+,\s*(?:payable\s*\(\s*)?msg\.sender\b|"
    r"\bmstore\s*\([\s\S]{0,240}\bcaller\s*\(\s*\)[\s\S]{0,700}\bsafeERC20\s*\("
    r")",
    re.S,
)

SELF_PAYER_BRANCH_RE = re.compile(
    r"("
    r"\bpayer\b[\s\S]{0,240}==\s*address\s*\(\s*this\s*\)|"
    r"address\s*\(\s*this\s*\)\s*==[\s\S]{0,240}\bpayer\b|"
    r"\beq\s*\(\s*payer\s*,\s*address\s*\(\s*\)\s*\)|"
    r"\beq\s*\(\s*address\s*\(\s*\)\s*,\s*payer\s*\)|"
    r"\bpayer\s*:=\s*calldataload\s*\(\s*0x84\s*\)[\s\S]{0,320}address\s*\(\s*\)"
    r")",
    re.S,
)


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    callback_function: str
    sink_kind: str
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


def _has_direct_caller_transfer(body: str) -> bool:
    return CALLER_TRANSFER_RE.search(body) is not None


def _has_auth_guard(body: str) -> bool:
    return AUTH_GUARD_RE.search(body) is not None


def _sink_kind(name: str, body: str) -> str | None:
    if name == "curveSwapCallback":
        if _has_direct_caller_transfer(body):
            return "curve-callback-direct-transfer-to-caller"
        return None

    if name == "uniswapV3SwapCallback":
        if _has_direct_caller_transfer(body) and SELF_PAYER_BRANCH_RE.search(body):
            return "uniswap-v3-self-payer-transfer-to-caller"
        return None

    return None


def detect_source(source: str, path: str) -> list[Hit]:
    hits: list[Hit] = []
    for name, start, body in functions(source):
        if name not in {"curveSwapCallback", "uniswapV3SwapCallback"}:
            continue
        header = body[: body.find("{")]
        if PUBLIC_OR_EXTERNAL_RE.search(header) is None:
            continue
        if _has_auth_guard(body):
            continue
        sink_kind = _sink_kind(name, body)
        if sink_kind is None:
            continue
        hits.append(
            Hit(
                path=path,
                line=source.count("\n", 0, start) + 1,
                callback_function=name,
                sink_kind=sink_kind,
                packet_id="LCCR-PKT-012",
                title="Permissionless swap callback can rescue router-held funds",
                message=(
                    "Swap callback transfers tokens from the callback contract to "
                    "msg.sender/caller without authenticating the pool caller; "
                    "router-held tokens can be rescued by a direct callback call."
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
        "selected_packet": "LCCR-PKT-012",
        "detector": "local-corpus-permissionless-callback-rescue",
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
