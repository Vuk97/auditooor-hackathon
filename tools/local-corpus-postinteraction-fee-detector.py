#!/usr/bin/env python3
"""Detect maker-controlled postInteraction fee siphons from the local corpus.

This scanner is intentionally narrow. It looks for Solidity settlement
extensions where `_parseFeeData()` derives an integration fee from
maker-controlled `extraData`, and `postInteraction()` transfers that fee after
the order fill without applying taker-threshold or max-fee protection. The
source packet is Hexens 1inch ONN-1.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SCHEMA = "auditooor.local_corpus.postinteraction_fee_detector.v1"

FUNCTION_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)[^{;]*\{",
    re.S,
)

EXTRA_DATA_FEE_RE = re.compile(
    r"(?:uint(?:256)?\s*\(\s*)?uint32\s*\(\s*bytes4\s*\(\s*"
    r"[A-Za-z_][A-Za-z0-9_]*\s*\[\s*20\s*:\s*24\s*\]\s*\)\s*\)",
    re.S,
)

FEE_CALC_RE = re.compile(
    r"\bintegrationFee\b\s*=\s*[^;]*\bactualTakingAmount\b[^;]*/\s*"
    r"\b_TAKING_FEE_BASE\b",
    re.S,
)

MAX_FEE_GUARD_RE = re.compile(
    r"("
    r"\brequire\s*\([^;]*(?:<=|<)\s*_TAKING_FEE_BASE\b|"
    r"\bif\s*\([^;]*(?:>|>=)\s*_TAKING_FEE_BASE\b\s*\)\s*(?:revert|{[^}]*\brevert\b)|"
    r"\b(?:min|Math\s*\.\s*min)\s*\([^;]*_TAKING_FEE_BASE"
    r")",
    re.S,
)

POST_INTERACTION_FEE_RE = re.compile(
    r"\b_parseFeeData\s*\([^;]*\)|\bintegrationFee\b",
    re.S,
)

TAKER_TOKEN_TRANSFER_RE = re.compile(
    r"\b(?:safeTransferFrom|transferFrom|uniTransferFrom|safeTransfer)\s*\("
    r"[^;]*(?:takerAsset|order\s*\.\s*takerAsset|get\(\)|taker)[^;]*"
    r"\bintegrationFee\b",
    re.S,
)

THRESHOLD_GUARD_RE = re.compile(
    r"\b(?:takerTraits\s*\.\s*)?threshold\s*\(|\bthreshold\b|\bmax(?:imum)?Fee\b|"
    r"\bmax(?:imum)?TakingFee\b",
    re.S,
)


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    parse_function: str
    post_function: str
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


def _parse_fee_functions(function_bodies: list[tuple[str, int, str]]) -> list[tuple[str, int]]:
    matches: list[tuple[str, int]] = []
    for name, start, body in function_bodies:
        if "extraData" not in body or "integrationFee" not in body:
            continue
        if EXTRA_DATA_FEE_RE.search(body) is None:
            continue
        if FEE_CALC_RE.search(body) is None:
            continue
        if MAX_FEE_GUARD_RE.search(body):
            continue
        matches.append((name, start))
    return matches


def _post_interaction_functions(function_bodies: list[tuple[str, int, str]]) -> list[tuple[str, int]]:
    matches: list[tuple[str, int]] = []
    for name, start, body in function_bodies:
        if name != "postInteraction":
            continue
        if POST_INTERACTION_FEE_RE.search(body) is None:
            continue
        if TAKER_TOKEN_TRANSFER_RE.search(body) is None:
            continue
        if THRESHOLD_GUARD_RE.search(body):
            continue
        matches.append((name, start))
    return matches


def detect_source(source: str, path: str) -> list[Hit]:
    function_bodies = list(functions(source))
    parse_functions = _parse_fee_functions(function_bodies)
    post_functions = _post_interaction_functions(function_bodies)
    if not parse_functions or not post_functions:
        return []

    hits: list[Hit] = []
    for parse_name, parse_start in parse_functions:
        for post_name, _post_start in post_functions:
            hits.append(
                Hit(
                    path=path,
                    line=source.count("\n", 0, parse_start) + 1,
                    parse_function=parse_name,
                    post_function=post_name,
                    packet_id="LCCR-PKT-011",
                    title="Maker-controlled postInteraction fee bypasses taker threshold",
                    message=(
                        "Settlement extension parses integrationFee from maker-controlled "
                        "extraData and later transfers that fee in postInteraction without "
                        "a max-fee cap or taker-threshold-side protection."
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
        "selected_packet": "LCCR-PKT-011",
        "detector": "local-corpus-maker-controlled-postinteraction-fee",
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
