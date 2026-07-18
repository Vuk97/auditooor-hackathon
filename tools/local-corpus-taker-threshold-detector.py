#!/usr/bin/env python3
"""Detect the local-corpus optional taker threshold order-fill shape.

This scanner is intentionally narrow. It looks for Solidity order fill
functions that call maker-controlled amount calculators and only enforce the
taker's rate threshold inside `if (threshold > 0)` / non-zero guards. The source
packet is Hexens 1inch ONI-6.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SCHEMA = "auditooor.local_corpus.taker_threshold_detector.v1"

FUNCTION_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)[^{;]*\{",
    re.S,
)

AMOUNT_CALLBACK_RE = re.compile(
    r"\b(?:order\s*\.\s*)?calculate(?:Making|Taking)Amount\s*\(",
    re.S,
)

THRESHOLD_ASSIGN_RE = re.compile(
    r"\b(?:uint(?:256)?\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"takerTraits\s*\.\s*threshold\s*\(\s*\)\s*;",
    re.S,
)


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    function: str
    threshold_variable: str
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


def _guard_re(var: str) -> re.Pattern[str]:
    escaped = re.escape(var)
    return re.compile(
        rf"\bif\s*\(\s*(?:{escaped}\s*(?:>|!=)\s*0|0\s*(?:<|!=)\s*{escaped})\s*\)",
        re.S,
    )


def _mandatory_or_default_re(var: str) -> re.Pattern[str]:
    escaped = re.escape(var)
    return re.compile(
        rf"("
        rf"\brequire\s*\(\s*(?:{escaped}\s*(?:>|!=)\s*0|0\s*<\s*{escaped})\b|"
        rf"\bif\s*\(\s*(?:{escaped}\s*(?:==|<=)\s*0|0\s*(?:==|>=)\s*{escaped})\s*\)"
        rf"\s*(?:revert|{{[^}}]*\brevert\b)|"
        rf"\bif\s*\(\s*(?:{escaped}\s*==\s*0|0\s*==\s*{escaped})\s*\)"
        rf"\s*{{?[^{{;}}]*\b{escaped}\s*=|"
        rf"\b{escaped}\s*=\s*{escaped}\s*==\s*0\s*\?"
        rf")",
        re.S,
    )


def _has_optional_threshold_guard(body: str) -> str | None:
    for assign in THRESHOLD_ASSIGN_RE.finditer(body):
        var = assign.group("var")
        tail = body[assign.end():]
        guard = _guard_re(var).search(tail)
        if guard is None:
            continue
        before_guard = body[: assign.end() + guard.start()]
        if _mandatory_or_default_re(var).search(before_guard):
            continue
        return var
    return None


def detect_source(source: str, path: str) -> list[Hit]:
    hits: list[Hit] = []
    for name, start, body in functions(source):
        if "takerTraits" not in body:
            continue
        if AMOUNT_CALLBACK_RE.search(body) is None:
            continue
        threshold_var = _has_optional_threshold_guard(body)
        if threshold_var is None:
            continue
        hits.append(
            Hit(
                path=path,
                line=source.count("\n", 0, start) + 1,
                function=name,
                threshold_variable=threshold_var,
                packet_id="LCCR-PKT-002",
                title="Order fill skips taker threshold when threshold is zero",
                message=(
                    "Order fill computes maker/taker amounts through callback-capable "
                    "helpers, then enforces the taker threshold only when the decoded "
                    "threshold is non-zero; a zero/default threshold skips rate "
                    "protection."
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
        "selected_packet": "LCCR-PKT-002",
        "detector": "local-corpus-taker-threshold-optional-zero",
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
