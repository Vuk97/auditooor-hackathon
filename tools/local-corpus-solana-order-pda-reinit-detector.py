#!/usr/bin/env python3
"""Detect the local-corpus Solana reusable order-PDA lifecycle shape.

This scanner is intentionally narrow. It looks for Anchor/Rust order escrow
accounts derived from a maker plus an order id, then closed during the order
lifecycle without any source-level evidence that the order id is burned or
recorded as used. The source packet is Hexens 1inch Solana Fusion OIN8-4.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SCHEMA = "auditooor.local_corpus.solana_order_pda_reinit_detector.v1"

SEEDS_RE = re.compile(r"seeds\s*=\s*\[(?P<seeds>.*?)\]", re.S)
FN_RE = re.compile(
    r"\bpub\s+fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)[^{;]*\{",
    re.S,
)

ORDER_ID_RE = re.compile(r"\b(order_id|order\.id|id)\b")
MAKER_SEED_RE = re.compile(r"\bmaker\s*\.\s*key\s*\(\s*\)\s*\.\s*as_ref\s*\(\s*\)")
ORDER_ID_SEED_RE = re.compile(
    r"(?:order_id|order\s*\.\s*id|id)\s*\.\s*to_(?:be|le)_bytes\s*\(\s*\)\s*"
    r"\.\s*as_ref\s*\(\s*\)"
)
ESCROW_SEED_RE = re.compile(r"(?i)(?:b?\"escrow\"|ESCROW[_A-Z0-9]*SEED)")
CLOSE_LIFECYCLE_RE = re.compile(
    r"(?i)(close_escrow\s*\(|\bclose\s*=\s*(?:maker|owner|authority|payer)|"
    r"\.close\s*\(|system_instruction::transfer\s*\([^;]*lamports)",
    re.S,
)
USED_ID_GUARD_RE = re.compile(
    r"(?i)(used_order|used[_\s-]*ids?|consumed_order|burn(?:ed)?_order|"
    r"order_id_bitmap|bitmap|nonce_registry|reserved_order|spent_order|"
    r"seen_order|order_history|maker_to_order|order_id_state)"
)


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    packet_id: str
    title: str
    message: str
    seed_snippet: str


def rust_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_file() and path.suffix == ".rs":
            yield path
        elif path.is_dir():
            yield from sorted(path.rglob("*.rs"))


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
    for match in FN_RE.finditer(source):
        open_index = source.find("{", match.start())
        if open_index == -1:
            continue
        yield match.group("name"), match.start(), source[match.start():find_matching_brace(source, open_index)]


def compact_snippet(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()[:220]


def account_attrs(source: str) -> Iterable[tuple[int, str]]:
    for match in SEEDS_RE.finditer(source):
        attr_start = source.rfind("#[account", 0, match.start())
        if attr_start == -1:
            continue
        body = source[attr_start:match.end()]
        if not re.search(r"\binit\b", body):
            continue
        yield match.start(), match.group("seeds")


def has_order_pda_init(source: str) -> tuple[int, str] | None:
    for start, body in account_attrs(source):
        if not ESCROW_SEED_RE.search(body):
            continue
        if not MAKER_SEED_RE.search(body):
            continue
        if not ORDER_ID_SEED_RE.search(body):
            continue
        return start, body
    return None


def has_order_lifecycle_close(source: str) -> bool:
    if CLOSE_LIFECYCLE_RE.search(source):
        return True
    for name, _start, body in functions(source):
        if re.search(r"(?i)(cancel|fill|settle|close)", name) and "escrow" in body:
            if "close" in body.lower() or "lamports" in body.lower():
                return True
    return False


def has_used_order_id_guard(source: str) -> bool:
    if not USED_ID_GUARD_RE.search(source):
        return False
    for name, _start, body in functions(source):
        lowered = name.lower()
        if any(word in lowered for word in ("create", "init", "cancel", "fill")):
            if ORDER_ID_RE.search(body) and USED_ID_GUARD_RE.search(body):
                return True
    return False


def detect_source(source: str, path: str) -> list[Hit]:
    if "anchor_lang" not in source and "#[account" not in source:
        return []
    order_pda = has_order_pda_init(source)
    if order_pda is None:
        return []
    if not has_order_lifecycle_close(source):
        return []
    if has_used_order_id_guard(source):
        return []

    start, seed_body = order_pda
    return [
        Hit(
            path=path,
            line=source.count("\n", 0, start) + 1,
            packet_id="LCCR-PKT-004",
            title="Solana order PDA reinitialization via reusable order ID",
            message=(
                "Anchor order escrow PDA is initialized from maker plus order id "
                "and the lifecycle closes the escrow account, but no used-order-id "
                "or bitmap-style reservation guard was found. Reusing the same "
                "order id can rederive the same PDA after close."
            ),
            seed_snippet=compact_snippet(seed_body),
        )
    ]


def scan_paths(paths: Iterable[Path]) -> list[Hit]:
    hits: list[Hit] = []
    for path in rust_files(paths):
        try:
            source = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            source = path.read_text(encoding="latin-1")
        hits.extend(detect_source(source, str(path)))
    return hits


def build_payload(hits: list[Hit]) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "selected_packet": "LCCR-PKT-004",
        "detector": "local-corpus-solana-order-pda-reinit",
        "hit_count": len(hits),
        "hits": [asdict(hit) for hit in hits],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="Rust file or directory to scan")
    args = parser.parse_args(argv)
    payload = build_payload(scan_paths(args.paths))
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if payload["hit_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
