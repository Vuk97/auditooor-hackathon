#!/usr/bin/env python3
"""Advisory seed scanner for Go txid chain-truth workflow gaps.

This detector is intentionally conservative and only emits a finding when a
single function contains all of the following:
1) txid bytes accepted with a length-only check,
2) the txid is persisted/stored,
3) later logic matches the stored txid against block txids,
4) no obvious raw transaction input/spend validation nearby.

Output is JSON-only and advisory. This is a seed detector and not wired as a
submission-ready severity signal.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.go_txid_chain_truth_scan.seed.v1"
PATTERN_ID = "go_txid_chain_truth_scan_seed"

LEN_CHECK_RE = re.compile(
    r"\blen\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*(?:==|!=|<=|>=|<|>)\s*"
    r"(?:32|[A-Za-z_][A-Za-z0-9_]*\.(?:HashSize|TxIDSize)|[A-Za-z_][A-Za-z0-9_]*)"
)
FUNC_START_RE = re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(")
STORE_ASSIGN_RE = re.compile(r"=\s*([A-Za-z_][A-Za-z0-9_]*)\b")
VALIDATION_TOKENS = (
    "rawtx",
    "raw_tx",
    "decoderawtransaction",
    "decode",
    "deserialize",
    "vin",
    "prevout",
    "input",
    "spend",
    "utxo",
    "script",
    "witness",
    "verifyinput",
    "validateinput",
    "checkinputs",
)
BLOCK_TOKENS = (
    "block",
    "blk",
    "transactions",
    "txs",
    "blocktxid",
    "txhash",
)


def _looks_like_txid_identifier(name: str) -> bool:
    normalized = name.replace("_", "").lower()
    return "txid" in normalized


def _line_has_txid_token(line: str) -> bool:
    normalized = line.replace("_", "").lower()
    return "txid" in normalized


def _is_store_line(line: str, txid_var: str) -> bool:
    lowered = line.lower()
    if txid_var not in line and not _line_has_txid_token(line):
        return False
    call_tokens = ("append(", ".put(", ".set(", ".store(", ".insert(", ".save(")
    if any(token in lowered for token in call_tokens):
        return True
    if "[" in line and "]" in line and "=" in line:
        assign = STORE_ASSIGN_RE.search(line)
        if assign and (assign.group(1) == txid_var or _looks_like_txid_identifier(assign.group(1))):
            return True
    return False


def _is_block_txid_match_line(line: str, txid_var: str) -> bool:
    lowered = line.lower()
    if txid_var not in line and not _line_has_txid_token(line):
        return False
    has_compare = "==" in line or "bytes.equal(" in lowered or ".equal(" in lowered
    has_block_context = any(token in lowered for token in BLOCK_TOKENS)
    return has_compare and has_block_context


def _window_contains_validation(lines: list[str], center: int, radius: int = 6) -> bool:
    start = max(0, center - radius)
    end = min(len(lines), center + radius + 1)
    window = "\n".join(lines[start:end]).lower()
    return any(token in window for token in VALIDATION_TOKENS)


def _function_ranges(lines: list[str]) -> list[tuple[str, int, int]]:
    ranges: list[tuple[str, int, int]] = []
    i = 0
    while i < len(lines):
        match = FUNC_START_RE.search(lines[i])
        if not match:
            i += 1
            continue
        name = match.group(1)
        depth = lines[i].count("{") - lines[i].count("}")
        start = i
        j = i + 1
        while j < len(lines) and depth > 0:
            depth += lines[j].count("{") - lines[j].count("}")
            j += 1
        end = j - 1 if j > start else start
        if end < start:
            end = start
        ranges.append((name, start, min(end, len(lines) - 1)))
        i = end + 1
    if not ranges:
        ranges.append(("<global>", 0, max(0, len(lines) - 1)))
    return ranges


def _build_finding(
    path: Path,
    function_name: str,
    lines: list[str],
    len_line: int,
    store_line: int,
    match_line: int,
    txid_var: str,
) -> dict[str, Any]:
    snippet = " | ".join(
        lines[idx].strip() for idx in (len_line, store_line, match_line) if 0 <= idx < len(lines)
    )
    return {
        "file": str(path),
        "line": match_line + 1,
        "function": function_name,
        "pattern_id": PATTERN_ID,
        "txid_variable": txid_var,
        "length_check_line": len_line + 1,
        "store_line": store_line + 1,
        "match_line": match_line + 1,
        "summary": (
            "txid accepted with length-only parsing, persisted, then matched "
            "against block txids without nearby raw transaction input/spend validation"
        ),
        "advisory_only": True,
        "submission_posture": "NOT_SUBMIT_READY",
        "snippet": snippet,
    }


def scan_source(source: str, path: Path) -> list[dict[str, Any]]:
    lines = source.splitlines()
    findings: list[dict[str, Any]] = []
    for function_name, start, end in _function_ranges(lines):
        for rel_idx, line in enumerate(lines[start : end + 1], start=start):
            len_match = LEN_CHECK_RE.search(line)
            if not len_match:
                continue
            txid_var = len_match.group(1)
            if not _looks_like_txid_identifier(txid_var):
                continue

            store_idx = None
            for idx in range(rel_idx + 1, end + 1):
                if _is_store_line(lines[idx], txid_var):
                    store_idx = idx
                    break
            if store_idx is None:
                continue

            match_idx = None
            for idx in range(store_idx + 1, end + 1):
                if _is_block_txid_match_line(lines[idx], txid_var):
                    match_idx = idx
                    break
            if match_idx is None:
                continue

            if (
                _window_contains_validation(lines, rel_idx)
                or _window_contains_validation(lines, store_idx)
                or _window_contains_validation(lines, match_idx)
            ):
                continue

            findings.append(
                _build_finding(
                    path=path,
                    function_name=function_name,
                    lines=lines,
                    len_line=rel_idx,
                    store_line=store_idx,
                    match_line=match_idx,
                    txid_var=txid_var,
                )
            )
    return findings


def _iter_go_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            for candidate in sorted(path.rglob("*.go")):
                if "/vendor/" in str(candidate):
                    continue
                if candidate.name.endswith("_test.go"):
                    continue
                files.append(candidate)
        elif path.suffix == ".go":
            files.append(path)
    return files


def scan_paths(paths: list[Path]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for go_file in _iter_go_files(paths):
        try:
            source = go_file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            source = go_file.read_text(errors="replace")
        findings.extend(scan_source(source, go_file))
    return findings


def build_output(paths: list[Path]) -> dict[str, Any]:
    findings = scan_paths(paths)
    return {
        "schema_version": SCHEMA_VERSION,
        "detector": PATTERN_ID,
        "advisory": True,
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline advisory Go txid chain-truth seed scanner.")
    parser.add_argument("paths", nargs="+", type=Path, help="Go files or directories to scan")
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    args = parser.parse_args()

    output = build_output(args.paths)
    if args.pretty:
        print(json.dumps(output, indent=2))
    else:
        print(json.dumps(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
