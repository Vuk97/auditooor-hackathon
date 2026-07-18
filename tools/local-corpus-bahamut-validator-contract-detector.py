#!/usr/bin/env python3
"""Detect the local-corpus Bahamut validator-contract replacement shape.

This scanner is intentionally narrow. It looks for the Hexens Bahamut FTN-2/3
shape where deposit processing detects an already-registered validator
contract, then appends a zero contract for a new validator, or where the helper
that updates a validator's contract list only appends the replacement contract
without evidence that the old contract entry is removed.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SCHEMA = "auditooor.local_corpus.bahamut_validator_contract_detector.v1"

GO_FUNCTION_RE = re.compile(
    r"\bfunc\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)[^{;]*\{",
    re.S,
)

CONTRACT_EXIST_LOOKUP_RE = re.compile(r"\bValidatorIndexByContractAddress\s*\([^)]*\bcontract\b[^)]*\)")
CONTRACT_EXIST_IF_RE = re.compile(r"\bif\s+contractExist\s*\{")
ZERO_CONTRACT_RE = re.compile(r"make\s*\(\s*\[\]\s*byte\s*,\s*20\s*\)")
APPEND_CONTRACTS_RE = re.compile(
    r"\bAppendContracts\s*\(\s*&?ethpb\.ContractsContainer\s*\{[\s\S]{0,320}\bContracts\s*:\s*contracts\b",
    re.S,
)
APPEND_HELPER_NAME_RE = re.compile(r"(?i)^appendValidatorContracts(?:WithVal)?$")
APPEND_HELPER_BODY_RE = re.compile(
    r"\bappend\s*\(\s*(?:contracts|cc\.Contracts)\s*,\s*contract\s*\)[\s\S]{0,220}\bcc\.Contracts\s*=",
    re.S,
)
REPLACEMENT_OR_DELETE_RE = re.compile(
    r"(?i)\b(delete[A-Za-z0-9_]*|remove[A-Za-z0-9_]*|replace[A-Za-z0-9_]*|setValidatorContracts|setContracts|"
    r"ValidatorIndexByContractAddress|contractExist|oldContract|existingContract|isZeroContract)\b"
)


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    function: str
    issue_kind: str
    packet_id: str
    title: str
    message: str
    snippet: str


@dataclass(frozen=True)
class FunctionBlock:
    name: str
    start: int
    body: str


def go_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_file() and path.suffix == ".go":
            yield path
        elif path.is_dir():
            yield from sorted(path.rglob("*.go"))


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
    for match in GO_FUNCTION_RE.finditer(source):
        open_index = source.find("{", match.start())
        if open_index == -1:
            continue
        end = find_matching_brace(source, open_index)
        yield FunctionBlock(match.group("name"), match.start(), source[match.start():end])


def compact_snippet(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()[:220]


def _append_after_contract_exist_zero_block(fn: FunctionBlock) -> tuple[int, str] | None:
    if fn.name != "ProcessDeposit":
        return None
    if CONTRACT_EXIST_LOOKUP_RE.search(fn.body) is None:
        return None

    for match in CONTRACT_EXIST_IF_RE.finditer(fn.body):
        open_index = fn.body.find("{", match.start())
        if open_index == -1:
            continue
        end = find_matching_brace(fn.body, open_index)
        contract_exist_block = fn.body[match.start():end]
        if ZERO_CONTRACT_RE.search(contract_exist_block) is None:
            continue

        tail = fn.body[end:]
        if re.match(r"\s*else\b", tail):
            continue
        append_window = tail[:900]
        if APPEND_CONTRACTS_RE.search(append_window) is None:
            continue
        return match.start(), compact_snippet(contract_exist_block + append_window)
    return None


def _append_helper_without_replacement(fn: FunctionBlock) -> bool:
    if APPEND_HELPER_NAME_RE.match(fn.name) is None:
        return False
    if APPEND_HELPER_BODY_RE.search(fn.body) is None:
        return False
    return REPLACEMENT_OR_DELETE_RE.search(fn.body) is None


def detect_source(source: str, path: str) -> list[Hit]:
    hits: list[Hit] = []
    for fn in functions(source):
        zero_append = _append_after_contract_exist_zero_block(fn)
        if zero_append is not None:
            offset, snippet = zero_append
            hits.append(
                Hit(
                    path=path,
                    line=source.count("\n", 0, fn.start + offset) + 1,
                    function=fn.name,
                    issue_kind="zero_contract_append_after_contract_exists",
                    packet_id="LCCR-PKT-018",
                    title="Validator contract replacement appends stale or zero contract entries",
                    message=(
                        "ProcessDeposit detects an already-registered contract, "
                        "assigns a zero contract entry, and still appends the "
                        "contracts container outside the contractExist branch."
                    ),
                    snippet=snippet,
                )
            )

        if _append_helper_without_replacement(fn):
            hits.append(
                Hit(
                    path=path,
                    line=source.count("\n", 0, fn.start) + 1,
                    function=fn.name,
                    issue_kind="helper_appends_contract_without_replacement",
                    packet_id="LCCR-PKT-018",
                    title="Validator contract replacement appends stale or zero contract entries",
                    message=(
                        "Validator contract helper appends the replacement "
                        "contract to the existing Contracts slice without local "
                        "delete, remove, replace, or existing-contract guard evidence."
                    ),
                    snippet=compact_snippet(fn.body),
                )
            )
    return hits


def scan_paths(paths: Iterable[Path]) -> list[Hit]:
    hits: list[Hit] = []
    for path in go_files(paths):
        try:
            source = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            source = path.read_text(encoding="latin-1")
        hits.extend(detect_source(source, str(path)))
    return hits


def build_payload(hits: list[Hit]) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "selected_packet": "LCCR-PKT-018",
        "detector": "local-corpus-bahamut-validator-contract",
        "hit_count": len(hits),
        "hits": [asdict(hit) for hit in hits],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="Go file or directory to scan")
    args = parser.parse_args(argv)
    payload = build_payload(scan_paths(args.paths))
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if payload["hit_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
