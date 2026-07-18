#!/usr/bin/env python3
"""Flag verifier immutables that never enter hash preimages.

Base-Azul Cantina M-3 taught the abstract pattern: verifier-shaped contracts
may carry deployment immutables that appear security-relevant but are not
actually bound into keccak256/sha256/abi.encode preimages. This scanner is a
small grep-grade advisory tool, not a Solidity parser.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


IMMUTABLE_RE = re.compile(r"\bimmutable\s+([A-Za-z_][A-Za-z0-9_]*)\b")
CONTRACT_RE = re.compile(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)\b")
HASH_CALLS = ("keccak256", "sha256", "abi.encode")


def _line_for_offset(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _extract_balanced_arg(source: str, open_paren: int) -> str:
    depth = 0
    for idx in range(open_paren, len(source)):
        ch = source[idx]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return source[open_paren + 1 : idx]
    return ""


def _hash_preimages(source: str) -> list[str]:
    preimages: list[str] = []
    for name in HASH_CALLS:
        start = 0
        needle = f"{name}("
        while True:
            idx = source.find(needle, start)
            if idx < 0:
                break
            preimages.append(_extract_balanced_arg(source, idx + len(name)))
            start = idx + len(needle)
    return preimages


def _is_verifier_shape(source: str, path: Path) -> bool:
    contract_names = CONTRACT_RE.findall(source)
    joined_names = " ".join(contract_names + [path.stem])
    lowered = source.lower()
    return (
        "verifier" in joined_names.lower()
        or "verify(" in lowered
        or " proof" in lowered
        or "journal" in lowered
    )


def scan_file(path: Path) -> list[dict[str, Any]]:
    source = path.read_text(errors="replace")
    if not _is_verifier_shape(source, path):
        return []

    preimages = _hash_preimages(source)
    findings: list[dict[str, Any]] = []
    for match in IMMUTABLE_RE.finditer(source):
        name = match.group(1)
        if any(re.search(rf"\b{re.escape(name)}\b", preimage) for preimage in preimages):
            continue
        findings.append(
            {
                "file": str(path),
                "line": _line_for_offset(source, match.start(1)),
                "immutable": name,
                "pattern": "stale_immutable_not_used_in_hash_preimage",
                "severity": "advisory",
            }
        )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Advisory scanner for verifier immutables absent from hash preimages."
    )
    parser.add_argument("paths", nargs="+", type=Path, help="Solidity files or directories")
    parser.add_argument("--json", action="store_true", help="Emit JSON findings")
    args = parser.parse_args()

    files: list[Path] = []
    for path in args.paths:
        if path.is_dir():
            files.extend(sorted(path.rglob("*.sol")))
        elif path.suffix == ".sol":
            files.append(path)

    findings: list[dict[str, Any]] = []
    for file_path in files:
        findings.extend(scan_file(file_path))

    if args.json:
        print(json.dumps({"findings": findings}, indent=2))
    else:
        for finding in findings:
            print(
                "{file}:{line}: {pattern}: immutable {immutable} is not used in "
                "keccak256/sha256/abi.encode preimages".format(**finding)
            )

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
