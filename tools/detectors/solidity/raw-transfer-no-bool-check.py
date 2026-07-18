#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path


CONTRACT_RE = re.compile(
    r"\b(?:abstract\s+)?contract\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:\s+is\s+(?P<bases>[^{]+))?\s*\{",
    re.S,
)
FUNCTION_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\s*\([^;{]*\)[^;{]*\{",
    re.S,
)
TRANSFER_CALL_RE = re.compile(
    r"(?P<receiver>\bsuper\b|[A-Za-z_]\w*(?:\s*\([^;\n]*?\))?)"
    r"\s*\.\s*(?P<method>transfer|transferFrom)\s*\([^;]*?\)\s*;",
    re.S,
)
ERC20_BASE_RE = re.compile(r"\bI?ERC20(?:Upgradeable)?\b")


@dataclass(frozen=True)
class ContractCtx:
    name: str
    bases: str
    start: int
    end: int


@dataclass(frozen=True)
class FunctionCtx:
    name: str
    start: int
    body_start: int
    end: int
    source: str
    contract: ContractCtx


def strip_comments(text: str) -> str:
    def block_repl(match: re.Match[str]) -> str:
        return "\n" * match.group(0).count("\n")

    text = re.sub(r"/\*.*?\*/", block_repl, text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def find_matching_brace(text: str, open_brace: int) -> int:
    depth = 0
    for idx in range(open_brace, len(text)):
        char = text[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return idx + 1
    return len(text)


def line_no(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def iter_contracts(text: str) -> list[ContractCtx]:
    contracts: list[ContractCtx] = []
    for match in CONTRACT_RE.finditer(text):
        open_brace = text.find("{", match.start())
        end = find_matching_brace(text, open_brace)
        contracts.append(
            ContractCtx(
                name=match.group("name"),
                bases=match.group("bases") or "",
                start=match.start(),
                end=end,
            )
        )
    return contracts


def iter_functions(text: str, contract: ContractCtx) -> list[FunctionCtx]:
    functions: list[FunctionCtx] = []
    for match in FUNCTION_RE.finditer(text, contract.start, contract.end):
        open_brace = text.find("{", match.start())
        end = find_matching_brace(text, open_brace)
        functions.append(
            FunctionCtx(
                name=match.group("name"),
                start=match.start(),
                body_start=open_brace + 1,
                end=end,
                source=text[match.start():end],
                contract=contract,
            )
        )
    return functions


def is_erc20_override(function: FunctionCtx) -> bool:
    return (
        function.name in {"transfer", "transferFrom"}
        and ERC20_BASE_RE.search(function.contract.bases) is not None
    )


def unchecked_transfer_hits(path: Path) -> list[tuple[int, str]]:
    original = path.read_text(errors="replace")
    stripped = strip_comments(original)
    lines = original.splitlines()
    hits: list[tuple[int, str]] = []

    for contract in iter_contracts(stripped):
        for function in iter_functions(stripped, contract):
            if is_erc20_override(function):
                continue
            for match in TRANSFER_CALL_RE.finditer(stripped, function.body_start, function.end):
                receiver = re.sub(r"\s+", "", match.group("receiver"))
                if receiver == "super":
                    continue
                start = match.start()
                prefix = stripped[max(function.body_start, start - 40):start]
                if re.search(r"(require|assert)\s*\([^;]*$", prefix):
                    continue
                if re.search(r"=\s*$", prefix):
                    continue
                line = line_no(stripped, start)
                snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
                hits.append((line, snippet))
    return hits


def iter_solidity_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*.sol")
        if not any(part in {"test", "tests", "mocks"} for part in path.parts)
        and not path.name.endswith(".t.sol")
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: raw-transfer-no-bool-check.py <src-dir>", file=sys.stderr)
        return 2
    root = Path(argv[1])
    for path in iter_solidity_files(root):
        for line, snippet in unchecked_transfer_hits(path):
            print(f"{path}:{line}:{snippet}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
