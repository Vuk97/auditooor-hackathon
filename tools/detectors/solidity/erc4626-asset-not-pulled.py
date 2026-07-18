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
    r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)"
    r"(?P<suffix>[^;{}]*)\{",
    re.S,
)
ASSET_PULL_RE = re.compile(r"\b(?:safeTransferFrom|transferFrom)\s*\(")
SHARE_MINT_RE = re.compile(r"\b_mint\s*\(")
HELPER_CALL_RE = re.compile(
    r"\b(?P<name>_(?:deposit|pullAsset|pullAssets|collectAssets|takeAsset|takeAssets|transferIn|receiveAsset|receiveAssets))\s*\("
)


@dataclass(frozen=True)
class ContractCtx:
    name: str
    bases: str
    start: int
    end: int


@dataclass(frozen=True)
class FunctionCtx:
    name: str
    params: str
    suffix: str
    start: int
    body_start: int
    end: int
    body: str
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
                params=match.group("params"),
                suffix=match.group("suffix"),
                start=match.start(),
                body_start=open_brace + 1,
                end=end,
                body=text[open_brace + 1:end - 1],
                contract=contract,
            )
        )
    return functions


def is_public_erc4626_entry(function: FunctionCtx) -> bool:
    if function.name not in {"deposit", "mint"}:
        return False
    if not re.search(r"\b(public|external)\b", function.suffix):
        return False
    return re.search(r"^\s*uint256\b", function.params) is not None and re.search(
        r"\baddress\b", function.params
    ) is not None


def non_empty_loc(body: str) -> int:
    return sum(1 for line in body.splitlines() if line.strip())


def helper_to_trace(function: FunctionCtx) -> str | None:
    if non_empty_loc(function.body) > 10:
        return None
    helpers = {match.group("name") for match in HELPER_CALL_RE.finditer(function.body)}
    if len(helpers) != 1:
        return None
    return next(iter(helpers))


def body_pulls_asset(body: str) -> bool:
    return ASSET_PULL_RE.search(body) is not None


def body_mints_shares(body: str) -> bool:
    return SHARE_MINT_RE.search(body) is not None


def erc4626_hits(path: Path) -> list[tuple[int, str]]:
    original = path.read_text(errors="replace")
    stripped = strip_comments(original)
    lines = original.splitlines()
    hits: list[tuple[int, str]] = []

    for contract in iter_contracts(stripped):
        functions = iter_functions(stripped, contract)
        by_name = {function.name: function for function in functions}
        inherits_oz_erc4626 = re.search(r"\bERC4626Upgradeable\b", contract.bases) is not None

        for function in functions:
            if not is_public_erc4626_entry(function):
                continue
            if body_pulls_asset(function.body):
                continue

            traced_body = ""
            helper_name = helper_to_trace(function)
            if helper_name:
                helper = by_name.get(helper_name)
                if helper is None and inherits_oz_erc4626:
                    continue
                if helper is not None:
                    traced_body = helper.body
                    if body_pulls_asset(traced_body):
                        continue

            if not (body_mints_shares(function.body) or body_mints_shares(traced_body) or helper_name):
                continue

            line = line_no(stripped, function.start)
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
        print("usage: erc4626-asset-not-pulled.py <src-dir>", file=sys.stderr)
        return 2
    root = Path(argv[1])
    for path in iter_solidity_files(root):
        for line, snippet in erc4626_hits(path):
            print(f"{path}:{line}:{snippet}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
