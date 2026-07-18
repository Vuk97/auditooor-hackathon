#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


STRUCT_RE = re.compile(r"\bstruct\s+(?P<name>[A-Za-z_]\w*)\s*\{", re.S)
MAPPING_RE = re.compile(
    r"\bmapping\s*\([^)]*=>\s*(?P<value>[A-Za-z_][\w.]*)\s*\)"
    r"\s*(?:public|private|internal)?\s+(?P<name>[A-Za-z_]\w*)\b",
    re.S,
)
DELETE_RE = re.compile(r"\bdelete\s+(?P<name>[A-Za-z_]\w*)\s*\[[^\]]+\]\s*;")
BYTES32_ARRAY_RE = re.compile(r"\bbytes32\s*\[\s*\]\s+[A-Za-z_]\w*\b")
INDEX_MAPPING_RE = re.compile(
    r"\bmapping\s*\(\s*bytes32\s*=>\s*uint256\s*\)\s+[A-Za-z_]\w*\b"
)
FIELD_TYPE_RE = re.compile(r"\b(?P<type>[A-Za-z_]\w*)\s+[A-Za-z_]\w*\s*;")


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


def parse_structs(text: str) -> dict[str, str]:
    structs: dict[str, str] = {}
    for match in STRUCT_RE.finditer(text):
        open_brace = text.find("{", match.start())
        end = find_matching_brace(text, open_brace)
        structs[match.group("name")] = text[open_brace + 1:end - 1]
    return structs


def parse_mappings(text: str) -> dict[str, str]:
    return {
        match.group("name"): match.group("value")
        for match in MAPPING_RE.finditer(text)
    }


def struct_has_enumerable_layout(
    type_name: str,
    structs: dict[str, str],
    seen: set[str] | None = None,
) -> bool:
    if type_name.startswith("EnumerableSet."):
        return True
    short_name = type_name.split(".")[-1]
    if seen is None:
        seen = set()
    if short_name in seen:
        return False
    seen.add(short_name)

    body = structs.get(short_name)
    if body is None:
        return False
    if BYTES32_ARRAY_RE.search(body) and INDEX_MAPPING_RE.search(body):
        return True

    for field in FIELD_TYPE_RE.finditer(body):
        field_type = field.group("type")
        if field_type in structs and struct_has_enumerable_layout(field_type, structs, seen):
            return True
    return False


def delete_enumerable_hits(path: Path) -> list[tuple[int, str]]:
    original = path.read_text(errors="replace")
    stripped = strip_comments(original)
    lines = original.splitlines()
    structs = parse_structs(stripped)
    mappings = parse_mappings(stripped)
    hits: list[tuple[int, str]] = []

    for match in DELETE_RE.finditer(stripped):
        value_type = mappings.get(match.group("name"))
        if not value_type:
            continue
        if not struct_has_enumerable_layout(value_type, structs):
            continue
        line = line_no(stripped, match.start())
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
        print("usage: delete-enumerable-set-struct.py <src-dir>", file=sys.stderr)
        return 2
    root = Path(argv[1])
    for path in iter_solidity_files(root):
        for line, snippet in delete_enumerable_hits(path):
            print(f"{path}:{line}:{snippet}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
