#!/usr/bin/env python3
"""Anti-pattern catalog build / list / validate / query tool (PLAN-P3 prescaffold).

This is the STUB form of the P3 catalog tool committed by
lane-P3-SOLIDITY-COLLAPSE-PRESCAFF and expanded by subsequent V3 lanes. It
loads hand-curated anti-pattern YAML records, validates them against
`tools.lib.antipattern_schema.SCHEMA_VERSION`, and exposes the catalog
through three CLI modes:

* ``--list``         enumerate every pattern with its key headline fields.
* ``--validate``     schema-validate every pattern file; non-zero exit on first
                     failure.
* ``--scan-corpus``  emits the expanded hand-curated records and a quality
                     summary that separates directly executable grep records
                     from non-executed semantic command plans.
* ``--query``        a minimal bounded grep-style runner for records whose
                     first ``query_source`` line is ``inline-regex: ...`` or a
                     simple ``grep -nE ... --include='*.ext' -r .`` command.
                     Semantic query types that do not carry executable rule
                     bodies return honest command-plan/degraded results instead
                     of unsupported or overclaimed matches.

The tool is deliberately stdlib-only with an OPTIONAL ``yaml`` import. If the
PyYAML dependency is unavailable the loader falls back to a tiny line-based
parser that handles the simple key:value / list-of-strings / pipe-block
subset used by the prescaffold patterns. The fallback is documented in the
module docstring and kept narrow so the canonical loader (PyYAML) is the
preferred path on any CI host.

Schema: ``auditooor.antipattern_catalog.v1``.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

# Make tools.lib importable when invoked as a script.
_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.lib.antipattern_schema import (  # noqa: E402
    SCHEMA_VERSION,
    AntipatternValidationError,
    validate_record,
)


DEFAULT_CATALOG_ROOT = _REPO_ROOT / "obsidian-vault" / "anti-patterns" / "v2"

QUERY_MAX_FILES = 2_000
QUERY_MAX_BYTES_PER_FILE = 1_000_000
QUERY_MAX_TOTAL_BYTES = 10_000_000
QUERY_MAX_MATCHES = 50
QUERY_MATCH_CONTEXT_CHARS = 240

QUERY_EXCLUDED_DIRS = frozenset({
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
})

SLITHER_QUERY_DETECTOR_ARGUMENTS = {
    "solidity.unchecked-external-call-return-value": [
        "unchecked-lowlevel",
        "unchecked-send",
        "unchecked-transfer",
    ],
    "solidity.reentrancy-without-modifier": [
        "reentrancy-eth",
        "reentrancy-no-eth",
        "reentrancy-benign",
        "reentrancy-events",
        "reentrancy-unlimited-gas",
        "reentrancy-balance",
    ],
    "solidity.unbounded-loop-over-user-input": [
        "calls-loop",
        "costly-loop",
        "delegatecall-loop",
        "msg-value-loop",
        "cache-array-length",
    ],
}

LANGUAGE_DEFAULT_GLOBS = {
    "circom": ["*.circom"],
    "go": ["*.go"],
    "go-cosmos-sdk": ["*.go"],
    "halo2": ["*.rs"],
    "move": ["*.move"],
    "rust": ["*.rs"],
    "rust-solana-anchor": ["*.rs"],
    "solidity": ["*.sol"],
    "substrate-rust": ["*.rs"],
}

AST_ENGINE_LANGUAGE_MAP = {
    "go": "go",
    "go-cosmos-sdk": "go",
    "move": "move",
    "rust": "rust",
    "rust-solana-anchor": "rust",
    "solidity": "solidity",
    "substrate-rust": "rust",
    # Halo2 catalog rows describe Rust host code that builds/verifies circuits.
    "halo2": "rust",
}

SEMANTIC_COMMAND_PLAN_QUERY_TYPES = frozenset({
    "ast",
    "semgrep",
    "tree-sitter",
})

PLACEHOLDER_MARKERS = (
    "TODO",
    "TBD",
    "FIXME",
    "placeholder",
    "template",
    "<materialized-rule-from-query_source>",
    "<source-file>",
    "example canonical record",
    "synthetic anti-pattern",
)


# ---------------------------------------------------------------------------
# YAML loader (PyYAML when available; otherwise narrow stdlib fallback).
# ---------------------------------------------------------------------------

def _load_yaml_text(text: str) -> dict[str, Any]:
    """Load a single YAML document. Prefer PyYAML; fall back to a narrow stdlib parser."""
    try:
        import yaml  # type: ignore
    except ImportError:
        return _load_yaml_text_fallback(text)
    return yaml.safe_load(text)


def _load_yaml_text_fallback(text: str) -> dict[str, Any]:
    """Stdlib-only loader for the prescaffold YAML shape.

    Handles only what the catalog's hand-curated records use:
      * top-level ``key: value`` pairs
      * list members ``  - value``
      * pipe-blocks ``key: |`` followed by indented lines

    Anything else raises so callers know to install PyYAML.
    """
    result: dict[str, Any] = {}
    lines = text.splitlines()
    i = 0
    current_list_key: str | None = None
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()
        if not stripped or stripped.lstrip().startswith("#"):
            i += 1
            continue
        # List item?
        ls = line.lstrip()
        if ls.startswith("- "):
            if current_list_key is None:
                raise ValueError(
                    f"fallback YAML loader: orphan list item at line {i + 1}"
                )
            value = ls[2:].strip()
            # Strip optional surrounding quotes.
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            elif value.startswith("'") and value.endswith("'"):
                value = value[1:-1]
            result.setdefault(current_list_key, []).append(value)
            i += 1
            continue
        # key: value or key: |
        if ":" not in line:
            raise ValueError(
                f"fallback YAML loader: unparseable line {i + 1}: {line!r}"
            )
        # Reset list-tracking on a new top-level key.
        current_list_key = None
        key, _, raw = line.partition(":")
        key = key.strip()
        raw = raw.strip()
        if raw == "|":
            # Pipe-block: collect indented lines until dedent.
            i += 1
            block_lines: list[str] = []
            while i < len(lines):
                bl = lines[i]
                if not bl.strip():
                    block_lines.append("")
                    i += 1
                    continue
                if not bl.startswith(" "):
                    break
                block_lines.append(bl)
                i += 1
            # Strip common leading whitespace.
            non_empty = [b for b in block_lines if b.strip()]
            if non_empty:
                indent = min(len(b) - len(b.lstrip(" ")) for b in non_empty)
            else:
                indent = 0
            result[key] = "\n".join(
                (b[indent:] if b.strip() else "") for b in block_lines
            ).rstrip() + "\n"
            continue
        if raw == "":
            # The key opens a list; collect upcoming dash-prefixed items.
            current_list_key = key
            result[key] = []
            i += 1
            continue
        # Inline scalar: int / float / bool / quoted string / bare string.
        result[key] = _coerce_scalar(raw)
        i += 1
    return result


def _coerce_scalar(raw: str) -> Any:
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw.startswith("'") and raw.endswith("'"):
        return raw[1:-1]
    if raw.lower() in {"true", "false"}:
        return raw.lower() == "true"
    if raw.lower() == "null":
        return None
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


# ---------------------------------------------------------------------------
# Catalog scan.
# ---------------------------------------------------------------------------

def iter_pattern_files(catalog_root: Path) -> Iterable[Path]:
    """Yield every ``*.yaml`` file under ``catalog_root`` in sorted order."""
    if not catalog_root.exists():
        return
    for path in sorted(catalog_root.rglob("*.yaml")):
        yield path


def load_catalog(catalog_root: Path) -> list[dict[str, Any]]:
    """Load every pattern in the catalog, validating each one.

    Raises ``AntipatternValidationError`` (subclass of ``ValueError``) on the
    first failing record so callers can surface a precise error.
    """
    records: list[dict[str, Any]] = []
    for path in iter_pattern_files(catalog_root):
        text = path.read_text(encoding="utf-8")
        try:
            record = _load_yaml_text(text)
        except Exception as exc:  # pragma: no cover - defensive
            raise AntipatternValidationError(
                f"{path}: failed to parse YAML: {exc}"
            ) from exc
        try:
            validate_record(record)
        except AntipatternValidationError as exc:
            raise AntipatternValidationError(f"{path}: {exc}") from exc
        records.append(record)
    return records


def _record_placeholder_hits(record: dict[str, Any]) -> list[str]:
    """Return placeholder-like markers found in catalog record fields."""
    haystack = "\n".join(
        str(record.get(key, ""))
        for key in (
            "pattern_id",
            "query_source",
            "description",
            "source_finding_ids",
            "target_invariants",
        )
    )
    lowered = haystack.lower()
    return [
        marker
        for marker in PLACEHOLDER_MARKERS
        if marker.lower() in lowered
    ]


def catalog_quality_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize executable rows separately from degraded command-plan rows."""
    query_type_counts: dict[str, int] = {}
    language_counts: dict[str, int] = {}
    placeholder_records: list[dict[str, Any]] = []
    for record in records:
        query_type = record["query_type"]
        language = record["language"]
        query_type_counts[query_type] = query_type_counts.get(query_type, 0) + 1
        language_counts[language] = language_counts.get(language, 0) + 1
        hits = _record_placeholder_hits(record)
        if hits:
            placeholder_records.append({
                "pattern_id": record["pattern_id"],
                "markers": hits,
            })

    executable_query_records = query_type_counts.get("grep", 0)
    degraded_query_types = SEMANTIC_COMMAND_PLAN_QUERY_TYPES | {"slither-detector"}
    command_plan_records = sum(
        query_type_counts.get(query_type, 0)
        for query_type in degraded_query_types
    )
    if len(records) > 120:
        band_status = "above-target-expanded"
    elif len(records) >= 80:
        band_status = "within-target"
    else:
        band_status = "below-target"
    return {
        "target_band": {"min": 80, "max": 120},
        "pattern_count": len(records),
        "target_band_status": band_status,
        "query_type_counts": dict(sorted(query_type_counts.items())),
        "language_counts": dict(sorted(language_counts.items())),
        "executable_query_records": executable_query_records,
        "command_plan_records": command_plan_records,
        "placeholder_record_count": len(placeholder_records),
        "placeholder_records": placeholder_records,
        "degraded_query_types": sorted(degraded_query_types),
    }


# ---------------------------------------------------------------------------
# Minimal bounded query engine.
# ---------------------------------------------------------------------------

def _first_query_source_line(record: dict[str, Any]) -> str:
    """Return the first non-empty line from query_source."""
    for line in str(record["query_source"]).splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _parse_query_spec(record: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """Parse the MVP-supported query_source first-line forms.

    Supported:
      * inline-regex: <python-compatible regex>
      * grep -nE '<regex>' --include='*.ext' -r .

    The tool never executes the grep shell command; it treats the command line
    as declarative metadata for the internal bounded regex walker.
    """
    first_line = _first_query_source_line(record)
    if record.get("query_type") != "grep":
        return (
            None,
            f"query_type {record.get('query_type')!r} is not supported by "
            "the MVP grep engine",
        )
    if first_line.startswith("inline-regex:"):
        regex = first_line.split("inline-regex:", 1)[1].strip()
        if not regex:
            return None, "inline-regex query_source first line has an empty regex"
        if record.get("pattern_id") == "solidity.external-call-before-state-update":
            regex = (
                r"(?:\bcall\s*\{\s*value:|\.call\s*\{\s*value:|sendValue|"
                r"transfer\s*\(|\.call\s*\()"
            )
        return {
            "source_form": "inline-regex",
            "query_line": first_line,
            "regex": regex,
            "include_globs": LANGUAGE_DEFAULT_GLOBS.get(record["language"], ["*"]),
        }, None

    try:
        tokens = shlex.split(first_line)
    except ValueError as exc:
        return None, f"query_source first line could not be parsed with shlex: {exc}"
    if not tokens or tokens[0] != "grep":
        return None, "query_source first line is not an MVP-supported inline-regex or grep command"

    regex: str | None = None
    include_globs: list[str] = []
    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token == "--include":
            if i + 1 >= len(tokens):
                return None, "grep query_source has --include without a glob"
            include_globs.append(tokens[i + 1])
            i += 2
            continue
        if token.startswith("--include="):
            include_globs.append(token.split("=", 1)[1])
            i += 1
            continue
        if token.startswith("-") and "E" in token:
            if i + 1 >= len(tokens):
                return None, "grep query_source has -E/-nE without a regex"
            regex = tokens[i + 1]
            i += 2
            continue
        i += 1

    if regex is None:
        return None, "grep query_source first line does not contain an -E regex"
    if record.get("pattern_id") == "solidity.external-call-before-state-update":
        regex = (
            r"(?:\bcall\s*\{\s*value:|\.call\s*\{\s*value:|sendValue|"
            r"transfer\s*\(|\.call\s*\()"
        )
    if not include_globs:
        include_globs = LANGUAGE_DEFAULT_GLOBS.get(record["language"], ["*"])
    return {
        "source_form": "grep-nE",
        "query_line": first_line,
        "regex": regex,
        "include_globs": include_globs,
    }, None


def _candidate_files(target_path: Path, include_globs: list[str]) -> Iterable[Path]:
    """Yield candidate files under target_path without following symlinks."""
    if target_path.is_file():
        if _path_matches_any_glob(target_path.name, include_globs):
            yield target_path
        return
    for root, dirs, files in os.walk(target_path, followlinks=False):
        dirs[:] = [
            d for d in dirs
            if d not in QUERY_EXCLUDED_DIRS and not d.startswith(".")
        ]
        for filename in sorted(files):
            path = Path(root) / filename
            if path.is_symlink():
                continue
            if _path_matches_any_glob(filename, include_globs):
                yield path


def _path_matches_any_glob(filename: str, include_globs: list[str]) -> bool:
    return any(fnmatch.fnmatch(filename, glob) for glob in include_globs)


def _shorten_line(line: str) -> str:
    line = line.rstrip("\r\n")
    if len(line) <= QUERY_MATCH_CONTEXT_CHARS:
        return line
    return line[: QUERY_MATCH_CONTEXT_CHARS - 3] + "..."


CAP_PRECISION_GUARD_PATTERN_IDS = frozenset({
    "solidity.inverted-verify-return",
    "solidity.division-by-zero",
    "solidity.erc2771-msgsender-forgery",
    "solidity.external-call-before-state-update",
    "solidity.batch03-bridge-proof-verifier-accepts-zero-root-or-default-branch",
    "solidity.pausable-no-unpause-exposed",
    "solidity.lzreceive-no-sender-check",
})


_SOLIDITY_CONTRACT_RE = re.compile(
    r"\b(?:abstract\s+)?(?:contract|library|interface)\s+"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\s+is\s+[^{]+)?\s*\{",
    re.S,
)

_SOLIDITY_WRITE_RE = re.compile(
    r"(?:delete\s+)?"
    r"(?P<slot>[A-Za-z_][A-Za-z0-9_]*(?:\s*(?:\[[^\]]+\]|\.[A-Za-z_][A-Za-z0-9_]*))*)"
    r"\s*(?:[+\-*/]?=|\+\+|--)",
    re.S,
)


def _strip_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"//[^\n\r]*", "", source)


def _strip_comments_and_strings(source: str) -> str:
    source = _strip_comments(source)
    return re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', source, flags=re.S)


def _find_matching_brace(text: str, open_brace: int) -> int | None:
    """Return the matching ``}`` while ignoring strings and comments."""
    if open_brace < 0 or open_brace >= len(text) or text[open_brace] != "{":
        return None
    depth = 0
    i = open_brace
    in_string: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
            i += 1
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
            else:
                i += 1
            continue
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_string:
                in_string = None
            i += 1
            continue
        if ch == "/" and nxt == "/":
            line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            block_comment = True
            i += 2
            continue
        if ch in {"'", '"'}:
            in_string = ch
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _line_offsets(text: str) -> list[int]:
    offsets: list[int] = []
    offset = 0
    for line in text.splitlines(True):
        offsets.append(offset)
        offset += len(line)
    if not offsets:
        offsets.append(0)
    return offsets


def _solidity_contract_context_at(source: str, offset: int) -> tuple[str, int]:
    for match in _SOLIDITY_CONTRACT_RE.finditer(source):
        open_brace = source.rfind("{", match.start(), match.end())
        close_brace = _find_matching_brace(source, open_brace)
        if close_brace is None:
            continue
        if match.start() <= offset <= close_brace:
            return source[match.start() : close_brace + 1], match.start()
    return source, 0


def _solidity_function_context_at(source: str, offset: int) -> tuple[str, int]:
    for match in re.finditer(r"\bfunction\s+[A-Za-z_][A-Za-z0-9_]*\s*\(", source):
        open_brace = source.find("{", match.end())
        if open_brace < 0:
            continue
        semi = source.find(";", match.end(), open_brace)
        if semi >= 0:
            continue
        close_brace = _find_matching_brace(source, open_brace)
        if close_brace is None:
            continue
        if match.start() <= offset <= close_brace:
            return source[match.start() : close_brace + 1], match.start()
    return "", -1


def _normalise_expr(expr: str) -> str:
    return re.sub(r"\s+", "", expr)


def _solidity_write_rows(source: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    clean = _strip_comments_and_strings(source)
    for match in _SOLIDITY_WRITE_RE.finditer(clean):
        slot = _normalise_expr(match.group("slot"))
        if slot in {"return", "require", "assert", "if", "for", "while", "emit"}:
            continue
        stmt_end = clean.find(";", match.end())
        if stmt_end < 0:
            stmt_end = match.end()
        stmt = clean[match.start() : stmt_end]
        rows.append({
            "slot": slot,
            "statement": stmt,
            "statement_norm": _normalise_expr(stmt),
        })
    return rows


def _solidity_write_debits_amount(row: dict[str, str], amount_expr: str) -> bool:
    stmt = row["statement"]
    stmt_norm = row["statement_norm"]
    return bool(
        f"-={amount_expr}" in stmt_norm
        or f"-{amount_expr}" in stmt_norm
        or re.search(r"-=\s*[A-Za-z_][A-Za-z0-9_]*", stmt)
        or re.search(
            r"=\s*[A-Za-z_][A-Za-z0-9_]*\s*-\s*[A-Za-z_][A-Za-z0-9_]*",
            stmt,
        )
    )


def _has_storage_write_after_call(function_context: str, match_offset: int, function_start: int) -> bool:
    local = max(0, match_offset - function_start)
    return bool(_solidity_write_rows(function_context[local:]))


def _native_value_call_predebited(function_context: str, match_offset: int, function_start: int) -> bool:
    local = max(0, match_offset - function_start)
    call_window = function_context[local : local + 260]
    value_match = re.search(r"\.call\s*\{\s*value\s*:\s*([^}]+)\}", call_window, re.S)
    if not value_match:
        return False
    amount_expr = _normalise_expr(value_match.group(1)).strip()
    if not amount_expr:
        return False
    before = function_context[:local]
    after = function_context[local:]
    after_amount_debits = [
        row for row in _solidity_write_rows(after)
        if _solidity_write_debits_amount(row, amount_expr)
    ]
    for row in _solidity_write_rows(before):
        if not _solidity_write_debits_amount(row, amount_expr):
            continue
        same_slot_after = any(after_row["slot"] == row["slot"] for after_row in after_amount_debits)
        other_slot_after = any(after_row["slot"] != row["slot"] for after_row in after_amount_debits)
        if not same_slot_after and not other_slot_after:
            return True
    return False


def _cap005_nonzero_constant_names(source: str) -> set[str]:
    names: set[str] = set()
    for stmt in _strip_comments(source).split(";"):
        if "constant" not in stmt.lower():
            continue
        match = re.search(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
            r"((?:[1-9]\d*(?:e\d+)?)|(?:10\s*\*\*\s*[^;\n]+))\s*$",
            stmt.strip(),
            re.I | re.S,
        )
        if match:
            names.add(match.group(1))
    return names


def _cap005_divisors(source: str) -> list[str]:
    divisors: list[str] = []
    for match in re.finditer(
        r"/\s*(?P<divisor>10\s*\*\*\s*[^;\n,)]+|[1-9]\d*(?:e\d+)?|[A-Za-z_][A-Za-z0-9_]*)\b",
        source,
        re.I,
    ):
        divisors.append(match.group("divisor").strip())
    return divisors


def _cap005_divisor_guarded_before(before: str, divisor: str) -> bool:
    escaped = re.escape(divisor)
    guard_patterns = [
        rf"\brequire\s*\([^;{{}}]*\b{escaped}\b\s*!=\s*0\b",
        rf"\brequire\s*\([^;{{}}]*0\s*!=\s*\b{escaped}\b",
        rf"\brequire\s*\([^;{{}}]*\b{escaped}\b\s*>\s*0\b",
        rf"\brequire\s*\([^;{{}}]*0\s*<\s*\b{escaped}\b",
        rf"\bif\s*\([^;{{}}]*\b{escaped}\b\s*==\s*0\b[^;{{}}]*\)\s*(?:revert|return)",
        rf"\bif\s*\([^;{{}}]*0\s*==\s*\b{escaped}\b[^;{{}}]*\)\s*(?:revert|return)",
        rf"%\s*{escaped}\b",
    ]
    return any(re.search(pattern, before, re.I | re.S) for pattern in guard_patterns)


def _contract_exposes_effective_unpause(contract_context: str) -> bool:
    clean = _strip_comments(contract_context)
    for match in re.finditer(r"\bfunction\s+unpause\s*\(", clean, re.S):
        open_brace = clean.find("{", match.end())
        if open_brace < 0:
            continue
        semi = clean.find(";", match.end(), open_brace)
        if semi >= 0:
            continue
        close_brace = _find_matching_brace(clean, open_brace)
        if close_brace is None:
            continue
        signature = clean[match.start():open_brace]
        body = clean[open_brace + 1:close_brace]
        if not re.search(r"\b(?:external|public)\b", signature):
            continue
        if re.search(r"\b(?:internal|private)\b", signature):
            continue
        if re.search(r"\b_unpause\s*\(", body):
            return True
        if any(
            "paused" in assign.group(1).lower()
            for assign in re.finditer(
                r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*false\b",
                body,
                re.I,
            )
        ):
            return True
    return False


def _is_revert_only_function(function_context: str) -> bool:
    open_brace = function_context.find("{")
    if open_brace < 0:
        return False
    close_brace = _find_matching_brace(function_context, open_brace)
    if close_brace is None:
        return False
    body = _strip_comments_and_strings(function_context[open_brace + 1:close_brace]).strip()
    return bool(re.fullmatch(r"revert(?:\s+[A-Za-z_][A-Za-z0-9_.]*)?\s*\([^;{}]*\)\s*;", body, re.S))


def _cap019_lzreceive_call_position(function_context: str, match_offset: int, function_start: int) -> int:
    local = max(0, match_offset - function_start)
    lower = function_context.lower()
    dot_pos = lower.find(".lzreceive", max(0, local - 80), local + 80)
    if dot_pos >= 0:
        return dot_pos
    return lower.find("lzreceive", max(0, local - 80), local + 80)


def _cap019_validated_oapp_delivery(function_context: str, match_offset: int, function_start: int) -> bool:
    clean = _strip_comments_and_strings(function_context)
    call_pos = clean.lower().find(".lzreceive")
    if call_pos < 0:
        call_pos = _cap019_lzreceive_call_position(clean, match_offset, function_start)
    if call_pos < 0:
        return False
    before_call = clean[:call_pos].lower()
    signature = clean[: clean.find("{")] if "{" in clean else before_call
    if not re.search(r"\bonlyhost\b", signature, re.I):
        return False
    from_validation = re.search(
        r"\b(?:if|require)\s*\([^;{}]*request\.from[^;{}]*(?:==|!=)[^;{}]*\)",
        before_call,
        re.I | re.S,
    )
    source_validation = (
        ("request.source" in before_call or "_statemachinetoeid" in before_call)
        and re.search(
            r"\b(?:if|require)\s*\([^;{}]*(?:request\.source|expectedeid|srceid|_statemachinetoeid)"
            r"[^;{}]*(?:==|!=)[^;{}]*\)",
            before_call,
            re.I | re.S,
        )
    )
    nonce_validation = (
        "_inboundnonce" in before_call
        and re.search(
            r"\b(?:if|require)\s*\([^;{}]*nonce[^;{}]*(?:==|!=|<=|>=|<|>)[^;{}]*"
            r"(?:expectednonce|_inboundnonce|nonce)[^;{}]*\)",
            before_call,
            re.I | re.S,
        )
    )
    nonce_consumed = re.search(r"_inboundnonce\s*\[[^;]+?\]\s*=\s*nonce\b", before_call, re.I | re.S)
    return bool(from_validation and source_validation and nonce_validation and nonce_consumed)


def _function_has_public_msgsender_state_path(function_context: str) -> bool:
    signature = function_context[: function_context.find("{")] if "{" in function_context else function_context
    if not re.search(r"\b(?:external|public)\b", signature):
        return False
    clean = _strip_comments_and_strings(function_context)
    if "_msgSender" not in clean:
        return False
    return bool(
        _solidity_write_rows(clean)
        or re.search(r"\brequire\s*\([^;{}]*_msgSender\s*\(", clean, re.S)
        or re.search(r"\b(?:transfer|transferFrom|safeTransfer|_mint|_burn)\s*\(", clean)
    )


def _cap006_has_relevant_erc2771_path(contract_context: str) -> bool:
    clean = _strip_comments_and_strings(contract_context)
    has_forwarder_context = re.search(
        r"\b(?:ERC2771Context|isTrustedForwarder\s*\(|_trustedForwarder|trustedForwarder|MinimalForwarder)\b",
        clean,
    )
    if not has_forwarder_context:
        return False
    if "_msgSender" not in clean:
        return False
    for match in re.finditer(r"\bfunction\s+[A-Za-z_][A-Za-z0-9_]*\s*\(", clean):
        open_brace = clean.find("{", match.end())
        if open_brace < 0:
            continue
        semi = clean.find(";", match.end(), open_brace)
        if semi >= 0:
            continue
        close_brace = _find_matching_brace(clean, open_brace)
        if close_brace is None:
            continue
        if _function_has_public_msgsender_state_path(clean[match.start() : close_brace + 1]):
            return True
    return False


def _catalog_query_guard_decision(
    record: dict[str, Any],
    *,
    source: str,
    line: str,
    match_offset: int,
) -> tuple[bool, str | None]:
    """Apply CAP precision gates documented in the catalog query_source."""
    pattern_id = record["pattern_id"]
    if pattern_id not in CAP_PRECISION_GUARD_PATTERN_IDS:
        return True, None

    contract_context, contract_start = _solidity_contract_context_at(source, match_offset)
    function_context, function_start = _solidity_function_context_at(source, match_offset)
    function_context = function_context or line
    if function_start < 0:
        function_start = match_offset

    if pattern_id == "solidity.inverted-verify-return":
        clean_function = _strip_comments_and_strings(function_context)
        clean_contract = _strip_comments_and_strings(contract_context)
        inverted_flow = bool(
            re.search(r"\brequire\s*\(\s*!\s*[^;{}]*\bverify\w*\s*\(", clean_function, re.I | re.S)
            or re.search(r"\bif\s*\([^;{}]*\bverify\w*\s*\([^;{}]*\)[^;{}]*\)\s*revert\b", clean_function, re.I | re.S)
        )
        bool_evidence = bool(
            re.search(
                r"\bfunction\s+verify\w*\s*\([^;{}]*\)[^;{}]*returns\s*\(\s*bool\b",
                clean_contract,
                re.I | re.S,
            )
            or re.search(r"\bbool\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;{}]*\bverify\w*\s*\(", clean_function, re.I | re.S)
        )
        if inverted_flow and bool_evidence:
            return True, None
        return False, "CAP-004 precision gate: no inverted bool verifier evidence"

    if pattern_id == "solidity.division-by-zero":
        line_without_comments = _strip_comments(line)
        divisors = _cap005_divisors(line_without_comments)
        if not divisors:
            return False, "CAP-005 precision gate: no reported division expression"
        constants = _cap005_nonzero_constant_names(contract_context)
        local = max(0, match_offset - function_start)
        before = _strip_comments(function_context[:local])
        for divisor in divisors:
            if re.fullmatch(r"(?:[1-9]\d*(?:e\d+)?|10\s*\*\*\s*.+)", divisor, re.I):
                continue
            if divisor in constants:
                continue
            if _cap005_divisor_guarded_before(before, divisor):
                continue
            return True, None
        return False, "CAP-005 precision gate: divisor is constant or already guarded"

    if pattern_id == "solidity.erc2771-msgsender-forgery":
        if _cap006_has_relevant_erc2771_path(contract_context):
            return True, None
        return False, "CAP-006 precision gate: no state-changing ERC2771 _msgSender path"

    if pattern_id == "solidity.external-call-before-state-update":
        clean_line = _strip_comments_and_strings(line)
        if not re.search(r"(?:\.call\s*\{|\.call\s*\(|sendValue|transfer\s*\()", clean_line):
            return False, "CAP-007 precision gate: no external call on reported line"
        if _native_value_call_predebited(function_context, match_offset, function_start):
            return False, "CAP-007 precision gate: native value call is pre-debited"
        if not _has_storage_write_after_call(function_context, match_offset, function_start):
            return False, "CAP-007 precision gate: no post-call storage mutation"
        lowered = clean_line.lower() + "\n" + function_context.lower()
        if "sig_validation_failed" in lowered or "session key" in lowered:
            return False, "CAP-007 precision gate: view/session-key call shape"
        return True, None

    if pattern_id == "solidity.batch03-bridge-proof-verifier-accepts-zero-root-or-default-branch":
        clean_line = _strip_comments_and_strings(line)
        if not re.search(
            r"\b(?:root|branch|sibling|default branch|zero)\b|bytes32\s*\(\s*0\s*\)",
            clean_line,
            re.I,
        ):
            return False, "CAP-020 precision gate: no proof/root/default-branch evidence"
        context = _strip_comments_and_strings(
            "\n".join((contract_context, function_context, line))
        )
        has_bridge_verifier_context = bool(
            re.search(
                r"\b(?:bridge|verif(?:y|ier)|proof|relay|withdraw|finalize|claim)\w*\b",
                context,
                re.I,
            )
        )
        has_source_domain = bool(
            re.search(
                r"\b(?:source|src|origin)\w*(?:Domain|DomainId|ChainId|NetworkId)\b"
                r"|\b(?:sourceChain|srcChain|srcEid)\b",
                context,
                re.I,
            )
        )
        has_destination_domain = bool(
            re.search(
                r"\b(?:destination|dest|dst|target|local)\w*(?:Domain|DomainId|ChainId|NetworkId)\b"
                r"|\b(?:destinationChain|destChain|dstChain|targetChain|localDomain)\b",
                context,
                re.I,
            )
        )
        if not (has_bridge_verifier_context and has_source_domain and has_destination_domain):
            return False, "CAP-020 precision gate: no bridge proof verifier domain-binding context"
        return True, None

    if pattern_id == "solidity.pausable-no-unpause-exposed":
        clean_contract = _strip_comments_and_strings(contract_context)
        has_pause_gate = re.search(r"\b(?:whenNotPaused|_pause\s*\(|paused\s*=|Pausable)\b", clean_contract)
        if not has_pause_gate:
            return False, "CAP-018 precision gate: no pause gate in cited contract"
        if _contract_exposes_effective_unpause(contract_context):
            return False, "CAP-018 precision gate: same contract exposes effective unpause"
        return True, None

    if pattern_id == "solidity.lzreceive-no-sender-check":
        clean_line = _strip_comments_and_strings(line)
        if "lzReceive" not in clean_line:
            return False, "CAP-019 precision gate: no lzReceive on reported line"
        if re.search(r"\bfunction\s+lzReceive\s*\(", function_context) and _is_revert_only_function(function_context):
            return False, "CAP-019 precision gate: lzReceive is a revert tombstone"
        if ".lzReceive" in clean_line and _cap019_validated_oapp_delivery(
            function_context,
            match_offset,
            function_start,
        ):
            return False, "CAP-019 precision gate: delivery has source and nonce validation"
        return True, None

    return True, None


def _run_bounded_regex_query(
    target_path: Path,
    spec: dict[str, Any],
    record: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    """Run the internal bounded lexical matcher.

    Returns ``(stats, state)`` where state is one of matched, no_matches, or
    query_error. Matches are lexical candidate hits only.
    """
    stats: dict[str, Any] = {
        "files_scanned": 0,
        "bytes_scanned": 0,
        "truncated": False,
        "truncation_reason": None,
        "matches": [],
        "filtered_match_count": 0,
        "filtered_matches_by_guard": {},
    }
    try:
        compiled = re.compile(spec["regex"])
    except re.error as exc:
        stats["error"] = f"invalid regex: {exc}"
        return stats, "query_error"
    for path in _candidate_files(target_path, spec["include_globs"]):
        if stats["files_scanned"] >= QUERY_MAX_FILES:
            stats["truncated"] = True
            stats["truncation_reason"] = "max_files"
            break
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > QUERY_MAX_BYTES_PER_FILE:
            continue
        if stats["bytes_scanned"] + size > QUERY_MAX_TOTAL_BYTES:
            stats["truncated"] = True
            stats["truncation_reason"] = "max_total_bytes"
            break
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in data[:4096]:
            continue
        stats["files_scanned"] += 1
        stats["bytes_scanned"] += len(data)
        text = data.decode("utf-8", errors="replace")
        offsets = _line_offsets(text)
        for line_no, line in enumerate(text.splitlines(), start=1):
            hit = compiled.search(line)
            if hit is None:
                continue
            line_start = offsets[line_no - 1] if line_no - 1 < len(offsets) else 0
            emit, guard_reason = _catalog_query_guard_decision(
                record,
                source=text,
                line=line,
                match_offset=line_start + hit.start(),
            )
            if not emit:
                stats["filtered_match_count"] += 1
                if guard_reason:
                    by_guard = stats["filtered_matches_by_guard"]
                    by_guard[guard_reason] = by_guard.get(guard_reason, 0) + 1
                continue
            try:
                rel_path = path.relative_to(target_path)
            except ValueError:
                rel_path = path
            stats["matches"].append({
                "path": str(rel_path),
                "line_number": line_no,
                "line": _shorten_line(line),
                "matched_text": _shorten_line(hit.group(0)),
            })
            if len(stats["matches"]) >= QUERY_MAX_MATCHES:
                stats["truncated"] = True
                stats["truncation_reason"] = "max_matches"
                return stats, "matched"

    return stats, ("matched" if stats["matches"] else "no_matches")


def _slither_dependency_manifest() -> dict[str, Any]:
    """Return best-effort local Slither availability without requiring it."""
    slither_path = shutil.which("slither")
    manifest: dict[str, Any] = {
        "available": bool(slither_path),
        "path": slither_path,
        "version": None,
        "version_error": None,
    }
    if not slither_path:
        manifest["version_error"] = "slither executable not found on PATH"
        return manifest
    try:
        proc = subprocess.run(
            [slither_path, "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        manifest["version_error"] = str(exc)
        return manifest
    output = (proc.stdout or proc.stderr).strip()
    if proc.returncode == 0 and output:
        manifest["version"] = output.splitlines()[0]
    else:
        manifest["version_error"] = output or f"slither --version exited {proc.returncode}"
    return manifest


def _semgrep_dependency_manifest() -> dict[str, Any]:
    """Return best-effort local Semgrep availability without requiring it."""
    semgrep_path = shutil.which("semgrep")
    manifest: dict[str, Any] = {
        "available": bool(semgrep_path),
        "path": semgrep_path,
        "version": None,
        "version_error": None,
    }
    if not semgrep_path:
        manifest["version_error"] = "semgrep executable not found on PATH"
        return manifest
    try:
        proc = subprocess.run(
            [semgrep_path, "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        manifest["version_error"] = str(exc)
        return manifest
    output = (proc.stdout or proc.stderr).strip()
    if proc.returncode == 0 and output:
        manifest["version"] = output.splitlines()[0]
    else:
        manifest["version_error"] = output or f"semgrep --version exited {proc.returncode}"
    return manifest


def _ast_engine_dependency_manifest(record: dict[str, Any]) -> dict[str, Any]:
    """Return local ast-engine availability for command-plan adapters."""
    ast_engine_path = _HERE / "ast-engine.py"
    ast_lang = AST_ENGINE_LANGUAGE_MAP.get(record["language"])
    manifest: dict[str, Any] = {
        "available": ast_engine_path.exists() and ast_lang is not None,
        "path": str(ast_engine_path),
        "language": ast_lang,
        "adapter_supported": ast_lang is not None,
        "adapter_error": None,
    }
    if not ast_engine_path.exists():
        manifest["adapter_error"] = "tools/ast-engine.py not found"
    elif ast_lang is None:
        manifest["adapter_error"] = (
            "tools/ast-engine.py has no catalog-tool language adapter for "
            f"{record['language']!r}"
        )
    return manifest


def _build_semantic_query_plan(
    record: dict[str, Any],
    target_path: Path,
) -> tuple[dict[str, Any] | None, str | None]:
    """Build an honest non-executed plan for semantic query-type rows.

    The current Batch-03 ``semgrep`` / ``ast`` / ``tree-sitter`` records store
    prose query intents, not executable Semgrep YAML or tree-sitter
    S-expressions. Returning a command plan makes the CLI wireable while
    preserving the boundary: this tool did not run a semantic engine and did
    not produce true-positive findings.
    """
    query_type = record.get("query_type")
    if query_type not in SEMANTIC_COMMAND_PLAN_QUERY_TYPES:
        return None, (
            f"query_type {query_type!r} is not one of "
            f"{sorted(SEMANTIC_COMMAND_PLAN_QUERY_TYPES)}"
        )

    first_line = _first_query_source_line(record)
    if query_type == "semgrep":
        dependency = _semgrep_dependency_manifest()
        return {
            "source_form": "semgrep-command-plan",
            "query_line": first_line,
            "query_source_is_executable": False,
            "rule_materialization_required": True,
            "command_plan": {
                "tool": "semgrep",
                "argv": [
                    "semgrep",
                    "--json",
                    "--config",
                    "<materialized-rule-from-query_source>",
                    str(target_path),
                ],
                "cwd": str(target_path if target_path.is_dir() else target_path.parent),
            },
            "dependency": dependency,
            "degraded_reason": (
                "semgrep catalog row is wired to a command plan, but "
                "query_source is descriptive prose rather than an executable "
                "Semgrep rule file."
            ),
        }, None

    dependency = _ast_engine_dependency_manifest(record)
    ast_lang = dependency["language"] or "<unsupported-language>"
    return {
        "source_form": f"{query_type}-command-plan",
        "query_line": first_line,
        "query_source_is_executable": False,
        "rule_materialization_required": True,
        "command_plan": {
            "tool": "tools/ast-engine.py",
            "argv_template": [
                sys.executable,
                str(_HERE / "ast-engine.py"),
                "--lang",
                ast_lang,
                "--file",
                "<source-file>",
            ],
            "cwd": str(_REPO_ROOT),
        },
        "dependency": dependency,
        "degraded_reason": (
            f"{query_type} catalog row is wired to the local AST command-plan "
            "adapter, but query_source is descriptive prose rather than an "
            "executable AST/tree-sitter query."
        ),
    }, None


def _build_slither_query_plan(
    record: dict[str, Any],
    target_path: Path,
) -> tuple[dict[str, Any] | None, str | None]:
    """Build an honest Slither detector command plan for mapped catalog rows.

    The catalog's three ``slither-detector`` records are bug-class records, not
    exact one-detector bindings. Returning a command plan preserves provenance
    and gives callers a runnable next step without claiming that this stdlib
    catalog tool executed Slither or produced semantic findings.
    """
    detectors = SLITHER_QUERY_DETECTOR_ARGUMENTS.get(record["pattern_id"])
    if record.get("query_type") != "slither-detector":
        return None, f"query_type {record.get('query_type')!r} is not slither-detector"
    if not detectors:
        return (
            None,
            (
                "slither-detector query has no catalog-tool detector argument "
                f"mapping for pattern_id {record['pattern_id']!r}"
            ),
        )
    detect_arg = ",".join(detectors)
    return {
        "source_form": "slither-detector-command-plan",
        "query_line": _first_query_source_line(record),
        "detector_arguments": detectors,
        "command_plan": {
            "tool": "slither",
            "argv": ["slither", str(target_path), "--detect", detect_arg, "--json", "-"],
            "detector_argument": detect_arg,
            "cwd": str(target_path if target_path.is_dir() else target_path.parent),
        },
        "dependency": _slither_dependency_manifest(),
    }, None


# ---------------------------------------------------------------------------
# CLI command handlers.
# ---------------------------------------------------------------------------

def cmd_list(records: list[dict[str, Any]], as_json: bool) -> int:
    """Print a human or machine-readable list of patterns."""
    quality = catalog_quality_summary(records)
    if as_json:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "command": "list",
            "pattern_count": len(records),
            "quality": quality,
            "patterns": [
                {
                    "pattern_id": r["pattern_id"],
                    "language": r["language"],
                    "category": r["category"],
                    "severity_floor": r["severity_floor"],
                    "severity_ceiling": r["severity_ceiling"],
                    "query_type": r["query_type"],
                    "fpr_estimate": r["false_positive_rate_estimate"],
                    "target_invariants": r["target_invariants"],
                }
                for r in records
            ],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Anti-pattern catalog ({SCHEMA_VERSION}); patterns: {len(records)}")
        print(
            "Quality: "
            f"executable_grep={quality['executable_query_records']} "
            f"command_plans={quality['command_plan_records']} "
            f"placeholder_records={quality['placeholder_record_count']} "
            f"target_band={quality['target_band_status']}"
        )
        print("=" * 80)
        for r in records:
            print(
                f"  {r['pattern_id']:<60s} "
                f"{r['language']:<10s} "
                f"{r['severity_floor']}->{r['severity_ceiling']:<10s} "
                f"{r['query_type']}"
            )
            invariants = ", ".join(r["target_invariants"]) or "(none)"
            print(f"      invariants: {invariants}")
    return 0


def cmd_validate(records: list[dict[str, Any]], as_json: bool) -> int:
    """Re-validate every record (load_catalog already validated; this is the
    explicit ``--validate`` flag).  Returns 0 on success."""
    quality = catalog_quality_summary(records)
    if as_json:
        print(json.dumps({
            "schema_version": SCHEMA_VERSION,
            "command": "validate",
            "pattern_count": len(records),
            "quality": quality,
            "verdict": "pass-all-records-valid",
        }, indent=2, sort_keys=True))
    else:
        print(
            f"validate: {len(records)} record(s) PASS against {SCHEMA_VERSION}"
        )
        print(
            "quality: "
            f"executable_grep={quality['executable_query_records']} "
            f"command_plans={quality['command_plan_records']} "
            f"placeholder_records={quality['placeholder_record_count']} "
            f"target_band={quality['target_band_status']}"
        )
    return 0


def cmd_scan_corpus(records: list[dict[str, Any]], as_json: bool) -> int:
    """Emit the expanded catalog plus build-quality evidence."""
    quality = catalog_quality_summary(records)
    if as_json:
        print(json.dumps({
            "schema_version": SCHEMA_VERSION,
            "command": "scan-corpus",
            "stage": "expanded-hand-curated-catalog",
            "note": (
                "Expanded P3 catalog output. Quality fields distinguish "
                "directly executable grep records from semantic command-plan "
                "records that are intentionally degraded until rule bodies "
                "are materialized."
            ),
            "pattern_count": len(records),
            "quality": quality,
            "patterns": [
                {
                    "pattern_id": r["pattern_id"],
                    "language": r["language"],
                    "source_finding_ids": r["source_finding_ids"],
                }
                for r in records
            ],
        }, indent=2, sort_keys=True))
    else:
        print(
            "scan-corpus (expanded-hand-curated-catalog): emits "
            f"{len(records)} pattern(s); "
            f"executable_grep={quality['executable_query_records']} "
            f"command_plans={quality['command_plan_records']} "
            f"placeholder_records={quality['placeholder_record_count']}:"
        )
        for r in records:
            print(f"  - {r['pattern_id']} (sources: {len(r['source_finding_ids'])})")
    return 0


def cmd_query(
    records: list[dict[str, Any]],
    pattern_id: str,
    target_dir: str,
    as_json: bool,
) -> int:
    """Minimal bounded grep query runner.

    This intentionally reports lexical candidate matches only. It does not
    claim semantic true positives. Slither-backed rows return a concrete
    command plan/degraded result rather than running compilation-sensitive
    analysis inside this stdlib catalog tool.
    """
    matched = next(
        (r for r in records if r["pattern_id"] == pattern_id),
        None,
    )
    if matched is None:
        msg = (
            f"query: unknown pattern_id {pattern_id!r}; "
            f"see --list for the {len(records)} known patterns"
        )
        if as_json:
            print(json.dumps({
                "schema_version": SCHEMA_VERSION,
                "command": "query",
                "verdict": "fail-unknown-pattern-id",
                "pattern_id": pattern_id,
                "error": msg,
            }, indent=2, sort_keys=True))
        else:
            print(msg, file=sys.stderr)
        return 2
    target_path = Path(target_dir)
    target_exists = target_path.exists()
    if matched.get("query_type") == "slither-detector":
        plan, unsupported_reason = _build_slither_query_plan(matched, target_path)
        base_payload = {
            "schema_version": SCHEMA_VERSION,
            "command": "query",
            "pattern_id": pattern_id,
            "query_type": matched["query_type"],
            "target_dir": str(target_path),
            "target_dir_exists": target_exists,
            "engine": "slither-detector-command-plan",
            "semantic_tp_claim": False,
            "execution_state": "planned-not-executed",
            "note": (
                "This result is a Slither detector command plan only. The "
                "catalog tool did not run Slither, compile Solidity, or claim "
                "semantic true positives."
            ),
        }
        if plan is not None:
            base_payload.update({
                "query_source_first_line": plan["query_line"],
                "slither_detector_arguments": plan["detector_arguments"],
                "command_plan": plan["command_plan"],
                "slither_dependency": plan["dependency"],
            })
        if unsupported_reason is not None:
            payload = {
                **base_payload,
                "verdict": "query_unsupported",
                "unsupported_reason": unsupported_reason,
                "matches": [],
            }
            if as_json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print(
                    f"query: pattern={pattern_id} target={target_dir} "
                    f"state=query_unsupported reason={unsupported_reason}"
                )
            return 0
        if not target_exists:
            payload = {
                **base_payload,
                "verdict": "query_error",
                "error": f"target path does not exist: {target_path}",
                "matches": [],
            }
            if as_json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print(payload["error"], file=sys.stderr)
            return 1
        payload = {
            **base_payload,
            "verdict": "query_degraded",
            "degraded_reason": (
                "slither-detector catalog rows are mapped to Slither detector "
                "arguments, but execution is intentionally delegated to the "
                "caller or a compile-aware scan runner."
            ),
            "matches": [],
        }
        if as_json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            detectors = ",".join(plan["detector_arguments"])
            print(
                f"query: pattern={pattern_id} target={target_dir} "
                f"state=query_degraded slither_detectors={detectors} "
                "semantic_tp_claim=false"
            )
        return 0

    if matched.get("query_type") in SEMANTIC_COMMAND_PLAN_QUERY_TYPES:
        plan, unsupported_reason = _build_semantic_query_plan(matched, target_path)
        base_payload = {
            "schema_version": SCHEMA_VERSION,
            "command": "query",
            "pattern_id": pattern_id,
            "query_type": matched["query_type"],
            "target_dir": str(target_path),
            "target_dir_exists": target_exists,
            "engine": f"{matched['query_type']}-command-plan",
            "semantic_tp_claim": False,
            "execution_state": "planned-not-executed",
            "note": (
                "This result is a semantic query command plan only. The "
                "catalog tool did not run Semgrep, ast-engine, tree-sitter, "
                "or claim semantic true positives."
            ),
        }
        if plan is not None:
            base_payload.update({
                "query_source_first_line": plan["query_line"],
                "query_source_is_executable": plan["query_source_is_executable"],
                "rule_materialization_required": plan["rule_materialization_required"],
                "command_plan": plan["command_plan"],
                "dependency": plan["dependency"],
            })
        if unsupported_reason is not None:
            payload = {
                **base_payload,
                "verdict": "query_unsupported",
                "unsupported_reason": unsupported_reason,
                "matches": [],
            }
            if as_json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print(
                    f"query: pattern={pattern_id} target={target_dir} "
                    f"state=query_unsupported reason={unsupported_reason}"
                )
            return 0
        if not target_exists:
            payload = {
                **base_payload,
                "verdict": "query_error",
                "error": f"target path does not exist: {target_path}",
                "matches": [],
            }
            if as_json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print(payload["error"], file=sys.stderr)
            return 1
        payload = {
            **base_payload,
            "verdict": "query_degraded",
            "degraded_reason": plan["degraded_reason"],
            "matches": [],
        }
        if as_json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(
                f"query: pattern={pattern_id} target={target_dir} "
                f"state=query_degraded engine={matched['query_type']}-command-plan "
                "semantic_tp_claim=false"
            )
        return 0

    spec, unsupported_reason = _parse_query_spec(matched)
    base_payload = {
        "schema_version": SCHEMA_VERSION,
        "command": "query",
        "pattern_id": pattern_id,
        "query_type": matched["query_type"],
        "target_dir": str(target_path),
        "target_dir_exists": target_exists,
        "engine": "bounded-regex-grep-mvp",
        "semantic_tp_claim": False,
        "note": (
            "Matches are lexical grep-style candidate hits from the first "
            "query_source line only; they are not semantic true positives."
        ),
    }
    if spec is not None:
        base_payload.update({
            "query_source_first_line": spec["query_line"],
            "query_regex": spec["regex"],
            "include_globs": spec["include_globs"],
        })
    if unsupported_reason is not None:
        payload = {
            **base_payload,
            "verdict": "query_unsupported",
            "unsupported_reason": unsupported_reason,
            "limits": {
                "max_files": QUERY_MAX_FILES,
                "max_bytes_per_file": QUERY_MAX_BYTES_PER_FILE,
                "max_total_bytes": QUERY_MAX_TOTAL_BYTES,
                "max_matches": QUERY_MAX_MATCHES,
            },
            "matches": [],
        }
        if as_json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(
                f"query: pattern={pattern_id} target={target_dir} "
                f"state=query_unsupported reason={unsupported_reason}"
            )
        return 0
    if not target_exists:
        payload = {
            **base_payload,
            "verdict": "query_error",
            "error": f"target path does not exist: {target_path}",
            "limits": {
                "max_files": QUERY_MAX_FILES,
                "max_bytes_per_file": QUERY_MAX_BYTES_PER_FILE,
                "max_total_bytes": QUERY_MAX_TOTAL_BYTES,
                "max_matches": QUERY_MAX_MATCHES,
            },
            "matches": [],
        }
        if as_json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(payload["error"], file=sys.stderr)
        return 1

    stats, state = _run_bounded_regex_query(target_path, spec, matched)
    payload = {
        **base_payload,
        "verdict": state,
        "limits": {
            "max_files": QUERY_MAX_FILES,
            "max_bytes_per_file": QUERY_MAX_BYTES_PER_FILE,
            "max_total_bytes": QUERY_MAX_TOTAL_BYTES,
            "max_matches": QUERY_MAX_MATCHES,
        },
        **stats,
    }
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            f"query: pattern={pattern_id} target={target_dir} "
            f"state={state} matches={len(payload['matches'])} "
            "semantic_tp_claim=false"
        )
    return 1 if state == "query_error" else 0


# ---------------------------------------------------------------------------
# CLI entrypoint.
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Anti-pattern catalog build / list / validate / query tool. "
            "Schema: " + SCHEMA_VERSION + ". Expanded P3 catalog stage; see "
            "reports/v3_iter_2026-05-23_iter17/plan_swarm_hacker_brain/"
            "PLAN_P3_antipattern_catalog.md for the full design."
        )
    )
    parser.add_argument(
        "--catalog-root",
        default=str(DEFAULT_CATALOG_ROOT),
        help=(
            "Catalog root directory (default: " + str(DEFAULT_CATALOG_ROOT) + ")"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of human-friendly text.",
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--list",
        action="store_true",
        help="List every pattern in the catalog.",
    )
    mode.add_argument(
        "--validate",
        action="store_true",
        help="Schema-validate every pattern file; non-zero exit on first failure.",
    )
    mode.add_argument(
        "--scan-corpus",
        action="store_true",
        help=(
            "Emit the expanded hand-curated catalog plus quality evidence "
            "for executable vs degraded query records."
        ),
    )
    mode.add_argument(
        "--query",
        nargs=2,
        metavar=("PATTERN_ID", "TARGET_DIR"),
        help=(
            "Run the named pattern's first-line grep/inline-regex query "
            "against TARGET_DIR with bounded lexical matching."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    catalog_root = Path(args.catalog_root).expanduser().resolve()
    try:
        records = load_catalog(catalog_root)
    except AntipatternValidationError as exc:
        msg = f"catalog load failed: {exc}"
        if args.json:
            print(json.dumps({
                "schema_version": SCHEMA_VERSION,
                "verdict": "fail-catalog-load",
                "error": str(exc),
            }, indent=2, sort_keys=True))
        else:
            print(msg, file=sys.stderr)
        return 2

    if args.list:
        return cmd_list(records, args.json)
    if args.validate:
        return cmd_validate(records, args.json)
    if args.scan_corpus:
        return cmd_scan_corpus(records, args.json)
    if args.query:
        pattern_id, target_dir = args.query
        return cmd_query(records, pattern_id, target_dir, args.json)
    parser.error("no command selected")  # pragma: no cover - guarded by mutex
    return 2


if __name__ == "__main__":
    sys.exit(main())
