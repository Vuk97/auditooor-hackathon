#!/usr/bin/env python3
"""Fail-closed semantic validator for ``.auditooor/inscope_units.jsonl``.

The manifest is an authority consumed by scope tooling, so syntactically valid
JSON alone is insufficient.  This command never writes the workspace: it
validates each row and compares the normalized sequence with the current
producer output.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from lib.source_extensions import EXT_TO_LANG, lang_of

SCHEMA = "auditooor.inscope_manifest_validation.v1"
_LANG_ALIASES = {
    "sol": "solidity",
    "evm": "solidity",
    "vy": "vyper",
    "rs": "rust",
    "golang": "go",
    "ts": "typescript",
    "js": "javascript",
    "aa": "oscript",
    "obyte": "oscript",
    "zok": "zokrates",
}


def _diagnostic(code: str, message: str, **detail: object) -> dict:
    return {"code": code, "message": message, **detail}


def _canonical_language(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip().lower()
    normalized = re.sub(r"[^a-z0-9]+", "", raw)
    aliases = {
        re.sub(r"[^a-z0-9]+", "", key): canonical
        for key, canonical in _LANG_ALIASES.items()
    }
    for canonical in set(EXT_TO_LANG.values()):
        aliases[re.sub(r"[^a-z0-9]+", "", canonical)] = canonical
    return aliases.get(normalized)


def _load_producer() -> object:
    """Load the hyphenated producer by path without importing this validator."""
    tool = Path(__file__).with_name("workspace-coverage-heatmap.py")
    spec = importlib.util.spec_from_file_location("_inscope_manifest_producer", tool)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load producer: {tool}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _normalize_row(ws: Path, row: dict, line: int, diagnostics: list[dict]) -> dict | None:
    file_value = row.get("file")
    if not isinstance(file_value, str) or not file_value.strip():
        diagnostics.append(_diagnostic("MISSING_FILE", "row has no non-empty file path", line=line))
        return None
    file_path = file_value.replace("\\", "/").strip()
    candidate = Path(file_path)
    if candidate.is_absolute():
        diagnostics.append(_diagnostic("ABSOLUTE_FILE_PATH", "row file path must be workspace-relative", line=line, file=file_value))
        return None
    try:
        resolved = (ws / candidate).resolve(strict=True)
        resolved.relative_to(ws.resolve())
    except (OSError, ValueError):
        diagnostics.append(_diagnostic("ESCAPING_OR_MISSING_FILE", "row file does not resolve to an existing workspace file", line=line, file=file_value))
        return None
    expected_lang = lang_of(file_path)
    if expected_lang is None:
        diagnostics.append(_diagnostic("UNRECOGNIZED_SOURCE_EXTENSION", "row file extension is not in the canonical source registry", line=line, file=file_value))
        return None
    actual_lang = _canonical_language(row.get("lang"))
    if actual_lang is None:
        diagnostics.append(_diagnostic("MISSING_LANGUAGE", "row has no recognized language", line=line, file=file_value))
        return None
    if actual_lang != expected_lang:
        diagnostics.append(_diagnostic("LANGUAGE_EXTENSION_MISMATCH", "row language disagrees with the canonical source extension", line=line, file=file_value, language=row.get("lang"), expected_language=expected_lang))
        return None
    normalized = dict(row)
    normalized["file"] = file_path
    normalized["lang"] = actual_lang
    return normalized


def validate_manifest(workspace: Path | str) -> dict:
    """Validate an existing manifest without modifying ``workspace``."""
    ws = Path(workspace).expanduser().resolve()
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    diagnostics: list[dict] = []
    rows: list[dict] = []
    if not manifest.is_file():
        diagnostics.append(_diagnostic("MISSING_MANIFEST", "manifest does not exist", manifest_path=str(manifest)))
    else:
        try:
            lines = manifest.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            diagnostics.append(_diagnostic("UNREADABLE_MANIFEST", str(exc), manifest_path=str(manifest)))
            lines = []
        if not lines:
            diagnostics.append(_diagnostic("EMPTY_MANIFEST", "manifest contains no rows", manifest_path=str(manifest)))
        for line_no, text in enumerate(lines, start=1):
            if not text.strip():
                diagnostics.append(_diagnostic("EMPTY_ROW", "manifest contains an empty row", line=line_no))
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                diagnostics.append(_diagnostic("MALFORMED_JSON", exc.msg, line=line_no))
                continue
            if not isinstance(row, dict):
                diagnostics.append(_diagnostic("NON_OBJECT_ROW", "manifest row must be a JSON object", line=line_no))
                continue
            normalized = _normalize_row(ws, row, line_no, diagnostics)
            if normalized is not None:
                rows.append(normalized)

    identities: dict[tuple[str, str], int] = {}
    for line_no, row in enumerate(rows, start=1):
        identity = (str(row.get("file") or ""), str(row.get("function") or ""))
        previous = identities.get(identity)
        if previous is not None:
            diagnostics.append(_diagnostic("DUPLICATE_UNIT_IDENTITY", "duplicate file/function unit identity", line=line_no, first_line=previous, file=identity[0], function=identity[1]))
        else:
            identities[identity] = line_no

    producer = None
    expected_rows: list[dict] = []
    try:
        producer = _load_producer()
        expected_rows = producer.build_expected_inscope_manifest_rows(ws)
    except Exception as exc:  # pragma: no cover - producer faults must fail closed
        diagnostics.append(_diagnostic("EXPECTED_ROW_RECOMPUTE_FAILED", str(exc)))

    if producer is not None:
        expected_key = producer._inscope_row_sort_key
        if rows != sorted(rows, key=expected_key):
            diagnostics.append(_diagnostic("NONDETERMINISTIC_ORDER", "manifest rows are not in canonical deterministic order"))
        if rows != expected_rows:
            diagnostics.append(_diagnostic("EXPECTED_ROW_SET_MISMATCH", "manifest rows do not match freshly recomputed producer output", actual_rows=len(rows), expected_rows=len(expected_rows)))

    return {
        "schema": SCHEMA,
        "workspace": str(ws),
        "manifest_path": str(manifest),
        "valid": not diagnostics,
        "diagnostics": diagnostics,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-path", required=True, help="workspace containing .auditooor/inscope_units.jsonl")
    args = parser.parse_args(argv)
    result = validate_manifest(args.workspace_path)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
