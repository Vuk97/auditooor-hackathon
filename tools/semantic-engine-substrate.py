#!/usr/bin/env python3
"""Materialize a strict deep-engine substrate from current compiler/IR evidence.

Step 1c owns compiler/IR execution. This adapter is deliberately read-only over
that evidence: it binds the current in-scope source snapshot, the matching
language backend receipt, and only valid semantic DefUsePath rows into the
artifact consumed by Step 2. It never upgrades AST, lexical, or degraded rows.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.semantic_engine_substrate.v1"
EXPECTATIONS = {
    "solidity": ("slither", {"solidity", "evm"}),
    "go": ("go-ssa", {"go"}),
    "rust": ("mir", {"rust"}),
}


class SubstrateError(ValueError):
    pass


def _load_schema() -> Any:
    path = ROOT / "tools" / "dataflow_schema.py"
    spec = importlib.util.spec_from_file_location("semantic_engine_dataflow_schema", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DATAFLOW = _load_schema()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _record_digest(records: list[dict[str, Any]]) -> str:
    """Return the strict producer's digest for the exact admitted semantic rows."""
    return hashlib.sha256(_canonical(records)).hexdigest()


def _inventory(workspace: Path, language: str) -> tuple[list[str], str]:
    workspace = workspace.resolve()
    path = workspace / ".auditooor" / "inscope_units.jsonl"
    if not path.is_file():
        raise SubstrateError("missing_canonical_inventory")
    files: list[str] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            raise SubstrateError(f"malformed_inventory_blank_row:{number}")
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SubstrateError(f"malformed_inventory_row:{number}") from exc
        if not isinstance(row, dict) or not isinstance(row.get("file"), str) or not isinstance(row.get("lang"), str):
            raise SubstrateError(f"malformed_inventory_row:{number}")
        if row["lang"].lower() in EXPECTATIONS[language][1]:
            source = (workspace / row["file"]).resolve()
            if not source.is_file() or workspace not in source.parents:
                raise SubstrateError(f"inventory_source_missing:{row['file']}")
            files.append(row["file"].replace("\\", "/"))
    if not files:
        raise SubstrateError(f"language_not_in_canonical_inventory:{language}")
    hashes = [{"file": item, "sha256": _sha(workspace / item)} for item in sorted(set(files))]
    return sorted(set(files)), hashlib.sha256(_canonical(hashes)).hexdigest()


def _receipt(workspace: Path, language: str, source_set_sha256: str, unit_count: int) -> dict[str, Any]:
    path = workspace / ".auditooor" / "language_backend_receipts" / "dataflow.jsonl"
    if not path.is_file():
        raise SubstrateError("missing_current_language_backend_receipt")
    expected, aliases = EXPECTATIONS[language]
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    matches = [row for row in rows if isinstance(row, dict) and str(row.get("language", "")).lower() in aliases]
    if len(matches) != 1:
        raise SubstrateError(f"backend_receipt_count_invalid:{language}")
    row = matches[0]
    # dataflow.py owns this receipt and names the version field receipt_schema.
    # Accept the former schema spelling only for historical already-recorded runs;
    # a fresh strict producer always emits receipt_schema.
    receipt_schema = row.get("receipt_schema", row.get("schema"))
    if receipt_schema != "auditooor.language_backend_receipt.v1" or row.get("status") != "pass":
        raise SubstrateError(f"backend_receipt_not_terminal:{language}")
    if str(row.get("confidence", "")).lower() != "semantic-ssa":
        raise SubstrateError(f"backend_receipt_not_semantic:{language}")
    backend = str(row.get("backend", "")).lower()
    if expected not in backend:
        raise SubstrateError(f"backend_receipt_backend_mismatch:{language}")
    if row.get("source_set_sha256") != source_set_sha256:
        raise SubstrateError(f"backend_receipt_source_snapshot_stale:{language}")
    if row.get("inventory_unit_count") != unit_count:
        raise SubstrateError(f"backend_receipt_inventory_count_mismatch:{language}")
    execution = row.get("execution")
    if not isinstance(execution, dict):
        raise SubstrateError(f"backend_receipt_execution_missing:{language}")
    argv = execution.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(part, str) and part for part in argv):
        raise SubstrateError(f"backend_receipt_execution_argv_invalid:{language}")
    if execution.get("executable") != argv[0] or execution.get("returncode") != 0:
        raise SubstrateError(f"backend_receipt_execution_result_invalid:{language}")
    for field in ("command_sha256", "stdout_sha256", "stderr_sha256", "artifact_sha256"):
        value = execution.get(field)
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise SubstrateError(f"backend_receipt_execution_{field}_invalid:{language}")
    if execution.get("artifact_kind") != f"{expected}-semantic-rows":
        raise SubstrateError(f"backend_receipt_execution_artifact_kind_invalid:{language}")
    return row


def build(workspace: Path, language: str, output: Path, records_output: Path) -> dict[str, Any]:
    if language not in EXPECTATIONS:
        raise SubstrateError(f"unsupported_semantic_engine_language:{language}")
    files, source_set_sha256 = _inventory(workspace, language)
    receipt = _receipt(workspace, language, source_set_sha256, len(files))
    source = workspace / ".auditooor" / "dataflow_paths.jsonl"
    if not source.is_file():
        raise SubstrateError("missing_dataflow_evidence")
    aliases = EXPECTATIONS[language][1]
    selected: list[dict[str, Any]] = []
    for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SubstrateError(f"malformed_dataflow_row:{number}") from exc
        if str(row.get("language", "")).lower() not in aliases:
            continue
        valid, errors = DATAFLOW.validate(row)
        if not valid or row.get("degraded") or row.get("confidence") != "semantic-ssa":
            raise SubstrateError(f"nonsemantic_dataflow_row:{number}:{';'.join(errors[:1])}")
        expected = EXPECTATIONS[language][0]
        if expected not in str(row.get("engine", "")).lower():
            raise SubstrateError(f"dataflow_engine_mismatch:{number}")
        selected.append(row)
    if not selected and receipt.get("examined_empty") is not True:
        raise SubstrateError(f"semantic_engine_rows_missing:{language}")
    execution = receipt["execution"]
    if execution["artifact_sha256"] != _record_digest(selected):
        raise SubstrateError(f"backend_receipt_artifact_mismatch:{language}")
    records_output.parent.mkdir(parents=True, exist_ok=True)
    records_output.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in selected), encoding="utf-8")
    result = {
        "schema": SCHEMA,
        "status": "passed",
        "evidence_tier": "semantic/compiler-backed",
        "language": language,
        "backend": receipt["backend"],
        "source_snapshot_sha256": source_set_sha256,
        "degraded": False,
        "warnings": [],
        "record_count": len(selected),
        "examined_empty": receipt.get("examined_empty") is True,
        "artifact_count": 2,
        "artifacts": [
            {"path": records_output.relative_to(workspace).as_posix(), "sha256": _sha(records_output)},
            {"path": ".auditooor/language_backend_receipts/dataflow.jsonl", "sha256": _sha(workspace / ".auditooor" / "language_backend_receipts" / "dataflow.jsonl")},
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--language", required=True, choices=sorted(EXPECTATIONS))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--records-output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = build(args.workspace.resolve(), args.language, args.output.resolve(), args.records_output.resolve())
    except (SubstrateError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"schema": SCHEMA, "status": "failed", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps({
        "schema": SCHEMA,
        "status": result["status"],
        "language": result["language"],
        "record_count": result["record_count"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
