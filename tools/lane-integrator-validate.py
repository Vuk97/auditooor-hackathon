#!/usr/bin/env python3
"""
tools/lane-integrator-validate.py

Validate JSONL corpus files against their declared schemas.
Currently wired for: auditooor.invariant_candidate.v1 (CODEX-2 deliverable).

Usage:
  python3 tools/lane-integrator-validate.py \
      --jsonl audit/corpus_tags/derived/invariants_extracted.jsonl \
      --schema audit/corpus_tags/schemas/auditooor.invariant_candidate.v1.schema.json \
      [--strict] [--json]

Exit codes: 0 = all pass, 1 = validation failures, 2 = usage/IO error.

Schema: auditooor.lane_integrator_validate.v1
Lane: lane234-codex2-schema-2026-05-26
R36: declared in .auditooor/agent_pathspec.json
R37: this validator READS records, does NOT modify them.
L34: workspace-ledger bucket; auto-executable.
"""

import argparse
import json
import re
import sys
from pathlib import Path


def load_schema(schema_path: Path) -> dict:
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_jsonl(jsonl_path: Path) -> list:
    """Return list of (lineno, record_dict)."""
    records = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            records.append((lineno, json.loads(line)))
    return records


def _type_ok(value, expected_type: str) -> bool:
    type_map = {
        "string": str,
        "integer": int,
        "boolean": bool,
        "array": list,
        "object": dict,
        "number": (int, float),
    }
    py_type = type_map.get(expected_type)
    if py_type is None:
        return True
    # bool is subclass of int; reject bool for integer fields
    if expected_type == "integer" and isinstance(value, bool):
        return False
    return isinstance(value, py_type)


def validate_record(record: dict, schema: dict, lineno: int) -> list:
    """
    Lightweight JSON Schema draft-2020-12 validator covering:
    required, type, enum, pattern, minLength, maxLength, minimum,
    array items type + minItems.
    Returns list of error strings (empty = pass).
    """
    errors = []
    props = schema.get("properties", {})
    required = set(schema.get("required", []))
    additional_ok = schema.get("additionalProperties", True)

    # Required field presence
    for field in required:
        if field not in record:
            errors.append(f"line {lineno}: missing required field '{field}'")

    # Per-field validation
    for field, value in record.items():
        if field not in props:
            if additional_ok is False:
                errors.append(
                    f"line {lineno}: unexpected field '{field}' (additionalProperties=false)"
                )
            continue

        spec = props[field]
        expected_type = spec.get("type")

        if expected_type and not _type_ok(value, expected_type):
            errors.append(
                f"line {lineno}: field '{field}' expected type {expected_type}, "
                f"got {type(value).__name__}"
            )
            continue  # skip further checks when type is wrong

        if "enum" in spec and value not in spec["enum"]:
            errors.append(
                f"line {lineno}: field '{field}' value {value!r} not in enum {spec['enum']}"
            )

        if expected_type == "string" and isinstance(value, str):
            if "pattern" in spec and not re.match(spec["pattern"], value):
                errors.append(
                    f"line {lineno}: field '{field}' value {value!r} does not match "
                    f"pattern {spec['pattern']!r}"
                )
            if "minLength" in spec and len(value) < spec["minLength"]:
                errors.append(
                    f"line {lineno}: field '{field}' length {len(value)} "
                    f"< minLength {spec['minLength']}"
                )
            if "maxLength" in spec and len(value) > spec["maxLength"]:
                errors.append(
                    f"line {lineno}: field '{field}' length {len(value)} "
                    f"> maxLength {spec['maxLength']}"
                )

        if expected_type in ("integer", "number") and isinstance(value, (int, float)):
            if "minimum" in spec and value < spec["minimum"]:
                errors.append(
                    f"line {lineno}: field '{field}' value {value} "
                    f"< minimum {spec['minimum']}"
                )

        if expected_type == "array" and isinstance(value, list):
            if "minItems" in spec and len(value) < spec["minItems"]:
                errors.append(
                    f"line {lineno}: field '{field}' has {len(value)} items "
                    f"< minItems {spec['minItems']}"
                )
            items_spec = spec.get("items", {})
            items_type = items_spec.get("type")
            if items_type:
                for idx, item in enumerate(value):
                    if not _type_ok(item, items_type):
                        errors.append(
                            f"line {lineno}: field '{field}[{idx}]' expected items type "
                            f"{items_type}, got {type(item).__name__}"
                        )
                        continue
                    if items_type == "string" and isinstance(item, str):
                        if "minLength" in items_spec and len(item) < items_spec["minLength"]:
                            errors.append(
                                f"line {lineno}: field '{field}[{idx}]' length {len(item)} "
                                f"< items.minLength {items_spec['minLength']}"
                            )
                        if "maxLength" in items_spec and len(item) > items_spec["maxLength"]:
                            errors.append(
                                f"line {lineno}: field '{field}[{idx}]' length {len(item)} "
                                f"> items.maxLength {items_spec['maxLength']}"
                            )

    return errors


def main():
    parser = argparse.ArgumentParser(
        description="Validate a JSONL corpus file against a JSON Schema."
    )
    parser.add_argument(
        "--jsonl",
        default="audit/corpus_tags/derived/invariants_extracted.jsonl",
        help="Path to the JSONL corpus file to validate.",
    )
    parser.add_argument(
        "--schema",
        default="audit/corpus_tags/schemas/auditooor.invariant_candidate.v1.schema.json",
        help="Path to the JSON Schema file.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors.",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output results as JSON.",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent

    jsonl_path = Path(args.jsonl)
    if not jsonl_path.is_absolute():
        jsonl_path = repo_root / jsonl_path

    schema_path = Path(args.schema)
    if not schema_path.is_absolute():
        schema_path = repo_root / schema_path

    if not jsonl_path.exists():
        print(f"ERROR: JSONL file not found: {jsonl_path}", file=sys.stderr)
        sys.exit(2)
    if not schema_path.exists():
        print(f"ERROR: Schema file not found: {schema_path}", file=sys.stderr)
        sys.exit(2)

    schema = load_schema(schema_path)
    records = load_jsonl(jsonl_path)
    total = len(records)

    all_errors: list = []
    failed_linenos: set = set()

    for lineno, record in records:
        errs = validate_record(record, schema, lineno)
        if errs:
            failed_linenos.add(lineno)
            all_errors.extend(errs)

    passed = total - len(failed_linenos)
    failed = len(failed_linenos)
    verdict = "PASS" if failed == 0 else "FAIL"

    result = {
        "schema": str(schema_path),
        "jsonl": str(jsonl_path),
        "total_records": total,
        "passed": passed,
        "failed": failed,
        "error_count": len(all_errors),
        "errors": all_errors[:50],
        "verdict": verdict,
    }

    if args.json_output:
        print(json.dumps(result, indent=2))
    else:
        print(f"Schema:  {schema_path.name}")
        print(f"JSONL:   {jsonl_path.name}")
        print(f"Records: {total}")
        print(f"Passed:  {passed}/{total}")
        if all_errors:
            print(f"\nERRORS ({len(all_errors)}):")
            for e in all_errors[:20]:
                print(f"  {e}")
            if len(all_errors) > 20:
                print(f"  ... and {len(all_errors) - 20} more (use --json to see all)")
        print(f"\nVerdict: {verdict}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
