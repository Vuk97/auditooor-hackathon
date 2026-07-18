#!/usr/bin/env python3
"""Verify the P2 causal-chain strict projection sidecar.

The extractor writes compact causal-chain JSONL and a four-block compatibility
projection JSONL used for review and downstream R43-style wiring. This verifier
recomputes the expected strict projections from the compact rows and checks that
the sidecar and index summary are still in sync.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.causal_chain_strict_projection_verification.v1"
DEFAULT_CHAINS_JSONL = Path("audit/corpus_tags/derived/causal_chains.jsonl")
DEFAULT_INDEX_JSON = Path("audit/corpus_tags/derived/causal_chain_index.json")
DEFAULT_STRICT_PROJECTION_JSONL = Path(
    "audit/corpus_tags/derived/causal_chain_strict_projection.jsonl"
)


def _load_extractor() -> Any:
    tool_path = Path(__file__).resolve().with_name("causal-chain-extract.py")
    spec = importlib.util.spec_from_file_location("causal_chain_extract_for_projection_verify", tool_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not import extractor at {tool_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EXTRACTOR = _load_extractor()


def _load_jsonl(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    with path.open("r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"{path}:{lineno}: invalid jsonl: {exc}")
                continue
            if not isinstance(payload, dict):
                errors.append(f"{path}:{lineno}: row is not an object")
                continue
            rows.append(payload)
    return rows, errors


def _load_index(path: Path) -> tuple[dict[str, Any], str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {}, f"{path}: invalid json: {exc}"
    if not isinstance(payload, dict):
        return {}, f"{path}: index is not an object"
    return payload, ""


def _projection_digest(row: dict[str, Any]) -> str:
    return json.dumps(row, sort_keys=True)


def _expected_projection_map(rows: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    projections: dict[str, dict[str, Any]] = {}
    warning_counts: Counter[str] = Counter()
    four_block_rows = 0
    for row in rows:
        projection = EXTRACTOR.strict_projection_for_row(row)
        EXTRACTOR.validate_strict_projection(projection)
        chain_id = EXTRACTOR.compact_text(projection.get("chain_id"))
        if not chain_id:
            continue
        projections[chain_id] = projection
        warning_counts.update(projection.get("projection_warnings") or [])
        if (
            projection.get("entry_point")
            and projection.get("mutations")
            and projection.get("invariant_violation")
            and projection.get("impact")
        ):
            four_block_rows += 1
    summary = {
        "row_count": len(projections),
        "four_block_rows": four_block_rows,
        "projection_status": "compatibility_projection",
        "warning_counts": dict(sorted(warning_counts.items())),
        "block_order": ["entry_point", "mutations", "invariant_violation", "impact"],
    }
    return projections, summary


def _actual_projection_map(
    rows: list[dict[str, Any]],
    *,
    max_diff_examples: int,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    projections: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, Any]] = []
    for row in rows:
        try:
            EXTRACTOR.validate_strict_projection(row)
        except (TypeError, ValueError) as exc:
            errors.append({"code": "strict_projection_invalid_row", "detail": str(exc)})
            continue
        chain_id = EXTRACTOR.compact_text(row.get("chain_id"))
        if not chain_id:
            errors.append({"code": "strict_projection_missing_chain_id"})
            continue
        if chain_id in projections:
            if len(errors) < max_diff_examples:
                errors.append({"code": "strict_projection_duplicate_chain_id", "chain_id": chain_id})
            continue
        projections[chain_id] = row
    return projections, errors


def _diff_examples(values: list[str], *, limit: int) -> list[str]:
    return sorted(values)[:limit]


def verify_strict_projection(
    *,
    chains_jsonl: Path = DEFAULT_CHAINS_JSONL,
    index_json: Path = DEFAULT_INDEX_JSON,
    strict_projection_jsonl: Path = DEFAULT_STRICT_PROJECTION_JSONL,
    max_diff_examples: int = 5,
) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    warnings: list[str] = []

    if not chains_jsonl.is_file():
        errors.append({"code": "chains_jsonl_missing", "path": chains_jsonl.as_posix()})
        compact_rows: list[dict[str, Any]] = []
        bad_compact_rows: list[str] = []
    else:
        compact_rows, bad_compact_rows = _load_jsonl(chains_jsonl)
        for item in bad_compact_rows[:max_diff_examples]:
            errors.append({"code": "chains_jsonl_bad_row", "detail": item})
        if len(bad_compact_rows) > max_diff_examples:
            errors.append(
                {
                    "code": "chains_jsonl_bad_row_overflow",
                    "remaining": len(bad_compact_rows) - max_diff_examples,
                }
            )

    index_payload: dict[str, Any] = {}
    if not index_json.is_file():
        errors.append({"code": "index_json_missing", "path": index_json.as_posix()})
    else:
        index_payload, index_error = _load_index(index_json)
        if index_error:
            errors.append({"code": "index_json_invalid", "detail": index_error})

    expected_map, expected_summary = _expected_projection_map(compact_rows)

    if not strict_projection_jsonl.is_file():
        errors.append(
            {
                "code": "strict_projection_jsonl_missing",
                "path": strict_projection_jsonl.as_posix(),
            }
        )
        actual_rows: list[dict[str, Any]] = []
        bad_projection_rows: list[str] = []
        actual_map: dict[str, dict[str, Any]] = {}
    else:
        actual_rows, bad_projection_rows = _load_jsonl(strict_projection_jsonl)
        for item in bad_projection_rows[:max_diff_examples]:
            errors.append({"code": "strict_projection_jsonl_bad_row", "detail": item})
        if len(bad_projection_rows) > max_diff_examples:
            errors.append(
                {
                    "code": "strict_projection_jsonl_bad_row_overflow",
                    "remaining": len(bad_projection_rows) - max_diff_examples,
                }
            )
        actual_map, row_errors = _actual_projection_map(
            actual_rows,
            max_diff_examples=max_diff_examples,
        )
        errors.extend(row_errors[:max_diff_examples])

    missing_chain_ids = sorted(set(expected_map) - set(actual_map))
    extra_chain_ids = sorted(set(actual_map) - set(expected_map))
    mismatched_chain_ids: list[str] = []
    for chain_id in sorted(set(expected_map) & set(actual_map)):
        if _projection_digest(expected_map[chain_id]) != _projection_digest(actual_map[chain_id]):
            mismatched_chain_ids.append(chain_id)

    if len(actual_map) != len(expected_map):
        errors.append(
            {
                "code": "strict_projection_row_count_mismatch",
                "expected": len(expected_map),
                "actual": len(actual_map),
            }
        )
    if missing_chain_ids:
        errors.append(
            {
                "code": "strict_projection_missing_chain_ids",
                "count": len(missing_chain_ids),
                "examples": _diff_examples(missing_chain_ids, limit=max_diff_examples),
            }
        )
    if extra_chain_ids:
        errors.append(
            {
                "code": "strict_projection_extra_chain_ids",
                "count": len(extra_chain_ids),
                "examples": _diff_examples(extra_chain_ids, limit=max_diff_examples),
            }
        )
    if mismatched_chain_ids:
        errors.append(
            {
                "code": "strict_projection_mismatched_rows",
                "count": len(mismatched_chain_ids),
                "examples": _diff_examples(mismatched_chain_ids, limit=max_diff_examples),
            }
        )

    if index_payload:
        if index_payload.get("row_count") != len(compact_rows):
            errors.append(
                {
                    "code": "index_row_count_mismatch",
                    "expected": len(compact_rows),
                    "actual": index_payload.get("row_count"),
                }
            )
        strict_summary = index_payload.get("strict_projection")
        if not isinstance(strict_summary, dict):
            errors.append({"code": "index_strict_projection_summary_missing"})
        else:
            for key in ("row_count", "four_block_rows", "projection_status", "warning_counts", "block_order"):
                expected_value = expected_summary.get(key)
                actual_value = strict_summary.get(key)
                if actual_value != expected_value:
                    errors.append(
                        {
                            "code": f"index_strict_projection_{key}_mismatch",
                            "expected": expected_value,
                            "actual": actual_value,
                        }
                    )

    if compact_rows and expected_summary["four_block_rows"] == 0:
        warnings.append("no_four_block_rows_expected_from_source_rows")

    sample_chain_ids = sorted(set(expected_map) & set(actual_map))[:3]
    return {
        "schema": SCHEMA,
        "met": not errors,
        "inputs": {
            "chains_jsonl": chains_jsonl.as_posix(),
            "index_json": index_json.as_posix(),
            "strict_projection_jsonl": strict_projection_jsonl.as_posix(),
        },
        "source_rows": len(compact_rows),
        "bad_compact_rows": len(bad_compact_rows),
        "bad_projection_rows": len(bad_projection_rows),
        "expected_summary": expected_summary,
        "actual_summary": {
            "row_count": len(actual_map),
            "sample_chain_ids": sample_chain_ids,
        },
        "warnings": warnings,
        "error_codes": sorted({str(error.get("code")) for error in errors}),
        "errors": errors,
    }


def _format_text(summary: dict[str, Any]) -> str:
    status = "PASS" if summary.get("met") else "FAIL"
    lines = [
        f"P2 causal-chain strict projection verification: {status}",
        f"- source rows: {summary.get('source_rows', 0)}",
        f"- expected summary: {json.dumps(summary.get('expected_summary', {}), sort_keys=True)}",
        f"- actual summary: {json.dumps(summary.get('actual_summary', {}), sort_keys=True)}",
    ]
    warnings = summary.get("warnings") or []
    if warnings:
        lines.append(f"- warnings: {json.dumps(warnings, sort_keys=True)}")
    errors = summary.get("errors") or []
    if errors:
        lines.append(f"- errors: {json.dumps(errors, sort_keys=True)}")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chains-jsonl", type=Path, default=DEFAULT_CHAINS_JSONL)
    parser.add_argument("--index-json", type=Path, default=DEFAULT_INDEX_JSON)
    parser.add_argument(
        "--strict-projection-jsonl",
        type=Path,
        default=DEFAULT_STRICT_PROJECTION_JSONL,
    )
    parser.add_argument("--max-diff-examples", type=int, default=5)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    summary = verify_strict_projection(
        chains_jsonl=args.chains_jsonl,
        index_json=args.index_json,
        strict_projection_jsonl=args.strict_projection_jsonl,
        max_diff_examples=max(args.max_diff_examples, 0),
    )
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(_format_text(summary))
    return 0 if summary["met"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
