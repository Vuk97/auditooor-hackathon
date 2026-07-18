#!/usr/bin/env python3
"""Verify the P2 causal-chain reverse-lookup SQLite index.

The extractor writes compact causal-chain JSONL plus a SQLite reverse index
used for entry/mutation-prefix lookups. This verifier recomputes the expected
index rows from the JSONL using the extractor's own normalization helpers and
checks that the SQLite tables and index summary are in sync.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.causal_chain_reverse_lookup_verification.v1"
DEFAULT_CHAINS_JSONL = Path("audit/corpus_tags/derived/causal_chains.jsonl")
DEFAULT_INDEX_JSON = Path("audit/corpus_tags/derived/causal_chain_index.json")
DEFAULT_REVERSE_SQLITE = Path(
    "audit/corpus_tags/derived/causal_chain_reverse_lookup.sqlite"
)
REQUIRED_TABLES = (
    "chains_by_prefix_2",
    "chains_by_prefix_3",
    "chains_by_state_field",
)


def _load_extractor() -> Any:
    tool_path = Path(__file__).resolve().with_name("causal-chain-extract.py")
    spec = importlib.util.spec_from_file_location("causal_chain_extract_for_verify", tool_path)
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


def _expected_sets(
    rows: Iterable[dict[str, Any]],
) -> dict[str, set[tuple[Any, ...]]]:
    expected: dict[str, set[tuple[Any, ...]]] = {
        "chains_by_prefix_2": set(),
        "chains_by_prefix_3": set(),
        "chains_by_state_field": set(),
    }
    for row in rows:
        chain_id = EXTRACTOR.compact_text(row.get("chain_id"))
        if not chain_id:
            continue
        entry_signature = EXTRACTOR.entry_signature_for_row(row)
        mutation_texts = EXTRACTOR.mutation_texts_for_row(row)
        if entry_signature and mutation_texts:
            expected["chains_by_prefix_2"].add(
                (entry_signature, mutation_texts[0], chain_id)
            )
        if entry_signature and len(mutation_texts) >= 2:
            expected["chains_by_prefix_3"].add(
                (entry_signature, mutation_texts[0], mutation_texts[1], chain_id)
            )
        for step, mutation_text in enumerate(mutation_texts, 1):
            expected["chains_by_state_field"].add((mutation_text, chain_id, step))
    return expected


def _required_tables(conn: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
    }


def _actual_sets(conn: sqlite3.Connection) -> dict[str, set[tuple[Any, ...]]]:
    return {
        "chains_by_prefix_2": {
            tuple(row)
            for row in conn.execute(
                """
                SELECT entry_signature_norm, mutation_0_norm, chain_id
                FROM chains_by_prefix_2
                """
            )
        },
        "chains_by_prefix_3": {
            tuple(row)
            for row in conn.execute(
                """
                SELECT entry_signature_norm, mutation_0_norm, mutation_1_norm, chain_id
                FROM chains_by_prefix_3
                """
            )
        },
        "chains_by_state_field": {
            tuple(row)
            for row in conn.execute(
                """
                SELECT state_field_norm, chain_id, step
                FROM chains_by_state_field
                """
            )
        },
    }


def _sample_prefix_queries(
    conn: sqlite3.Connection,
    expected: dict[str, set[tuple[Any, ...]]],
) -> dict[str, dict[str, Any]]:
    samples: dict[str, dict[str, Any]] = {}
    prefix2_rows = sorted(expected["chains_by_prefix_2"])
    if prefix2_rows:
        entry, mutation_0, chain_id = prefix2_rows[0]
        matched = conn.execute(
            """
            SELECT COUNT(*) FROM chains_by_prefix_2
            WHERE entry_signature_norm = ? AND mutation_0_norm = ? AND chain_id = ?
            """,
            (entry, mutation_0, chain_id),
        ).fetchone()[0]
        samples["prefix_2_exact"] = {
            "entry_signature_norm": entry,
            "mutation_0_norm": mutation_0,
            "chain_id": chain_id,
            "matched": bool(matched),
        }
    prefix3_rows = sorted(expected["chains_by_prefix_3"])
    if prefix3_rows:
        entry, mutation_0, mutation_1, chain_id = prefix3_rows[0]
        matched = conn.execute(
            """
            SELECT COUNT(*) FROM chains_by_prefix_3
            WHERE entry_signature_norm = ?
              AND mutation_0_norm = ?
              AND mutation_1_norm = ?
              AND chain_id = ?
            """,
            (entry, mutation_0, mutation_1, chain_id),
        ).fetchone()[0]
        samples["prefix_3_exact"] = {
            "entry_signature_norm": entry,
            "mutation_0_norm": mutation_0,
            "mutation_1_norm": mutation_1,
            "chain_id": chain_id,
            "matched": bool(matched),
        }
    return samples


def _diff_examples(
    values: set[tuple[Any, ...]],
    *,
    limit: int,
) -> list[list[Any]]:
    return [list(row) for row in sorted(values)[:limit]]


def verify_reverse_lookup(
    *,
    chains_jsonl: Path = DEFAULT_CHAINS_JSONL,
    index_json: Path = DEFAULT_INDEX_JSON,
    reverse_sqlite: Path = DEFAULT_REVERSE_SQLITE,
    max_diff_examples: int = 5,
) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    warnings: list[str] = []

    if not chains_jsonl.is_file():
        errors.append({"code": "chains_jsonl_missing", "path": chains_jsonl.as_posix()})
        rows: list[dict[str, Any]] = []
        bad_jsonl: list[str] = []
    else:
        rows, bad_jsonl = _load_jsonl(chains_jsonl)
        for item in bad_jsonl[:max_diff_examples]:
            errors.append({"code": "chains_jsonl_bad_row", "detail": item})
        if len(bad_jsonl) > max_diff_examples:
            errors.append(
                {
                    "code": "chains_jsonl_bad_row_overflow",
                    "remaining": len(bad_jsonl) - max_diff_examples,
                }
            )

    index_payload: dict[str, Any] = {}
    if not index_json.is_file():
        errors.append({"code": "index_json_missing", "path": index_json.as_posix()})
    else:
        index_payload, index_error = _load_index(index_json)
        if index_error:
            errors.append({"code": "index_json_invalid", "detail": index_error})

    expected = _expected_sets(rows)
    expected_counts = {table: len(values) for table, values in expected.items()}
    actual_counts: dict[str, int] = {table: 0 for table in REQUIRED_TABLES}
    sample_prefix_queries: dict[str, dict[str, Any]] = {}

    if not reverse_sqlite.is_file():
        errors.append({"code": "reverse_sqlite_missing", "path": reverse_sqlite.as_posix()})
    else:
        try:
            with closing(sqlite3.connect(reverse_sqlite)) as conn:
                present_tables = _required_tables(conn)
                missing_tables = sorted(set(REQUIRED_TABLES) - present_tables)
                if missing_tables:
                    errors.append(
                        {
                            "code": "reverse_sqlite_missing_tables",
                            "tables": missing_tables,
                        }
                    )
                else:
                    actual = _actual_sets(conn)
                    actual_counts = {table: len(values) for table, values in actual.items()}
                    sample_prefix_queries = _sample_prefix_queries(conn, expected)
                    for table in REQUIRED_TABLES:
                        missing_rows = expected[table] - actual[table]
                        extra_rows = actual[table] - expected[table]
                        if len(actual[table]) != len(expected[table]):
                            errors.append(
                                {
                                    "code": f"{table}_count_mismatch",
                                    "expected": len(expected[table]),
                                    "actual": len(actual[table]),
                                }
                            )
                        if missing_rows:
                            errors.append(
                                {
                                    "code": f"{table}_missing_rows",
                                    "count": len(missing_rows),
                                    "examples": _diff_examples(
                                        missing_rows,
                                        limit=max_diff_examples,
                                    ),
                                }
                            )
                        if extra_rows:
                            errors.append(
                                {
                                    "code": f"{table}_extra_rows",
                                    "count": len(extra_rows),
                                    "examples": _diff_examples(
                                        extra_rows,
                                        limit=max_diff_examples,
                                    ),
                                }
                            )
        except sqlite3.DatabaseError as exc:
            errors.append({"code": "reverse_sqlite_invalid", "detail": str(exc)})

    if index_payload:
        index_row_count = index_payload.get("row_count")
        if index_row_count != len(rows):
            errors.append(
                {
                    "code": "index_row_count_mismatch",
                    "expected": len(rows),
                    "actual": index_row_count,
                }
            )
        reverse_summary = index_payload.get("reverse_lookup")
        if not isinstance(reverse_summary, dict):
            errors.append({"code": "index_reverse_lookup_summary_missing"})
        else:
            index_count_keys = {
                "chains_by_prefix_2": "chains_by_prefix_2_rows",
                "chains_by_prefix_3": "chains_by_prefix_3_rows",
                "chains_by_state_field": "chains_by_state_field_rows",
            }
            for table, key in index_count_keys.items():
                indexed = reverse_summary.get(key)
                if indexed != actual_counts.get(table):
                    errors.append(
                        {
                            "code": f"index_{key}_mismatch",
                            "expected": actual_counts.get(table),
                            "actual": indexed,
                        }
                    )

    if rows and expected_counts["chains_by_prefix_2"] == 0:
        warnings.append("no_prefix_2_rows_expected_from_source_rows")
    if rows and expected_counts["chains_by_state_field"] == 0:
        warnings.append("no_state_field_rows_expected_from_source_rows")

    return {
        "schema": SCHEMA,
        "met": not errors,
        "inputs": {
            "chains_jsonl": chains_jsonl.as_posix(),
            "index_json": index_json.as_posix(),
            "reverse_sqlite": reverse_sqlite.as_posix(),
        },
        "source_rows": len(rows),
        "bad_jsonl_rows": len(bad_jsonl),
        "expected_counts": expected_counts,
        "actual_counts": actual_counts,
        "sample_prefix_queries": sample_prefix_queries,
        "warnings": warnings,
        "error_codes": sorted({str(error.get("code")) for error in errors}),
        "errors": errors,
    }


def _format_text(summary: dict[str, Any]) -> str:
    status = "PASS" if summary.get("met") else "FAIL"
    lines = [
        f"P2 causal-chain reverse lookup verification: {status}",
        f"- source rows: {summary.get('source_rows', 0)}",
        f"- expected counts: {json.dumps(summary.get('expected_counts', {}), sort_keys=True)}",
        f"- actual counts: {json.dumps(summary.get('actual_counts', {}), sort_keys=True)}",
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
    parser.add_argument("--reverse-sqlite", type=Path, default=DEFAULT_REVERSE_SQLITE)
    parser.add_argument("--max-diff-examples", type=int, default=5)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    summary = verify_reverse_lookup(
        chains_jsonl=args.chains_jsonl,
        index_json=args.index_json,
        reverse_sqlite=args.reverse_sqlite,
        max_diff_examples=max(args.max_diff_examples, 0),
    )
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(_format_text(summary))
    return 0 if summary["met"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
