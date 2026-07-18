#!/usr/bin/env python3
"""Materialize validated live-topology manual proofs into canonical import files.

This runs after ``live-topology-proof-input-validator.py``. It does not call
RPC, does not import rows into ``live_topology_checks.json``, and never marks a
proof pair closed. Its only job is to take operator-provided proof JSON files,
validate them against the exact pair/row requirements, and write importable
``manual_proofs/<row_id>.json`` files when both rows in a pair are executed at
the same block.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.live_topology_manual_proof_materializer.v1"
DEFAULT_VALIDATOR = ".auditooor/live_topology_proof_input_validator.json"
DEFAULT_PROVIDED_DIR = ".auditooor/live_topology_provided_manual_proofs"
DEFAULT_MANUAL_PROOFS = "manual_proofs"
DEFAULT_OUT_JSON = ".auditooor/live_topology_manual_proof_materializer.json"
DEFAULT_OUT_MD = ".auditooor/live_topology_manual_proof_materializer.md"
ADVISORY_POSTURE = {
    "advisory_only": True,
    "promotion_allowed": False,
    "submission_posture": "NOT_SUBMIT_READY",
    "severity": "none",
    "selected_impact": "",
    "impact_contract_required": True,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def resolve_path(workspace: Path, path: Path | None, default: str) -> Path:
    candidate = path or Path(default)
    candidate = candidate.expanduser()
    if not candidate.is_absolute():
        candidate = workspace / candidate
    return candidate.resolve()


def safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value).strip("_") or "unknown"


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise SystemExit(f"[live-topology-manual-proof-materializer] missing {label}: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[live-topology-manual-proof-materializer] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[live-topology-manual-proof-materializer] expected object JSON for {label}: {path}")
    return payload


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def is_placeholder(value: Any) -> bool:
    raw = str(value or "").strip()
    return not raw or raw.startswith("<") or raw.endswith(">") or "placeholder" in raw.lower()


def is_address_like(value: Any) -> bool:
    return bool(re.fullmatch(r"0x[a-fA-F0-9]{40}", str(value or "").strip()))


def read_provided_row(path: Path, row_id: str) -> tuple[dict[str, Any] | None, list[str]]:
    if not path.is_file():
        return None, ["provided_manual_proof_missing"]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, [f"provided_manual_proof_unreadable:{exc}"]
    if not isinstance(payload, dict):
        return None, ["provided_manual_proof_not_object"]
    rows = payload.get("results")
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict) and str(row.get("id") or row.get("row_id") or "").strip() == row_id:
                return row, []
        return None, ["provided_manual_proof_results_missing_row"]
    return payload, []


def normalize_row(raw: dict[str, Any], row_id: str, pair_id: str) -> dict[str, Any]:
    row = dict(raw)
    row["id"] = str(row.get("id") or row.get("row_id") or row_id)
    row["row_id"] = str(row.get("row_id") or row.get("id") or row_id)
    row["proof_pair_id"] = str(row.get("proof_pair_id") or row.get("pair_id") or pair_id)
    row["pair_id"] = str(row.get("pair_id") or row.get("proof_pair_id") or pair_id)
    row.setdefault("evidence_class", "topology-relation")
    row.setdefault("execution_mode", "manual-proof")
    row.setdefault("replay_command", f"python3 tools/live-check-runner.py --workspace <ws> --import-manual-proofs --manual-proof-id {row_id}")
    return row


def validate_row(row: dict[str, Any], expected: dict[str, Any], pair_id: str) -> list[str]:
    problems: list[str] = []
    row_id = str(expected.get("row_id") or "").strip()
    if str(row.get("id") or row.get("row_id") or "").strip() != row_id:
        problems.append("row_id_mismatch")
    if str(row.get("proof_pair_id") or row.get("pair_id") or "").strip() != pair_id:
        problems.append("proof_pair_id_mismatch")
    if str(row.get("evidence_class") or "").strip() != "topology-relation":
        problems.append("wrong_evidence_class")
    if str(row.get("status") or "").strip() not in {"pass", "fail"}:
        problems.append("status_not_executed")
    if is_placeholder(row.get("block")):
        problems.append("missing_or_placeholder_block")
    if not is_address_like(row.get("address")):
        problems.append("missing_or_invalid_address")
    if is_placeholder(row.get("expected")) and is_placeholder(row.get("expected_value")):
        problems.append("missing_or_placeholder_expected")
    if is_placeholder(row.get("actual")) and is_placeholder(row.get("observed_value")):
        problems.append("missing_or_placeholder_actual")
    expected_contract = str(expected.get("contract") or "").strip()
    if expected_contract and str(row.get("contract") or "").strip() != expected_contract:
        problems.append("contract_mismatch")
    return sorted(set(problems))


def canonical_payload(workspace: Path, row: dict[str, Any], pair_rows: list[str]) -> dict[str, Any]:
    canonical_row = dict(row)
    if "expected_value" in canonical_row and "expected" not in canonical_row:
        canonical_row["expected"] = canonical_row["expected_value"]
    if "observed_value" in canonical_row and "actual" not in canonical_row:
        canonical_row["actual"] = canonical_row["observed_value"]
    canonical_row["same_block"] = True
    canonical_row["pair_complete"] = True
    canonical_row["pair_blocks"] = [str(canonical_row.get("block"))]
    canonical_row["edge_row_id"] = pair_rows[0] if pair_rows else None
    canonical_row["authority_row_id"] = pair_rows[1] if len(pair_rows) > 1 else None
    return {
        "schema": "auditooor.manual_live_topology_proof.v1",
        "workspace": str(workspace),
        "generated_at": now_iso(),
        "canonical_dossier": "live_topology_checks.json",
        "advisory_only": False,
        "summary": {
            "dry_run": False,
            "materialized_by": SCHEMA,
            "proof_claim": "none_until_import_and_executor_validation",
        },
        "results": [canonical_row],
    }


def import_command(workspace: Path, row_ids: list[str]) -> str:
    args = " ".join(f"--manual-proof-id {row_id}" for row_id in row_ids)
    return (
        f"python3 tools/live-check-runner.py {workspace} --import-manual-proofs {args} "
        f"--out-json {workspace / 'live_topology_checks.json'} --out-md {workspace / 'LIVE_TOPOLOGY.md'}"
    )


def build_payload(
    workspace: Path,
    validator: dict[str, Any],
    provided_dir: Path,
    manual_dir: Path,
    *,
    write_canonical: bool,
) -> dict[str, Any]:
    pair_results: list[dict[str, Any]] = []
    pair_counts: Counter[str] = Counter()
    row_counts: Counter[str] = Counter()
    materialized_files: list[str] = []

    for pair in validator.get("pair_validations") or []:
        if not isinstance(pair, dict):
            continue
        pair_id = str(pair.get("proof_pair_id") or "").strip()
        row_validations = [row for row in pair.get("row_validations") or [] if isinstance(row, dict)]
        row_ids = [str(row.get("row_id") or "").strip() for row in row_validations if row.get("row_id")]
        row_results: list[dict[str, Any]] = []
        blocks: set[str] = set()
        ready_rows: list[tuple[str, dict[str, Any]]] = []

        for row_validation in row_validations:
            row_id = str(row_validation.get("row_id") or "").strip()
            source_path = provided_dir / f"{safe_name(row_id)}.json"
            raw, problems = read_provided_row(source_path, row_id)
            row = normalize_row(raw or {}, row_id, pair_id) if raw is not None else None
            if row is not None:
                problems.extend(validate_row(row, row_validation, pair_id))
                block = str(row.get("block") or "").strip()
                if block:
                    blocks.add(block)
            if row is not None and not problems:
                ready_rows.append((row_id, row))
                row_state = "canonical_manual_proof_ready"
            else:
                row_state = "provided_manual_proof_invalid" if raw is not None else "provided_manual_proof_missing"
            row_counts[row_state] += 1
            row_results.append(
                {
                    "row_id": row_id,
                    "provided_path": str(source_path),
                    "canonical_path": str(manual_dir / f"{row_id}.json"),
                    "materialization_state": row_state,
                    "problems": sorted(set(problems)),
                    "manual_block": str(row.get("block") or "") if row else None,
                    "proof_claim": "none",
                    **ADVISORY_POSTURE,
                }
            )

        if len(ready_rows) == len(row_ids) and len(blocks) == 1 and row_ids:
            pair_state = "canonical_manual_proofs_ready_for_import"
            if write_canonical:
                for row_id, row in ready_rows:
                    out_path = manual_dir / f"{row_id}.json"
                    write_json(out_path, canonical_payload(workspace, row, row_ids))
                    materialized_files.append(str(out_path))
        elif ready_rows:
            pair_state = "partial_canonical_manual_proofs_ready"
        else:
            pair_state = "no_canonical_manual_proofs_ready"
        pair_counts[pair_state] += 1
        pair_results.append(
            {
                "proof_pair_id": pair_id,
                "row_ids": row_ids,
                "materialization_state": pair_state,
                "manual_blocks_seen": sorted(blocks),
                "row_materializations": row_results,
                "import_command_if_ready": import_command(workspace, row_ids),
                "executor_command_after_import": pair.get("executor_command_after_import"),
                "proof_claim": "none",
                **ADVISORY_POSTURE,
            }
        )

    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "generated_at": now_iso(),
        "source_validator_schema": validator.get("schema"),
        "provided_manual_proofs_dir": str(provided_dir),
        "canonical_manual_proofs_dir": str(manual_dir),
        "summary": {
            "proof_pairs_total": len(pair_results),
            "rows_total": sum(len(pair.get("row_ids") or []) for pair in pair_results),
            "proof_pairs_closed": 0,
            "proof_pairs_promoted": 0,
            "canonical_import_ready_pairs": pair_counts.get("canonical_manual_proofs_ready_for_import", 0),
            "canonical_rows_materialized": len(materialized_files),
            "pair_materialization_state_counts": dict(sorted(pair_counts.items())),
            "row_materialization_state_counts": dict(sorted(row_counts.items())),
        },
        "pair_materializations": pair_results,
        "materialized_files": materialized_files,
        "why_no_more_local_closure_safe": (
            "This tool only validates provided manual proof files and writes canonical import files. "
            "A proof pair is not closed until live-check-runner imports both same-block rows and "
            "live-topology-proof-executor validates the canonical dossier."
        ),
        **ADVISORY_POSTURE,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Live Topology Manual Proof Materializer",
        "",
        "Validates provided manual proof files and materializes canonical `manual_proofs/` imports.",
        "This does not import rows or claim proof closure.",
        "",
        f"- proof pairs processed: `{summary['proof_pairs_total']}`",
        f"- rows processed: `{summary['rows_total']}`",
        f"- canonical import-ready pairs: `{summary['canonical_import_ready_pairs']}`",
        f"- canonical rows materialized: `{summary['canonical_rows_materialized']}`",
        f"- proof pairs closed: `{summary['proof_pairs_closed']}`",
        f"- submission posture: `{payload['submission_posture']}`",
        "",
        "## Pair States",
        "",
    ]
    for name, count in summary["pair_materialization_state_counts"].items():
        lines.append(f"- `{name}`: {count}")
    lines.extend(["", "## Row States", ""])
    for name, count in summary["row_materialization_state_counts"].items():
        lines.append(f"- `{name}`: {count}")
    lines.extend(["", "## First 25 Pairs", "", "| Pair | State | Rows |", "|---|---|---|"])
    for pair in payload.get("pair_materializations", [])[:25]:
        lines.append(
            f"| `{pair.get('proof_pair_id')}` | `{pair.get('materialization_state')}` | "
            f"`{', '.join(pair.get('row_ids') or [])}` |"
        )
    lines.extend(["", "## Why No Further Local Closure", "", payload["why_no_more_local_closure_safe"], ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--validator", type=Path)
    parser.add_argument("--provided-dir", type=Path)
    parser.add_argument("--manual-proofs", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[live-topology-manual-proof-materializer] workspace not found: {workspace}")
        return 2
    validator_path = resolve_path(workspace, args.validator, DEFAULT_VALIDATOR)
    provided_dir = resolve_path(workspace, args.provided_dir, DEFAULT_PROVIDED_DIR)
    manual_dir = resolve_path(workspace, args.manual_proofs, DEFAULT_MANUAL_PROOFS)
    out_json = resolve_path(workspace, args.out_json, DEFAULT_OUT_JSON)
    out_md = resolve_path(workspace, args.out_md, DEFAULT_OUT_MD)

    payload = build_payload(
        workspace,
        load_json(validator_path, "proof input validator"),
        provided_dir,
        manual_dir,
        write_canonical=not args.dry_run,
    )
    write_json(out_json, payload)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[live-topology-manual-proof-materializer] OK "
        f"pairs={payload['summary']['proof_pairs_total']} "
        f"import_ready={payload['summary']['canonical_import_ready_pairs']} "
        f"materialized={payload['summary']['canonical_rows_materialized']} json={out_json}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
