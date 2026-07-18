#!/usr/bin/env python3
"""Route operator/RPC live-topology proof inputs into the manual-proof pipeline.

This is the real-input layer after ``live-topology-proof-input-bridge.py`` and
before ``live-topology-manual-proof-materializer.py``. It accepts evidence files
under ``.auditooor/live_topology_real_proof_inputs`` and, only when both rows in
one proof pair are exact same-block passing topology evidence, writes
``.auditooor/live_topology_provided_manual_proofs/<row_id>.json`` files for the
materializer.

It does not call RPC, import rows, run the executor, or close proof pairs.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.live_topology_real_proof_input_router.v1"
DEFAULT_BRIDGE = ".auditooor/live_topology_proof_input_bridge.json"
DEFAULT_INPUT_DIR = ".auditooor/live_topology_real_proof_inputs"
DEFAULT_PROVIDED_DIR = ".auditooor/live_topology_provided_manual_proofs"
DEFAULT_OUT_JSON = ".auditooor/live_topology_real_proof_input_router.json"
DEFAULT_OUT_MD = ".auditooor/live_topology_real_proof_input_router.md"
DEFAULT_BUNDLE_DIR = ".auditooor/live_topology_real_proof_input_routing"
ADVISORY_POSTURE = {
    "advisory_only": True,
    "promotion_allowed": False,
    "submission_posture": "NOT_SUBMIT_READY",
    "severity": "none",
    "selected_impact": "",
    "impact_contract_required": True,
}
SOURCE_REF_FIELDS = (
    "source_refs",
    "source_ref",
    "source_file",
    "source_file_line",
    "source_path",
)
REF_VALUE_KEYS = {
    "artifact_path",
    "config_path",
    "deployment_path",
    "harness_path",
    "proof_path",
    "source_ref",
    "source_refs",
    "source_file",
    "source_path",
    "transcript_path",
    "file",
    "file_path",
    "path",
}
TOPOLOGY_EVIDENCE_FIELDS = (
    "configured_topology_evidence",
    "topology_evidence",
    "deployment_topology_evidence",
    "configuration_evidence",
    "configuration_precondition",
)
PROOF_EVIDENCE_FIELDS = (
    "proof_evidence",
    "harness_evidence",
    "proof_artifact",
    "proof_artifacts",
    "proof_path",
    "harness_path",
    "transcript_path",
    "capture_result",
    "capture_result_path",
)
BLOCKER_FIELDS = (
    "blockers",
    "promotion_blockers",
    "blocking_reasons",
    "blocked_reasons",
    "blocker",
    "blocker_reason",
    "blocked_reason",
    "why_blocked",
    "why_not_routed",
)
ADVISORY_FALSE_FIELDS = {
    "promotion_allowed": "promotion_allowed",
}
ADVISORY_TRUE_FIELDS = {
    "advisory_only": "advisory_only",
    "row_is_advisory": "row_is_advisory",
}
ADVISORY_STRING_FIELDS = {
    "submission_posture": {"NOT_SUBMIT_READY", "ADVISORY_ONLY"},
    "proof_claim": {
        "none",
        "none_until_materialize_import_executor_validation",
        "none_until_import_and_executor_validation",
    },
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
        raise SystemExit(f"[live-topology-real-proof-input-router] missing {label}: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[live-topology-real-proof-input-router] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[live-topology-real-proof-input-router] expected object JSON for {label}: {path}")
    return payload


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def is_placeholder(value: Any) -> bool:
    raw = str(value or "").strip()
    return not raw or raw.startswith("<") or raw.endswith(">") or "placeholder" in raw.lower()


def is_address(value: Any) -> bool:
    return bool(re.fullmatch(r"0x[a-fA-F0-9]{40}", str(value or "").strip()))


def problem_token(value: Any) -> str:
    raw = str(value or "").strip().lower()
    token = re.sub(r"[^a-z0-9_.:-]+", "_", raw).strip("_")
    return token[:120] or "unknown"


def is_present(value: Any) -> bool:
    if isinstance(value, dict):
        return any(is_present(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(is_present(item) for item in value)
    return not is_placeholder(value)


def values_for_fields(row: dict[str, Any], fields: tuple[str, ...]) -> list[Any]:
    return [row[field] for field in fields if field in row]


def collect_ref_candidates(value: Any) -> list[str]:
    if isinstance(value, dict):
        refs: list[str] = []
        for key, item in value.items():
            if key in REF_VALUE_KEYS:
                refs.extend(collect_ref_candidates(item))
        return refs
    if isinstance(value, (list, tuple, set)):
        refs = []
        for item in value:
            refs.extend(collect_ref_candidates(item))
        return refs
    if isinstance(value, str) and not is_placeholder(value):
        return [value.strip()]
    return []


def ref_to_workspace_path(workspace: Path, ref: str) -> Path | None:
    raw = ref.strip()
    if not raw or "://" in raw:
        return None
    if raw.startswith("workspace:"):
        raw = raw[len("workspace:") :]
    if "#" in raw:
        raw = raw.split("#", 1)[0]
    match = re.fullmatch(r"(.+?)(?::L?\d+(?:-L?\d+)?)?", raw)
    if not match:
        return None
    path_text = match.group(1).strip()
    if not path_text:
        return None
    candidate = Path(path_text).expanduser()
    if not candidate.is_absolute():
        candidate = workspace / candidate
    return candidate.resolve(strict=False)


def is_current_workspace_file_ref(workspace: Path, ref: str) -> bool:
    resolved = ref_to_workspace_path(workspace, ref)
    if resolved is None:
        return False
    try:
        resolved.relative_to(workspace)
    except ValueError:
        return False
    return resolved.is_file()


def source_ref_problems(row: dict[str, Any], workspace: Path) -> list[str]:
    values = values_for_fields(row, SOURCE_REF_FIELDS)
    refs: list[str] = []
    for value in values:
        refs.extend(collect_ref_candidates(value))
    refs = [ref for ref in refs if ref.strip()]
    if not refs:
        return ["missing_current_workspace_source_refs"]
    if any(not is_current_workspace_file_ref(workspace, ref) for ref in refs):
        return ["stale_or_unresolved_source_refs"]
    return []


def required_evidence_problem(
    row: dict[str, Any],
    fields: tuple[str, ...],
    missing_reason: str,
    *,
    workspace: Path | None = None,
    stale_reason: str = "",
) -> list[str]:
    values = values_for_fields(row, fields)
    if not any(is_present(value) for value in values):
        return [missing_reason]
    if workspace is not None:
        refs: list[str] = []
        for value in values:
            refs.extend(collect_ref_candidates(value))
        if not refs or any(not is_current_workspace_file_ref(workspace, ref) for ref in refs):
            return [stale_reason or missing_reason]
    return []


def input_blockers(row: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    for value in values_for_fields(row, BLOCKER_FIELDS):
        if isinstance(value, dict):
            for key, item in value.items():
                if is_present(item):
                    blockers.append(f"{key}:{item}")
        elif isinstance(value, (list, tuple, set)):
            blockers.extend(str(item) for item in value if is_present(item))
        elif is_present(value):
            blockers.append(str(value))
    if row.get("blocked") is True:
        blockers.append("blocked_flag")
    return list(dict.fromkeys(blockers))


def blocker_marker_problems(row: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    for blocker in input_blockers(row):
        problems.append(f"input_blocker_present:{problem_token(blocker)}")
    for field, label in ADVISORY_TRUE_FIELDS.items():
        if row.get(field) is True:
            problems.append(f"advisory_only_marker_present:{label}")
    for field, label in ADVISORY_FALSE_FIELDS.items():
        if row.get(field) is False:
            problems.append(f"advisory_only_marker_present:{label}")
    for field, blocked_values in ADVISORY_STRING_FIELDS.items():
        value = str(row.get(field) or "").strip()
        if value in blocked_values or value.lower() in blocked_values or value.upper() in blocked_values:
            problems.append(f"advisory_only_marker_present:{field}")
    return problems


def first_result(payload: dict[str, Any]) -> dict[str, Any]:
    results = payload.get("results")
    if isinstance(results, list):
        for item in results:
            if isinstance(item, dict):
                return item
    return payload


def rows_from_input(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = payload.get("rows")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    results = payload.get("results")
    if isinstance(results, list):
        return [row for row in results if isinstance(row, dict)]
    return [payload]


def read_input_rows(input_dir: Path, pair_id: str, row_ids: list[str]) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]]]:
    rows: dict[str, dict[str, Any]] = {}
    problems: dict[str, list[str]] = {}
    pair_path = input_dir / f"{safe_name(pair_id)}.json"
    if pair_path.is_file():
        try:
            payload = json.loads(pair_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                for row in rows_from_input(payload):
                    row_id = str(row.get("id") or row.get("row_id") or "").strip()
                    if row_id:
                        rows[row_id] = row
            else:
                problems[pair_id] = ["pair_input_not_object"]
        except (OSError, json.JSONDecodeError) as exc:
            problems[pair_id] = [f"pair_input_unreadable:{exc}"]

    for row_id in row_ids:
        row_path = input_dir / f"{safe_name(row_id)}.json"
        if row_id in rows:
            continue
        if not row_path.is_file():
            problems[row_id] = ["real_proof_input_missing"]
            continue
        try:
            payload = json.loads(row_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            problems[row_id] = [f"real_proof_input_unreadable:{exc}"]
            continue
        if not isinstance(payload, dict):
            problems[row_id] = ["real_proof_input_not_object"]
            continue
        row = first_result(payload)
        if not isinstance(row, dict):
            problems[row_id] = ["real_proof_input_row_not_object"]
            continue
        rows[row_id] = row
    return rows, problems


def normalize_row(row: dict[str, Any], row_id: str, pair_id: str) -> dict[str, Any]:
    normalized = dict(row)
    normalized["id"] = str(normalized.get("id") or normalized.get("row_id") or row_id)
    normalized["row_id"] = str(normalized.get("row_id") or normalized.get("id") or row_id)
    normalized["proof_pair_id"] = str(normalized.get("proof_pair_id") or normalized.get("pair_id") or pair_id)
    normalized["pair_id"] = str(normalized.get("pair_id") or normalized.get("proof_pair_id") or pair_id)
    normalized.setdefault("evidence_class", "topology-relation")
    normalized.setdefault("execution_mode", "manual-proof")
    if "expected_value" in normalized and "expected" not in normalized:
        normalized["expected"] = normalized["expected_value"]
    if "observed_value" in normalized and "actual" not in normalized:
        normalized["actual"] = normalized["observed_value"]
    return normalized


def validate_row(row: dict[str, Any], expected: dict[str, Any], pair_id: str, workspace: Path) -> list[str]:
    problems: list[str] = []
    row_id = str(expected.get("row_id") or "").strip()
    expected_contract = str(expected.get("contract") or "").strip()
    expected_network = str(expected.get("network") or "").strip()

    if str(row.get("id") or row.get("row_id") or "").strip() != row_id:
        problems.append("row_id_mismatch")
    if str(row.get("proof_pair_id") or row.get("pair_id") or "").strip() != pair_id:
        problems.append("proof_pair_id_mismatch")
    if str(row.get("evidence_class") or "").strip() != "topology-relation":
        problems.append("wrong_evidence_class")
    if str(row.get("status") or "").strip() != "pass":
        problems.append("status_not_passing")
    if is_placeholder(row.get("block")):
        problems.append("missing_or_placeholder_block")
    if not is_address(row.get("address")):
        problems.append("missing_or_invalid_address")
    if is_placeholder(row.get("expected")) and is_placeholder(row.get("expected_value")):
        problems.append("missing_or_placeholder_expected")
    if is_placeholder(row.get("actual")) and is_placeholder(row.get("observed_value")):
        problems.append("missing_or_placeholder_actual")
    if expected_contract and str(row.get("contract") or "").strip() != expected_contract:
        problems.append("contract_mismatch")
    if expected_network and str(row.get("network") or "").strip() != expected_network:
        problems.append("network_mismatch")
    if is_placeholder(row.get("capture_command")) and is_placeholder(row.get("source_capture_command")):
        problems.append("missing_capture_command")
    source_kind = str(row.get("source_kind") or row.get("evidence_source") or "").strip().lower()
    if source_kind and source_kind not in {"operator", "rpc", "live-state-checker", "manual-proof"}:
        problems.append("unsupported_evidence_source")
    problems.extend(source_ref_problems(row, workspace))
    problems.extend(
        required_evidence_problem(row, TOPOLOGY_EVIDENCE_FIELDS, "missing_configured_topology_evidence")
    )
    problems.extend(
        required_evidence_problem(
            row,
            PROOF_EVIDENCE_FIELDS,
            "missing_concrete_proof_or_harness_evidence",
            workspace=workspace,
            stale_reason="stale_or_unresolved_proof_or_harness_evidence",
        )
    )
    problems.extend(blocker_marker_problems(row))
    return sorted(set(problems))


def import_command(workspace: Path, row_ids: list[str]) -> str:
    row_args = " ".join(f"--manual-proof-id {row_id}" for row_id in row_ids)
    return (
        f"python3 tools/live-check-runner.py {workspace} --import-manual-proofs {row_args} "
        f"--out-json {workspace / 'live_topology_checks.json'} --out-md {workspace / 'LIVE_TOPOLOGY.md'}"
    )


def canonical_provided_payload(workspace: Path, row: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "auditooor.live_topology_real_proof_input_router.provided_row.v1",
        "workspace": str(workspace),
        "generated_at": now_iso(),
        "proof_claim": "none_until_materialize_import_executor_validation",
        "results": [row],
    }


def build_payload(
    workspace: Path,
    bridge: dict[str, Any],
    input_dir: Path,
    provided_dir: Path,
    *,
    write_provided: bool,
) -> dict[str, Any]:
    pair_results: list[dict[str, Any]] = []
    pair_counts: Counter[str] = Counter()
    row_counts: Counter[str] = Counter()
    provided_files: list[str] = []

    for pair in bridge.get("proof_pairs") or []:
        if not isinstance(pair, dict):
            continue
        pair_id = str(pair.get("proof_pair_id") or "").strip()
        row_requirements = [row for row in pair.get("rows") or [] if isinstance(row, dict)]
        row_ids = [str(row.get("row_id") or "").strip() for row in row_requirements if row.get("row_id")]
        input_rows, input_errors = read_input_rows(input_dir, pair_id, row_ids)
        row_results: list[dict[str, Any]] = []
        ready_rows: list[tuple[str, dict[str, Any]]] = []
        blocks: set[str] = set()

        for expected in row_requirements:
            row_id = str(expected.get("row_id") or "").strip()
            raw = input_rows.get(row_id)
            problems = list(input_errors.get(row_id) or [])
            row = normalize_row(raw, row_id, pair_id) if raw is not None else None
            if row is not None:
                problems.extend(validate_row(row, expected, pair_id, workspace))
                block = str(row.get("block") or "").strip()
                if block:
                    blocks.add(block)
            if row is not None and not problems:
                row_state = "real_proof_row_ready"
                ready_rows.append((row_id, row))
            elif raw is not None:
                row_state = "real_proof_row_invalid"
            else:
                row_state = "real_proof_row_missing"
            row_counts[row_state] += 1
            row_results.append(
                {
                    "row_id": row_id,
                    "expected_contract": expected.get("contract"),
                    "input_path": str(input_dir / f"{safe_name(row_id)}.json"),
                    "provided_path": str(provided_dir / f"{safe_name(row_id)}.json"),
                    "routing_state": row_state,
                    "manual_block": str(row.get("block") or "") if row else None,
                    "input_blockers": input_blockers(row) if row else [],
                    "problems": sorted(set(problems)),
                    "proof_claim": "none",
                    **ADVISORY_POSTURE,
                }
            )

        pair_problems: list[str] = []
        if ready_rows and len(blocks) > 1:
            pair_problems.append("cross_block_real_proof_inputs")
        if ready_rows and len(ready_rows) != len(row_ids):
            pair_problems.append("partial_real_proof_inputs")

        if len(ready_rows) == len(row_ids) and row_ids and len(blocks) == 1:
            pair_state = "same_block_real_proof_ready_for_materializer"
            if write_provided:
                for row_id, row in ready_rows:
                    out_path = provided_dir / f"{safe_name(row_id)}.json"
                    write_json(out_path, canonical_provided_payload(workspace, row))
                    provided_files.append(str(out_path))
        elif ready_rows:
            pair_state = "partial_or_cross_block_real_proof_inputs"
        elif any(result["routing_state"] == "real_proof_row_invalid" for result in row_results):
            pair_state = "real_proof_inputs_present_but_invalid"
        else:
            pair_state = "real_proof_inputs_missing"
        pair_counts[pair_state] += 1
        pair_results.append(
            {
                "proof_pair_id": pair_id,
                "requirement_id": pair.get("requirement_id"),
                "row_ids": row_ids,
                "input_acquisition_class": pair.get("input_acquisition_class"),
                "routing_state": pair_state,
                "manual_blocks_seen": sorted(blocks),
                "pair_problems": pair_problems,
                "row_routes": row_results,
                "provided_rows_written": [path for path in provided_files if any(row_id in path for row_id in row_ids)],
                "materializer_command_if_ready": (
                    f"python3 tools/live-topology-manual-proof-materializer.py --workspace {workspace} "
                    f"--provided-dir {provided_dir}"
                ),
                "import_command_after_materializer": import_command(workspace, row_ids),
                "executor_command_after_import": pair.get("executor_command_after_import"),
                "proof_claim": "none",
                **ADVISORY_POSTURE,
            }
        )

    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "generated_at": now_iso(),
        "source_bridge_schema": bridge.get("schema"),
        "real_proof_input_dir": str(input_dir),
        "provided_manual_proofs_dir": str(provided_dir),
        "summary": {
            "proof_pairs_total": len(pair_results),
            "rows_total": sum(len(pair.get("row_ids") or []) for pair in pair_results),
            "same_block_ready_pairs": pair_counts.get("same_block_real_proof_ready_for_materializer", 0),
            "provided_rows_written": len(provided_files),
            "proof_pairs_closed": 0,
            "proof_pairs_promoted": 0,
            "pair_routing_state_counts": dict(sorted(pair_counts.items())),
            "row_routing_state_counts": dict(sorted(row_counts.items())),
        },
        "pair_routes": pair_results,
        "provided_files": provided_files,
        "why_no_more_local_closure_safe": (
            "Real proof inputs are only routed into provided manual-proof files here. "
            "Closure still requires materialization, import into live_topology_checks.json, "
            "and live-topology-proof-executor validation of an exact same-block pair."
        ),
        **ADVISORY_POSTURE,
    }


def write_bundles(bundle_dir: Path, payload: dict[str, Any]) -> list[str]:
    pair_dir = bundle_dir / "pairs"
    pair_dir.mkdir(parents=True, exist_ok=True)
    files: list[str] = []
    for pair in payload.get("pair_routes") or []:
        path = pair_dir / f"{safe_name(str(pair.get('proof_pair_id') or 'unknown'))}.json"
        write_json(path, pair)
        files.append(str(path))
    return files


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Live Topology Real Proof Input Router",
        "",
        "Validates operator/RPC-provided same-block evidence and routes exact pairs to the manual-proof materializer.",
        "This does not import rows, run the executor, or claim proof closure.",
        "",
        f"- proof pairs processed: `{summary['proof_pairs_total']}`",
        f"- rows processed: `{summary['rows_total']}`",
        f"- same-block ready pairs: `{summary['same_block_ready_pairs']}`",
        f"- provided rows written: `{summary['provided_rows_written']}`",
        f"- proof pairs closed: `{summary['proof_pairs_closed']}`",
        f"- submission posture: `{payload['submission_posture']}`",
        "",
        "## Pair Routing States",
        "",
    ]
    for name, count in summary["pair_routing_state_counts"].items():
        lines.append(f"- `{name}`: {count}")
    lines.extend(["", "## Row Routing States", ""])
    for name, count in summary["row_routing_state_counts"].items():
        lines.append(f"- `{name}`: {count}")
    lines.extend(["", "## First 25 Pairs", "", "| Pair | State | Rows |", "|---|---|---|"])
    for pair in payload.get("pair_routes", [])[:25]:
        lines.append(
            f"| `{pair.get('proof_pair_id')}` | `{pair.get('routing_state')}` | "
            f"`{', '.join(pair.get('row_ids') or [])}` |"
        )
    lines.extend(["", "## Why No Further Local Closure", "", payload["why_no_more_local_closure_safe"], ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--bridge", type=Path)
    parser.add_argument("--input-dir", type=Path)
    parser.add_argument("--provided-dir", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-write-bundles", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[live-topology-real-proof-input-router] workspace not found: {workspace}")
        return 2
    bridge_path = resolve_path(workspace, args.bridge, DEFAULT_BRIDGE)
    input_dir = resolve_path(workspace, args.input_dir, DEFAULT_INPUT_DIR)
    provided_dir = resolve_path(workspace, args.provided_dir, DEFAULT_PROVIDED_DIR)
    out_json = resolve_path(workspace, args.out_json, DEFAULT_OUT_JSON)
    out_md = resolve_path(workspace, args.out_md, DEFAULT_OUT_MD)
    bundle_dir = resolve_path(workspace, args.bundle_dir, DEFAULT_BUNDLE_DIR)

    payload = build_payload(
        workspace,
        load_json(bridge_path, "proof input bridge"),
        input_dir,
        provided_dir,
        write_provided=not args.dry_run,
    )
    if not args.no_write_bundles:
        payload["bundle_dir"] = str(bundle_dir)
        payload["bundle_files"] = write_bundles(bundle_dir, payload)
    write_json(out_json, payload)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[live-topology-real-proof-input-router] OK "
        f"pairs={payload['summary']['proof_pairs_total']} "
        f"same_block_ready={payload['summary']['same_block_ready_pairs']} "
        f"provided_rows={payload['summary']['provided_rows_written']} json={out_json}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
