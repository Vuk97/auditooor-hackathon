#!/usr/bin/env python3
"""Validate live-topology proof input bundles before import.

This runs after ``live-topology-proof-input-bridge.py``. It does not call RPC,
does not import rows, and never marks proof pairs closed. It validates any
existing ``manual_proofs/<row_id>.json`` files against the exact pair bundle,
writes sample manual-proof schemas for missing rows, and emits per-network
capture/import command manifests.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.live_topology_proof_input_validator.v1"
DEFAULT_BRIDGE = ".auditooor/live_topology_proof_input_bridge.json"
DEFAULT_OUT_JSON = ".auditooor/live_topology_proof_input_validator.json"
DEFAULT_OUT_MD = ".auditooor/live_topology_proof_input_validator.md"
DEFAULT_BUNDLE_DIR = ".auditooor/live_topology_proof_input_validation"
DEFAULT_MANUAL_PROOFS = "manual_proofs"
ADVISORY_POSTURE = {
    "advisory_only": True,
    "promotion_allowed": False,
    "submission_posture": "NOT_SUBMIT_READY",
    "severity": "none",
    "selected_impact": "",
    "impact_contract_required": True,
}
ENVELOPE_EVIDENCE_KEYS = (
    "workspace",
    "source_refs",
    "source_ref",
    "workspace_source_refs",
    "configured_source_refs",
    "topology_source_refs",
    "configured_topology_evidence",
    "topology_evidence",
    "deployment_topology_evidence",
    "configuration_evidence",
    "proof_evidence",
    "harness_evidence",
    "proof_artifacts",
    "execution_evidence",
    "proof_transcript",
    "harness_command",
    "test_transcript",
    "capture_artifact",
    "blockers",
    "promotion_blockers",
    "proof_blockers",
    "terminal_blockers",
    "required_unblockers",
    "advisory_only",
)
SOURCE_REF_KEYS = (
    "source_refs",
    "source_ref",
    "workspace_source_refs",
    "configured_source_refs",
    "topology_source_refs",
)
TOPOLOGY_EVIDENCE_KEYS = (
    "configured_topology_evidence",
    "topology_evidence",
    "deployment_topology_evidence",
    "configuration_evidence",
)
PROOF_EVIDENCE_KEYS = (
    "proof_evidence",
    "harness_evidence",
    "proof_artifacts",
    "execution_evidence",
    "proof_transcript",
    "harness_command",
    "test_transcript",
    "capture_artifact",
)
BLOCKER_KEYS = (
    "blockers",
    "promotion_blockers",
    "proof_blockers",
    "terminal_blockers",
    "required_unblockers",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def resolve_path(workspace: Path, path: Path | None, default: str) -> Path:
    candidate = path or Path(default)
    candidate = candidate.expanduser()
    if not candidate.is_absolute():
        candidate = workspace / candidate
    return candidate.resolve()


def load_json(path: Path, label: str, *, required: bool = True) -> dict[str, Any]:
    if not path.is_file():
        if required:
            raise SystemExit(f"[live-topology-proof-input-validator] missing {label}: {path}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[live-topology-proof-input-validator] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[live-topology-proof-input-validator] expected object JSON for {label}: {path}")
    return payload


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value).strip("_") or "unknown"


def is_placeholder(value: Any) -> bool:
    raw = str(value or "").strip()
    if not raw:
        return True
    lowered = raw.lower()
    return raw.startswith("<") or raw.endswith(">") or lowered in {
        "n/a",
        "na",
        "none",
        "null",
        "todo",
        "tbd",
        "unknown",
        "placeholder",
    }


def is_trueish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "advisory", "advisory_only", "advisory-only"}


def values_from(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def has_concrete_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, dict):
        return any(has_concrete_value(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(has_concrete_value(item) for item in value)
    return not is_placeholder(value)


def collect_source_refs(manual: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in SOURCE_REF_KEYS:
        for item in values_from(manual.get(key)):
            if isinstance(item, dict):
                for nested_key in SOURCE_REF_KEYS:
                    refs.extend(str(ref).strip() for ref in values_from(item.get(nested_key)) if not is_placeholder(ref))
            elif not is_placeholder(item):
                refs.append(str(item).strip())
    for key in TOPOLOGY_EVIDENCE_KEYS + PROOF_EVIDENCE_KEYS:
        refs.extend(nested_source_refs(manual.get(key)))
    return sorted(set(refs))


def nested_source_refs(value: Any) -> list[str]:
    refs: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in SOURCE_REF_KEYS:
                refs.extend(str(ref).strip() for ref in values_from(item) if not is_placeholder(ref))
            else:
                refs.extend(nested_source_refs(item))
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            refs.extend(nested_source_refs(item))
    return refs


def parse_source_ref(ref: str) -> tuple[str, int | None]:
    raw = ref.split("#", 1)[0].strip()
    if raw.startswith("file://"):
        raw = raw[len("file://") :]
    line: int | None = None
    path_part = raw
    if ":" in raw:
        maybe_path, maybe_line = raw.rsplit(":", 1)
        clean_line = maybe_line.strip().lstrip("Ll")
        if clean_line.isdigit():
            path_part = maybe_path
            line = int(clean_line)
    return path_part.strip(), line


def source_ref_errors(workspace: Path, refs: list[str]) -> list[str]:
    errors: list[str] = []
    for ref in refs:
        path_part, line = parse_source_ref(ref)
        if not path_part or "://" in path_part:
            errors.append(f"{ref}:not_workspace_source_ref")
            continue
        path = Path(path_part).expanduser()
        if not path.is_absolute():
            path = workspace / path
        resolved = path.resolve()
        try:
            resolved.relative_to(workspace)
        except ValueError:
            errors.append(f"{ref}:outside_workspace")
            continue
        if not resolved.is_file():
            errors.append(f"{ref}:missing_file")
            continue
        if line is not None:
            try:
                line_count = len(resolved.read_text(encoding="utf-8", errors="replace").splitlines())
            except OSError as exc:
                errors.append(f"{ref}:unreadable:{exc}")
                continue
            if line < 1 or line > line_count:
                errors.append(f"{ref}:missing_line")
    return errors


def has_any_keyed_evidence(manual: dict[str, Any], keys: tuple[str, ...]) -> bool:
    return any(has_concrete_value(manual.get(key)) for key in keys)


def blocker_values(manual: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    for key in BLOCKER_KEYS:
        for item in values_from(manual.get(key)):
            if isinstance(item, dict):
                label = item.get("blocker") or item.get("blocker_id") or item.get("reason") or item.get("kind")
                if not is_placeholder(label):
                    blockers.append(str(label).strip())
            elif not is_placeholder(item):
                blockers.append(str(item).strip())
    return sorted(set(blockers))


def has_advisory_only_marker(manual: dict[str, Any]) -> bool:
    if is_trueish(manual.get("advisory_only")):
        return True
    for key in ("evidence_class", "evidence_source", "source_kind", "proof_claim"):
        raw = str(manual.get(key) or "").strip().lower()
        if "advisory" in raw or raw in {"none", "no_proof", "not_proof"}:
            return True
    for key in PROOF_EVIDENCE_KEYS:
        for item in values_from(manual.get(key)):
            if isinstance(item, dict) and is_trueish(item.get("advisory_only")):
                return True
            if isinstance(item, str) and "advisory only" in item.lower():
                return True
    return False


def manual_input_invalid_reasons(workspace: Path, manual: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    invalid: list[str] = []
    workspace_value = str(manual.get("workspace") or "").strip()
    if workspace_value and Path(workspace_value).expanduser().resolve() != workspace:
        invalid.append("stale_workspace_ref")

    refs = collect_source_refs(manual)
    if not refs:
        invalid.append("missing_source_refs")
        ref_errors: list[str] = []
    else:
        ref_errors = source_ref_errors(workspace, refs)
        if ref_errors:
            invalid.append("stale_workspace_ref")

    if not has_any_keyed_evidence(manual, TOPOLOGY_EVIDENCE_KEYS):
        invalid.append("missing_configured_topology_evidence")
    if not has_any_keyed_evidence(manual, PROOF_EVIDENCE_KEYS):
        invalid.append("missing_concrete_proof_evidence")
    if has_advisory_only_marker(manual):
        invalid.append("advisory_only_evidence")

    blockers = blocker_values(manual)
    if blockers:
        invalid.append("proof_blockers_present")

    return sorted(set(invalid)), ref_errors, blockers


def first_result(payload: dict[str, Any]) -> dict[str, Any]:
    results = payload.get("results")
    if isinstance(results, list):
        for item in results:
            if isinstance(item, dict):
                return item
    return payload


def read_manual_proof(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    if not path.is_file():
        return None, ["missing_manual_proof_file"]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, [f"invalid_manual_proof_json:{exc}"]
    if not isinstance(payload, dict):
        return None, ["invalid_manual_proof_json:not_object"]
    result = first_result(payload)
    manual = dict(result)
    if result is not payload:
        for key in ENVELOPE_EVIDENCE_KEYS:
            if key not in manual and key in payload:
                manual[key] = payload[key]
    return manual, []


def sample_manual_proof(row: dict[str, Any], pair: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "auditooor.manual_live_topology_proof.sample.v1",
        "id": row.get("row_id"),
        "row_id": row.get("row_id"),
        "proof_pair_id": pair.get("proof_pair_id"),
        "evidence_class": "topology-relation",
        "contract": row.get("contract"),
        "network": row.get("network"),
        "address": row.get("candidate_address") or row.get("required_address") or "<verified-address>",
        "status": "<pass|fail>",
        "block": "<shared-block-number>",
        "expected_value": row.get("expected_value") or "<expected-value>",
        "observed_value": "<observed-value-from-live-call>",
        "capture_command": row.get("capture_command_after_candidate_verification")
        or row.get("capture_command_template"),
        "operator_notes": [
            "Replace placeholders with real RPC-backed values.",
            "Both rows in one proof_pair_id must use the same block.",
            "This sample is not proof until captured and imported.",
        ],
        **ADVISORY_POSTURE,
    }


def validate_manual_row(row: dict[str, Any], pair: dict[str, Any], manual_dir: Path, workspace: Path) -> dict[str, Any]:
    row_id = str(row.get("row_id") or "").strip()
    proof_path = manual_dir / f"{row_id}.json"
    manual, problems = read_manual_proof(proof_path)
    if manual is None:
        return {
            "row_id": row_id,
            "proof_path": str(proof_path),
            "validation_state": "missing_manual_proof_file",
            "problems": problems,
            "manual_block": None,
            "ready_for_import": False,
        }

    expected_pair = str(pair.get("proof_pair_id") or "").strip()
    expected_contract = str(row.get("contract") or "").strip()
    status = str(manual.get("status") or "").strip()
    block = str(manual.get("block") or "").strip()
    evidence_class = str(manual.get("evidence_class") or "").strip()
    pair_id = str(manual.get("proof_pair_id") or "").strip()
    contract = str(manual.get("contract") or "").strip()
    manual_row_id = str(manual.get("id") or manual.get("row_id") or "").strip()

    if manual_row_id and manual_row_id != row_id:
        problems.append("manual_proof_row_id_mismatch")
    if pair_id != expected_pair:
        problems.append("manual_proof_pair_mismatch")
    if evidence_class != "topology-relation":
        problems.append("manual_proof_wrong_evidence_class")
    if status not in {"pass", "fail"}:
        problems.append("manual_proof_not_executed")
    if not block:
        problems.append("manual_proof_missing_block")
    if expected_contract and contract and contract != expected_contract:
        problems.append("manual_proof_contract_mismatch")

    invalid_reasons, ref_errors, blockers = manual_input_invalid_reasons(workspace, manual)
    problems.extend(invalid_reasons)

    return {
        "row_id": row_id,
        "proof_path": str(proof_path),
        "validation_state": "manual_proof_ready_for_import" if not problems else "manual_proof_schema_invalid",
        "problems": sorted(set(problems)),
        "invalid_reasons": invalid_reasons,
        "source_refs": collect_source_refs(manual),
        "source_ref_errors": ref_errors,
        "configured_topology_evidence_present": has_any_keyed_evidence(manual, TOPOLOGY_EVIDENCE_KEYS),
        "concrete_proof_evidence_present": has_any_keyed_evidence(manual, PROOF_EVIDENCE_KEYS),
        "proof_blockers": blockers,
        "manual_block": block or None,
        "manual_status": status or None,
        "ready_for_import": not problems,
    }


def import_command(workspace: Path, row_ids: list[str]) -> str:
    row_args = " ".join(f"--manual-proof-id {row_id}" for row_id in row_ids)
    return (
        f"python3 tools/live-check-runner.py {workspace} --import-manual-proofs {row_args} "
        f"--out-json {workspace / 'live_topology_checks.json'} --out-md {workspace / 'LIVE_TOPOLOGY.md'}"
    )


def build_payload(workspace: Path, bridge: dict[str, Any], manual_dir: Path) -> dict[str, Any]:
    pair_results: list[dict[str, Any]] = []
    row_state_counts: Counter[str] = Counter()
    pair_state_counts: Counter[str] = Counter()
    network_commands: dict[str, list[dict[str, Any]]] = defaultdict(list)
    sample_rows: list[dict[str, Any]] = []

    for pair in bridge.get("proof_pairs") or []:
        if not isinstance(pair, dict):
            continue
        rows = [row for row in pair.get("rows") or [] if isinstance(row, dict)]
        validations = [validate_manual_row(row, pair, manual_dir, workspace) for row in rows]
        row_state_counts.update(item["validation_state"] for item in validations)
        blocks = {str(item.get("manual_block") or "") for item in validations if item.get("manual_block")}
        ready_rows = [item["row_id"] for item in validations if item.get("ready_for_import")]
        row_ids = [str(row.get("row_id") or "") for row in rows if row.get("row_id")]

        if len(ready_rows) == len(row_ids) and len(blocks) == 1 and row_ids:
            pair_state = "manual_proofs_same_block_import_ready"
        elif ready_rows:
            pair_state = "partial_manual_proofs_valid"
        elif any(item["validation_state"] == "manual_proof_schema_invalid" for item in validations):
            pair_state = "manual_proofs_present_but_invalid"
        else:
            pair_state = "manual_proof_files_missing"
        pair_state_counts[pair_state] += 1

        for row in rows:
            network = str(row.get("network") or "mainnet")
            network_commands[network].append(
                {
                    "proof_pair_id": pair.get("proof_pair_id"),
                    "row_id": row.get("row_id"),
                    "rpc_env_var": row.get("rpc_env_var") or "MAINNET_RPC_URL",
                    "capture_command": row.get("capture_command_after_candidate_verification")
                    or row.get("capture_command_template"),
                    "sample_manual_proof_file": f"manual_proof_samples/{safe_name(str(row.get('row_id') or 'unknown'))}.json",
                }
            )
            sample_rows.append({"pair": pair, "row": row, "sample": sample_manual_proof(row, pair)})

        pair_results.append(
            {
                "proof_pair_id": pair.get("proof_pair_id"),
                "row_ids": row_ids,
                "input_acquisition_class": pair.get("input_acquisition_class"),
                "validation_state": pair_state,
                "manual_blocks_seen": sorted(blocks),
                "ready_row_ids": ready_rows,
                "row_validations": validations,
                "import_command_if_ready": import_command(workspace, row_ids),
                "executor_command_after_import": pair.get("executor_command_after_import"),
                "proof_claim": "none",
                **ADVISORY_POSTURE,
            }
        )

    command_manifests = []
    for network, commands in sorted(network_commands.items()):
        command_manifests.append(
            {
                "network": network,
                "row_count": len(commands),
                "pair_count": len({str(item.get("proof_pair_id") or "") for item in commands}),
                "rpc_env_vars": sorted({str(item.get("rpc_env_var") or "MAINNET_RPC_URL") for item in commands}),
                "capture_commands": commands,
            }
        )

    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "generated_at": now_iso(),
        "source_bridge_schema": bridge.get("schema"),
        "manual_proofs_dir": str(manual_dir),
        "summary": {
            "proof_pairs_total": len(pair_results),
            "rows_total": sum(len(pair.get("row_ids") or []) for pair in pair_results),
            "proof_pairs_closed": 0,
            "proof_pairs_promoted": 0,
            "pair_validation_state_counts": dict(sorted(pair_state_counts.items())),
            "row_validation_state_counts": dict(sorted(row_state_counts.items())),
            "sample_manual_proof_rows": len(sample_rows),
            "network_command_manifests": len(command_manifests),
            "import_ready_pairs": pair_state_counts.get("manual_proofs_same_block_import_ready", 0),
        },
        "pair_validations": pair_results,
        "network_command_manifests": command_manifests,
        "_sample_rows_for_writer": sample_rows,
        "why_no_more_local_closure_safe": (
            "Input validation can only preflight local manual proof files. No same-block proof pair is closed "
            "until capture files exist, import succeeds, and live-topology-proof-executor validates the imported rows."
        ),
        **ADVISORY_POSTURE,
    }


def write_bundles(bundle_dir: Path, payload: dict[str, Any]) -> dict[str, list[str]]:
    samples_dir = bundle_dir / "manual_proof_samples"
    commands_dir = bundle_dir / "network_command_manifests"
    pairs_dir = bundle_dir / "pair_validations"
    samples_dir.mkdir(parents=True, exist_ok=True)
    commands_dir.mkdir(parents=True, exist_ok=True)
    pairs_dir.mkdir(parents=True, exist_ok=True)

    sample_files: list[str] = []
    for item in payload.pop("_sample_rows_for_writer", []):
        row = item["row"]
        path = samples_dir / f"{safe_name(str(row.get('row_id') or 'unknown'))}.json"
        write_json(path, item["sample"])
        sample_files.append(str(path))

    command_files: list[str] = []
    for manifest in payload.get("network_command_manifests") or []:
        path = commands_dir / f"{safe_name(str(manifest.get('network') or 'unknown'))}.json"
        write_json(path, manifest)
        command_files.append(str(path))

    pair_files: list[str] = []
    for pair in payload.get("pair_validations") or []:
        path = pairs_dir / f"{safe_name(str(pair.get('proof_pair_id') or 'unknown'))}.json"
        write_json(path, pair)
        pair_files.append(str(path))

    return {
        "sample_manual_proof_files": sample_files,
        "network_command_manifest_files": command_files,
        "pair_validation_files": pair_files,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Live Topology Proof Input Validator",
        "",
        "Validates local manual-proof inputs and writes sample capture/import files.",
        "This is not proof and does not promote any pair.",
        "",
        f"- proof pairs processed: `{summary['proof_pairs_total']}`",
        f"- rows processed: `{summary['rows_total']}`",
        f"- import-ready pairs: `{summary['import_ready_pairs']}`",
        f"- proof pairs closed: `{summary['proof_pairs_closed']}`",
        f"- submission posture: `{payload['submission_posture']}`",
        "",
        "## Pair Validation States",
        "",
    ]
    for name, count in summary["pair_validation_state_counts"].items():
        lines.append(f"- `{name}`: {count}")
    lines.extend(["", "## Row Validation States", ""])
    for name, count in summary["row_validation_state_counts"].items():
        lines.append(f"- `{name}`: {count}")
    lines.extend(["", "## Command Manifests", ""])
    for manifest in payload.get("network_command_manifests", []):
        lines.append(
            f"- `{manifest.get('network')}`: {manifest.get('row_count')} rows, "
            f"{manifest.get('pair_count')} pairs, env={','.join(manifest.get('rpc_env_vars') or [])}"
        )
    lines.extend(["", "## First 25 Pair Validations", "", "| Pair | State | Ready Rows |", "|---|---|---|"])
    for pair in payload.get("pair_validations", [])[:25]:
        lines.append(
            f"| `{pair.get('proof_pair_id')}` | `{pair.get('validation_state')}` | "
            f"`{', '.join(pair.get('ready_row_ids') or [])}` |"
        )
    lines.extend(["", "## Why No Further Local Closure", "", payload["why_no_more_local_closure_safe"], ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--bridge", type=Path)
    parser.add_argument("--manual-proofs", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--no-write-bundles", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[live-topology-proof-input-validator] workspace not found: {workspace}")
        return 2
    bridge_path = resolve_path(workspace, args.bridge, DEFAULT_BRIDGE)
    manual_dir = resolve_path(workspace, args.manual_proofs, DEFAULT_MANUAL_PROOFS)
    out_json = resolve_path(workspace, args.out_json, DEFAULT_OUT_JSON)
    out_md = resolve_path(workspace, args.out_md, DEFAULT_OUT_MD)
    bundle_dir = resolve_path(workspace, args.bundle_dir, DEFAULT_BUNDLE_DIR)

    payload = build_payload(workspace, load_json(bridge_path, "proof input bridge"), manual_dir)
    if not args.no_write_bundles:
        payload["bundle_dir"] = str(bundle_dir)
        payload["bundle_files"] = write_bundles(bundle_dir, payload)
    else:
        payload.pop("_sample_rows_for_writer", None)
    write_json(out_json, payload)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[live-topology-proof-input-validator] OK "
        f"pairs={payload['summary']['proof_pairs_total']} "
        f"import_ready={payload['summary']['import_ready_pairs']} json={out_json}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
