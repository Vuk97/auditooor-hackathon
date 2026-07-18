#!/usr/bin/env python3
"""
live-check-runner.py — run declarative live-topology checks for a workspace.

This turns one-off deploy-state-lookup / live-state-checker invocations into a
durable dossier:
  - <workspace>/live_topology_checks.json
  - <workspace>/LIVE_TOPOLOGY.md

Checks come from either:
  - <workspace>/monitoring/live_checks.generated.json
  - <workspace>/monitoring/live_checks.json
  - <repo>/projects/<workspace-name>/live_checks.json

The runner prefers private/workspace RPC URLs. Unless --allow-public-rpc is
set, missing/private-RPC gaps degrade to dry-run evidence instead of attempting
flaky public RPC execution.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib import error as urllib_error
from urllib import request as urllib_request

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
LIVE_STATE_CHECKER = HERE / "live-state-checker.py"


def parse_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    try:
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("'").strip('"')
            if key:
                values[key] = value
    except OSError:
        pass
    return values


def load_workspace_env(workspace: Path) -> Dict[str, str]:
    env: Dict[str, str] = {}
    candidates = [
        workspace / ".env",
        workspace / ".env.local",
        workspace / "env" / ".env",
        workspace / "env" / ".env.local",
    ]
    env_dir = workspace / "env"
    if env_dir.is_dir():
        candidates.extend(sorted(env_dir.glob("*.env")))
    for candidate in candidates:
        if candidate.is_file():
            env.update(parse_env_file(candidate))
    return env


def get_rpc_url(network: str, *, explicit: str = "", env: Dict[str, str] | None = None) -> Tuple[str, str]:
    if explicit:
        return explicit, "spec"

    merged_env = dict(os.environ)
    if env:
        merged_env.update(env)

    env_map = {
        "mainnet": "MAINNET_RPC_URL",
        "polygon": "POLYGON_RPC_URL",
        "arbitrum": "ARBITRUM_RPC_URL",
        "optimism": "OPTIMISM_RPC_URL",
        "base": "BASE_RPC_URL",
    }
    env_key = env_map.get(network.lower(), f"{network.upper()}_RPC_URL")
    url = merged_env.get(env_key)
    if url:
        source = "workspace-env" if env and env_key in env else "env"
        return url, f"{source}:{env_key}"

    public = {
        "mainnet": "https://rpc.ankr.com/eth",
        "polygon": "https://polygon.drpc.org",
        "arbitrum": "https://rpc.ankr.com/arbitrum",
        "optimism": "https://rpc.ankr.com/optimism",
        "base": "https://rpc.ankr.com/base",
    }
    fallback = public.get(network.lower(), "")
    return (fallback, "public-fallback") if fallback else ("", "")


def resolve_spec_path(workspace: Path, explicit: str | None) -> Path | None:
    if explicit:
        path = Path(explicit).expanduser().resolve()
        return path if path.exists() else None
    candidates = [
        workspace / "monitoring" / "live_checks.generated.json",
        workspace / "monitoring" / "live_checks.json",
        REPO / "projects" / workspace.name / "live_checks.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def is_address_like(value: Any) -> bool:
    raw = str(value or "").strip()
    return raw.startswith("0x") and len(raw) == 42


def load_spec(path: Path) -> Dict[str, Any]:
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError("live check spec must be a JSON object")
    checks = payload.get("checks")
    if not isinstance(checks, list):
        raise ValueError("live check spec must contain a 'checks' array")
    return payload


def build_expression_from_manual_row(row: Dict[str, Any]) -> str:
    check = row.get("live_result")
    if isinstance(check, dict):
        if check.get("sig"):
            args = normalize_args(check.get("args"))
            return f"{check['sig']}({', '.join(args)})" if args else str(check["sig"])
        if check.get("slot"):
            return f"slot {check['slot']}"
        if check.get("min") is not None:
            return f"balance >= {check['min']}"
        if check.get("command_preview"):
            return str(check["command_preview"])
    return "manual-proof"


def normalize_manual_status(row: Dict[str, Any], *, dry_run: bool) -> str:
    status = str(row.get("status") or "").strip()
    if status:
        return status
    if dry_run:
        return "dry_run"
    execution_mode = str(row.get("execution_mode") or "").strip()
    if execution_mode == "dry_run":
        return "dry_run"
    if row.get("error"):
        return "error"
    if row.get("match") is True:
        return "pass"
    if row.get("match") is False:
        return "fail"
    return "error"


def result_signature(row: Dict[str, Any]) -> Tuple[Any, ...]:
    check = row.get("check") if isinstance(row.get("check"), dict) else {}
    return (
        row.get("network"),
        row.get("address"),
        check.get("call"),
        tuple(normalize_args(check.get("args"))),
        check.get("slot"),
        check.get("balance_min"),
        row.get("expected"),
    )


def is_executed_status(status: str) -> bool:
    return status in {"pass", "fail"}


def enrich_imported_result(existing: Dict[str, Any], imported: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(imported)
    if not merged.get("title") or merged.get("title") == merged.get("id"):
        merged["title"] = existing.get("title") or merged.get("title")
    imported_contract = str(merged.get("contract") or "")
    if not imported_contract or imported_contract == merged.get("id") or is_address_like(imported_contract):
        merged["contract"] = existing.get("contract") or imported_contract or "UNKNOWN"
    for field in ("rationale", "implication_if_match"):
        if not merged.get(field) and existing.get(field):
            merged[field] = existing.get(field)
    imported_evidence_class = str(merged.get("evidence_class") or "").strip()
    if (not imported_evidence_class or imported_evidence_class == "manual-proof") and existing.get("evidence_class"):
        merged["evidence_class"] = existing.get("evidence_class")
    if (not merged.get("related_angle_ids")) and existing.get("related_angle_ids"):
        merged["related_angle_ids"] = existing.get("related_angle_ids")
    for field in (
        "pair_id",
        "proof_pair_id",
        "angle_id",
        "pair_complete",
        "same_block",
        "pair_blocks",
        "edge_row_id",
        "authority_row_id",
    ):
        if not merged.get(field) and existing.get(field):
            merged[field] = existing.get(field)
    return merged


def pair_id_slug(raw: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")
    return value or "topology"


def build_pair_record(
    *,
    pair_id: str,
    rows: List[Dict[str, Any]],
    angle_ids: List[str],
    provenance_kind: str,
) -> Dict[str, Any]:
    blocks = sorted(
        {
            str(row.get("block") or "").strip()
            for row in rows
            if str(row.get("block") or "").strip()
        }
    )
    statuses = {
        str(row.get("id") or "").strip(): str(row.get("status") or "").strip()
        for row in rows
        if str(row.get("id") or "").strip()
    }
    executed = [row for row in rows if is_executed_status(str(row.get("status") or ""))]
    passed = [row for row in rows if str(row.get("status") or "").strip() == "pass"]
    failed = [row for row in rows if str(row.get("status") or "").strip() == "fail"]
    if len(rows) < 2:
        status = "missing"
    elif len(executed) < 2:
        status = "partial"
    elif failed:
        status = "failed"
    elif len(blocks) != 1:
        status = "conflicting"
    else:
        status = "proved"
    angle_label = ", ".join(angle_ids) if angle_ids else None
    return {
        "id": pair_id,
        "angle_id": angle_label,
        "kind": "topology-same-block",
        "required_for_angle_ids": angle_ids,
        "row_ids": [
            str(row.get("id") or "").strip()
            for row in rows
            if str(row.get("id") or "").strip()
        ],
        "status": status,
        "same_block_required": True,
        "shared_block": blocks[0] if len(blocks) == 1 else None,
        "pair_blocks": blocks,
        "row_statuses": statuses,
        "executed_row_ids": [
            str(row.get("id") or "").strip()
            for row in executed
            if str(row.get("id") or "").strip()
        ],
        "passed_row_ids": [
            str(row.get("id") or "").strip()
            for row in passed
            if str(row.get("id") or "").strip()
        ],
        "failed_row_ids": [
            str(row.get("id") or "").strip()
            for row in failed
            if str(row.get("id") or "").strip()
        ],
        "unexecuted_row_ids": [
            str(row.get("id") or "").strip()
            for row in rows
            if str(row.get("id") or "").strip()
            and not is_executed_status(str(row.get("status") or ""))
        ],
        "pair_complete": len(rows) >= 2,
        "same_block": len(blocks) == 1 if blocks else False,
        "block_mismatch": len(blocks) > 1,
        "missing_rows": [] if len(rows) >= 2 else ["authority-or-counterparty"],
        "notes": "Cross-contract topology claims should preserve both the live edge and its controlling authority/wiring proof.",
        "provenance": {"kind": provenance_kind},
    }


def build_proof_pairs(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    pair_angles = {"A-RACE", "A-AUTH", "A-ORACLE"}
    topology_rows = [
        row for row in results
        if isinstance(row, dict) and str(row.get("evidence_class") or "").strip() == "topology-relation"
    ]
    explicit_groups: Dict[str, List[Dict[str, Any]]] = {}
    for row in topology_rows:
        pair_key = str(row.get("proof_pair_id") or row.get("pair_id") or "").strip()
        if pair_key:
            explicit_groups.setdefault(pair_key, []).append(row)
    available_angles = sorted(
        {
            str(angle_id).strip()
            for row in topology_rows
            for angle_id in row.get("related_angle_ids", [])
            if str(angle_id).strip() in pair_angles
        }
    )
    pairs: List[Dict[str, Any]] = []
    explicit_row_ids: set[str] = set()
    covered_angles: set[str] = set()
    for pair_key in sorted(explicit_groups):
        rows = explicit_groups[pair_key]
        angle_ids = sorted(
            {
                str(angle_id).strip()
                for row in rows
                for angle_id in row.get("related_angle_ids", [])
                if str(angle_id).strip() in pair_angles
            }
        )
        pairs.append(
            build_pair_record(
                pair_id=pair_key,
                rows=rows,
                angle_ids=angle_ids,
                provenance_kind="explicit-row-pair",
            )
        )
        explicit_row_ids.update(
            str(row.get("id") or "").strip()
            for row in rows
            if str(row.get("id") or "").strip()
        )
        covered_angles.update(angle_ids)
    for angle_id in available_angles:
        if angle_id in covered_angles:
            continue
        matching = [
            row for row in topology_rows
            if str(row.get("id") or "").strip() not in explicit_row_ids
            if angle_id in {
                str(item).strip()
                for item in row.get("related_angle_ids", [])
                if str(item).strip()
            }
        ]
        distinct_contracts: List[str] = []
        pair_rows: List[Dict[str, Any]] = []
        for row in matching:
            contract = str(row.get("contract") or "").strip()
            if contract and contract not in distinct_contracts:
                distinct_contracts.append(contract)
                pair_rows.append(row)
            if len(pair_rows) >= 2:
                break
        pairs.append(
            build_pair_record(
                pair_id=f"{pair_id_slug(angle_id)}-topology-pair",
                rows=pair_rows,
                angle_ids=[angle_id],
                provenance_kind="runner-derived",
            )
        )
    return pairs


def summarize_proof_pairs(pairs: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = {
        "declared": len(pairs),
        "proved": 0,
        "partial": 0,
        "missing": 0,
        "conflicting": 0,
        "failed": 0,
    }
    for pair in pairs:
        status = str(pair.get("status") or "").strip()
        if status in summary:
            summary[status] += 1
    return summary


def canonical_check_value(value: Any) -> str:
    if isinstance(value, list):
        return json.dumps([str(item) for item in value], separators=(",", ":"))
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value or "").strip()


def find_executed_live_proof_contradictions(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    buckets: Dict[Tuple[str, str, str, str, str, str, str], List[Dict[str, Any]]] = {}
    for row in results:
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "").strip()
        if status not in {"pass", "fail"}:
            continue
        check = row.get("check") if isinstance(row.get("check"), dict) else {}
        block = str(row.get("block") or check.get("block") or "").strip()
        if not block:
            continue
        claim_key = (
            block,
            str(row.get("evidence_class") or "").strip(),
            str(row.get("contract") or "").strip(),
            str(row.get("address") or "").strip().lower(),
            str(row.get("network") or "").strip(),
            str(check.get("call") or check.get("slot") or "balance_min").strip(),
            "|".join(
                [
                    canonical_check_value(check.get("args")),
                    canonical_check_value(check.get("expect")),
                    canonical_check_value(check.get("slot")),
                    canonical_check_value(check.get("balance_min")),
                ]
            ),
        )
        buckets.setdefault(claim_key, []).append(row)

    contradictions: List[Dict[str, Any]] = []
    for bucket_key, rows in buckets.items():
        statuses = {str(row.get("status") or "").strip() for row in rows}
        if not {"pass", "fail"}.issubset(statuses):
            continue
        block, evidence_class, contract, address, network, check_kind, check_signature = bucket_key
        pass_rows = [
            {
                "id": str(row.get("id") or "").strip(),
                "status": "pass",
                "manual_proof_source": str(row.get("manual_proof_source") or "").strip(),
            }
            for row in rows
            if str(row.get("status") or "").strip() == "pass"
        ]
        fail_rows = [
            {
                "id": str(row.get("id") or "").strip(),
                "status": "fail",
                "manual_proof_source": str(row.get("manual_proof_source") or "").strip(),
            }
            for row in rows
            if str(row.get("status") or "").strip() == "fail"
        ]
        contradictions.append(
            {
                "claim_key": {
                    "evidence_class": evidence_class,
                    "contract": contract,
                    "address": address,
                    "network": network,
                    "check_kind": check_kind,
                    "check_signature": check_signature,
                },
                "block": block,
                "pass_rows": pass_rows,
                "fail_rows": fail_rows,
                "row_ids": [item["id"] for item in [*pass_rows, *fail_rows] if item.get("id")],
                "provenance": {"kind": "runner-derived"},
            }
        )
    contradictions.sort(
        key=lambda item: (
            str(item.get("claim_key", {}).get("contract") or ""),
            str(item.get("claim_key", {}).get("check_kind") or ""),
            str(item.get("block") or ""),
        )
    )
    return contradictions


def load_manual_proof_rows(
    workspace: Path,
    selected_ids: set[str] | None = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    proof_dir = workspace / "manual_proofs"
    metadata: Dict[str, Any] = {
        "enabled": proof_dir.is_dir(),
        "path": str(proof_dir),
        "files_scanned": 0,
        "imported_rows": 0,
        "skipped_unselected": 0,
        "requested_ids": sorted(selected_ids) if selected_ids else [],
        "errors": [],
    }
    if not proof_dir.is_dir():
        return [], metadata

    imported: List[Dict[str, Any]] = []
    for proof_path in sorted(proof_dir.glob("*.json")):
        metadata["files_scanned"] += 1
        try:
            payload = json.loads(proof_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            metadata["errors"].append({"path": str(proof_path), "error": str(exc)})
            continue
        if not isinstance(payload, dict):
            metadata["errors"].append({"path": str(proof_path), "error": "manual proof is not a JSON object"})
            continue
        rows = payload.get("results")
        if not isinstance(rows, list):
            metadata["errors"].append({"path": str(proof_path), "error": "manual proof missing results[]"})
            continue
        advisory_only = bool(payload.get("advisory_only"))
        for raw_row in rows:
            if not isinstance(raw_row, dict):
                continue
            row_id = str(raw_row.get("id") or proof_path.stem).strip() or proof_path.stem
            if selected_ids and row_id not in selected_ids:
                metadata["skipped_unselected"] += 1
                continue
            status = normalize_manual_status(raw_row, dry_run=bool(payload.get("summary", {}).get("dry_run")))
            live_result = raw_row.get("live_result") if isinstance(raw_row.get("live_result"), dict) else {}
            contract = raw_row.get("contract")
            if is_address_like(contract):
                contract = raw_row.get("title") or raw_row.get("id") or contract
            imported.append({
                "id": row_id,
                "title": str(raw_row.get("title") or row_id),
                "contract": str(contract or raw_row.get("address") or "UNKNOWN"),
                "network": raw_row.get("network"),
                "block": raw_row.get("block"),
                "block_source": "manual-proof-import",
                "address": raw_row.get("address"),
                "address_source": "manual-proof-import",
                "rpc_source": raw_row.get("rpc_source"),
                "execution_mode": raw_row.get("execution_mode"),
                "status": status,
                "actual": raw_row.get("actual"),
                "expected": raw_row.get("expected"),
                "comparator": raw_row.get("comparator"),
                "normalization": live_result.get("normalization"),
                "actual_normalized": live_result.get("actual_normalized"),
                "expected_normalized": live_result.get("expected_normalized"),
                "checker_error": live_result.get("error"),
                "check": {
                    "call": live_result.get("sig"),
                    "args": normalize_args(live_result.get("args")),
                    "expect": raw_row.get("expected"),
                    "expect_source": "manual-proof-import",
                    "slot": live_result.get("slot"),
                    "balance_min": live_result.get("min"),
                    "block": raw_row.get("block"),
                    "block_source": "manual-proof-import",
                    "expression": build_expression_from_manual_row(raw_row),
                },
                "rationale": raw_row.get("rationale"),
                "evidence_class": raw_row.get("evidence_class") or "manual-proof",
                "related_angle_ids": list(
                    dict.fromkeys(
                        str(angle_id).strip()
                        for angle_id in raw_row.get("related_angle_ids", [])
                        if str(angle_id).strip()
                    )
                ),
                "implication_if_match": raw_row.get("implication_if_match"),
                "spec_source": "manual-proof-import",
                "generated": False,
                "replay_command": raw_row.get("replay_command"),
                "manual_proof_source": str(proof_path),
                "manual_proof_advisory_only": advisory_only,
                "manual_proof_status": str(raw_row.get("status") or status),
                "manual_proof_workspace": str(payload.get("workspace") or workspace),
                "manual_proof_generated_at": payload.get("generated_at"),
                "manual_proof_canonical_dossier": payload.get("canonical_dossier"),
                "manual_proof_summary": payload.get("summary"),
                "canonical_dossier": payload.get("canonical_dossier"),
                "proof_pair_id": raw_row.get("proof_pair_id"),
                "pair_id": raw_row.get("pair_id"),
                "angle_id": raw_row.get("angle_id"),
                "pair_complete": raw_row.get("pair_complete"),
                "same_block": raw_row.get("same_block"),
                "pair_blocks": raw_row.get("pair_blocks"),
                "edge_row_id": raw_row.get("edge_row_id"),
                "authority_row_id": raw_row.get("authority_row_id"),
                "provenance": {
                    "kind": "manual-proof-import",
                    "source_path": str(proof_path),
                    "imported_at": datetime.now(timezone.utc).isoformat(),
                },
                "live_result": live_result,
            })
            metadata["imported_rows"] += 1
    return imported, metadata


def merge_manual_results(
    base_results: List[Dict[str, Any]],
    manual_results: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    merged: List[Dict[str, Any]] = []
    by_id: Dict[str, int] = {}
    stats = {"added": 0, "replaced": 0, "kept_existing": 0, "skipped_conflicts": 0}
    for result in base_results:
        result_id = str(result.get("id") or "")
        by_id[result_id] = len(merged)
        merged.append(result)
    for result in manual_results:
        result_id = str(result.get("id") or "")
        if result_id in by_id:
            existing = merged[by_id[result_id]]
            if result_signature(existing) != result_signature(result):
                stats["skipped_conflicts"] += 1
                continue
            existing_status = str(existing.get("status") or "")
            imported_status = str(result.get("status") or "")
            if is_executed_status(existing_status) and is_executed_status(imported_status):
                if any(existing.get(field) != result.get(field) for field in ("status", "block", "actual", "expected")):
                    stats["skipped_conflicts"] += 1
                    continue
                stats["kept_existing"] += 1
                continue
            if is_executed_status(existing_status) and not is_executed_status(imported_status):
                stats["kept_existing"] += 1
                continue
            if not is_executed_status(existing_status) and is_executed_status(imported_status):
                merged[by_id[result_id]] = enrich_imported_result(existing, result)
                stats["replaced"] += 1
                continue
            if existing_status in {"blocked_missing_rpc", "blocked_unresolved_address", "error"} and imported_status == "dry_run":
                merged[by_id[result_id]] = enrich_imported_result(existing, result)
                stats["replaced"] += 1
                continue
            if existing_status == "dry_run" and imported_status == "dry_run":
                merged[by_id[result_id]] = enrich_imported_result(existing, result)
                stats["replaced"] += 1
                continue
            stats["kept_existing"] += 1
        else:
            by_id[result_id] = len(merged)
            merged.append(result)
            stats["added"] += 1
    return merged, stats


def load_topology(workspace: Path) -> Dict[str, Dict[str, Any]]:
    path = workspace / "deployment_topology.json"
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    entries = payload.get("entries", [])
    topology: Dict[str, Dict[str, Any]] = {}
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                contract = entry.get("contract")
                if isinstance(contract, str) and contract:
                    topology[contract] = entry
    return topology


def normalize_args(raw: Any) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [item.strip() for item in raw.split(",") if item.strip()]
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    return [str(raw).strip()]


def resolve_topology_ref(topology: Dict[str, Dict[str, Any]], contract: str) -> Tuple[str, List[str], str]:
    entry = topology.get(contract, {})
    resolved = str(entry.get("resolved_address") or "").strip()
    candidates = entry.get("candidate_addresses", [])
    if not isinstance(candidates, list):
        candidates = []
    status = str(entry.get("status") or "")
    return resolved, [str(candidate).strip() for candidate in candidates if str(candidate).strip()], status


def render_check_expression(check: Dict[str, Any]) -> str:
    if check.get("call"):
        args = ", ".join(normalize_args(check.get("args")))
        return f"{check['call']}({args})" if args else str(check["call"])
    if check.get("slot"):
        return f"slot {check['slot']}"
    if check.get("balance_min") is not None:
        return f"balance >= {check['balance_min']}"
    return "unknown-check"


def rpc_env_var(network: str) -> str:
    env_map = {
        "mainnet": "MAINNET_RPC_URL",
        "polygon": "POLYGON_RPC_URL",
        "arbitrum": "ARBITRUM_RPC_URL",
        "optimism": "OPTIMISM_RPC_URL",
        "base": "BASE_RPC_URL",
    }
    return env_map.get(network.lower(), f"{network.upper()}_RPC_URL")


def planned_comparator(check: Dict[str, Any]) -> str | None:
    if check.get("balance_min") is not None:
        return "gte"
    if check.get("slot"):
        return "contains"
    if check.get("call"):
        return "exact"
    return None


def planned_normalization(comparator: str | None) -> List[str]:
    if comparator == "gte":
        return ["strip", "int"]
    if comparator:
        return ["strip", "lower"]
    return []


def dry_run_reason_message(reason: str, network: str) -> Tuple[str, str | None]:
    if reason == "flag":
        return ("dry-run requested (--dry-run)", None)
    if reason == "missing-rpc":
        return (f"missing private RPC for {network}", rpc_env_var(network))
    if reason == "public-rpc-disabled":
        return (f"public fallback RPC disabled for {network}", rpc_env_var(network))
    return (reason, None)


def resolve_latest_block(rpc_url: str) -> str:
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_blockNumber",
            "params": [],
        }
    ).encode()
    req = urllib_request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib_request.urlopen(req, timeout=20) as resp:
        body = json.loads(resp.read().decode())
    result = str(body.get("result") or "").strip()
    if not result:
        raise ValueError("missing result from eth_blockNumber")
    if result.startswith("0x"):
        return str(int(result, 16))
    return result


def resolve_run_pin_blocks(
    checks: List[Dict[str, Any]],
    workspace_env: Dict[str, str],
    *,
    pin_block: str,
    allow_public_rpc: bool,
) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {
        "requested": pin_block,
        "resolved_by_network": {},
        "unresolved_by_network": {},
    }
    if not pin_block:
        return metadata

    networks = sorted(
        {
            str(check.get("network") or "mainnet").strip() or "mainnet"
            for check in checks
            if isinstance(check, dict)
            and check.get("enabled", True)
            and not str(check.get("block") or "").strip()
        }
    )
    if not networks:
        return metadata

    if pin_block != "latest":
        for network in networks:
            metadata["resolved_by_network"][network] = pin_block
        return metadata

    for network in networks:
        rpc_url_explicit = ""
        for check in checks:
            if not isinstance(check, dict) or not check.get("enabled", True):
                continue
            check_network = str(check.get("network") or "mainnet").strip() or "mainnet"
            if check_network != network:
                continue
            rpc_url_explicit = str(check.get("rpc_url") or "").strip()
            if rpc_url_explicit:
                break
        rpc_url, rpc_source = get_rpc_url(network, explicit=rpc_url_explicit, env=workspace_env)
        if not rpc_url:
            metadata["unresolved_by_network"][network] = {
                "reason": "missing-rpc",
                "rpc_source": rpc_source or None,
            }
            continue
        if rpc_source == "public-fallback" and not allow_public_rpc:
            metadata["unresolved_by_network"][network] = {
                "reason": "public-rpc-disabled",
                "rpc_source": rpc_source,
            }
            continue
        try:
            metadata["resolved_by_network"][network] = resolve_latest_block(rpc_url)
        except (OSError, ValueError, json.JSONDecodeError, urllib_error.URLError) as exc:
            metadata["unresolved_by_network"][network] = {
                "reason": f"resolve-latest-failed: {exc}",
                "rpc_source": rpc_source or None,
            }
    return metadata


def run_single_check(
    workspace: Path,
    check: Dict[str, Any],
    topology: Dict[str, Dict[str, Any]],
    workspace_env: Dict[str, str],
    *,
    force_dry_run: bool,
    allow_public_rpc: bool,
    default_block: str = "",
) -> Dict[str, Any]:
    contract = str(check.get("contract") or "UNKNOWN")
    topology_entry = topology.get(contract, {})
    explicit_address = str(check.get("address") or "").strip()
    address_ref = str(check.get("address_ref") or "").strip()
    if explicit_address:
        resolved_address = explicit_address
    elif address_ref:
        resolved_address, _address_candidates, _address_status = resolve_topology_ref(topology, address_ref)
    else:
        resolved_address = str(topology_entry.get("resolved_address") or "").strip()
    network = str(check.get("network") or "mainnet")
    explicit_block = str(check.get("block") or "").strip()
    block = explicit_block or default_block
    block_source = "spec" if explicit_block else ("run-pin" if default_block else None)
    rpc_url_explicit = str(check.get("rpc_url") or "").strip()
    rpc_url, rpc_source = get_rpc_url(network, explicit=rpc_url_explicit, env=workspace_env)
    explicit_expect = check.get("expect")
    expect_ref = str(check.get("expect_ref") or "").strip()
    resolved_expect = explicit_expect
    expect_source = "spec"
    if resolved_expect is None and expect_ref:
        resolved_expect, _expect_candidates, _expect_status = resolve_topology_ref(topology, expect_ref)
        if resolved_expect:
            expect_source = "topology-ref"
        else:
            resolved_expect = None

    result: Dict[str, Any] = {
        "id": str(check.get("id") or contract.lower()),
        "title": str(check.get("title") or contract),
        "contract": contract,
        "network": network,
        "block": block or None,
        "block_source": block_source,
        "address": resolved_address or None,
        "address_source": "spec" if explicit_address else ("topology-ref" if address_ref else "topology"),
        "address_ref": address_ref or None,
        "topology_status": topology_entry.get("status"),
        "candidate_addresses": topology_entry.get("candidate_addresses", []),
        "rpc_source": rpc_source,
        "execution_mode": "planned",
        "check": {
            "call": check.get("call"),
            "args": normalize_args(check.get("args")),
            "expect": resolved_expect,
            "expect_source": expect_source,
            "expect_ref": expect_ref or None,
            "slot": check.get("slot"),
            "balance_min": check.get("balance_min"),
            "block": block or None,
            "block_source": block_source,
            "expression": render_check_expression(check),
        },
        "rationale": check.get("rationale"),
        "evidence_class": check.get("evidence_class"),
        "related_angle_ids": list(
            dict.fromkeys(
                str(angle_id).strip()
                for angle_id in check.get("related_angle_ids", [])
                if str(angle_id).strip()
            )
        ),
        "implication_if_match": check.get("implication_if_match"),
        "spec_source": check.get("spec_source"),
        "generated": bool(check.get("generated")),
    }
    for field in (
        "pair_id",
        "proof_pair_id",
        "angle_id",
        "pair_complete",
        "same_block",
        "pair_blocks",
        "edge_row_id",
        "authority_row_id",
        "requirement_id",
        "requirement_role",
        "source_item_id",
    ):
        if check.get(field) not in (None, "", []):
            result[field] = check.get(field)
    if isinstance(check.get("heuristic_provenance"), dict):
        result["heuristic_provenance"] = check.get("heuristic_provenance")
    for field in (
        "pair_id",
        "proof_pair_id",
        "angle_id",
        "local_only_runner",
        "local_only_policy",
        "execution_policy",
    ):
        if check.get(field) is not None:
            result[field] = check.get(field)

    synthesis_status = str(check.get("synthesis_status") or "").strip()
    if synthesis_status == "ambiguous-source":
        # P1-3 burn-down: synthesizer found multiple plausible getters and
        # refused to pick one. Surface that as a fail-closed dossier row
        # instead of silently picking the first candidate.
        candidates = [
            str(item).strip()
            for item in check.get("ambiguous_alias_candidates") or []
            if str(item).strip()
        ]
        result["status"] = "ambiguous_source"
        result["execution_mode"] = "skipped"
        result["blocked_reason"] = (
            "synthesizer refused to pick a single getter — "
            f"{len(candidates)} candidates tied at the top heuristic score"
        )
        result["ambiguous_alias_candidates"] = candidates
        result["needed_input"] = (
            f"operator must pick the canonical getter on {contract} that "
            f"returns the {check.get('expect_ref') or 'target'} address"
        )
        return result

    if not resolved_address:
        result["status"] = "blocked_unresolved_address"
        result["blocked_reason"] = "no resolved address in spec or deployment_topology.json"
        if address_ref:
            result["needed_input"] = f"resolved address for {address_ref}"
        return result
    if explicit_expect is None and expect_ref and resolved_expect is None:
        result["status"] = "blocked_unresolved_address"
        result["blocked_reason"] = f"expected contract reference {expect_ref} is unresolved in deployment_topology.json"
        result["needed_input"] = f"resolved expected address for {expect_ref}"
        return result

    dry_run_reason = ""
    if force_dry_run:
        dry_run_reason = "flag"
    elif not rpc_url:
        dry_run_reason = "missing-rpc"
    elif rpc_source == "public-fallback" and not allow_public_rpc:
        dry_run_reason = "public-rpc-disabled"

    cmd = [
        sys.executable,
        str(LIVE_STATE_CHECKER),
        "--workspace",
        str(workspace),
        "--address",
        resolved_address,
        "--network",
        network,
        "--json",
    ]
    if rpc_url_explicit:
        cmd.extend(["--rpc-url", rpc_url_explicit])
    if check.get("call"):
        cmd.extend(["--call", str(check["call"])])
    args = normalize_args(check.get("args"))
    if args:
        cmd.extend(["--args", ",".join(args)])
    if resolved_expect is not None:
        cmd.extend(["--expect", str(resolved_expect)])
    if check.get("slot"):
        cmd.extend(["--slot", str(check["slot"])])
    if check.get("balance_min") is not None:
        cmd.extend(["--balance-min", str(check["balance_min"])])
    if block:
        cmd.extend(["--block", block])
    if dry_run_reason:
        cmd.append("--dry-run")

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    result["command"] = cmd

    payload: Dict[str, Any] = {}
    if proc.stdout.strip():
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            result["status"] = "error"
            result["reason"] = "invalid JSON from live-state-checker.py"
            result["raw_stdout"] = proc.stdout[:2000]
            result["stderr"] = proc.stderr[:1000]
            return result

    result["live_result"] = payload
    result["exit_code"] = proc.returncode
    payload_block = payload.get("block") if isinstance(payload, dict) else None
    if payload_block and not result.get("block"):
        result["block"] = str(payload_block)
        result["check"]["block"] = str(payload_block)
        result["block_source"] = "checker"
        result["check"]["block_source"] = "checker"

    if dry_run_reason:
        if dry_run_reason == "flag":
            result["status"] = "dry_run"
        else:
            result["status"] = "blocked_missing_rpc"
        result["execution_mode"] = "dry_run"
        comparator = planned_comparator(check)
        blocked_reason, needed_input = dry_run_reason_message(dry_run_reason, network)
        result["blocked_reason"] = blocked_reason
        if needed_input:
            result["needed_input"] = needed_input
        if resolved_expect is not None:
            result["expected"] = resolved_expect
        if comparator:
            result["comparator"] = comparator
            result["normalization"] = planned_normalization(comparator)
        return result

    if proc.returncode not in (0, 1):
        result["status"] = "error"
        result["execution_mode"] = "executed"
        result["blocked_reason"] = proc.stderr.strip()[:400] or f"live-state-checker rc={proc.returncode}"
        return result

    checks = payload.get("checks", [])
    matched = any(bool(item.get("match")) for item in checks if isinstance(item, dict))
    result["status"] = "pass" if matched else "fail"
    result["execution_mode"] = "executed"
    for item in checks:
        if not isinstance(item, dict):
            continue
        if item.get("actual") is not None:
            result["actual"] = item.get("actual")
        if item.get("expected") is not None:
            result["expected"] = item.get("expected")
        if item.get("comparator") is not None:
            result["comparator"] = item.get("comparator")
        if item.get("normalization") is not None:
            result["normalization"] = item.get("normalization")
        if item.get("actual_normalized") is not None:
            result["actual_normalized"] = item.get("actual_normalized")
        if item.get("expected_normalized") is not None:
            result["expected_normalized"] = item.get("expected_normalized")
        if item.get("error"):
            result["checker_error"] = item.get("error")
        break
    return result


def disabled_check_result(
    check: Dict[str, Any],
    topology: Dict[str, Dict[str, Any]],
    *,
    default_block: str = "",
) -> Dict[str, Any]:
    """Render disabled spec rows as explicit blockers instead of hiding them."""
    contract = str(check.get("contract") or "UNKNOWN")
    explicit_address = str(check.get("address") or "").strip()
    address_ref = str(check.get("address_ref") or "").strip()
    resolved_address = explicit_address
    if not resolved_address and address_ref:
        resolved_address, _address_candidates, _address_status = resolve_topology_ref(topology, address_ref)
    if not resolved_address:
        resolved_address = str(topology.get(contract, {}).get("resolved_address") or "").strip()
    explicit_block = str(check.get("block") or "").strip()
    block = explicit_block or default_block
    result: Dict[str, Any] = {
        "id": str(check.get("id") or contract.lower()),
        "title": str(check.get("title") or contract),
        "contract": contract,
        "network": str(check.get("network") or "mainnet"),
        "block": block or None,
        "block_source": "spec" if explicit_block else ("run-pin" if default_block else None),
        "address": resolved_address or None,
        "address_source": "spec" if explicit_address else ("topology-ref" if address_ref else "topology"),
        "address_ref": address_ref or None,
        "execution_mode": "skipped",
        "status": "disabled",
        "blocked_reason": str(check.get("blocked_reason") or "check disabled in live-check spec"),
        "needed_input": check.get("needed_input"),
        "check": {
            "call": check.get("call"),
            "args": normalize_args(check.get("args")),
            "expect": check.get("expect"),
            "expect_source": "spec" if check.get("expect") is not None else None,
            "expect_ref": check.get("expect_ref"),
            "slot": check.get("slot"),
            "balance_min": check.get("balance_min"),
            "block": block or None,
            "block_source": "spec" if explicit_block else ("run-pin" if default_block else None),
            "expression": render_check_expression(check),
        },
        "rationale": check.get("rationale"),
        "evidence_class": check.get("evidence_class"),
        "related_angle_ids": list(
            dict.fromkeys(
                str(angle_id).strip()
                for angle_id in check.get("related_angle_ids", [])
                if str(angle_id).strip()
            )
        ),
        "implication_if_match": check.get("implication_if_match"),
        "spec_source": check.get("spec_source"),
        "generated": bool(check.get("generated")),
    }
    for field in (
        "pair_id",
        "proof_pair_id",
        "angle_id",
        "local_only_runner",
        "local_only_policy",
        "execution_policy",
    ):
        if check.get(field) is not None:
            result[field] = check.get(field)
    return result


def summarize(results: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts = {
        "declared": 0,
        "pass": 0,
        "fail": 0,
        "blocked_unresolved_address": 0,
        "blocked_missing_rpc": 0,
        "ambiguous_source": 0,
        "disabled": 0,
        "dry_run": 0,
        "error": 0,
    }
    for result in results:
        counts["declared"] += 1
        status = str(result.get("status") or "error")
        counts[status] = counts.get(status, 0) + 1
    counts["ready"] = counts["pass"] + counts["fail"]
    return counts


def render_markdown(workspace: Path, artifact: Dict[str, Any]) -> str:
    summary = artifact["summary"]
    results = artifact["results"]
    manual_imports = artifact.get("manual_imports") or {}
    proof_pairs = artifact.get("proof_pairs") or []
    proof_pair_summary = artifact.get("proof_pair_summary") or {}
    proof_contradictions = artifact.get("proof_contradictions") or []
    lines = [
        "# Live Topology Checks",
        "",
        f"- Workspace: `{workspace}`",
        f"- Spec: `{artifact['spec']}`",
        f"- Generated at: `{artifact['generated_at']}`",
    ]
    if manual_imports.get("enabled"):
        requested = manual_imports.get("requested_ids") or []
        lines.extend([
            f"- Manual imports: `{manual_imports.get('imported_rows', 0)}` rows",
            f"- Manual proof ids: {', '.join(f'`{item}`' for item in requested[:6]) or '—'}",
        ])
    if proof_pair_summary.get("declared"):
        lines.extend([
            f"- Proof pairs: `{proof_pair_summary.get('declared', 0)}` declared",
            f"- Proved pairs: `{proof_pair_summary.get('proved', 0)}`",
            f"- Partial pairs: `{proof_pair_summary.get('partial', 0)}`",
            f"- Conflicting pairs: `{proof_pair_summary.get('conflicting', 0)}`",
        ])
    if proof_contradictions:
        lines.append(f"- Executed proof contradictions: `{len(proof_contradictions)}`")
    lines.extend([
        f"- Declared: {summary['declared']}",
        f"- Pass: {summary['pass']}",
        f"- Fail: {summary['fail']}",
        f"- Blocked (unresolved address): {summary['blocked_unresolved_address']}",
        f"- Blocked (missing RPC): {summary['blocked_missing_rpc']}",
        f"- Ambiguous source: {summary.get('ambiguous_source', 0)}",
        f"- Disabled: {summary.get('disabled', 0)}",
        f"- Dry-run: {summary['dry_run']}",
        f"- Errors: {summary['error']}",
        "",
        "| Status | ID | Contract | Address | Check | Block |",
        "|---|---|---|---|---|---|",
    ])
    for result in results:
        addr = result.get("address") or "—"
        expr = result.get("check", {}).get("expression") or "—"
        block = result.get("block") or "—"
        lines.append(
            f"| `{result.get('status')}` | `{result.get('id')}` | "
            f"`{result.get('contract')}` | `{addr}` | `{expr}` | `{block}` |"
        )
    lines.append("")

    for result in results:
        status = result.get("status")
        if status == "pass":
            continue
        lines.extend([
            f"## {result.get('id')} — {result.get('title')}",
            "",
            f"- Status: `{status}`",
            f"- Contract: `{result.get('contract')}`",
            f"- Address: `{result.get('address') or 'unresolved'}`",
        ])
        rationale = result.get("rationale")
        if rationale:
            lines.append(f"- Rationale: {rationale}")
        related_angles = result.get("related_angle_ids") or []
        if related_angles:
            lines.append(f"- Related angles: {', '.join(f'`{angle}`' for angle in related_angles)}")
        implication = result.get("implication_if_match")
        if implication:
            lines.append(f"- Implication if match: {implication}")
        reason = result.get("reason")
        blocked_reason = result.get("blocked_reason")
        if blocked_reason:
            lines.append(f"- Blocked reason: {blocked_reason}")
        elif reason:
            lines.append(f"- Reason: {reason}")
        if result.get("execution_mode"):
            lines.append(f"- Execution mode: `{result.get('execution_mode')}`")
        if result.get("rpc_source"):
            lines.append(f"- RPC source: `{result.get('rpc_source')}`")
        if result.get("address_source"):
            lines.append(f"- Address source: `{result.get('address_source')}`")
        expect_source = result.get("check", {}).get("expect_source")
        if expect_source:
            lines.append(f"- Expected source: `{expect_source}`")
        if result.get("comparator"):
            lines.append(f"- Comparator: `{result.get('comparator')}`")
        if result.get("expected") is not None:
            lines.append(f"- Expected: `{result.get('expected')}`")
        if result.get("actual") is not None:
            lines.append(f"- Actual: `{result.get('actual')}`")
        if result.get("normalization"):
            lines.append(f"- Normalization: {', '.join(result.get('normalization') or [])}")
        if result.get("needed_input"):
            lines.append(f"- Needed input: `{result.get('needed_input')}`")
        if result.get("candidate_addresses"):
            lines.append("- Candidate addresses:")
            for candidate in result["candidate_addresses"][:6]:
                lines.append(f"  - `{candidate}`")
        heuristic_provenance = result.get("heuristic_provenance")
        if isinstance(heuristic_provenance, dict):
            signals = heuristic_provenance.get("signals") if isinstance(heuristic_provenance.get("signals"), dict) else {}
            source = heuristic_provenance.get("source_contract") or "?"
            getter = heuristic_provenance.get("getter") or "?"
            target = heuristic_provenance.get("target_contract") or "?"
            lines.append(
                f"- Heuristic provenance: `{heuristic_provenance.get('confidence') or 'heuristic'}` "
                f"`{source}.{getter} -> {target}`"
            )
            if heuristic_provenance.get("ambiguous"):
                candidates = heuristic_provenance.get("candidates") or []
                rendered = ", ".join(
                    f"`{entry.get('alias')}`" for entry in candidates if isinstance(entry, dict)
                ) or "—"
                lines.append(f"- Ambiguous-source candidates: {rendered}")
            discriminator = heuristic_provenance.get("discriminator")
            if isinstance(discriminator, dict) and discriminator.get("unique_signals"):
                signals_str = ", ".join(f"`{item}`" for item in discriminator.get("unique_signals", []))
                lines.append(
                    f"- Ambiguity discriminator: winner=`{discriminator.get('winner')}` "
                    f"runner_up=`{discriminator.get('runner_up')}` "
                    f"signals={signals_str}"
                )
            if signals.get("source_mentions_target_type") is not None:
                lines.append(f"- Source mentions target type: `{bool(signals.get('source_mentions_target_type'))}`")
            overlap = signals.get("meaningful_token_overlap")
            if isinstance(overlap, list) and overlap:
                lines.append(f"- Getter/target token overlap: {', '.join(f'`{item}`' for item in overlap)}")
            semantic_edges = signals.get("semantic_graph_relation_edges")
            if isinstance(semantic_edges, list) and semantic_edges:
                lines.append(f"- Semantic graph relation edges: `{len(semantic_edges)}` matched")
        if result.get("status") == "ambiguous_source" and result.get("ambiguous_alias_candidates"):
            rendered = ", ".join(
                f"`{item}`" for item in result.get("ambiguous_alias_candidates") or []
            )
            lines.append(f"- Ambiguous alias candidates: {rendered}")
        if result.get("manual_proof_source"):
            lines.append(f"- Manual proof source: `{result.get('manual_proof_source')}`")
        if result.get("manual_proof_status"):
            lines.append(f"- Manual proof status: `{result.get('manual_proof_status')}`")
        if result.get("proof_pair_id") or result.get("pair_id"):
            lines.append(f"- Proof pair: `{result.get('proof_pair_id') or result.get('pair_id')}`")
        if result.get("pair_complete") is not None:
            lines.append(f"- Pair complete: `{bool(result.get('pair_complete'))}`")
        if result.get("same_block") is not None:
            lines.append(f"- Same block: `{bool(result.get('same_block'))}`")
        if isinstance(result.get("pair_blocks"), list) and result.get("pair_blocks"):
            lines.append(f"- Pair blocks: {', '.join(f'`{block}`' for block in result.get('pair_blocks') or [])}")
        if result.get("edge_row_id"):
            lines.append(f"- Edge row: `{result.get('edge_row_id')}`")
        if result.get("authority_row_id"):
            lines.append(f"- Authority row: `{result.get('authority_row_id')}`")
        if result.get("replay_command"):
            lines.append(f"- Replay command: `{result.get('replay_command')}`")
        cmd = result.get("command")
        if cmd:
            lines.append(f"- Command: `{ ' '.join(cmd) }`")
        lines.append("")
    if proof_pairs:
        lines.extend([
            "## Proof Pairs",
            "",
            "| Status | Pair | Angle | Rows | Shared block |",
            "|---|---|---|---|---|",
        ])
        for pair in proof_pairs:
            row_list = ", ".join(f"`{row_id}`" for row_id in pair.get("row_ids", [])) or "—"
            shared_block = pair.get("shared_block") or "—"
            lines.append(
                f"| `{pair.get('status')}` | `{pair.get('id')}` | `{pair.get('angle_id')}` | {row_list} | `{shared_block}` |"
            )
        lines.append("")
    if proof_contradictions:
        lines.extend([
            "## Proof Contradictions",
            "",
            "| Block | Contract | Check | Pass rows | Fail rows |",
            "|---|---|---|---|---|",
        ])
        for item in proof_contradictions:
            claim_key = item.get("claim_key") if isinstance(item.get("claim_key"), dict) else {}
            pass_rows = ", ".join(
                f"`{row.get('id')}`"
                for row in item.get("pass_rows", [])
                if isinstance(row, dict) and str(row.get("id") or "").strip()
            ) or "—"
            fail_rows = ", ".join(
                f"`{row.get('id')}`"
                for row in item.get("fail_rows", [])
                if isinstance(row, dict) and str(row.get("id") or "").strip()
            ) or "—"
            lines.append(
                f"| `{item.get('block') or '—'}` | "
                f"`{claim_key.get('contract') or '—'}` | "
                f"`{claim_key.get('check_kind') or '—'}` | "
                f"{pass_rows} | {fail_rows} |"
            )
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run declarative live topology checks")
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("--spec", help="Optional explicit live-check spec path")
    parser.add_argument("--out-json", help="Output JSON path (default: <workspace>/live_topology_checks.json)")
    parser.add_argument("--out-md", help="Output Markdown path (default: <workspace>/LIVE_TOPOLOGY.md)")
    parser.add_argument("--dry-run", action="store_true", help="Plan checks without hitting RPC")
    parser.add_argument("--allow-public-rpc", action="store_true", help="Allow public fallback RPC execution")
    parser.add_argument("--import-manual-proofs", action="store_true",
                        help="Import <workspace>/manual_proofs/*.json into the canonical dossier")
    parser.add_argument("--manual-proof-id", action="append",
                        help="Import only the selected manual proof row id(s) from <workspace>/manual_proofs/*.json")
    parser.add_argument(
        "--pin-block",
        help="Apply one shared block to every check without an explicit block. Use a number or 'latest'.",
    )
    parser.add_argument("--json", action="store_true", help="Print artifact JSON to stdout")
    args = parser.parse_args()

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.exists():
        print(f"[live-checks] Workspace not found: {workspace}", file=sys.stderr)
        sys.exit(2)

    spec_path = resolve_spec_path(workspace, args.spec)
    selected_manual_ids = {
        str(item).strip()
        for item in (args.manual_proof_id or [])
        if str(item).strip()
    }
    import_manual_proofs = bool(args.import_manual_proofs or selected_manual_ids)
    if spec_path is None and not import_manual_proofs:
        print("[live-checks] No live check spec found.", file=sys.stderr)
        sys.exit(3)

    spec: Dict[str, Any] = {"checks": []}
    if spec_path is not None:
        try:
            spec = load_spec(spec_path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"[live-checks] Invalid spec: {exc}", file=sys.stderr)
            sys.exit(2)

    topology = load_topology(workspace)
    workspace_env = load_workspace_env(workspace)
    checks = spec.get("checks", [])
    pin_metadata = resolve_run_pin_blocks(
        checks,
        workspace_env,
        pin_block=str(args.pin_block or "").strip(),
        allow_public_rpc=args.allow_public_rpc,
    )
    results = []
    for check in checks:
        if not isinstance(check, dict):
            continue
        default_block = str(
            pin_metadata.get("resolved_by_network", {}).get(
                str(check.get("network") or "mainnet").strip() or "mainnet",
                "",
            )
        )
        if not check.get("enabled", True):
            results.append(disabled_check_result(check, topology, default_block=default_block))
            continue
        results.append(
            run_single_check(
                workspace,
                check,
                topology,
                workspace_env,
                force_dry_run=args.dry_run,
                allow_public_rpc=args.allow_public_rpc,
                default_block=default_block,
            )
        )
    manual_imports: Dict[str, Any] = {
        "enabled": False,
        "path": str(workspace / "manual_proofs"),
        "files_scanned": 0,
        "imported_rows": 0,
        "added": 0,
        "replaced": 0,
        "errors": [],
    }
    if import_manual_proofs:
        manual_rows, manual_metadata = load_manual_proof_rows(
            workspace,
            selected_ids=selected_manual_ids or None,
        )
        manual_imports.update(manual_metadata)
        results, merge_stats = merge_manual_results(results, manual_rows)
        manual_imports.update(merge_stats)
    proof_pairs = build_proof_pairs(results)
    proof_pair_summary = summarize_proof_pairs(proof_pairs)
    proof_contradictions = find_executed_live_proof_contradictions(results)

    out_json = Path(args.out_json).expanduser().resolve() if args.out_json else workspace / "live_topology_checks.json"
    out_md = Path(args.out_md).expanduser().resolve() if args.out_md else workspace / "LIVE_TOPOLOGY.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)

    artifact = {
        "workspace": str(workspace),
        "spec": str(spec_path) if spec_path else "(manual proofs only)",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pin_block": pin_metadata,
        "manual_imports": manual_imports,
        "proof_pairs": proof_pairs,
        "proof_pair_summary": proof_pair_summary,
        "proof_contradictions": proof_contradictions,
        "summary": summarize(results),
        "results": results,
    }
    out_json.write_text(json.dumps(artifact, indent=2) + "\n")
    out_md.write_text(render_markdown(workspace, artifact) + "\n")

    summary = artifact["summary"]
    summary_line = (
        "[live-checks] "
        f"wrote {out_json} and {out_md} "
        f"(pass={summary['pass']}, fail={summary['fail']}, "
        f"manual={manual_imports['imported_rows']}, "
        f"blocked={summary['blocked_unresolved_address'] + summary['blocked_missing_rpc']}, "
        f"ambiguous_source={summary.get('ambiguous_source', 0)}, "
        f"disabled={summary.get('disabled', 0)}, "
        f"dry_run={summary['dry_run']}, error={summary['error']})"
    )
    if args.json:
        print(json.dumps(artifact, indent=2))
        print(summary_line, file=sys.stderr)
    else:
        print(summary_line)


if __name__ == "__main__":
    main()
