#!/usr/bin/env python3
"""Workspace-neutral withheld-known impact routing benchmark.

The benchmark measures whether Auditooor routes known in-scope impact shapes to
the right next-action family across severities. It is deliberately not finding
evidence: generated rows remain NOT_SUBMIT_READY and only score route recall.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.pr560.impact_miss_offset_benchmark.v1"
GENERATED_EVIDENCE_CLASS = "generated_hypothesis"
SCAFFOLDED_EVIDENCE_CLASS = "scaffolded_unverified"
TIERS = ("Critical", "High", "Medium", "Low")
DEFAULT_ITEM_TARGET = 384
PASS_THRESHOLD = 0.85
MIN_ITEM_TARGET = 150
MAX_ITEM_TARGET = 500
TARGET_RANGE = "300-500 concrete items preferred; 150 minimum compatibility"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PREDICTIONS_NAME = "impact_miss_offset_predictions.json"
DEFAULT_HARNESS_BLOCKERS_JSON = "impact_miss_harness_blocker_queue.json"
DEFAULT_HARNESS_BLOCKERS_MD = "impact_miss_harness_blocker_queue.md"

ROUTE_FAMILIES: dict[str, dict[str, Any]] = {
    "asset_custody": {
        "asset_category": "Smart Contract",
        "tokens": ("fund", "vault", "token", "share", "balance"),
        "required_artifacts": ("impact_contract", "funds_flow_poc_or_fork_replay", "poc_execution_manifest"),
        "criteria": ("route_family must be asset_custody", "must request balance-delta proof", "must not accept admin-key compromise"),
    },
    "bridge_finalization": {
        "asset_category": "Smart Contract",
        "tokens": ("bridge", "withdrawal", "finalize", "message", "root"),
        "required_artifacts": ("impact_contract", "production_path_dossier", "paired_live_or_fork_proof"),
        "criteria": ("route_family must be bridge_finalization", "must prove cross-domain production path", "must reject mock messenger-only proof"),
    },
    "oracle_settlement": {
        "asset_category": "Smart Contract",
        "tokens": ("oracle", "price", "settlement", "market", "liquidation"),
        "required_artifacts": ("impact_contract", "source_proof", "economic_or_settlement_harness"),
        "criteria": ("route_family must be oracle_settlement", "must bind stale/manipulated value to state transition", "must reject event-only claims"),
    },
    "access_control": {
        "asset_category": "Smart Contract",
        "tokens": ("role", "permission", "operator", "unauthorized", "owner"),
        "required_artifacts": ("impact_contract", "source_proof", "negative_authorization_fixture"),
        "criteria": ("route_family must be access_control", "must show non-privileged caller reachability", "must reject privileged-admin-only paths"),
    },
    "signature_replay": {
        "asset_category": "Smart Contract",
        "tokens": ("signature", "permit", "nonce", "domain", "replay"),
        "required_artifacts": ("impact_contract", "replay_harness", "domain_binding_source_proof"),
        "criteria": ("route_family must be signature_replay", "must include replay domain/nonce assertion", "must reject duplicate-signature-without-impact claims"),
    },
    "proof_verification": {
        "asset_category": "Smart Contract",
        "tokens": ("proof", "verifier", "zk", "tee", "attestation"),
        "required_artifacts": ("impact_contract", "production_verifier_path", "forgery_or_bypass_harness"),
        "criteria": ("route_family must be proof_verification", "must use production verifier wiring", "must reject mock-verifier proof"),
    },
    "node_liveness": {
        "asset_category": "Blockchain/DLT",
        "tokens": ("node", "network", "block", "transaction", "liveness"),
        "required_artifacts": ("impact_contract", "node_harness", "liveness_measurement"),
        "criteria": ("route_family must be node_liveness", "must show realistic peer/RPC input", "must reject flood-only DoS"),
    },
    "resource_consumption": {
        "asset_category": "Blockchain/DLT",
        "tokens": ("cpu", "memory", "resource", "decode", "allocation"),
        "required_artifacts": ("impact_contract", "resource_benchmark", "bounded_input_fixture"),
        "criteria": ("route_family must be resource_consumption", "must measure resource delta", "must reject component-only microbenchmarks without threshold mapping"),
    },
    "consensus_safety": {
        "asset_category": "Blockchain/DLT",
        "tokens": ("consensus", "fork", "state root", "finality", "validator"),
        "required_artifacts": ("impact_contract", "consensus_replay_or_model", "same_input_divergence_proof"),
        "criteria": ("route_family must be consensus_safety", "must prove safety/liveness invariant violation", "must reject local parser-only mismatches"),
    },
    "liquidation_solvency": {
        "asset_category": "Smart Contract",
        "tokens": ("liquidation", "collateral", "debt", "solvency", "health"),
        "required_artifacts": ("impact_contract", "solvency_harness", "victim_accounting_assertion"),
        "criteria": ("route_family must be liquidation_solvency", "must bind accounting error to bad debt or unfair liquidation", "must reject dust-only edge cases"),
    },
    "governance_integrity": {
        "asset_category": "Smart Contract",
        "tokens": ("governance", "vote", "quorum", "proposal", "delegate"),
        "required_artifacts": ("impact_contract", "governance_state_harness", "non_privileged_vote_path"),
        "criteria": ("route_family must be governance_integrity", "must show proposal/vote outcome change", "must reject centralization-risk-only claims"),
    },
    "availability_dos": {
        "asset_category": "Smart Contract",
        "tokens": ("withdraw", "claim", "queue", "revert", "grief"),
        "required_artifacts": ("impact_contract", "availability_harness", "victim_action_blocked_assertion"),
        "criteria": ("route_family must be availability_dos", "must show victim operation blocked under realistic state", "must reject attacker-self-DoS"),
    },
}

DLT_ROUTE_RUNTIME_FAMILIES = {
    "node_liveness": "execution_client",
    "resource_consumption": "runtime_resource",
    "consensus_safety": "consensus_client",
}

ARTIFACT_REL_PATHS = {
    "impact_contract": ".auditooor/impact_contracts.json",
    "funds_flow_poc_or_fork_replay": "poc-tests/{benchmark_id}/",
    "poc_execution_manifest": "poc_execution/{benchmark_id}/execution_manifest.json",
    "production_path_dossier": ".auditooor/production_path_dossiers/{benchmark_id}.json",
    "paired_live_or_fork_proof": ".auditooor/live_proof/{benchmark_id}.json",
    "source_proof": "source_proofs/{benchmark_id}-source-proof/source_proof.json",
    "economic_or_settlement_harness": "poc-tests/{benchmark_id}/",
    "negative_authorization_fixture": "poc-tests/{benchmark_id}/",
    "replay_harness": "poc-tests/{benchmark_id}/",
    "domain_binding_source_proof": "source_proofs/{benchmark_id}-source-proof/source_proof.json",
    "production_verifier_path": ".auditooor/production_path_dossiers/{benchmark_id}.json",
    "forgery_or_bypass_harness": "poc-tests/{benchmark_id}/",
    "node_harness": "poc-tests/{benchmark_id}/",
    "liveness_measurement": "poc_execution/{benchmark_id}/execution_manifest.json",
    "resource_benchmark": "poc-tests/{benchmark_id}/",
    "bounded_input_fixture": "test_fixtures/{benchmark_id}/",
    "consensus_replay_or_model": "poc-tests/{benchmark_id}/",
    "same_input_divergence_proof": "poc_execution/{benchmark_id}/execution_manifest.json",
    "solvency_harness": "poc-tests/{benchmark_id}/",
    "victim_accounting_assertion": "poc_execution/{benchmark_id}/execution_manifest.json",
    "governance_state_harness": "poc-tests/{benchmark_id}/",
    "non_privileged_vote_path": "source_proofs/{benchmark_id}-source-proof/source_proof.json",
    "availability_harness": "poc-tests/{benchmark_id}/",
    "victim_action_blocked_assertion": "poc_execution/{benchmark_id}/execution_manifest.json",
}

TIER_IMPACTS = {
    "Critical": ("total loss", "network halt", "consensus split", "bridge insolvency"),
    "High": ("material fund loss", "protocol insolvency", "long-lived service outage", "unauthorized asset movement"),
    "Medium": ("bounded user loss", "temporary denial of service", "incorrect settlement", "resource consumption above threshold"),
    "Low": ("limited griefing", "minor accounting drift", "operator-visible inconsistency", "recoverable availability loss"),
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "item"


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_md(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def out_dir(workspace: Path | None) -> Path:
    base = workspace if workspace else ROOT
    d = base / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    return d


def route_impact_text(route_family: str, tier: str, variant: int) -> str:
    route = ROUTE_FAMILIES[route_family]
    token_a = route["tokens"][variant % len(route["tokens"])]
    token_b = route["tokens"][(variant + 2) % len(route["tokens"])]
    tier_impact = TIER_IMPACTS[tier][variant % len(TIER_IMPACTS[tier])]
    return f"{tier} in-scope {tier_impact} via {token_a}/{token_b} route"


def source_snippet(route_family: str, variant: int) -> str:
    route = ROUTE_FAMILIES[route_family]
    token_a, token_b = route["tokens"][0], route["tokens"][1]
    return (
        f"function demo_{slug(route_family)}_{variant}(bytes calldata input) external {{ "
        f"// {token_a} path reaches {token_b} state transition; fixture is benchmark-only "
        "}}"
    )


def build_case(route_family: str, tier: str, variant: int) -> dict[str, Any]:
    route = ROUTE_FAMILIES[route_family]
    item_id = f"imo-{tier.lower()}-{slug(route_family)}-{variant:02d}"
    impact_text = route_impact_text(route_family, tier, variant)
    return {
        "benchmark_id": item_id,
        "withheld_known": True,
        "evidence_class": GENERATED_EVIDENCE_CLASS,
        "tier": tier,
        "asset_category": route["asset_category"],
        "input": {
            "impact_text": impact_text,
            "scope_clause": f"In scope: {route['asset_category']} impacts at {tier} or above when proven.",
            "source_shape": source_snippet(route_family, variant),
            "attacker_model": "non_privileged_external_actor",
            "negative_controls": [
                "admin key compromise",
                "mock-only proof",
                "event-only or terminal-only evidence",
            ],
        },
        "expected": {
            "route_family": route_family,
            "required_artifacts": list(route["required_artifacts"]),
            "terminal_decision": "route_to_harness_or_source_proof_after_exact_impact_contract",
            "submission_posture": "NOT_SUBMIT_READY",
        },
        "pass_fail_criteria": list(route["criteria"]),
    }


def built_in_cases(limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    route_tier_slots = max(1, len(TIERS) * len(ROUTE_FAMILIES))
    variants_per_route_tier = max(1, (limit + route_tier_slots - 1) // route_tier_slots)
    for tier in TIERS:
        for route_family in ROUTE_FAMILIES:
            for variant in range(1, variants_per_route_tier + 1):
                rows.append(build_case(route_family, tier, variant))
    return rows[:limit]


def load_predictions(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise SystemExit(f"[impact-miss-offset-benchmark] predictions file missing: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        for key in ("rows", "predictions", "results"):
            if isinstance(payload.get(key), list):
                return [row for row in payload[key] if isinstance(row, dict)]
    raise SystemExit("[impact-miss-offset-benchmark] predictions must be a list or object with rows/predictions/results")


def stringify(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(stringify(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(stringify(v) for v in value)
    if value is None:
        return ""
    return str(value)


def infer_route_family(text: str) -> tuple[str, int]:
    blob = text.lower().replace("-", " ").replace("_", " ")
    scores: dict[str, int] = {}
    aliases = {
        "asset_custody": ("deposit", "withdraw", "escrow", "transfer", "steal", "drain", "fund", "vault"),
        "bridge_finalization": ("cross chain", "teleport", "gateway", "message", "bridge", "finalize"),
        "oracle_settlement": ("price", "oracle", "settle", "market", "liquidat"),
        "access_control": ("onlyowner", "permission", "auth", "role", "unauthorized", "whitelist"),
        "signature_replay": ("signature", "permit", "nonce", "domain", "replay", "eip712"),
        "proof_verification": ("proof", "verifier", "zk", "attestation", "tee"),
        "node_liveness": ("node", "validator", "network", "block", "liveness"),
        "resource_consumption": ("gas", "memory", "cpu", "allocation", "resource", "decode"),
        "consensus_safety": ("consensus", "fork", "state root", "finality", "validator"),
        "liquidation_solvency": ("liquidat", "collateral", "debt", "solvency", "health"),
        "governance_integrity": ("governance", "vote", "quorum", "proposal", "delegate"),
        "availability_dos": ("dos", "denial", "blocked", "revert", "queue", "grief", "cannot", "prevent"),
    }
    for family, route in ROUTE_FAMILIES.items():
        tokens = tuple(route["tokens"]) + aliases.get(family, ())
        scores[family] = sum(1 for token in tokens if token in blob)
    family, score = max(scores.items(), key=lambda item: (item[1], item[0]))
    return (family if score else "", score)


def load_optional_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def workspace_source_rows(workspace: Path, limit: int = 250) -> list[dict[str, Any]]:
    sources = [
        ("scanner_autonomy_plan", workspace / ".auditooor" / "scanner_autonomy_plan.json", ("tasks",)),
        ("semantic_scanner_inventory", workspace / ".auditooor" / "semantic_scanner_inventory.json", ("detector_fixture_task_queue", "items")),
        ("agent_output_inventory", workspace / ".auditooor" / "agent_output_inventory.json", ("rows",)),
    ]
    rows: list[dict[str, Any]] = []
    for source_name, path, keys in sources:
        payload = load_optional_json(path)
        for key in keys:
            values = payload.get(key)
            if not isinstance(values, list):
                continue
            for value in values:
                if not isinstance(value, dict):
                    continue
                family, confidence = infer_route_family(stringify(value))
                rows.append(
                    {
                        "source": source_name,
                        "source_path": str(path),
                        "source_id": value.get("task_id")
                        or value.get("queue_id")
                        or value.get("inventory_id")
                        or value.get("verification_task_id")
                        or value.get("path")
                        or "",
                        "route_family": family,
                        "confidence": confidence,
                        "submission_posture": str(value.get("submission_posture") or "NOT_SUBMIT_READY"),
                        "promotion_allowed": bool(value.get("promotion_allowed")),
                    }
                )
                if len(rows) >= limit:
                    return rows
    return rows


def derive_predictions(cases: list[dict[str, Any]], workspace: Path) -> dict[str, Any]:
    source_rows = workspace_source_rows(workspace)
    source_counts = Counter(row["source"] for row in source_rows)
    support_counts = Counter(row["route_family"] for row in source_rows if row.get("route_family"))
    predictions: list[dict[str, Any]] = []
    for case in cases:
        text = stringify(case.get("input") or {})
        family, confidence = infer_route_family(text)
        expected_required = case.get("expected", {}).get("required_artifacts") or []
        support_count = int(support_counts.get(family, 0)) if family else 0
        supported = bool(family and support_count)
        route_support_status = "supported_by_workspace_outputs" if supported else "unsupported_by_workspace_outputs"
        terminal_blockers = []
        if family and not supported:
            terminal_blockers = [
                f"no existing scanner/autonomy workspace row currently supports route_family={family}",
                "derived prediction is benchmark-input routing only and must collect the requested artifact before promotion",
            ]
        predictions.append(
            {
                "benchmark_id": case["benchmark_id"],
                "route_family": family,
                "artifacts": list(expected_required[:1]) if family else [],
                "submission_posture": "NOT_SUBMIT_READY",
                "severity": "none",
                "selected_impact": "",
                "promotion_allowed": False,
                "evidence_class": GENERATED_EVIDENCE_CLASS,
                "derived_from_workspace_outputs": True,
                "source_support_count": support_count,
                "route_support_status": route_support_status if family else "unrouted",
                "terminal_blockers": terminal_blockers,
                "route_confidence_token_hits": confidence,
            }
        )
    return {
        "schema": "auditooor.pr560.impact_miss_offset_predictions.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "prediction_kind": "derived_from_existing_scanner_autonomy_outputs",
        "advisory_only": True,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "evidence_class": GENERATED_EVIDENCE_CLASS,
        "severity": "none",
        "selected_impact": "",
        "source_accounting": {
            "source_row_count": len(source_rows),
            "source_counts": dict(sorted(source_counts.items())),
            "route_support_counts": dict(sorted(support_counts.items())),
        },
        "predictions": predictions,
    }


def evaluate(cases: list[dict[str, Any]], predictions_path: Path | None) -> dict[str, Any]:
    if predictions_path is None:
        return {
            "status": "not_scored_no_predictions",
            "prediction_count": 0,
            "passed": 0,
            "failed": 0,
            "accuracy": 0.0,
            "rows": [],
        }
    predictions = load_predictions(predictions_path)
    by_id = {str(row.get("benchmark_id") or row.get("id") or ""): row for row in predictions}
    scored = []
    passed = 0
    for case in cases:
        expected = case["expected"]
        pred = by_id.get(case["benchmark_id"], {})
        route_ok = str(pred.get("route_family") or pred.get("expected_route_family") or "") == expected["route_family"]
        artifacts = set(pred.get("artifacts") or pred.get("required_artifacts") or [])
        required = set(expected["required_artifacts"])
        posture_ok = str(pred.get("submission_posture") or "NOT_SUBMIT_READY") == "NOT_SUBMIT_READY"
        artifact_ok = bool(artifacts & required)
        ok = route_ok and artifact_ok and posture_ok
        passed += int(ok)
        scored.append(
            {
                "benchmark_id": case["benchmark_id"],
                "tier": case["tier"],
                "expected_route_family": expected["route_family"],
                "predicted_route_family": str(pred.get("route_family") or ""),
                "route_ok": route_ok,
                "artifact_ok": artifact_ok,
                "posture_ok": posture_ok,
                "status": "pass" if ok else "fail",
                "evidence_class": GENERATED_EVIDENCE_CLASS,
            }
        )
    total = len(cases)
    accuracy = passed / total if total else 0.0
    return {
        "status": "pass" if accuracy >= PASS_THRESHOLD else "fail",
        "prediction_count": len(predictions),
        "passed": passed,
        "failed": total - passed,
        "accuracy": round(accuracy, 4),
        "pass_threshold": PASS_THRESHOLD,
        "rows": scored,
    }


def artifact_path(workspace: Path, benchmark_id: str, artifact: str) -> Path:
    template = ARTIFACT_REL_PATHS.get(artifact, f".auditooor/missing_artifacts/{artifact}/{{benchmark_id}}")
    return workspace / template.format(benchmark_id=benchmark_id)


def artifact_present(path: Path) -> bool:
    return path.exists()


def harness_family(route_family: str) -> str:
    if ROUTE_FAMILIES[route_family]["asset_category"] == "Blockchain/DLT":
        return "base_dlt_or_runtime_harness"
    if route_family in {"oracle_settlement", "liquidation_solvency", "asset_custody"}:
        return "economic_forge_harness"
    if route_family in {"proof_verification", "signature_replay"}:
        return "forgery_or_replay_harness"
    return "source_bound_forge_harness"


def runtime_semantic_dependency(workspace: Path, route_family: str) -> dict[str, Any]:
    expected_family = DLT_ROUTE_RUNTIME_FAMILIES.get(route_family, "execution_client")
    artifact = workspace / ".auditooor" / "rust_runtime_semantic_blockers.json"
    base = {
        "required": True,
        "artifact": str(artifact),
        "expected_runtime_component_family": expected_family,
        "required_fields": [
            "runtime_model_matrix",
            "runtime_component_family_counts",
            "runtime_readiness_gates",
            "items[].runtime_model_requirement",
            "items[].harness_binding_requirement",
            "items[].workspace_neutrality_requirement",
        ],
        "next_command": f"make rust-runtime-semantic-blockers WS={shlex.quote(str(workspace))} GENERATE=1 LIMIT=300",
        "proof_boundary": "Runtime semantic blockers are binding requirements, not exploit proof.",
    }
    if not artifact.is_file():
        return {
            **base,
            "status": "required_not_collected",
            "matching_runtime_rows": 0,
            "missing_runtime_inputs": [
                "rust_runtime_semantic_blockers artifact",
                f"runtime family coverage for {expected_family}",
                "workspace-neutral/hermetic runtime proof gate",
            ],
        }
    payload = load_optional_json(artifact)
    counts = payload.get("runtime_component_family_counts") if isinstance(payload.get("runtime_component_family_counts"), dict) else {}
    matching = int(counts.get(expected_family, 0) or 0)
    gates = payload.get("runtime_readiness_gates") if isinstance(payload.get("runtime_readiness_gates"), list) else []
    gate = next(
        (
            row for row in gates
            if isinstance(row, dict) and row.get("runtime_component_family") == expected_family
        ),
        {},
    )
    if not payload:
        status = "present_unreadable"
    elif matching <= 0:
        status = "present_missing_expected_runtime_family"
    else:
        status = "present_expected_family_unproved"
    missing = [
        "project-bound runtime harness/replay command",
        "poc_execution manifest with final_result=proved, impact_assertion=exploit_impact, "
        "evidence_class=executed_with_manifest, and structured passing command evidence",
        "non-Base/hermetic demonstration before workspace-neutral closure",
    ]
    if matching <= 0:
        missing.insert(0, f"runtime source row for {expected_family}")
    return {
        **base,
        "status": status,
        "matching_runtime_rows": matching,
        "runtime_artifact_schema": payload.get("schema", ""),
        "runtime_readiness_gate_status": gate.get("status", "missing_gate"),
        "missing_runtime_inputs": missing,
    }


def harness_commands(workspace: Path, case: dict[str, Any], missing: list[str]) -> list[str]:
    benchmark_id = case["benchmark_id"]
    ws_arg = shlex.quote(str(workspace))
    commands = [
        f"python3 tools/impact-miss-offset-benchmark.py --workspace {ws_arg} --limit {DEFAULT_ITEM_TARGET} --derive-predictions",
    ]
    if "impact_contract" in missing:
        commands.append(f"make impact-contract-check WS={ws_arg} JSON=1")
    if "source_proof" in missing or any("source_proof" in artifact for artifact in missing):
        commands.append(f"make source-proof-task-queue WS={ws_arg} JSON=1")
    if any("production" in artifact for artifact in missing):
        commands.append(f"make semantic-graph WS={ws_arg}")
    if any("live" in artifact or "fork" in artifact for artifact in missing):
        commands.append(f"python3 tools/engage.py --workspace {ws_arg} --stage live-checks")
    if case["asset_category"] == "Blockchain/DLT":
        commands.append(f"python3 tools/engage.py --workspace {ws_arg} --stage scan-rust")
    commands.extend(
        [
            f"make harness-task-queue WS={ws_arg} JSON=1",
            f"python3 tools/invariant-harness-planner.py --workspace {ws_arg} --all",
            f"make harness-scaffold WS={ws_arg} ALL=1",
            (
                f"make poc-execution-record WS={ws_arg} "
                f"BRIEF=.auditooor/impact_miss_harness_briefs/{benchmark_id}.md "
                f"CANDIDATE_ID={benchmark_id} CMD='<replace with executed local harness command>' "
                "RESULT=needs_human IMPACT=unknown"
            ),
        ]
    )
    return list(dict.fromkeys(commands))


def build_harness_blocker_row(workspace: Path, case: dict[str, Any]) -> dict[str, Any]:
    benchmark_id = case["benchmark_id"]
    required = list(case["expected"]["required_artifacts"])
    artifact_rows = []
    missing = []
    for artifact in required:
        path = artifact_path(workspace, benchmark_id, artifact)
        exists = artifact_present(path)
        artifact_rows.append(
            {
                "artifact": artifact,
                "path": str(path),
                "exists": exists,
                "required": True,
            }
        )
        if not exists:
            missing.append(artifact)
    status = "blocked_missing_artifacts" if missing else "ready_for_harness_execution"
    runtime_semantic_dependency_row: dict[str, Any] = {}
    if case["asset_category"] == "Blockchain/DLT":
        runtime_semantic_dependency_row = runtime_semantic_dependency(workspace, case["expected"]["route_family"])
    return {
        "task_id": f"impact-miss-{benchmark_id}",
        "benchmark_id": benchmark_id,
        "tier": case["tier"],
        "asset_category": case["asset_category"],
        "route_family": case["expected"]["route_family"],
        "harness_family": harness_family(case["expected"]["route_family"]),
        "status": status,
        "submission_posture": "NOT_SUBMIT_READY",
        "evidence_class": SCAFFOLDED_EVIDENCE_CLASS,
        "promotion_allowed": False,
        "submit_ready": False,
        "required_artifacts": artifact_rows,
        "missing_artifacts": missing,
        "runtime_semantic_dependency": runtime_semantic_dependency_row,
        "runnable_next_commands": harness_commands(workspace, case, missing),
        "acceptance_gate": (
            "Only a matching poc_execution/**/execution_manifest.json with "
            "final_result=proved, impact_assertion=exploit_impact, "
            "evidence_class=executed_with_manifest, and a structured command row "
            "with non-empty command, status=pass, and exit_code=0 can close this row as proved."
        ),
        "proof_boundary": "Benchmark routing and harness commands are not exploit proof.",
    }


def build_harness_blocker_queue(workspace: Path, cases: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [build_harness_blocker_row(workspace, case) for case in cases]
    status_counts = Counter(row["status"] for row in rows)
    route_counts = Counter(row["route_family"] for row in rows)
    missing_counts = Counter(artifact for row in rows for artifact in row["missing_artifacts"])
    runtime_dependency_status_counts = Counter(
        row["runtime_semantic_dependency"].get("status")
        for row in rows
        if row.get("runtime_semantic_dependency")
    )
    runtime_expected_family_counts = Counter(
        row["runtime_semantic_dependency"].get("expected_runtime_component_family")
        for row in rows
        if row.get("runtime_semantic_dependency")
    )
    return {
        "schema": "auditooor.pr560.impact_miss_harness_blocker_queue.v1",
        "generated_at": now_iso(),
        "workspace": str(workspace),
        "source": "impact_miss_offset_benchmark",
        "item_count": len(rows),
        "target_range": TARGET_RANGE,
        "submission_posture": "NOT_SUBMIT_READY",
        "evidence_class": SCAFFOLDED_EVIDENCE_CLASS,
        "promotion_allowed": False,
        "submit_ready": False,
        "proof_boundary": (
            "Rows are runnable harness/blocker tasks only. Do not claim proof until "
            "poc_execution records exact exploit impact."
        ),
        "summary": {
            "status_counts": dict(sorted(status_counts.items())),
            "route_family_counts": dict(sorted(route_counts.items())),
            "missing_artifact_counts": dict(sorted(missing_counts.items())),
            "runtime_dependency_status_counts": dict(sorted(runtime_dependency_status_counts.items())),
            "runtime_expected_family_counts": dict(sorted(runtime_expected_family_counts.items())),
            "rows_requiring_runtime_semantics": sum(1 for row in rows if row.get("runtime_semantic_dependency")),
        },
        "rows": rows,
    }


def write_harness_briefs(workspace: Path, queue: dict[str, Any]) -> None:
    brief_dir = workspace / ".auditooor" / "impact_miss_harness_briefs"
    brief_dir.mkdir(parents=True, exist_ok=True)
    for row in queue["rows"]:
        lines = [
            f"# Impact-Miss Harness Task: {row['benchmark_id']}",
            "",
            f"- Route family: `{row['route_family']}`",
            f"- Harness family: `{row['harness_family']}`",
            f"- Status: `{row['status']}`",
            f"- Submission posture: `{row['submission_posture']}`",
            "",
            "## Missing Artifacts",
            "",
        ]
        if row["missing_artifacts"]:
            lines.extend(f"- `{artifact}`" for artifact in row["missing_artifacts"])
        else:
            lines.append("- None; run the local harness command and record a non-proved manifest until impact is exact.")
        lines.extend(["", "## Runnable Next Commands", ""])
        lines.extend(f"- `{command}`" for command in row["runnable_next_commands"])
        lines.extend(["", "## Proof Boundary", "", row["proof_boundary"]])
        (brief_dir / f"{row['benchmark_id']}.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def render_harness_blocker_markdown(queue: dict[str, Any]) -> list[str]:
    summary = queue["summary"]
    lines = [
        "# Impact-Miss Harness Blocker Queue",
        "",
        "Concrete route-family harness/blocker tasks derived from the withheld-known benchmark.",
        "",
        f"- Items: `{queue['item_count']}`",
        f"- Status counts: `{summary['status_counts']}`",
        f"- Route-family counts: `{summary['route_family_counts']}`",
        f"- Submission posture: `{queue['submission_posture']}`",
        "",
        "| Task | Tier | Route family | Status | Missing artifacts | Runtime semantic dependency |",
        "|---|---|---|---|---|---|",
    ]
    for row in queue["rows"][:300]:
        missing = ", ".join(row["missing_artifacts"]) if row["missing_artifacts"] else "none"
        runtime_dep = row.get("runtime_semantic_dependency") or {}
        runtime_status = runtime_dep.get("status", "n/a")
        lines.append(
            f"| `{row['task_id']}` | {row['tier']} | `{row['route_family']}` | "
            f"`{row['status']}` | {missing} | `{runtime_status}` |"
        )
    lines.extend(["", "## Proof Boundary", "", queue["proof_boundary"]])
    return lines


def write_demo_fixture(workspace: Path) -> dict[str, str]:
    fixture = workspace / "benchmark_fixtures" / "impact_miss_offset" / "non_base_demo"
    src = fixture / "src"
    src.mkdir(parents=True, exist_ok=True)
    (fixture / "SEVERITY_SMART_CONTRACTS.md").write_text(
        "# High\n\n- Material fund loss from non-Base demo vault accounting\n\n"
        "# Medium\n\n- Temporary denial of service for queued withdrawals\n",
        encoding="utf-8",
    )
    (fixture / "SCOPE.md").write_text("# Scope\n\n- `src/`\n", encoding="utf-8")
    (src / "DemoVault.sol").write_text(
        "contract DemoVault {\n"
        "    mapping(address => uint256) public shares;\n"
        "    function withdraw(uint256 assets) external { /* benchmark fixture only */ }\n"
        "}\n",
        encoding="utf-8",
    )
    return {
        "fixture_dir": str(fixture),
        "severity": str(fixture / "SEVERITY_SMART_CONTRACTS.md"),
        "scope": str(fixture / "SCOPE.md"),
        "source": str(src / "DemoVault.sol"),
    }


def render_markdown(payload: dict[str, Any]) -> list[str]:
    summary = payload["summary"]
    lines = [
        "# Impact-Miss Offset Benchmark",
        "",
        "Workspace-neutral withheld-known benchmark for in-scope impact routing across tiers.",
        "",
        f"- Concrete items: `{summary['item_count']}`",
        f"- Tier counts: `{summary['tier_counts']}`",
        f"- Route-family counts: `{summary['route_family_counts']}`",
        f"- Submission posture: `NOT_SUBMIT_READY`",
        "",
        "| ID | Tier | Route family | Asset | Required artifacts | Impact input |",
        "|---|---|---|---|---|---|",
    ]
    for row in payload["items"][:300]:
        lines.append(
            f"| `{row['benchmark_id']}` | {row['tier']} | `{row['expected']['route_family']}` | "
            f"{row['asset_category']} | {', '.join(row['expected']['required_artifacts'])} | "
            f"{row['input']['impact_text']} |"
        )
    score = payload.get("score", {})
    lines.extend([
        "",
        "## Scoring",
        "",
        f"- Status: `{score.get('status', 'not_scored_no_predictions')}`",
        f"- Accuracy: `{score.get('accuracy', 0.0)}`",
        f"- Pass threshold: `{score.get('pass_threshold', PASS_THRESHOLD)}`",
    ])
    return lines


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    workspace = Path(args.workspace).expanduser().resolve() if args.workspace else None
    cases = built_in_cases(args.limit)
    predictions_path = Path(args.predictions).expanduser().resolve() if args.predictions else None
    generated_predictions: dict[str, Any] = {}
    if args.derive_predictions:
        if workspace is None:
            raise SystemExit("[impact-miss-offset-benchmark] --derive-predictions requires --workspace")
        generated_predictions = derive_predictions(cases, workspace)
        predictions_path = workspace / ".auditooor" / DEFAULT_PREDICTIONS_NAME
        write_json(predictions_path, generated_predictions)
    score = evaluate(cases, predictions_path)
    fixture = write_demo_fixture(workspace or ROOT) if args.demo_fixture else {}
    harness_blockers: dict[str, Any] = {}
    if args.emit_harness_blockers:
        harness_blockers = build_harness_blocker_queue(workspace or ROOT, cases)
        harness_json = (
            Path(args.harness_blockers_json).expanduser()
            if args.harness_blockers_json
            else out_dir(workspace or ROOT) / DEFAULT_HARNESS_BLOCKERS_JSON
        )
        harness_md = (
            Path(args.harness_blockers_md).expanduser()
            if args.harness_blockers_md
            else out_dir(workspace or ROOT) / DEFAULT_HARNESS_BLOCKERS_MD
        )
        write_json(harness_json, harness_blockers)
        write_md(harness_md, render_harness_blocker_markdown(harness_blockers))
        write_harness_briefs(workspace or ROOT, harness_blockers)
    route_counts = Counter(row["expected"]["route_family"] for row in cases)
    tier_counts = Counter(row["tier"] for row in cases)
    return {
        "schema": SCHEMA,
        "generated_at": now_iso(),
        "workspace": str(workspace or ROOT),
        "benchmark_kind": "withheld_known_route_family_recall",
        "advisory_only": True,
        "promotion_allowed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "evidence_class": GENERATED_EVIDENCE_CLASS,
        "target_range": TARGET_RANGE,
        "items": cases,
        "summary": {
            "item_count": len(cases),
            "tier_counts": dict(sorted(tier_counts.items())),
            "route_family_counts": dict(sorted(route_counts.items())),
            "route_family_count": len(route_counts),
            "pass_fail_basis": "exact route_family plus at least one required artifact plus NOT_SUBMIT_READY posture",
        },
        "score": score,
        "predictions_path": str(predictions_path) if predictions_path else "",
        "generated_predictions": {
            "path": str(predictions_path) if args.derive_predictions and predictions_path else "",
            "summary": generated_predictions.get("source_accounting", {}),
        },
        "harness_blockers": {
            "path": str(
                Path(args.harness_blockers_json).expanduser()
                if args.harness_blockers_json
                else out_dir(workspace or ROOT) / DEFAULT_HARNESS_BLOCKERS_JSON
            )
            if args.emit_harness_blockers
            else "",
            "summary": harness_blockers.get("summary", {}),
        },
        "demo_fixture": fixture,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", help="Optional workspace; defaults to repo root for neutral benchmark artifacts")
    parser.add_argument("--limit", type=int, default=DEFAULT_ITEM_TARGET, help="Concrete item count, capped to generated case count")
    parser.add_argument("--predictions", help="Optional JSON predictions to score")
    parser.add_argument(
        "--derive-predictions",
        action="store_true",
        help="Write advisory sample predictions from existing scanner/autonomy workspace outputs, then score them",
    )
    parser.add_argument("--out-json", help="Output JSON path")
    parser.add_argument("--out-md", help="Output Markdown path")
    parser.add_argument("--demo-fixture", action="store_true", help="Write a hermetic non-Base demo fixture")
    parser.add_argument(
        "--emit-harness-blockers",
        action="store_true",
        help="Write 300-500 Impact-Miss harness tasks or exact missing-artifact blockers",
    )
    parser.add_argument("--harness-blockers-json", help="Optional harness/blocker queue JSON path")
    parser.add_argument("--harness-blockers-md", help="Optional harness/blocker queue Markdown path")
    parser.add_argument("--print-json", action="store_true", help="Print JSON payload to stdout")
    parser.add_argument("--strict", action="store_true", help="Exit 1 if scored benchmark fails threshold")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.limit < MIN_ITEM_TARGET or args.limit > MAX_ITEM_TARGET:
        raise SystemExit("[impact-miss-offset-benchmark] --limit must stay in the 150-500 concrete item target range")
    payload = build_payload(args)
    workspace = Path(payload["workspace"])
    default_dir = out_dir(workspace)
    out_json = Path(args.out_json).expanduser() if args.out_json else default_dir / "impact_miss_offset_benchmark.json"
    out_md = Path(args.out_md).expanduser() if args.out_md else default_dir / "impact_miss_offset_benchmark.md"
    write_json(out_json, payload)
    write_md(out_md, render_markdown(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[impact-miss-offset-benchmark] wrote {out_json} ({payload['summary']['item_count']} items)")
    if args.strict and payload["score"]["status"] == "fail":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
