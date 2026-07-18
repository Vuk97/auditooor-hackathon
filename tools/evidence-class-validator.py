#!/usr/bin/env python3
"""evidence-class-validator.py — scan closeout artifacts and report
per-``evidence_class`` counts (KNOWN_LIMITATIONS item #14).

Background
----------
Closeout consumers must NEVER treat generated candidates as proof. This
tool scans every closeout artifact that is supposed to carry the
``evidence_class`` field, partitions records into the canonical buckets
defined in ``tools/evidence_class.py``, and reports how many rows are
verified (``executed_with_manifest`` or above) versus hypothetical
(``generated_hypothesis``, ``scaffolded_unverified``, or missing).

Discipline
----------
- Stdlib only.
- Read-only / hermetic; never modifies inputs.
- Deterministic: per-class counts are sorted by canonical class order.
- Workspace-rooted; no GitHub or network access.

Usage
-----
::

    python3 tools/evidence-class-validator.py --workspace <ws>
    python3 tools/evidence-class-validator.py --workspace <ws> --json
    python3 tools/evidence-class-validator.py --workspace <ws> --strict

``--strict`` exits non-zero when any artifact contains rows missing the
``evidence_class`` field (legacy artifacts).

Exit codes
----------
0  no missing fields (or ``--strict`` not passed)
1  ``--strict`` and at least one legacy row
2  argument / I/O error
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent


def _load_evidence_class():
    spec = importlib.util.spec_from_file_location(
        "_evidence_class", HERE / "evidence_class.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


EC = _load_evidence_class()


# (label, glob_or_path) — same shape as audit-closeout-check.
ARTIFACTS = (
    ("brief_candidates", "swarm/brief_candidates.json"),
    ("source_mining_survivors", "source_mining/**/survivors.json"),
    (
        "deep_counterexample_records",
        "deep_counterexamples/*.deep_counterexample.v1.json",
    ),
    ("deep_counterexample_queue", "deep_counterexamples/execution_queue.json"),
    ("poc_execution_manifests", "poc_execution/**/execution_manifest.json"),
    ("impact_miss_benchmark", ".auditooor/impact_miss_offset_benchmark.json"),
    ("impact_miss_predictions", ".auditooor/impact_miss_offset_predictions.json"),
    ("impact_miss_harness_blockers", ".auditooor/impact_miss_harness_blocker_queue.json"),
    ("impact_miss_harness_execution", ".auditooor/impact_miss_harness_blocker_execution.json"),
    ("impact_proof_requirements", ".auditooor/impact_proof_requirement_manifests.json"),
    ("scanner_autonomy_plan", ".auditooor/scanner_autonomy_plan.json"),
    ("scanner_autonomy_execution", ".auditooor/scanner_autonomy_execution.json"),
    ("callgraph_terminal_conversion", ".auditooor/callgraph_terminal_conversion_*.json"),
    ("callgraph_fixture_smoke_evidence", ".auditooor/callgraph_fixture_smoke_evidence_*.json"),
    ("semantic_detector_argument_resolver", ".auditooor/semantic_detector_argument_resolver.json"),
    ("source_proof_impact_bridge", ".auditooor/source_proof_impact_bridge.json"),
    ("semantic_live_depth_blockers", ".auditooor/semantic_live_depth_blockers.json"),
    ("semantic_live_depth_queue", ".auditooor/semantic_live_depth_queue.json"),
    ("live_topology_proof_requirements", ".auditooor/live_topology_proof_requirements.json"),
    ("execution_proof_task_queue", ".auditooor/execution_proof_task_queue.json"),
    ("execution_proof_command_manifest", ".auditooor/execution_proof_command_manifest.json"),
    ("execution_proof_outcomes", ".auditooor/execution_proof_outcomes/*.json"),
    ("live_provider_result_triage", ".audit_logs/pr560_worker_*/live_provider_result_triage.json"),
    ("provider_local_verification_queue", ".audit_logs/pr560_worker_*/local_provider_verification_queue.json"),
    ("provider_result_local_verification", ".audit_logs/pr560_worker_*/provider_result_local_verification.json"),
    ("provider_local_verification_closure", ".audit_logs/pr560_worker_*/provider_local_verification_closure.json"),
)

ROW_CONTAINER_KEYS = (
    "candidates",
    "items",
    "rows",
    "tasks",
    "predictions",
    "requirements",
    "outcomes",
    "results",
    "fixture_needed_tasks",
    "local_grep_tasks",
    "source_review_tasks",
    "killed_rows",
)


def _read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _iter_artifact_records(ws: Path, glob_or_path: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        matches = sorted(ws.glob(glob_or_path))
    except OSError:
        return rows
    for path in matches:
        if path.name == "collection_manifest.json":
            continue
        if not path.is_file():
            continue
        data = _read_json(path)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    rows.append({**item, "_artifact_path": str(path)})
                else:
                    rows.append({"_artifact_path": str(path)})
            continue
        if isinstance(data, dict):
            container = None
            for key in ROW_CONTAINER_KEYS:
                child = data.get(key)
                if isinstance(child, list):
                    container = child
                    break
            if container is not None:
                for item in container:
                    if isinstance(item, dict):
                        rows.append({**item, "_artifact_path": str(path)})
                    else:
                        rows.append({"_artifact_path": str(path)})
                continue
            rows.append({**data, "_artifact_path": str(path)})
            continue
        rows.append({"_artifact_path": str(path)})
    return rows


def _is_truthy_bool(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _is_nonempty_false(value: Any) -> bool:
    return value is False or (isinstance(value, str) and value.strip().lower() == "false")


def _has_exact_state(record: dict[str, Any]) -> bool:
    """Return True when a row carries at least one exact proof-state marker.

    This is intentionally broad: different PR560 producers name the fields
    differently, but a submit-ready/proof row must expose some exact
    impact/source/scope state for a reviewer to audit.
    """
    exact_keys = (
        "selected_impact",
        "exact_impact",
        "exact_impact_row",
        "impact_assertion",
        "listed_impact_proven",
        "source_proof",
        "source_proofs",
        "source_hits",
        "source_paths",
        "final_verdict",
        "oos_status",
        "oos_verdict",
        "scope_status",
        "submission_posture",
    )
    for key in exact_keys:
        value = record.get(key)
        if value not in (None, "", [], {}):
            return True
    return False


def _policy_violations(label: str, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Find rows that would let advisory artifacts masquerade as proof.

    Missing ``evidence_class`` is counted separately as legacy. Policy
    violations are stronger shape problems: unverified rows marked
    submit-ready/promotable, or verified rows with no auditable impact/source
    / scope state.
    """
    violations: list[dict[str, Any]] = []
    for idx, rec in enumerate(records):
        evidence_class = rec.get("evidence_class")
        verified = EC.is_verified(evidence_class)
        artifact = str(rec.get("_artifact_path") or label)
        row_id = str(
            rec.get("requirement_id")
            or rec.get("task_id")
            or rec.get("queue_id")
            or rec.get("candidate_id")
            or rec.get("benchmark_id")
            or rec.get("id")
            or idx
        )

        if not verified and _is_truthy_bool(rec.get("submit_ready")):
            violations.append(
                {
                    "artifact": label,
                    "path": artifact,
                    "row_id": row_id,
                    "reason": "unverified_row_submit_ready_true",
                }
            )
        if not verified and _is_truthy_bool(rec.get("promotion_allowed")):
            violations.append(
                {
                    "artifact": label,
                    "path": artifact,
                    "row_id": row_id,
                    "reason": "unverified_row_promotion_allowed_true",
                }
            )
        if (
            not verified
            and rec.get("submit_ready") is not None
            and not _is_truthy_bool(rec.get("submit_ready"))
            and not _is_nonempty_false(rec.get("submit_ready"))
        ):
            violations.append(
                {
                    "artifact": label,
                    "path": artifact,
                    "row_id": row_id,
                    "reason": "unverified_row_submit_ready_not_false",
                }
            )
        if verified and not _has_exact_state(rec):
            violations.append(
                {
                    "artifact": label,
                    "path": artifact,
                    "row_id": row_id,
                    "reason": "verified_row_missing_exact_impact_source_or_scope_state",
                }
            )
    return violations


def collect(ws: Path) -> dict[str, Any]:
    """Build the validator payload for ``ws``."""
    per_artifact: dict[str, dict[str, Any]] = {}
    aggregate = EC.empty_counts()
    legacy_paths: list[str] = []
    for label, glob_or_path in ARTIFACTS:
        records = _iter_artifact_records(ws, glob_or_path)
        counts = EC.count_records(records)
        policy_violations = _policy_violations(label, records)
        aggregate = EC.merge_counts(aggregate, counts)
        legacy = [
            rec.get("_artifact_path", "")
            for rec in records
            if not EC.is_known(rec.get("evidence_class"))
        ]
        legacy_paths.extend(p for p in legacy if p)
        per_artifact[label] = {
            "artifact_glob": glob_or_path,
            "row_count": len(records),
            "counts": counts,
            "verified_count": EC.verified_total(counts),
            "hypothesis_count": EC.hypothesis_total(counts),
            "legacy_count": counts.get(EC.MISSING, 0),
            "policy_violation_count": len(policy_violations),
            "policy_violations_sample": policy_violations[:8],
        }
    legacy_unique = sorted(set(legacy_paths))
    return {
        "schema_version": EC.SCHEMA_VERSION,
        "workspace": str(ws),
        "evidence_classes": list(EC.EVIDENCE_CLASSES),
        "verified_classes": sorted(EC.VERIFIED_CLASSES),
        "per_artifact": per_artifact,
        "aggregate_counts": aggregate,
        "verified_count": EC.verified_total(aggregate),
        "hypothesis_count": EC.hypothesis_total(aggregate),
        "legacy_count": aggregate.get(EC.MISSING, 0),
        "legacy_artifact_paths": legacy_unique[:32],
        "legacy_artifact_path_total": len(legacy_unique),
        "policy_violation_count": sum(
            row["policy_violation_count"] for row in per_artifact.values()
        ),
        "policy_violations_sample": [
            violation
            for row in per_artifact.values()
            for violation in row["policy_violations_sample"]
        ][:32],
        "descriptions": EC.DESCRIPTIONS,
    }


def render_human(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"workspace: {payload['workspace']}")
    lines.append("")
    lines.append("Per-artifact counts (item #14):")
    width = max(len(name) for name in payload["per_artifact"]) if payload["per_artifact"] else 20
    lines.append(f"  {'artifact'.ljust(width)}  rows  verified  hypothesis  legacy  policy")
    for label, row in payload["per_artifact"].items():
        lines.append(
            f"  {label.ljust(width)}  "
            f"{row['row_count']:>4}  "
            f"{row['verified_count']:>8}  "
            f"{row['hypothesis_count']:>10}  "
            f"{row['legacy_count']:>6}  "
            f"{row['policy_violation_count']:>6}"
        )
    lines.append("")
    lines.append("Aggregate counts:")
    for cls in payload["evidence_classes"]:
        lines.append(f"  {cls}: {payload['aggregate_counts'][cls]}")
    lines.append(f"  missing: {payload['aggregate_counts'][EC.MISSING]}")
    lines.append("")
    lines.append(f"verified total:   {payload['verified_count']}")
    lines.append(f"hypothesis total: {payload['hypothesis_count']}")
    lines.append(f"legacy total:     {payload['legacy_count']}")
    lines.append(f"policy violations:{payload['policy_violation_count']:>6}")
    if payload["legacy_artifact_paths"]:
        lines.append("")
        lines.append("Legacy artifacts (sample):")
        for p in payload["legacy_artifact_paths"]:
            lines.append(f"  - {p}")
        if payload["legacy_artifact_path_total"] > len(payload["legacy_artifact_paths"]):
            lines.append(
                f"  ... (+{payload['legacy_artifact_path_total'] - len(payload['legacy_artifact_paths'])} more)"
            )
    if payload["policy_violations_sample"]:
        lines.append("")
        lines.append("Policy violations (sample):")
        for row in payload["policy_violations_sample"]:
            lines.append(
                f"  - {row['artifact']}:{row['row_id']} {row['reason']} ({row['path']})"
            )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of the human table")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when any artifact has rows missing the evidence_class field",
    )
    parser.add_argument(
        "--out-json",
        type=Path,
        help="Optional path to write the JSON payload alongside the chosen output mode",
    )
    args = parser.parse_args(argv)

    ws = args.workspace.expanduser()
    if not ws.exists():
        print(f"[evidence-class-validator] error: workspace not found: {ws}", file=sys.stderr)
        return 2
    if not ws.is_dir():
        print(f"[evidence-class-validator] error: not a directory: {ws}", file=sys.stderr)
        return 2

    payload = collect(ws)

    if args.out_json is not None:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_human(payload))

    if args.strict and (payload["legacy_count"] > 0 or payload["policy_violation_count"] > 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
