#!/usr/bin/env python3
"""agent-learning-gate.py - strict safety gate for mined agent artifacts.

This is intentionally narrower than the future Lane K learning compiler.  It
consumes the existing ``agent-artifact-miner.py`` report and enforces the
invariants that are already safe to gate today:

* provider-only rows must remain tier-5 quarantine;
* proof-mapping candidates must carry local proof;
* strict closeout must not ignore obvious workspace artifacts when no miner
  report exists;
* the two report locations currently used by the repo must not silently diverge.

The tool is offline-only and deterministic.  It does not re-run mining and does
not promote any artifact into memory or corpus state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.agent_learning_gate.v1"

ROOT_REPORT = "agent_artifact_mining_report.json"
AUDITOOOR_REPORT = ".auditooor/agent_artifact_mining_report.json"
LEDGER_CANDIDATES = (
    ".auditooor/agent_artifacts/learning_ledger.jsonl",
    ".auditooor/learning_ledger.jsonl",
    "learning_ledger.jsonl",
)
TERMINAL_KINDS = {
    "attack_record",
    "detector_hypothesis",
    "hacker_question",
    "kill_reason",
    "no_action",
    "proof_artifact",
    "proof_obligation",
    "triager_lesson",
    "triager_objection",
    "typed_lesson",
    "workflow_gap",
}
TERMINAL_OUTCOMES = {
    "curated_lesson",
    "needs_human_primary_review",
    "no_action",
    "rejected_duplicate",
    "rejected_false_positive",
    "rejected_oos",
    "verified_actionable",
    "verified_no_action",
}
NO_ACTION_OUTCOMES = {
    "blocked_malformed_output",
    "blocked_missing_model",
    "blocked_missing_receipt",
    "blocked_no_output",
    "needs_more_source",
    "no_action",
    "verified_no_action",
}
NO_ACTION_REASON_KEYS = (
    "reason",
    "no_action_reason",
    "decision_reason",
    "terminal_reason",
    "rationale",
    "detail",
)
EVIDENCE_POLARITIES = {"supports", "contradicts", "limits", "context_only"}
# K3a - terminal kinds whose semantics are negative/kill-class.  A row with one
# of these kinds MUST NOT simultaneously claim evidence_polarity='supports' AND
# primary_for='proof' - that would reuse a negative outcome as positive proof of
# exploit mechanics, which K3a explicitly forbids.
K3A_NEGATIVE_KINDS = {"kill_reason", "triager_objection"}
PRIMARY_FOR_SCOPES = {
    "proof",
    "dupe",
    "OOS",
    "economics",
    "severity_cap",
    "team_position",
    "source_reachability",
    "harness_gap",
    "methodology",
}
# K3 - only a primary signal may PROMOTE to a proof_artifact terminal row.
PRIMARY_PROMOTABLE_KINDS = {"proof_artifact"}
# K4 - canonical reuse_action enum; promotable rows must declare one.
K4_REUSE_ACTIONS = {
    "add_detector",
    "add_kill_rubric",
    "add_pre_submit_gate",
    "add_originality_check",
    "add_provider_prompt_constraint",
    "add_harness_template",
    "add_hacker_question",
    "none",
}
OBVIOUS_INPUT_DIRS = (
    "agent_outputs",
    "reports",
    "poc-tests",
    "submissions",
    "docs/archive/handoffs",
)
OBVIOUS_INPUT_FILES = (
    "SUBMISSIONS.md",
    ".auditooor/commit_lifecycle_ledger.json",
)


@dataclass(frozen=True)
class ReportRef:
    path: Path
    sha256: str
    payload: dict[str, Any]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_report(path: Path) -> tuple[ReportRef | None, dict[str, Any] | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - surface malformed local reports.
        return None, {
            "code": "malformed_report",
            "severity": "fail",
            "path": str(path),
            "detail": str(exc),
        }
    if not isinstance(payload, dict):
        return None, {
            "code": "malformed_report",
            "severity": "fail",
            "path": str(path),
            "detail": "top-level JSON is not an object",
        }
    return ReportRef(path=path, sha256=_sha256(path), payload=payload), None


def _has_any_file(path: Path) -> bool:
    if path.is_file():
        return True
    if not path.is_dir():
        return False
    for child in path.rglob("*"):
        if child.is_file() and not child.name.startswith("."):
            return True
    return False


def _has_obvious_artifact_inputs(workspace: Path) -> tuple[bool, list[str]]:
    evidence: list[str] = []
    for rel in OBVIOUS_INPUT_DIRS:
        path = workspace / rel
        if _has_any_file(path):
            evidence.append(rel)
    for rel in OBVIOUS_INPUT_FILES:
        path = workspace / rel
        if path.is_file() and path.stat().st_size > 0:
            evidence.append(rel)
    return bool(evidence), evidence


def _ledger_present(workspace: Path) -> tuple[bool, list[str]]:
    paths = [workspace / rel for rel in LEDGER_CANDIDATES]
    present = [str(path) for path in paths if path.is_file() and path.stat().st_size > 0]
    return bool(present), present


def _load_ledger_rows(workspace: Path) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    paths: list[str] = []
    errors: list[dict[str, Any]] = []
    for rel in LEDGER_CANDIDATES:
        path = workspace / rel
        if not path.is_file() or path.stat().st_size <= 0:
            continue
        paths.append(str(path.resolve()))
        for line_no, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                errors.append(
                    {
                        "code": "malformed_learning_ledger",
                        "severity": "fail",
                        "path": str(path.resolve()),
                        "line": line_no,
                        "detail": str(exc),
                    }
                )
                continue
            if not isinstance(row, dict):
                errors.append(
                    {
                        "code": "malformed_learning_ledger",
                        "severity": "fail",
                        "path": str(path.resolve()),
                        "line": line_no,
                        "detail": "ledger row is not a JSON object",
                    }
                )
                continue
            row["_ledger_path"] = str(path.resolve())
            row["_ledger_line"] = line_no
            rows.append(row)
    return rows, paths, errors


def _report_candidates(workspace: Path, explicit: Path | None) -> list[Path]:
    if explicit is not None:
        return [explicit]
    return [workspace / ROOT_REPORT, workspace / AUDITOOOR_REPORT]


def _artifact_ref(artifact: dict[str, Any], idx: int) -> dict[str, Any]:
    return {
        "index": idx,
        "artifact_id": artifact.get("artifact_id"),
        "artifact_type": artifact.get("artifact_type"),
        "title": artifact.get("title"),
        "provenance_ref": artifact.get("provenance_ref"),
        "verification_tier": artifact.get("verification_tier"),
        "provider_only": artifact.get("provider_only"),
        "source_has_local_proof": artifact.get("source_has_local_proof"),
    }


def _artifact_id(artifact: dict[str, Any]) -> str:
    for key in ("artifact_id", "id", "candidate_id", "source_ref"):
        value = str(artifact.get(key) or "").strip()
        if value:
            return value
    return ""


def _ledger_artifact_ids(row: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for key in (
        "artifact_id",
        "agent_artifact_id",
        "source_artifact_id",
        "candidate_id",
        "source_ref",
        "queue_id",
    ):
        value = str(row.get(key) or "").strip()
        if value:
            ids.add(value)
    for key in ("artifact_ids", "source_refs", "agent_artifact_ids"):
        value = row.get(key)
        if isinstance(value, list):
            ids.update(str(item).strip() for item in value if str(item).strip())
    return ids


def _normalized_value(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(row.get(key) or "").strip()
        if value:
            return value.lower()
    return ""


def _row_terminal_kind(row: dict[str, Any]) -> str:
    return _normalized_value(row, "terminal_kind", "kind", "compiled_kind", "output_kind")


def _row_terminal_outcome(row: dict[str, Any]) -> str:
    return _normalized_value(row, "terminal_outcome", "decision_outcome", "outcome", "status")


def _row_is_terminal(row: dict[str, Any]) -> bool:
    kind = _row_terminal_kind(row)
    outcome = _row_terminal_outcome(row)
    if kind in TERMINAL_KINDS:
        return True
    if outcome in TERMINAL_OUTCOMES or outcome.startswith("blocked_"):
        return True
    if row.get("terminal_for_source_coverage") is True:
        return True
    return False


def _row_is_no_action(row: dict[str, Any]) -> bool:
    kind = _row_terminal_kind(row)
    outcome = _row_terminal_outcome(row)
    if kind == "no_action" or outcome in NO_ACTION_OUTCOMES or outcome.startswith("blocked_"):
        return True
    return False


def _row_has_no_action_reason(row: dict[str, Any]) -> bool:
    for key in NO_ACTION_REASON_KEYS:
        value = str(row.get(key) or "").strip()
        if value:
            return True
    verification = row.get("verification")
    if isinstance(verification, dict):
        for key in ("status", "verifier_notes"):
            if str(verification.get(key) or "").strip():
                return True
    judgment = row.get("terminal_judgment")
    if isinstance(judgment, dict):
        for key in ("reason", "rationale", "summary"):
            if str(judgment.get(key) or "").strip():
                return True
    return False


def _row_has_local_verification(row: dict[str, Any]) -> bool:
    if row.get("local_verification_required") is False and str(row.get("source_verification_result") or "").strip():
        return True
    if str(row.get("local_verification_ref") or row.get("local_proof_ref") or "").strip():
        return True
    verification = row.get("verification")
    if isinstance(verification, dict):
        for ref in verification.get("evidence_refs") or []:
            if isinstance(ref, dict) and ref.get("verified") is True and str(ref.get("path") or "").strip():
                return True
    return False


def _row_scope_violation(row: dict[str, Any]) -> str:
    if not _row_is_terminal(row):
        return ""
    proposition = str(row.get("proposition") or "").strip()
    polarity = str(row.get("evidence_polarity") or "").strip()
    primary_for = str(row.get("primary_for") or "").strip()
    if not proposition:
        return "missing_proposition"
    if polarity not in EVIDENCE_POLARITIES:
        return "missing_or_invalid_evidence_polarity"
    if primary_for not in PRIMARY_FOR_SCOPES:
        return "missing_or_invalid_primary_for"
    return ""


def _row_is_provider_only(row: dict[str, Any]) -> bool:
    if row.get("provider_only") is True:
        return True
    origin = str(row.get("origin") or row.get("source") or "").strip().lower()
    return origin in {"provider", "v3-provider-fanout-closeout", "worker_only"}


def _row_promotion_escape(row: dict[str, Any]) -> str:
    """K3 - a non-primary / provider-only ledger row must not be a proof_artifact.

    Returns a non-empty escape code when a row claims a promotable proof kind
    without primary-signal backing.  ``provider_only_promotion_escape_count``
    keys off this; the acceptance target is 0.
    """
    kind = _row_terminal_kind(row)
    if kind not in PRIMARY_PROMOTABLE_KINDS:
        return ""
    if _row_is_provider_only(row):
        return "provider_only_row_promoted_to_proof_artifact"
    # A proof_artifact row must self-declare it is a primary signal AND carry
    # local proof; the compiler sets is_primary_signal / can_promote_to_proof.
    if row.get("is_primary_signal") is False or row.get("can_promote_to_proof") is False:
        return "non_primary_row_promoted_to_proof_artifact"
    if not _row_has_local_verification(row) and row.get("source_has_local_proof") is not True:
        return "proof_artifact_row_without_local_proof"
    return ""


def _row_reuse_action_violation(row: dict[str, Any]) -> str:
    """K4 - a K3a-compiled terminal row must declare a canonical reuse_action.

    Scoped to K3a-era rows (those that already carry proposition scope) so a
    pre-K4 legacy ledger is not retroactively failed.  A declared reuse_action
    that is not in the K4 enum is always a violation.
    """
    if not _row_is_terminal(row):
        return ""
    reuse_action = str(row.get("reuse_action") or "").strip()
    if reuse_action and reuse_action not in K4_REUSE_ACTIONS:
        return "invalid_reuse_action"
    is_k3a_row = bool(
        str(row.get("proposition") or "").strip()
        and str(row.get("evidence_polarity") or "").strip()
        and str(row.get("primary_for") or "").strip()
    )
    if is_k3a_row and not reuse_action:
        return "missing_reuse_action"
    return ""


def _row_negative_kind_positive_proof_violation(row: dict[str, Any]) -> str:
    """K3a - a negative/kill-class terminal row must not claim positive proof scope.

    Returns ``'k3a_negative_kind_claims_positive_proof'`` when a row whose
    ``terminal_kind`` is in ``K3A_NEGATIVE_KINDS`` simultaneously carries
    ``evidence_polarity='supports'`` AND ``primary_for='proof'``.

    The contradiction: a kill outcome (kill_reason, triager_objection) means the
    evidence shows the thing did NOT work, is OOS, or was rejected.  Labelling
    that same row as ``supports`` + ``proof`` would allow a negative outcome to
    be reused as positive proof of exploit mechanics, which K3a forbids.

    Legitimate uses of a kill-class row are NOT blocked:
    - evidence_polarity in {contradicts, limits, context_only}  ->  fine
    - primary_for outside {proof}  (e.g. OOS, dupe, severity_cap)  ->  fine
    Only the specific combination supports + proof on a negative kind is refused.
    """
    if not _row_is_terminal(row):
        return ""
    kind = _row_terminal_kind(row)
    if kind not in K3A_NEGATIVE_KINDS:
        return ""
    polarity = str(row.get("evidence_polarity") or "").strip().lower()
    primary = str(row.get("primary_for") or "").strip().lower()
    if polarity == "supports" and primary == "proof":
        return "k3a_negative_kind_claims_positive_proof"
    return ""


def _ledger_coverage(
    artifacts: list[dict[str, Any]],
    ledger_rows: list[dict[str, Any]],
) -> tuple[
    dict[str, dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    int,
    dict[str, int],
    dict[str, int],
]:
    by_id: dict[str, list[dict[str, Any]]] = {}
    terminal_kind_counts: Counter[str] = Counter()
    no_action_summary: Counter[str] = Counter()
    for row in ledger_rows:
        for artifact_id in _ledger_artifact_ids(row):
            by_id.setdefault(artifact_id, []).append(row)
        if _row_is_terminal(row):
            terminal_kind_counts[_row_terminal_kind(row) or _row_terminal_outcome(row) or "unknown"] += 1
        if _row_is_no_action(row):
            reason = "missing_reason"
            for key in NO_ACTION_REASON_KEYS:
                value = str(row.get(key) or "").strip()
                if value:
                    reason = value
                    break
            no_action_summary[reason] += 1

    covered: dict[str, dict[str, Any]] = {}
    unclassified: list[dict[str, Any]] = []
    no_action_without_reason: list[dict[str, Any]] = []
    provider_only_promotions: list[dict[str, Any]] = []
    for idx, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            continue
        artifact_id = _artifact_id(artifact)
        if not artifact_id:
            unclassified.append(_artifact_ref(artifact, idx))
            continue
        rows = by_id.get(artifact_id, [])
        terminal_rows = [row for row in rows if _row_is_terminal(row)]
        if not terminal_rows:
            unclassified.append(_artifact_ref(artifact, idx))
            continue
        bad_no_action = [row for row in terminal_rows if _row_is_no_action(row) and not _row_has_no_action_reason(row)]
        if bad_no_action:
            no_action_without_reason.append(
                {
                    "artifact": _artifact_ref(artifact, idx),
                    "ledger_rows": [
                        {
                            "path": row.get("_ledger_path"),
                            "line": row.get("_ledger_line"),
                            "terminal_kind": row.get("terminal_kind"),
                            "terminal_outcome": row.get("terminal_outcome") or row.get("decision_outcome"),
                        }
                        for row in bad_no_action
                    ],
                }
            )
            continue
        row = terminal_rows[0]
        if artifact.get("provider_only") is True and not _row_is_no_action(row) and not _row_has_local_verification(row):
            provider_only_promotions.append(
                {
                    "artifact": _artifact_ref(artifact, idx),
                    "ledger_row": {
                        "path": row.get("_ledger_path"),
                        "line": row.get("_ledger_line"),
                        "terminal_kind": row.get("terminal_kind"),
                        "terminal_outcome": row.get("terminal_outcome") or row.get("decision_outcome"),
                    },
                }
            )
            continue
        covered[artifact_id] = {
            "artifact": _artifact_ref(artifact, idx),
            "ledger_path": row.get("_ledger_path"),
            "ledger_line": row.get("_ledger_line"),
            "terminal_kind": row.get("terminal_kind") or row.get("kind"),
            "terminal_outcome": row.get("terminal_outcome") or row.get("decision_outcome") or row.get("outcome"),
        }
    return (
        covered,
        unclassified,
        no_action_without_reason,
        provider_only_promotions,
        len(by_id),
        dict(sorted(terminal_kind_counts.items())),
        dict(sorted(no_action_summary.items())),
    )


def evaluate(workspace: Path, *, report_path: Path | None = None, strict: bool = False) -> dict[str, Any]:
    workspace = workspace.resolve()
    candidates = _report_candidates(workspace, report_path)
    existing_paths = [path for path in candidates if path.is_file()]
    report_errors: list[dict[str, Any]] = []
    reports: list[ReportRef] = []
    for path in existing_paths:
        report, error = _load_report(path)
        if error:
            report_errors.append(error)
        elif report:
            reports.append(report)

    has_inputs, input_evidence = _has_obvious_artifact_inputs(workspace)
    ledger_rows, ledger_paths, ledger_errors = _load_ledger_rows(workspace)
    terminal_scope_violations = [
        {
            "path": row.get("_ledger_path"),
            "line": row.get("_ledger_line"),
            "artifact_ids": sorted(_ledger_artifact_ids(row)),
            "terminal_kind": row.get("terminal_kind") or row.get("kind"),
            "terminal_outcome": row.get("terminal_outcome") or row.get("decision_outcome") or row.get("outcome"),
            "violation": violation,
        }
        for row in ledger_rows
        for violation in [_row_scope_violation(row)]
        if violation
    ]
    # K3 - ledger-level promotion escapes: a provider-only / non-primary row
    # that nonetheless reached a proof_artifact terminal kind.
    ledger_promotion_escapes = [
        {
            "path": row.get("_ledger_path"),
            "line": row.get("_ledger_line"),
            "artifact_ids": sorted(_ledger_artifact_ids(row)),
            "terminal_kind": row.get("terminal_kind") or row.get("kind"),
            "promotion_class": row.get("promotion_class"),
            "escape": escape,
        }
        for row in ledger_rows
        for escape in [_row_promotion_escape(row)]
        if escape
    ]
    # K4 - terminal rows missing a canonical reuse_action.
    reuse_action_violations = [
        {
            "path": row.get("_ledger_path"),
            "line": row.get("_ledger_line"),
            "artifact_ids": sorted(_ledger_artifact_ids(row)),
            "terminal_kind": row.get("terminal_kind") or row.get("kind"),
            "reuse_action": row.get("reuse_action"),
            "violation": violation,
        }
        for row in ledger_rows
        for violation in [_row_reuse_action_violation(row)]
        if violation
    ]
    # K3a - negative-kind rows that claim positive proof scope.
    negative_kind_positive_proof_violations = [
        {
            "path": row.get("_ledger_path"),
            "line": row.get("_ledger_line"),
            "artifact_ids": sorted(_ledger_artifact_ids(row)),
            "terminal_kind": row.get("terminal_kind") or row.get("kind"),
            "evidence_polarity": row.get("evidence_polarity"),
            "primary_for": row.get("primary_for"),
            "violation": violation,
        }
        for row in ledger_rows
        for violation in [_row_negative_kind_positive_proof_violation(row)]
        if violation
    ]
    ledger_ok = bool(ledger_paths)
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    for error in report_errors:
        blockers.append(error)
    for error in ledger_errors:
        blockers.append(error)
    # K3 - a ledger promotion escape is a hard fail even when no miner report
    # is present (a stray proof_artifact row must never escape unreviewed).
    if ledger_promotion_escapes:
        blockers.append(
            {
                "code": "ledger_proof_artifact_promotion_escape",
                "severity": "fail",
                "count": len(ledger_promotion_escapes),
                "sample": ledger_promotion_escapes[:10],
                "detail": (
                    "only a primary signal may promote a learning row to "
                    "proof_artifact; provider-only / non-primary rows cannot"
                ),
            }
        )
    # K3a - negative-kind rows claiming positive proof scope are a hard fail
    # regardless of whether a miner report is present.
    if negative_kind_positive_proof_violations:
        blockers.append(
            {
                "code": "k3a_negative_kind_claims_positive_proof",
                "severity": "fail",
                "count": len(negative_kind_positive_proof_violations),
                "sample": negative_kind_positive_proof_violations[:10],
                "detail": (
                    "a kill_reason or triager_objection row must not carry "
                    "evidence_polarity='supports' together with primary_for='proof'; "
                    "a negative outcome cannot be reused as positive proof of exploit mechanics"
                ),
            }
        )

    if not reports:
        row = {
            "code": "missing_agent_artifact_report",
            "severity": "fail" if strict and has_inputs else "warn",
            "expected_paths": [str(path) for path in candidates],
            "obvious_artifact_inputs": input_evidence,
        }
        if row["severity"] == "fail":
            blockers.append(row)
        elif has_inputs:
            warnings.append(row)
        status = "fail" if blockers else ("warn" if warnings else "pass")
        return {
            "schema": SCHEMA_VERSION,
            "workspace": str(workspace),
            "strict": strict,
            "status": status,
            "report_paths_considered": [str(path) for path in candidates],
            "selected_report_path": None,
            "report_path_mismatch": False,
            "obvious_artifact_inputs": input_evidence,
            "learning_ledger_present": ledger_ok,
            "learning_ledger_paths": ledger_paths,
            "learning_ledger_rows": len(ledger_rows),
            "learning_ledger_covered_count": 0,
            "learning_ledger_known_artifact_ids": 0,
            "terminal_kind_counts": {},
            "no_action_summary": {},
            "unclassified_agent_artifact_count": 0,
            "unclassified_artifacts": [],
            "no_action_without_reason_count": 0,
            "provider_only_terminal_promotion_count": 0,
            "terminal_scope_violation_count": len(terminal_scope_violations),
            "terminal_scope_violations": terminal_scope_violations[:10],
            "ledger_promotion_escape_count": len(ledger_promotion_escapes),
            "ledger_promotion_escapes": ledger_promotion_escapes[:10],
            "reuse_action_violation_count": len(reuse_action_violations),
            "reuse_action_violations": reuse_action_violations[:10],
            "negative_kind_positive_proof_violation_count": len(negative_kind_positive_proof_violations),
            "negative_kind_positive_proof_violations": negative_kind_positive_proof_violations[:10],
            "ledger_malformed_row_count": len(ledger_errors),
            "artifact_id_missing_count": 0,
            "duplicate_artifact_id_count": 0,
            "artifact_count": 0,
            "provider_only_promotion_escape_count": len(ledger_promotion_escapes),
            "proof_mapping_without_local_proof_count": 0,
            "blockers": blockers,
            "warnings": warnings,
        }

    selected = reports[0]
    if len(reports) > 1 and len({report.sha256 for report in reports}) > 1:
        row = {
            "code": "agent_artifact_report_path_mismatch",
            "severity": "fail" if strict else "warn",
            "paths": [{"path": str(report.path), "sha256": report.sha256} for report in reports],
            "detail": "root and .auditooor agent artifact reports differ",
        }
        if strict:
            blockers.append(row)
        else:
            warnings.append(row)

    artifacts_raw = selected.payload.get("artifacts") or []
    if artifacts_raw and not isinstance(artifacts_raw, list):
        blockers.append(
            {
                "code": "malformed_artifacts_list",
                "severity": "fail",
                "detail": "report artifacts field is not a list",
            }
        )
        artifacts = []
    else:
        artifacts = artifacts_raw if isinstance(artifacts_raw, list) else []
    artifact_dicts = [artifact for artifact in artifacts if isinstance(artifact, dict)]
    artifact_ids = [_artifact_id(artifact) for artifact in artifact_dicts]
    missing_id_artifacts = [
        _artifact_ref(artifact, idx)
        for idx, artifact in enumerate(artifact_dicts)
        if not _artifact_id(artifact)
    ]
    duplicate_artifact_ids = sorted(
        artifact_id for artifact_id, count in Counter(artifact_id for artifact_id in artifact_ids if artifact_id).items() if count > 1
    )
    if missing_id_artifacts:
        row = {
            "code": "artifact_id_missing",
            "severity": "fail" if strict else "warn",
            "count": len(missing_id_artifacts),
            "sample": missing_id_artifacts[:10],
            "detail": "artifact rows require stable ids before terminal learning coverage can be enforced",
        }
        if strict:
            blockers.append(row)
        else:
            warnings.append(row)
    if duplicate_artifact_ids:
        row = {
            "code": "duplicate_artifact_id",
            "severity": "fail" if strict else "warn",
            "artifact_ids": duplicate_artifact_ids[:20],
            "detail": "duplicate artifact ids make terminal learning coverage ambiguous",
        }
        if strict:
            blockers.append(row)
        else:
            warnings.append(row)
    provider_escape_count = 0
    proof_without_local_count = 0
    (
        covered_artifacts,
        unclassified_artifacts,
        no_action_without_reason,
        provider_only_promotions,
        ledger_known_ids,
        terminal_kind_counts,
        no_action_summary,
    ) = _ledger_coverage(
        artifact_dicts,
        ledger_rows,
    )

    for idx, artifact_raw in enumerate(artifacts):
        if not isinstance(artifact_raw, dict):
            continue
        artifact = artifact_raw
        if artifact.get("provider_only") is True and artifact.get("verification_tier") != "tier-5-quarantine":
            provider_escape_count += 1
            blockers.append(
                {
                    "code": "provider_only_promotion_escape",
                    "severity": "fail",
                    "artifact": _artifact_ref(artifact, idx),
                    "detail": "provider-only artifacts must remain tier-5-quarantine",
                }
            )
        if (
            artifact.get("artifact_type") == "proof_artifact_mapping_candidate"
            and artifact.get("source_has_local_proof") is not True
        ):
            proof_without_local_count += 1
            blockers.append(
                {
                    "code": "proof_mapping_without_local_proof",
                    "severity": "fail",
                    "artifact": _artifact_ref(artifact, idx),
                    "detail": "proof mapping candidates require local proof evidence",
                }
            )

    if artifacts and not ledger_ok:
        row = {
            "code": "learning_ledger_missing",
            "severity": "fail" if strict else "warn",
            "expected_paths": [str(workspace / rel) for rel in LEDGER_CANDIDATES],
            "detail": "artifact report exists, but terminal learning ledger is not present",
        }
        if strict:
            blockers.append(row)
        else:
            warnings.append(row)
    elif artifacts and unclassified_artifacts:
        row = {
            "code": "unclassified_agent_artifacts",
            "severity": "fail" if strict else "warn",
            "unclassified_count": len(unclassified_artifacts),
            "sample": unclassified_artifacts[:10],
            "detail": "each mined artifact requires a terminal learning-ledger row or typed NO_ACTION disposition",
        }
        if strict:
            blockers.append(row)
        else:
            warnings.append(row)
    if artifacts and no_action_without_reason:
        row = {
            "code": "no_action_without_reason",
            "severity": "fail",
            "count": len(no_action_without_reason),
            "sample": no_action_without_reason[:10],
            "detail": "NO_ACTION learning rows must include a reason",
        }
        blockers.append(row)
    if artifacts and provider_only_promotions:
        row = {
            "code": "provider_only_terminal_promotion_without_local_verification",
            "severity": "fail",
            "count": len(provider_only_promotions),
            "sample": provider_only_promotions[:10],
            "detail": "provider-only artifacts cannot become terminal lessons unless local verification is represented",
        }
        blockers.append(row)
    if artifacts and terminal_scope_violations:
        row = {
            "code": "terminal_learning_row_missing_scope",
            "severity": "fail" if strict else "warn",
            "count": len(terminal_scope_violations),
            "sample": terminal_scope_violations[:10],
            "detail": "terminal learning rows must declare proposition, evidence_polarity, and primary_for scope",
        }
        if strict:
            blockers.append(row)
        else:
            warnings.append(row)
    # K3 ledger promotion escapes are emitted as a hard blocker earlier (before
    # the no-report early return) so both paths fail closed; not re-added here.
    # K4 - terminal rows must declare a canonical reuse_action.
    if reuse_action_violations:
        row = {
            "code": "terminal_learning_row_missing_reuse_action",
            "severity": "fail" if strict else "warn",
            "count": len(reuse_action_violations),
            "sample": reuse_action_violations[:10],
            "detail": (
                "every terminal learning row must declare a K4 reuse_action: "
                + ", ".join(sorted(K4_REUSE_ACTIONS))
            ),
        }
        if strict:
            blockers.append(row)
        else:
            warnings.append(row)
    # K3a - negative-kind rows must not claim positive proof scope.  This is a
    # hard fail regardless of strict mode: a kill_reason / triager_objection row
    # that claims evidence_polarity='supports' + primary_for='proof' violates
    # the K3a invariant that a negative outcome cannot be reused as positive
    # proof of exploit mechanics.
    if negative_kind_positive_proof_violations:
        blockers.append(
            {
                "code": "k3a_negative_kind_claims_positive_proof",
                "severity": "fail",
                "count": len(negative_kind_positive_proof_violations),
                "sample": negative_kind_positive_proof_violations[:10],
                "detail": (
                    "a kill_reason or triager_objection row must not carry "
                    "evidence_polarity='supports' together with primary_for='proof'; "
                    "a negative outcome cannot be reused as positive proof of exploit mechanics"
                ),
            }
        )

    status = "fail" if blockers else ("warn" if warnings else "pass")
    return {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "strict": strict,
        "status": status,
        "report_paths_considered": [str(path) for path in candidates],
        "selected_report_path": str(selected.path),
        "report_path_mismatch": any(row["code"] == "agent_artifact_report_path_mismatch" for row in blockers + warnings),
        "obvious_artifact_inputs": input_evidence,
        "learning_ledger_present": ledger_ok,
        "learning_ledger_paths": ledger_paths,
        "learning_ledger_rows": len(ledger_rows),
        "learning_ledger_covered_count": len(covered_artifacts),
        "learning_ledger_known_artifact_ids": ledger_known_ids,
        "terminal_kind_counts": terminal_kind_counts,
        "no_action_summary": no_action_summary,
        "unclassified_agent_artifact_count": len(unclassified_artifacts) if artifacts else 0,
        "unclassified_artifacts": unclassified_artifacts[:10] if artifacts else [],
        "no_action_without_reason_count": len(no_action_without_reason) if artifacts else 0,
        "provider_only_terminal_promotion_count": len(provider_only_promotions) if artifacts else 0,
        "terminal_scope_violation_count": len(terminal_scope_violations) if artifacts else 0,
        "terminal_scope_violations": terminal_scope_violations[:10] if artifacts else [],
        "ledger_promotion_escape_count": len(ledger_promotion_escapes),
        "ledger_promotion_escapes": ledger_promotion_escapes[:10],
        "reuse_action_violation_count": len(reuse_action_violations),
        "reuse_action_violations": reuse_action_violations[:10],
        "negative_kind_positive_proof_violation_count": len(negative_kind_positive_proof_violations),
        "negative_kind_positive_proof_violations": negative_kind_positive_proof_violations[:10],
        "ledger_malformed_row_count": len(ledger_errors),
        "artifact_id_missing_count": len(missing_id_artifacts),
        "duplicate_artifact_id_count": len(duplicate_artifact_ids),
        "artifact_count": len(artifacts),
        # K3 acceptance metric - artifact-tier escapes + ledger-tier escapes.
        "provider_only_promotion_escape_count": provider_escape_count + len(ledger_promotion_escapes),
        "proof_mapping_without_local_proof_count": proof_without_local_count,
        "blockers": blockers,
        "warnings": warnings,
    }


def _format_human(payload: dict[str, Any]) -> str:
    lines = [
        f"agent-learning-gate: {payload['status'].upper()}",
        f"workspace: {payload['workspace']}",
        f"selected_report_path: {payload.get('selected_report_path') or 'NONE'}",
        f"artifact_count: {payload['artifact_count']}",
        f"provider_only_promotion_escape_count: {payload['provider_only_promotion_escape_count']}",
        f"proof_mapping_without_local_proof_count: {payload['proof_mapping_without_local_proof_count']}",
        f"learning_ledger_present: {payload['learning_ledger_present']}",
        f"learning_ledger_covered_count: {payload.get('learning_ledger_covered_count', 0)}",
        f"unclassified_agent_artifact_count: {payload.get('unclassified_agent_artifact_count', 0)}",
        f"no_action_without_reason_count: {payload.get('no_action_without_reason_count', 0)}",
        f"provider_only_terminal_promotion_count: {payload.get('provider_only_terminal_promotion_count', 0)}",
        f"terminal_scope_violation_count: {payload.get('terminal_scope_violation_count', 0)}",
        f"ledger_promotion_escape_count: {payload.get('ledger_promotion_escape_count', 0)}",
        f"reuse_action_violation_count: {payload.get('reuse_action_violation_count', 0)}",
        f"negative_kind_positive_proof_violation_count: {payload.get('negative_kind_positive_proof_violation_count', 0)}",
        f"ledger_malformed_row_count: {payload.get('ledger_malformed_row_count', 0)}",
    ]
    for label in ("blockers", "warnings"):
        rows = payload.get(label) or []
        if not rows:
            continue
        lines.append(f"{label}:")
        for row in rows:
            detail = row.get("detail") or row.get("path") or row.get("expected_paths") or ""
            lines.append(f"- {row.get('code')}: {detail}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gate mined agent/provider artifacts before closeout.")
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--report", type=Path, help="Explicit agent_artifact_mining_report.json path.")
    parser.add_argument("--strict", action="store_true", help="Fail when obvious artifacts exist without a report.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human text.")
    args = parser.parse_args(argv)

    payload = evaluate(args.workspace, report_path=args.report, strict=args.strict)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(_format_human(payload))
    return 1 if payload["status"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
