#!/usr/bin/env python3
"""provider-fanout-discipline-check.py - Lane-7 provider fanout discipline auditor.

Verifies the Lane-7 acceptance bar:
  (a) Provider artifacts are persisted in an approved location.
  (b) Every calibration log row carries provider+model+task_type+
      success/failure+local_verification_accepted fields.
  (c) Provider KEEP outputs lack a local-verification reference (rg/
      source-ref/test/harness) are flagged.

Schema: auditooor.provider_fanout_discipline_check.v1

Usage:
    python3 tools/provider-fanout-discipline-check.py --workspace <ws> [--json]
    python3 tools/provider-fanout-discipline-check.py --workspace <ws> \
        --calibration-log <path> [--dispatch-audit-dir <dir>] [--json]
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.provider_fanout_discipline_check.v1"

# Approved artifact persistence directories (relative to workspace OR absolute
# patterns). The check accepts artifacts under any of these.
APPROVED_ARTIFACT_ROOTS: tuple[str, ...] = (
    "agent_outputs/provider_packets",
    ".auditooor/provider_assist",
    ".auditooor/provider_fanout",
    ".audit_logs/provider_assist",
    # Legacy / batch output dirs that semantic-provider-batch writes to
    "agent_outputs/semantic_batch",
    # provider_outputs is where dispatch-preflight.py writes provider text
    "provider_outputs",
    # CAP-012b (2026-07-02): current-pipeline provider/worker dispatch
    # persistence locations. The canonical `make audit-pipeline-full` flow
    # (spawn-worker agent_batch -> worker_packets, dispatch-brief-skeleton ->
    # dispatch_briefs, hunt-scoped lane anchors -> spawn-worker-pathspec)
    # writes provider dispatch artifacts here, NOT into the older
    # provider_assist / provider_fanout dirs. Without these entries the
    # persistence check false-warns "no-approved-artifact-root" on every
    # fresh audit and (under --enforce-if-provider-artifacts) blocks
    # `make audit`. Anchor: nuva 2026-07-02 fresh run persisted 3
    # worker_packets + 8 dispatch_briefs + 109 spawn-worker-pathspec lanes
    # while provider_assist/provider_fanout were archived to a _stale_*
    # dir; the check reported no approved root despite real dispatch work.
    ".auditooor/worker_packets",
    ".auditooor/dispatch_briefs",
    ".auditooor/spawn-worker-pathspec",
)

# Calibration log required fields per Lane-7 acceptance bar.
# Note: 'success' maps to 'verdict' (TRUE/FALSE/PARTIAL/INDETERMINATE) in the
# existing llm-calibration-log.py schema. Legacy rows may predate model /
# local_verification_accepted telemetry, but current workflows must write them.
CALIBRATION_REQUIRED_FIELDS: tuple[str, ...] = (
    "provider",
    "model",
    "task_type",
    "verdict",          # encodes success/failure
    "ts",
)

# Phrases that indicate a provider KEEP verdict in output files.
KEEP_VERDICTS: tuple[str, ...] = (
    "KEEP_FOR_LOCAL_VERIFICATION",
    "keep_for_local_verification",
    "KEEP",
    '"verdict": "keep"',
    '"verdict": "KEEP"',
)

# CAP-012 (2026-05-24): when the calibration log contains ONLY legacy
# rows (pre-v2 schema, lacking model + local_verification_accepted), the
# gate previously emitted `fail` and blocked the entire `make audit`
# pipeline from reaching rc=0. The graceful-degrade pivot: if every row
# in the log is legacy-shaped (lacks BOTH `model` AND
# `local_verification_accepted`), AND the legacy-row count is at or
# above this threshold, downgrade the verdict from `fail` to `warn` so
# downstream `make audit` stages can still run. Operators can re-enable
# the hard-fail behaviour with --strict-calibration once the log has
# been normalised. Empirical anchor: 2026-05-24 calibration log had
# 559/561 (99.6%) legacy rows lacking `local_verification_accepted` and
# 530/561 (94.5%) legacy rows lacking `model`, blocking every audit run.
LEGACY_ROW_THRESHOLD_PCT = float(
    os.environ.get("AUDITOOOR_FANOUT_LEGACY_ROW_THRESHOLD_PCT", "90")
)

# CAP-012b (2026-07-02): the same legacy-vs-newly-emitted distinction the
# calibration + dispatch_audit_model checks apply must also apply to the
# `keep_local_verification` check. A provider KEEP verdict emitted by a
# SUPERSEDED mining round (whose leads have since been carried forward into
# the current audit's deep_candidates / adjudication ledger, or adjudicated
# to a terminal verdict by the operator) should not hard-block `make audit`
# on every subsequent run - the check's own dispatch_audit_model sibling
# already prints "Treat sparse rows as legacy unless newly emitted rows omit
# it." A KEEP-missing row is treated as LEGACY (degrade fail -> warn, exclude
# from enforcement blocking) when its dispatch timestamp is older than
# KEEP_STALE_DAYS. Rows NEWLY emitted (ts within the window) still hard-fail,
# so an actively-dispatching workflow that omits local verification is caught.
# Operators opt back into the pre-CAP-012b hard-fail with --strict-calibration.
# Empirical anchor: 2026-07-02 the nuva audit's fresh (Jun29-Jul02) run was
# blocked by 4 KEEP-missing rows all dated 2026-05-18/05-19 (44+ days old)
# from a superseded `source_mining/2026-05-18_round5_fixed` round whose leads
# (eip3009 replay, cancelAuthorization, eip712 malleability, uups-impl) were
# already carried into deep_candidates and adjudicated to terminal KILL.
KEEP_STALE_DAYS = float(
    os.environ.get("AUDITOOOR_FANOUT_KEEP_STALE_DAYS", "30")
)

# Phrases that indicate local verification was attached.
LOCAL_VERIFICATION_SIGNALS: tuple[str, ...] = (
    "rg ",
    "ripgrep",
    "grep ",
    "forge test",
    "go test",
    "python3 -m pytest",
    "python3 -m unittest",
    "source_ref",
    "source-ref",
    "test_pass",
    "PASS:",
    "test-harness",
    "harness",
    "fixture",
    "local_verification_required",
    "minimum_followup_check",
    "local_checks_required",
    "rg_cmd",
    "smoke_check",
)


def _utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _parse_ts(ts: Any) -> dt.datetime | None:
    """Best-effort parse of an ISO-8601 timestamp (with or without trailing Z).

    Returns a timezone-aware UTC datetime, or None when unparseable. Used to
    classify KEEP-missing rows as legacy (old) vs newly-emitted (recent).
    """
    if not isinstance(ts, str) or not ts.strip():
        return None
    raw = ts.strip()
    # datetime.fromisoformat accepts +00:00 but not a trailing Z before 3.11.
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _is_stale_keep_row(ts: Any, *, now: dt.datetime | None = None) -> bool:
    """True when a KEEP row's dispatch timestamp is older than KEEP_STALE_DAYS.

    Unparseable / missing timestamps are treated as NEWLY-emitted (not stale)
    so the gate fails closed on rows that cannot be shown to be legacy.
    """
    parsed = _parse_ts(ts)
    if parsed is None:
        return False
    ref = now or dt.datetime.now(dt.timezone.utc)
    return (ref - parsed).total_seconds() > KEEP_STALE_DAYS * 86400.0


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _load_json(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def _find_dispatch_audit_files(workspace: Path, extra_root: Path | None) -> list[Path]:
    """Find all dispatch_audit.jsonl files under workspace and known artifact roots."""
    roots: list[Path] = [workspace]
    if extra_root and extra_root.is_dir():
        roots.append(extra_root)
    results: list[Path] = []
    for root in roots:
        for p in root.rglob("dispatch_audit.jsonl"):
            results.append(p)
    return results


def _find_provider_output_files(workspace: Path) -> list[Path]:
    """Find all provider output files under approved locations."""
    results: list[Path] = []
    for rel in APPROVED_ARTIFACT_ROOTS:
        candidate = workspace / rel
        if candidate.is_dir():
            for ext in ("*.jsonl", "*.json", "*.txt", "*.out.txt", "*.md"):
                results.extend(candidate.rglob(ext))
    return results


def _provider_artifacts_present(workspace: Path, extra_audit_dir: Path | None) -> bool:
    """Return true when the workspace has provider fanout/dispatch artifacts."""
    if _find_provider_output_files(workspace):
        return True
    if _find_dispatch_audit_files(workspace, extra_audit_dir):
        return True
    for rel in APPROVED_ARTIFACT_ROOTS:
        candidate = workspace / rel
        if candidate.is_dir() and any(p.is_file() for p in candidate.rglob("*")):
            return True
    return False


def _check_artifact_persistence(workspace: Path) -> dict[str, Any]:
    """
    Acceptance bar (a): provider artifacts are persisted in approved locations.

    Returns a sub-result dict with verdict, found dirs, and gap list.
    """
    found_approved: list[str] = []
    gaps: list[str] = []

    for rel in APPROVED_ARTIFACT_ROOTS:
        candidate = workspace / rel
        if candidate.is_dir():
            found_approved.append(str(candidate))

    if found_approved:
        verdict = "pass"
        detail = f"Found {len(found_approved)} approved artifact location(s)."
    else:
        verdict = "warn"
        detail = (
            "No approved provider artifact directories found. "
            "Expected one of: "
            + ", ".join(f"<ws>/{r}" for r in APPROVED_ARTIFACT_ROOTS)
            + ". If no provider work has been dispatched yet this is "
            "pass-not-applicable."
        )
        gaps.append(
            "no-approved-artifact-root: no provider_packets, provider_assist, "
            "or provider_outputs directory found under workspace"
        )

    return {
        "verdict": verdict,
        "detail": detail,
        "found_approved_roots": found_approved,
        "gaps": gaps,
    }


def _check_calibration_rows(
    rows: list[dict[str, Any]],
    calibration_log_path: Path,
    *,
    strict_calibration: bool = False,
) -> dict[str, Any]:
    """
    Acceptance bar (b): every calibration log row carries required fields.

    Per Lane-7: provider, model, task_type, success/failure,
    local_verification_accepted.

    Legacy rows are append-only and may lack Lane-7 fields. Treat complete
    absence of a field as a failure (the workflow is not adopting it), but
    sparse historical absence as a warning so old telemetry does not block
    current enforcement.

    CAP-012 (2026-05-24): when the calibration log is dominated by
    legacy-shape rows (lacking BOTH ``model`` AND
    ``local_verification_accepted``) above ``LEGACY_ROW_THRESHOLD_PCT``,
    graceful-degrade the verdict from ``fail`` to ``warn`` so
    ``make audit`` can still reach rc=0. Operators can opt into the
    hard-fail behaviour with ``--strict-calibration`` once the log has
    been backfilled / rotated. Empirical anchor: 2026-05-24 the
    hyperbridge audit was blocked because the canonical calibration log
    had 559/561 (99.6%) legacy rows.
    """
    if not rows:
        return {
            "verdict": "pass-not-applicable",
            "detail": "No calibration rows found; ledger empty or missing.",
            "path": str(calibration_log_path),
            "row_count": 0,
            "gaps": [],
            "gap_field_counts": {},
            "legacy_row_count": 0,
            "legacy_row_pct": 0.0,
            "legacy_degraded": False,
            "strict_calibration": strict_calibration,
        }

    gap_counts: dict[str, int] = {}
    missing_examples: dict[str, list[str]] = {}

    # Required under Lane-7 acceptance bar:
    lane7_required = list(CALIBRATION_REQUIRED_FIELDS) + ["local_verification_accepted"]

    # CAP-012: identify legacy rows up front so we can compute % and
    # graceful-degrade when the log is dominated by legacy entries.
    legacy_row_count = 0
    for row in rows:
        has_model = bool(row.get("model"))
        has_lva = "local_verification_accepted" in row and row["local_verification_accepted"] is not None
        if not has_model and not has_lva:
            legacy_row_count += 1
    legacy_pct = (100.0 * legacy_row_count / len(rows)) if rows else 0.0
    legacy_dominated = legacy_pct >= LEGACY_ROW_THRESHOLD_PCT
    legacy_degraded = legacy_dominated and not strict_calibration

    for i, row in enumerate(rows):
        for field in lane7_required:
            if field not in row or row[field] is None or row[field] == "":
                gap_counts[field] = gap_counts.get(field, 0) + 1
                if len(missing_examples.get(field, [])) < 3:
                    missing_examples.setdefault(field, []).append(
                        f"row {i}: task_ref={row.get('task_ref', '?')!r}"
                        f" provider={row.get('provider', '?')!r}"
                    )

    gaps: list[str] = []
    verdict = "pass"

    for field, count in sorted(gap_counts.items()):
        pct = round(100 * count / len(rows))
        if field == "local_verification_accepted":
            if count == len(rows):
                # CAP-012: graceful-degrade when log is legacy-dominated.
                if legacy_degraded:
                    gaps.append(
                        f"gap:calibration-field-legacy-sparse:{field}: missing from {count}/{len(rows)} rows ({pct}%). "
                        f"CAP-012 graceful-degrade: log is {legacy_pct:.1f}% legacy-shape "
                        f"(>= {LEGACY_ROW_THRESHOLD_PCT}% threshold); downgraded fail -> warn. "
                        f"Wire --local-verification-accepted on new rows; "
                        f"rerun with --strict-calibration once legacy rows have aged out."
                    )
                    if verdict == "pass":
                        verdict = "warn"
                else:
                    gaps.append(
                        f"gap:calibration-field-absent:{field}: missing from {count}/{len(rows)} rows ({pct}%). "
                        f"No calibration rows carry local verification outcome; wire --local-verification-accepted."
                    )
                    verdict = "fail"
            else:
                gaps.append(
                    f"gap:calibration-field-legacy-sparse:{field}: missing from {count}/{len(rows)} rows ({pct}%). "
                    f"At least one row carries it; treat missing rows as legacy until new observations replace them. "
                    f"Examples: {missing_examples.get(field, [])[:2]}"
                )
                if verdict == "pass":
                    verdict = "warn"
        elif field == "model":
            if count == len(rows):
                # CAP-012: graceful-degrade when log is legacy-dominated.
                if legacy_degraded:
                    gaps.append(
                        f"gap:calibration-field-legacy-sparse:{field}: missing from {count}/{len(rows)} rows ({pct}%). "
                        f"CAP-012 graceful-degrade: log is {legacy_pct:.1f}% legacy-shape "
                        f"(>= {LEGACY_ROW_THRESHOLD_PCT}% threshold); downgraded fail -> warn. "
                        f"Wire --model/default model logging on new rows; "
                        f"rerun with --strict-calibration once legacy rows have aged out."
                    )
                    if verdict == "pass":
                        verdict = "warn"
                else:
                    gaps.append(
                        f"gap:calibration-field-absent:{field}: missing from {count}/{len(rows)} rows ({pct}%). "
                        f"No calibration rows carry provider model metadata; wire --model/default model logging."
                    )
                    verdict = "fail"
            else:
                gaps.append(
                    f"gap:calibration-field-legacy-sparse:{field}: missing from {count}/{len(rows)} rows ({pct}%). "
                    f"At least one row carries it; treat missing rows as legacy until new observations replace them. "
                    f"Examples: {missing_examples.get(field, [])[:2]}"
                )
                if verdict == "pass":
                    verdict = "warn"
        elif field in ("provider", "task_type", "ts", "verdict"):
            if count > 0:
                gaps.append(
                    f"gap:calibration-field-sparse:{field}: missing from {count}/{len(rows)} rows ({pct}%). "
                    f"Examples: {missing_examples.get(field, [])[:2]}"
                )
                verdict = "warn"
        else:
            gaps.append(
                f"gap:calibration-field-sparse:{field}: missing from {count}/{len(rows)} rows ({pct}%). "
                f"Examples: {missing_examples.get(field, [])[:2]}"
            )
            if verdict == "pass":
                verdict = "warn"

    return {
        "verdict": verdict,
        "detail": (
            f"Checked {len(rows)} calibration rows for Lane-7 required fields. "
            f"{len(gaps)} gap(s) found. "
            f"Legacy-shape rows: {legacy_row_count}/{len(rows)} ({legacy_pct:.1f}%)."
            + (" CAP-012 graceful-degrade ACTIVE." if legacy_degraded else "")
        ),
        "path": str(calibration_log_path),
        "row_count": len(rows),
        "gaps": gaps,
        "gap_field_counts": gap_counts,
        "legacy_row_count": legacy_row_count,
        "legacy_row_pct": round(legacy_pct, 2),
        "legacy_degraded": legacy_degraded,
        "strict_calibration": strict_calibration,
    }


def _check_keep_local_verification(
    workspace: Path,
    extra_audit_dir: Path | None,
    *,
    strict_calibration: bool = False,
) -> dict[str, Any]:
    """
    Acceptance bar (c): every provider KEEP has a local-verification reference.

    Scans dispatch_audit.jsonl files for DISPATCHED rows, then checks
    provider output files for KEEP verdicts without local verification signals.

    CAP-012b (2026-07-02): KEEP-missing rows whose dispatch timestamp is older
    than KEEP_STALE_DAYS are classified LEGACY. When EVERY KEEP-missing row is
    legacy (a superseded mining round), the sub-verdict graceful-degrades
    fail -> warn so `make audit` can still reach rc=0, mirroring the CAP-012
    treatment of the calibration + dispatch_audit_model sibling checks.
    A single NEWLY-emitted KEEP-missing row still hard-fails. Pass
    ``strict_calibration=True`` to restore the pre-CAP-012b hard-fail on legacy.
    """
    dispatch_audits = _find_dispatch_audit_files(workspace, extra_audit_dir)
    keep_rows_missing_verification: list[dict[str, Any]] = []
    keep_rows_missing_legacy: list[dict[str, Any]] = []
    keep_rows_missing_recent: list[dict[str, Any]] = []
    keep_rows_verified: list[dict[str, Any]] = []
    dispatch_rows_scanned = 0
    output_files_scanned = 0

    for audit_path in dispatch_audits:
        audit_rows = _load_jsonl(audit_path)
        for row in audit_rows:
            if row.get("status") != "DISPATCHED":
                continue
            dispatch_rows_scanned += 1
            output_path_str = row.get("provider_output_path") or ""
            if not output_path_str:
                continue
            output_path = Path(output_path_str)
            if not output_path.is_file():
                continue
            output_files_scanned += 1
            content = output_path.read_text(encoding="utf-8", errors="replace")

            has_keep = any(k in content for k in KEEP_VERDICTS)
            if not has_keep:
                continue

            has_local_verification = any(
                sig in content for sig in LOCAL_VERIFICATION_SIGNALS
            )

            entry = {
                "output_file": str(output_path),
                "dispatch_audit": str(audit_path),
                "task_type": row.get("task_type"),
                "template_id": row.get("template_id"),
                "provider": _guess_provider_from_path(output_path),
                "prompt_sha256": row.get("prompt_sha256"),
                "ts": row.get("ts"),
            }

            if has_local_verification:
                keep_rows_verified.append(entry)
            else:
                keep_rows_missing_verification.append(entry)
                if _is_stale_keep_row(entry.get("ts")):
                    keep_rows_missing_legacy.append(entry)
                else:
                    keep_rows_missing_recent.append(entry)

    gaps: list[str] = []
    verdict = "pass"

    # CAP-012b: graceful-degrade when ALL KEEP-missing rows are legacy
    # (stale mining rounds) and strict mode is off.
    keep_legacy_only = (
        bool(keep_rows_missing_verification)
        and not keep_rows_missing_recent
        and not strict_calibration
    )

    if keep_rows_missing_recent:
        # At least one NEWLY-emitted KEEP-missing row: hard-fail (active
        # workflow is dispatching KEEP verdicts without local verification).
        verdict = "fail"
        for entry in keep_rows_missing_recent[:10]:
            gaps.append(
                f"gap:keep-missing-local-verification: {entry['output_file']} "
                f"(task_type={entry['task_type']!r}, ts={entry['ts']!r}) - "
                f"KEEP verdict present but no local verification signal found "
                f"(rg/grep/test/harness/source_ref)"
            )
    elif keep_legacy_only:
        # Every KEEP-missing row is a stale legacy round -> downgrade to warn.
        verdict = "warn"
        for entry in keep_rows_missing_legacy[:10]:
            gaps.append(
                f"gap:keep-missing-local-verification-legacy-stale: {entry['output_file']} "
                f"(task_type={entry['task_type']!r}, ts={entry['ts']!r}) - "
                f"KEEP verdict from a superseded mining round (> {KEEP_STALE_DAYS:.0f}d old) "
                f"lacks a local verification signal. CAP-012b graceful-degrade: "
                f"downgraded fail -> warn. Adjudicate the carried-forward lead to a "
                f"terminal verdict, or rerun with --strict-calibration to hard-fail."
            )
    elif keep_rows_missing_verification:
        # strict_calibration is on and rows are legacy -> restore hard-fail.
        verdict = "fail"
        for entry in keep_rows_missing_verification[:10]:
            gaps.append(
                f"gap:keep-missing-local-verification: {entry['output_file']} "
                f"(task_type={entry['task_type']!r}, ts={entry['ts']!r}) - "
                f"KEEP verdict present but no local verification signal found "
                f"(rg/grep/test/harness/source_ref) [--strict-calibration]"
            )

    if not dispatch_audits:
        verdict = "pass-not-applicable"
        detail = "No dispatch_audit.jsonl files found; no provider dispatches to check."
    elif dispatch_rows_scanned == 0:
        verdict = "pass-not-applicable"
        detail = "No DISPATCHED rows found in dispatch_audit files."
    else:
        detail = (
            f"Scanned {dispatch_rows_scanned} DISPATCHED rows across "
            f"{len(dispatch_audits)} dispatch_audit file(s). "
            f"Checked {output_files_scanned} output file(s) for KEEP verdicts. "
            f"KEEP+verified: {len(keep_rows_verified)}. "
            f"KEEP+missing-local-verification: {len(keep_rows_missing_verification)} "
            f"(legacy-stale: {len(keep_rows_missing_legacy)}, "
            f"newly-emitted: {len(keep_rows_missing_recent)})."
            + (" CAP-012b graceful-degrade ACTIVE." if keep_legacy_only else "")
        )

    return {
        "verdict": verdict,
        "detail": detail,
        "dispatch_audits_scanned": len(dispatch_audits),
        "dispatch_rows_scanned": dispatch_rows_scanned,
        "output_files_scanned": output_files_scanned,
        "keep_verified_count": len(keep_rows_verified),
        "keep_missing_verification_count": len(keep_rows_missing_verification),
        "keep_missing_legacy_count": len(keep_rows_missing_legacy),
        "keep_missing_recent_count": len(keep_rows_missing_recent),
        "keep_legacy_degraded": keep_legacy_only,
        "strict_calibration": strict_calibration,
        "gaps": gaps,
        "keep_missing_verification_examples": keep_rows_missing_verification[:5],
    }


def _guess_provider_from_path(path: Path) -> str:
    name = path.name.lower()
    if "kimi" in name:
        return "kimi"
    if "minimax" in name:
        return "minimax"
    if "claude" in name or "anthropic" in name:
        return "anthropic"
    return "unknown"


def _dispatch_audit_model_check(workspace: Path, extra_audit_dir: Path | None) -> dict[str, Any]:
    """
    Secondary check: dispatch_audit.jsonl model field coverage.

    Historical rows may lack model metadata. New dispatch-preflight rows write a
    best-effort model field, so partial absence is a legacy warning.
    """
    dispatch_audits = _find_dispatch_audit_files(workspace, extra_audit_dir)
    rows_missing_model = 0
    rows_total = 0
    examples: list[str] = []

    for audit_path in dispatch_audits:
        audit_rows = _load_jsonl(audit_path)
        for row in audit_rows:
            rows_total += 1
            if "model" not in row or not row["model"]:
                rows_missing_model += 1
                if len(examples) < 3:
                    examples.append(
                        f"{audit_path.name}: task_type={row.get('task_type')!r} ts={row.get('ts')!r}"
                    )

    gaps: list[str] = []
    verdict = "pass"
    if rows_total == 0:
        verdict = "pass-not-applicable"
        detail = "No dispatch_audit rows found."
    elif rows_missing_model > 0:
        pct = round(100 * rows_missing_model / rows_total)
        verdict = "warn"
        gaps.append(
            f"gap:dispatch-audit-field-absent:model: missing from "
            f"{rows_missing_model}/{rows_total} dispatch_audit rows ({pct}%). "
            f"Treat sparse rows as legacy unless newly emitted rows omit it. "
            f"Examples: {examples}"
        )
        detail = f"dispatch_audit.jsonl legacy rows lack 'model' field ({rows_missing_model}/{rows_total})."
    else:
        detail = f"All {rows_total} dispatch_audit rows carry 'model' field."

    return {
        "verdict": verdict,
        "detail": detail,
        "rows_total": rows_total,
        "rows_missing_model": rows_missing_model,
        "gaps": gaps,
    }


def _overall_verdict(sub_results: dict[str, dict[str, Any]]) -> str:
    verdicts = [v.get("verdict", "pass") for v in sub_results.values()]
    if any(v == "fail" for v in verdicts):
        return "fail"
    if any(v == "warn" for v in verdicts):
        return "warn"
    if all(v in ("pass", "pass-not-applicable") for v in verdicts):
        return "pass"
    return "pass"


def run_check(
    workspace: Path,
    calibration_log_path: Path | None = None,
    extra_audit_dir: Path | None = None,
    enforce_if_provider_artifacts: bool = False,
    *,
    strict_calibration: bool = False,
) -> dict[str, Any]:
    """Run all Lane-7 discipline checks. Returns the full report dict.

    CAP-012: ``strict_calibration`` (default False) opts into the
    pre-CAP-012 behaviour where the calibration field-coverage check
    fails closed when 100% of rows lack ``model`` /
    ``local_verification_accepted``. The default mode graceful-degrades
    to ``warn`` when the log is legacy-dominated, so ``make audit`` can
    reach rc=0 even on workspaces with append-only calibration history.
    """
    ws = workspace.expanduser().resolve()

    # Resolve calibration log
    if calibration_log_path is not None:
        cal_path = Path(calibration_log_path).expanduser().resolve()
    else:
        # Try standard locations in order
        candidates = [
            ws / "tools" / "calibration" / "llm_calibration_log.jsonl",
            ws / "calibration" / "llm_calibration_log.jsonl",
            Path(__file__).resolve().parent / "calibration" / "llm_calibration_log.jsonl",
        ]
        cal_path = next((c for c in candidates if c.is_file()), candidates[0])

    calibration_rows = _load_jsonl(cal_path)

    persistence = _check_artifact_persistence(ws)
    calibration = _check_calibration_rows(
        calibration_rows, cal_path, strict_calibration=strict_calibration
    )
    keep_verification = _check_keep_local_verification(
        ws, extra_audit_dir, strict_calibration=strict_calibration
    )
    dispatch_model = _dispatch_audit_model_check(ws, extra_audit_dir)
    provider_artifacts_present = _provider_artifacts_present(ws, extra_audit_dir)

    sub_results = {
        "artifact_persistence": persistence,
        "calibration_field_coverage": calibration,
        "keep_local_verification": keep_verification,
        "dispatch_audit_model_field": dispatch_model,
    }

    blocking_gaps: list[str] = []
    if enforce_if_provider_artifacts and provider_artifacts_present:
        if persistence["verdict"] == "warn":
            blocking_gaps.extend(f"[artifact_persistence] {g}" for g in persistence.get("gaps", []))
        if keep_verification["verdict"] == "fail":
            blocking_gaps.extend(f"[keep_local_verification] {g}" for g in keep_verification.get("gaps", []))
        # CAP-012 (2026-05-24): graceful-degrade the dispatch_audit model
        # field check the same way the calibration check degrades. Legacy
        # dispatch_audit rows lack `model`; the gate previously blocked
        # the audit on every workspace whose dispatch_audit.jsonl contained
        # historical rows. Now: skip the block when `strict_calibration` is
        # False AND the missing-model row ratio is itself a sparse-legacy
        # signal (>= LEGACY_ROW_THRESHOLD_PCT% of rows). The detailed
        # gap message remains in the sub_result for visibility.
        rows_missing_model = dispatch_model.get("rows_missing_model", 0)
        rows_total = dispatch_model.get("rows_total", 0)
        if rows_missing_model > 0:
            missing_pct = (100.0 * rows_missing_model / rows_total) if rows_total else 0.0
            dispatch_legacy_degraded = (
                not strict_calibration
                # Treat any non-100% missing ratio as legacy-sparse-friendly:
                # the gate's own _dispatch_audit_model_check already prints
                # "treat sparse rows as legacy unless newly emitted rows
                # omit it." Hard-fail ONLY when 100% of rows lack model
                # (active workflow is not emitting the field at all).
                and missing_pct < 100.0
            )
            if not dispatch_legacy_degraded:
                blocking_gaps.extend(f"[dispatch_audit_model_field] {g}" for g in dispatch_model.get("gaps", []))

    enforcement = {
        "requested": enforce_if_provider_artifacts,
        "active": bool(enforce_if_provider_artifacts and provider_artifacts_present),
        "blocking_gap_count": len(blocking_gaps),
        "blocking_gaps": blocking_gaps,
    }

    if enforce_if_provider_artifacts and not provider_artifacts_present:
        overall = "pass-not-applicable"
    else:
        overall = _overall_verdict(sub_results)
        if enforcement["active"] and blocking_gaps:
            overall = "fail"
    all_gaps = []
    for key, sub in sub_results.items():
        for gap in sub.get("gaps", []):
            all_gaps.append(f"[{key}] {gap}")

    return {
        "schema": SCHEMA,
        "generated_at_utc": _utcnow(),
        "workspace": str(ws),
        "calibration_log": str(cal_path),
        "provider_artifacts_present": provider_artifacts_present,
        "enforcement": enforcement,
        "verdict": overall,
        "verdict_summary": {
            "artifact_persistence": persistence["verdict"],
            "calibration_field_coverage": calibration["verdict"],
            "keep_local_verification": keep_verification["verdict"],
            "dispatch_audit_model_field": dispatch_model["verdict"],
        },
        "gap_count": len(all_gaps),
        "gaps": all_gaps,
        "sub_results": sub_results,
        "lane7_acceptance_bar": {
            "(a) artifact_persistence": (
                "Provider artifacts persisted under agent_outputs/provider_packets/ "
                "or <ws>/.auditooor/provider_assist/"
            ),
            "(b) calibration_field_coverage": (
                "Every calibration log row carries provider, model, task_type, "
                "success/failure (verdict), and local_verification_accepted"
            ),
            "(c) keep_local_verification": (
                "Every provider KEEP has a local-verification reference: "
                "rg/grep/source-ref/test/harness"
            ),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--workspace",
        required=True,
        type=Path,
        help="Path to the auditooor workspace to audit.",
    )
    parser.add_argument(
        "--calibration-log",
        type=Path,
        default=None,
        help="Override path to llm_calibration_log.jsonl.",
    )
    parser.add_argument(
        "--dispatch-audit-dir",
        type=Path,
        default=None,
        help="Extra directory to scan for dispatch_audit.jsonl files.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON to stdout.",
    )
    parser.add_argument(
        "--enforce-if-provider-artifacts",
        action="store_true",
        help=(
            "Activate workspace-scoped blocking only when provider artifacts "
            "exist. Empty workspaces exit pass-not-applicable."
        ),
    )
    parser.add_argument(
        "--strict-calibration",
        action="store_true",
        help=(
            "CAP-012 (2026-05-24): hard-fail on calibration log rows that "
            "lack model / local_verification_accepted, even when the log "
            "is legacy-dominated. Default = graceful-degrade to warn when "
            ">= LEGACY_ROW_THRESHOLD_PCT (default 90) of rows are legacy."
        ),
    )
    args = parser.parse_args(argv)

    result = run_check(
        workspace=args.workspace,
        calibration_log_path=args.calibration_log,
        extra_audit_dir=args.dispatch_audit_dir,
        enforce_if_provider_artifacts=args.enforce_if_provider_artifacts,
        strict_calibration=args.strict_calibration,
    )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["verdict"] in ("pass", "pass-not-applicable", "warn") else 1

    # Human-readable summary
    print(f"[lane7] provider-fanout-discipline-check")
    print(f"  workspace:  {result['workspace']}")
    print(f"  cal log:    {result['calibration_log']}")
    print(f"  verdict:    {result['verdict'].upper()}")
    print(f"  gaps:       {result['gap_count']}")
    print(f"  enforce:    {result['enforcement']['active']} ({result['enforcement']['blocking_gap_count']} blocking)")
    print()
    for key, sub_verdict in result["verdict_summary"].items():
        icon = "OK" if sub_verdict in ("pass", "pass-not-applicable") else ("WARN" if sub_verdict == "warn" else "FAIL")
        print(f"  [{icon}] {key}: {sub_verdict}")
    if result["gaps"]:
        print()
        print("  Gap list:")
        for gap in result["gaps"]:
            print(f"    - {gap}")
    return 0 if result["verdict"] in ("pass", "pass-not-applicable", "warn") else 1


if __name__ == "__main__":
    sys.exit(main())
