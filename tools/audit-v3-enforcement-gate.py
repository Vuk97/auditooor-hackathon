#!/usr/bin/env python3
"""Strict HACKERMAN V3 enforcement gate.

This gate intentionally separates "generated useful advisory context" from
"safe to treat the V3 roadmap as enforced".  It reads the local roadmap and
sidecar artifacts emitted by ``make v3-roadmap-sidecars`` and fails closed when
blocking categories remain partial/unmet.

Documented-blocker mechanism
-----------------------------
Pass ``--documented-blockers <path>`` to supply a JSON file (schema
``auditooor.v3_documented_blockers.v1``) that lists categories blocked by
genuine external constraints (no provider subscription, awaiting live-audit
outcome, etc.).  A valid documented-blocker entry reclassifies its matching
hard blocker into a separate ``documented_blockers`` list instead of the main
``blockers`` list, yielding verdict ``pass_with_documented_blockers`` rather
than ``fail``.  This is NOT a silent green pass - the output always carries a
``claim_guard`` string making the incompleteness explicit.

Tooling-category rejections
-----------------------------
Pure tooling categories (``named_tools``, ``makefile_targets``,
``sidecar_coverage``, ``lesson_gates``, ``workflow_coverage``) cannot be
documented-blocked.  An attempt to do so is itself a hard fail with code
``illegitimate_documented_blocker``.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.audit_v3_enforcement_gate.v1"
DOCUMENTED_BLOCKERS_SCHEMA = "auditooor.v3_documented_blockers.v1"

# Categories that empirical/provider constraints can legitimately block.
DOCUMENTABLE_CATEGORIES: set[str] = {
    "field_validation",
    "source_miners",
    "provider_campaign_completeness",
    "provider_keep_verification",
    "real_hunt_validation",
    "named_providers",
    # code-keyed (non-roadmap-category) blockers in the same
    # provider/empirical class that may be document-blocked:
    "provider_campaign_incomplete",
}

# Tooling categories that CANNOT be document-blocked - tooling gaps must be fixed.
TOOLING_ONLY_CATEGORIES: set[str] = {
    "named_tools",
    "makefile_targets",
    "sidecar_coverage",
    "lesson_gates",
    "workflow_coverage",
}

VALID_REASON_CODES: set[str] = {
    "no_provider_subscription",
    "empirical_pending_live_outcome",
    "source_data_unavailable",
}

DEFAULT_BLOCKING_CATEGORIES = {
    "field_validation",
    "source_miners",
    "sidecar_coverage",
    "provider_campaign_completeness",
    "provider_keep_verification",
    "lesson_gates",
    "real_hunt_validation",
}

REQUIRED_WORKFLOW_CONCEPTS = {
    "mcp_recall",
    "brain_prime_hacker_brief",
    "hacker_questions",
    "oos_scope",
    "dupe_risk",
    "originality",
    "candidate_judgment",
    "severity_calibration",
}

CLAIM_GUARD_MESSAGE = (
    "documented blockers remain; V3 roadmap is NOT empirically complete"
)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _artifact_path(root: Path, workspace: Path | None, repo_rel: str, ws_rel: str | None = None) -> Path:
    if workspace is not None and ws_rel:
        candidate = workspace / ws_rel
        if candidate.exists():
            return candidate
    return root / repo_rel


def _blocker_ledger_local_actionable_open(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    ledger_path = root / "reports" / "v3_blocker_ledger" / "blocker_ledger.json"
    raw = _read_json(ledger_path)
    summary: dict[str, Any] = {
        "path": _rel(ledger_path, root),
        "status": "missing",
        "open_count": 0,
        "local_actionable_open_count": 0,
        "declared_local_actionable_open_count": None,
    }
    if not isinstance(raw, dict):
        return summary, []

    rows = [row for row in raw.get("blockers") or [] if isinstance(row, dict)]
    open_rows = [
        row
        for row in rows
        if not str(row.get("status") or "").startswith("closed")
    ]
    local_rows = [
        row
        for row in open_rows
        if not bool(row.get("external_state_required"))
    ]
    summary.update(
        {
            "status": "present",
            "schema": raw.get("schema", ""),
            "tracked_total": len(rows),
            "open_count": len(open_rows),
            "declared_open_blocker_count": raw.get("open_blocker_count"),
            "local_actionable_open_count": len(local_rows),
            "declared_local_actionable_open_count": raw.get("local_actionable_open_count"),
        }
    )
    return summary, local_rows


def _today_iso() -> str:
    return date.today().isoformat()


def _parse_documented_blockers(db_path: Path) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse a documented-blockers file.

    Returns:
        active_map   - category_id -> entry for non-expired, valid entries
        parse_errors - list of error dicts (returned as warnings)
        expired_skip - list of entries that were skipped due to expiry
    """
    active_map: dict[str, dict[str, Any]] = {}
    parse_errors: list[dict[str, Any]] = []
    expired_skip: list[dict[str, Any]] = []

    raw = _read_json(db_path)
    if not isinstance(raw, dict):
        parse_errors.append({
            "code": "documented_blockers_file_unreadable",
            "detail": f"could not read or parse {db_path}",
        })
        return active_map, parse_errors, expired_skip

    entries = raw.get("entries")
    if not isinstance(entries, list):
        parse_errors.append({
            "code": "documented_blockers_no_entries_list",
            "detail": f"{db_path} has no 'entries' list",
        })
        return active_map, parse_errors, expired_skip

    today = _today_iso()
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            parse_errors.append({"code": "documented_blockers_entry_not_dict", "index": idx})
            continue

        category_id = entry.get("category_id")
        reason_code = entry.get("reason_code")
        evidence = entry.get("evidence")
        expires_at = entry.get("expires_at")

        # Required fields
        if not category_id or not isinstance(category_id, str):
            parse_errors.append({"code": "documented_blockers_missing_category_id", "index": idx})
            continue

        if reason_code not in VALID_REASON_CODES:
            parse_errors.append({
                "code": "documented_blockers_invalid_reason_code",
                "category_id": category_id,
                "reason_code": reason_code,
                "valid_reason_codes": sorted(VALID_REASON_CODES),
            })
            continue

        if not evidence or not isinstance(evidence, str):
            parse_errors.append({
                "code": "documented_blockers_missing_evidence",
                "category_id": category_id,
                "detail": "evidence field must be a non-empty string",
            })
            continue

        if not expires_at or not isinstance(expires_at, str):
            parse_errors.append({
                "code": "documented_blockers_missing_expires_at",
                "category_id": category_id,
            })
            continue

        # Expiry check - expired entries are silently skipped (blocker resurfaces)
        try:
            exp_date = expires_at[:10]  # accept ISO datetime or date
            if exp_date < today:
                expired_skip.append({"category_id": category_id, "expires_at": expires_at})
                continue
        except Exception:
            parse_errors.append({
                "code": "documented_blockers_bad_expires_at",
                "category_id": category_id,
                "expires_at": expires_at,
            })
            continue

        active_map[category_id] = entry

    return active_map, parse_errors, expired_skip


def build_gate(
    root: Path,
    *,
    workspace: Path | None = None,
    progress_path: Path | None = None,
    required_categories: set[str] | None = None,
    documented_blockers_path: Path | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    workspace = workspace.resolve() if workspace is not None else None
    required_categories = required_categories or DEFAULT_BLOCKING_CATEGORIES
    progress_path = progress_path or (root / "reports" / "v3_roadmap_progress_report.json")

    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    artifacts: dict[str, str] = {"progress": _rel(progress_path, root)}

    # Load documented-blockers if provided
    db_active: dict[str, dict[str, Any]] = {}
    if documented_blockers_path is not None:
        db_active, db_errors, db_expired = _parse_documented_blockers(documented_blockers_path)
        artifacts["documented_blockers"] = _rel(documented_blockers_path, root)
        if db_errors:
            warnings.append({"code": "documented_blockers_parse_errors", "errors": db_errors})
        if db_expired:
            warnings.append({"code": "documented_blockers_expired_entries_ignored", "entries": db_expired})

    progress = _read_json(progress_path)
    if not isinstance(progress, dict):
        blockers.append(
            {
                "code": "progress_report_missing_or_unreadable",
                "detail": f"could not read {progress_path}",
            }
        )
        progress = {}

    ledger_summary, local_actionable_rows = _blocker_ledger_local_actionable_open(root)
    artifacts["blocker_ledger"] = ledger_summary["path"]
    if local_actionable_rows:
        blockers.append(
            {
                "code": "blocker_ledger_local_actionable_open",
                "detail": (
                    "blocker ledger contains open blockers that are not marked "
                    "external-state-required; local closure or reclassification is "
                    "required before the V3 enforcement gate can pass"
                ),
                "local_actionable_open_count": len(local_actionable_rows),
                "local_actionable_open_ids": [
                    str(row.get("blocker_id") or row.get("id") or "")
                    for row in local_actionable_rows
                    if row.get("blocker_id") or row.get("id")
                ],
            }
        )
    elif ledger_summary.get("declared_local_actionable_open_count") not in (None, 0):
        blockers.append(
            {
                "code": "blocker_ledger_declares_local_actionable_open",
                "detail": (
                    "blocker ledger declares local-actionable open blockers; "
                    "refresh or reconcile the ledger before passing enforcement"
                ),
                "declared_local_actionable_open_count": ledger_summary.get(
                    "declared_local_actionable_open_count"
                ),
            }
        )

    categories = progress.get("categories") if isinstance(progress.get("categories"), dict) else {}
    for category_id in sorted(required_categories):
        row = categories.get(category_id) if isinstance(categories.get(category_id), dict) else None
        status = str(row.get("status") if row else "missing")
        if status != "met":
            blockers.append(
                {
                    "code": "roadmap_category_not_met",
                    "category_id": category_id,
                    "status": status,
                    "detail": _category_reason(progress, category_id, row),
                }
            )

    workflow_path = _artifact_path(
        root,
        workspace,
        ".auditooor/audit_workflow_coverage_map.json",
        ".auditooor/audit_workflow_coverage_map.json",
    )
    artifacts["audit_workflow_coverage_map"] = _rel(workflow_path, root)
    workflow = _read_json(workflow_path)
    if not isinstance(workflow, dict):
        blockers.append(
            {
                "code": "workflow_coverage_map_missing_or_unreadable",
                "detail": f"could not read {workflow_path}",
            }
        )
    else:
        concept_summary = workflow.get("concept_summary")
        if not isinstance(concept_summary, dict):
            blockers.append(
                {
                    "code": "workflow_concept_summary_missing",
                    "detail": f"{workflow_path} has no concept_summary object",
                }
            )
        else:
            for concept_id in sorted(REQUIRED_WORKFLOW_CONCEPTS):
                row = concept_summary.get(concept_id)
                if not isinstance(row, dict):
                    blockers.append(
                        {
                            "code": "workflow_required_concept_missing",
                            "concept_id": concept_id,
                            "detail": "required workflow concept absent from audit_workflow_coverage_map",
                        }
                    )
                    continue
                try:
                    present = int(row.get("present", 0) or 0)
                except (TypeError, ValueError):
                    present = 0
                if present <= 0:
                    blockers.append(
                        {
                            "code": "workflow_required_concept_not_present",
                            "concept_id": concept_id,
                            "summary": row,
                            "detail": "required workflow concept has no direct workflow wiring evidence",
                        }
                    )

    sidecar_path = root / ".auditooor" / "hackerman_sidecar_coverage_report.json"
    artifacts["hackerman_sidecar_coverage"] = _rel(sidecar_path, root)
    sidecar = _read_json(sidecar_path)
    if not isinstance(sidecar, dict):
        blockers.append({"code": "sidecar_coverage_missing", "detail": f"could not read {sidecar_path}"})
    else:
        sidecar_blockers = sidecar.get("blockers") if isinstance(sidecar.get("blockers"), list) else []
        if sidecar.get("status") != "ok" or sidecar_blockers:
            blockers.append(
                {
                    "code": "sidecar_coverage_blocked",
                    "status": sidecar.get("status"),
                    "blockers": sidecar_blockers[:8],
                }
            )
        sidecar_warnings = []
        for row in sidecar.get("sidecars", []) if isinstance(sidecar.get("sidecars"), list) else []:
            if isinstance(row, dict) and row.get("warnings"):
                sidecar_warnings.append(
                    {
                        "name": row.get("name"),
                        "warnings": row.get("warnings"),
                        "size_bytes": row.get("size_bytes"),
                    }
                )
        if sidecar_warnings:
            warnings.append({"code": "sidecar_warnings", "sidecars": sidecar_warnings})

    lesson_path = root / ".auditooor" / "lesson_source_inventory.json"
    artifacts["lesson_source_inventory"] = _rel(lesson_path, root)
    lesson = _read_json(lesson_path)
    if not isinstance(lesson, dict):
        blockers.append({"code": "lesson_source_inventory_missing", "detail": f"could not read {lesson_path}"})
    else:
        source_blockers = lesson.get("coverage_blockers") if isinstance(lesson.get("coverage_blockers"), list) else []
        if source_blockers:
            blockers.append(
                {
                    "code": "lesson_source_coverage_blockers",
                    "blockers": source_blockers[:8],
                    "detail": "candidate lesson sources exist but are not promoted or explicitly rejected",
                }
            )

    anti_pattern_dir = root / "obsidian-vault" / "anti-patterns"
    anti_pattern_notes = sorted(anti_pattern_dir.glob("*.md")) if anti_pattern_dir.is_dir() else []
    artifacts["anti_pattern_corpus"] = _rel(anti_pattern_dir, root)
    if not anti_pattern_notes:
        blockers.append(
            {
                "code": "anti_pattern_corpus_empty",
                "detail": (
                    "vault_anti_pattern_corpus has no notes; run "
                    "`make anti-pattern-corpus-bootstrap` before strict V3 work"
                ),
            }
        )

    provider_path = _artifact_path(
        root,
        workspace,
        ".auditooor/v3_provider_campaign_completeness_gate.json",
        ".auditooor/v3_provider_campaign_completeness_gate.json",
    )
    artifacts["provider_campaign_completeness"] = _rel(provider_path, root)
    provider = _read_json(provider_path)
    if isinstance(provider, dict) and provider.get("status") not in (None, "pass", "ok"):
        blockers.append(
            {
                "code": "provider_campaign_incomplete",
                "status": provider.get("status"),
                "blockers": provider.get("blockers", [])[:8] if isinstance(provider.get("blockers"), list) else [],
                "claim_guard": "Provider output remains quarantined until this gate passes.",
            }
        )

    # ---- Documented-blocker reclassification ----
    # Runs only when db_active has entries (--documented-blockers was passed).
    hard_blockers: list[dict[str, Any]] = []
    documented_blockers_list: list[dict[str, Any]] = []
    illegitimate: list[dict[str, Any]] = []

    if db_active:
        # Check for illegitimate attempts to document-block tooling categories
        for cat_id, entry in db_active.items():
            if cat_id in TOOLING_ONLY_CATEGORIES:
                illegitimate.append({
                    "code": "illegitimate_documented_blocker",
                    "category_id": cat_id,
                    "detail": (
                        f"category '{cat_id}' is a tooling-only category and cannot be "
                        "document-blocked; fix the tooling gap instead"
                    ),
                })
            elif cat_id not in DOCUMENTABLE_CATEGORIES:
                # Unknown category - treat as illegitimate to be safe
                illegitimate.append({
                    "code": "illegitimate_documented_blocker",
                    "category_id": cat_id,
                    "detail": (
                        f"category '{cat_id}' is not in the documentable-categories allowlist"
                    ),
                })

        if illegitimate:
            # Illegitimate entries are themselves hard failures
            hard_blockers.extend(illegitimate)

        # Warn if an entry documents a category that is actually already met
        met_documented: list[str] = []
        remaining_after_reclassify: list[dict[str, Any]] = []
        for blocker in blockers:
            # Match a documented-blocker entry by roadmap category_id OR, for
            # non-category code-keyed blockers (e.g. provider_campaign_incomplete),
            # by the blocker's `code`.
            cat_id = blocker.get("category_id")
            if not (cat_id and cat_id in db_active):
                cat_id = blocker.get("code")
            if cat_id and cat_id in db_active and cat_id not in TOOLING_ONLY_CATEGORIES and cat_id in DOCUMENTABLE_CATEGORIES:
                # Reclassify into documented_blockers
                documented_blockers_list.append({
                    "blocker": blocker,
                    "documented_by": db_active[cat_id],
                })
            else:
                remaining_after_reclassify.append(blocker)

        hard_blockers.extend(remaining_after_reclassify)

        # Warn about met categories that have spurious documented-blocker entries
        original_cat_ids = {b.get("category_id") for b in blockers} | {b.get("code") for b in blockers}
        for cat_id in db_active:
            # If the category/code did not appear in blockers at all it was already met
            if cat_id not in original_cat_ids and cat_id not in TOOLING_ONLY_CATEGORIES and cat_id in DOCUMENTABLE_CATEGORIES:
                met_documented.append(cat_id)
        if met_documented:
            warnings.append({
                "code": "documented_blocker_for_already_met_category",
                "categories": met_documented,
                "detail": "documented-blocker entry exists for a category that is already met; entry is ignored",
            })
    else:
        hard_blockers = blockers

    # ---- Compute verdict ----
    if hard_blockers:
        verdict = "fail"
        claim_guard = None
    elif documented_blockers_list:
        verdict = "pass_with_documented_blockers"
        claim_guard = CLAIM_GUARD_MESSAGE
    else:
        verdict = "pass"
        claim_guard = None

    result: dict[str, Any] = {
        "schema": SCHEMA,
        "verdict": verdict,
        "status": verdict,
        "root": str(root),
        "workspace": str(workspace or ""),
        "required_categories": sorted(required_categories),
        "blockers": hard_blockers,
        "documented_blockers": documented_blockers_list,
        "warnings": warnings,
        "artifacts": artifacts,
        "policy": (
            "STRICT_HACKERMAN_V3 must fail on unresolved roadmap, sidecar, "
            "lesson-source, and provider-verification blockers."
        ),
    }
    if claim_guard is not None:
        result["claim_guard"] = claim_guard

    return result


def _category_reason(progress: dict[str, Any], category_id: str, row: dict[str, Any] | None) -> str:
    for blocker in progress.get("blocking_unmet_categories", []) if isinstance(progress.get("blocking_unmet_categories"), list) else []:
        if isinstance(blocker, dict) and blocker.get("category_id") == category_id:
            return str(blocker.get("reason") or "")
    if row:
        return str(row.get("summary") or row.get("reason") or "")
    return "category missing from progress report"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--progress", type=Path)
    parser.add_argument(
        "--required-category",
        action="append",
        default=[],
        help="Restrict blocking categories; may be repeated. Defaults to all roadmap blockers.",
    )
    parser.add_argument(
        "--documented-blockers",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Path to a JSON file (schema auditooor.v3_documented_blockers.v1) listing "
            "categories that are intentionally blocked by external constraints. Valid entries "
            "reclassify matching hard blockers into documented_blockers[], yielding verdict "
            "'pass_with_documented_blockers' instead of 'fail'. Tooling-only categories "
            "cannot be documented-blocked."
        ),
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out-json", type=Path)
    args = parser.parse_args(argv)

    required = set(args.required_category) if args.required_category else None
    gate = build_gate(
        args.root,
        workspace=args.workspace,
        progress_path=args.progress,
        required_categories=required,
        documented_blockers_path=args.documented_blockers,
    )
    text = json.dumps(gate, indent=2, sort_keys=True)
    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(text + "\n", encoding="utf-8")
    if args.json or not args.out_json:
        print(text)

    verdict = gate["verdict"]
    return 0 if verdict in ("pass", "pass_with_documented_blockers") else 1


if __name__ == "__main__":
    raise SystemExit(main())
