#!/usr/bin/env python3
"""Validate the latest chain-synthesis report for an audit-run stage.

This tool is the semantic gate for the ``post-coverage-chain-synth`` stage.
It does not run chain synthesis and does not mutate the audit manifest. It
checks that the newest ``.auditooor/chain_synthesis_*.json`` report belongs to
the current workspace, run id, and stage, was generated after the stage start
row in the audit-run manifest, contains current-run observability fields, and
has an acceptable terminal status.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.chain_synth_report_check.v1"
CHAIN_SYNTHESIS_SCHEMA = "auditooor.chain_synthesis_report.v1"
DEFAULT_MANIFEST = ".auditooor/audit_run_full_manifest.jsonl"
REPORT_GLOB = "chain_synthesis_*.json"

PASS_VERDICT = "pass-chain-synth-report-valid"
PASS_STATUSES = {"complete", "complete-with-dispatch-errors"}
FAIL_STATUSES = {
    "no-invariant-ids",
    "dry-run",
    "batch-generation-failed",
    "dispatch-failed",
    "dispatch-no-successful-narratives",
}
STATUS_KEYS = {
    "status",
    "verdict",
    "result",
    "final_result",
    "proof_status",
    "queue_status",
    "applicability_verdict",
}
NON_APPLICABLE_TOKENS = {
    "not_applicable",
    "non_applicable",
    "pass_not_applicable",
    "explicit_not_applicable",
}


@dataclass(frozen=True)
class LoadedReport:
    path: Path
    payload: dict[str, Any] | None
    error: str | None
    generated_at: datetime | None
    mtime: float


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _timestamp_text(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_json_object(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, "file-missing"
    except json.JSONDecodeError as exc:
        return None, f"json-decode-error:{exc.lineno}:{exc.colno}"
    except OSError as exc:
        return None, f"read-error:{exc.__class__.__name__}"
    if not isinstance(payload, dict):
        return None, "json-not-object"
    return payload, None


def _report_timestamp(payload: dict[str, Any] | None) -> datetime | None:
    if not payload:
        return None
    for key in ("generated_at", "generated_at_utc", "timestamp_utc", "created_at"):
        parsed = _parse_timestamp(payload.get(key))
        if parsed is not None:
            return parsed
    return None


def _load_report(path: Path) -> LoadedReport:
    payload, error = _load_json_object(path)
    try:
        mtime = path.stat().st_mtime
    except OSError:
        mtime = 0.0
    return LoadedReport(
        path=path,
        payload=payload,
        error=error,
        generated_at=_report_timestamp(payload),
        mtime=mtime,
    )


def _latest_report(workspace: Path) -> LoadedReport | None:
    reports = sorted((workspace / ".auditooor").glob(REPORT_GLOB))
    if not reports:
        return None
    loaded = [_load_report(path) for path in reports]
    return max(
        loaded,
        key=lambda report: (
            report.generated_at.timestamp() if report.generated_at else report.mtime,
            report.mtime,
            str(report.path),
        ),
    )


def _load_jsonl(path: Path) -> tuple[list[dict[str, Any]], str | None]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return rows, "manifest-missing"
    except OSError as exc:
        return rows, f"manifest-read-error:{exc.__class__.__name__}"
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            row = json.loads(stripped)
        except json.JSONDecodeError as exc:
            return rows, f"manifest-json-decode-error:{line_number}:{exc.colno}"
        if not isinstance(row, dict):
            return rows, f"manifest-json-row-not-object:{line_number}"
        rows.append(row)
    return rows, None


def _latest_stage_start(
    manifest_path: Path,
    *,
    run_id: str,
    stage: str,
) -> tuple[dict[str, Any] | None, str | None]:
    rows, error = _load_jsonl(manifest_path)
    if error:
        return None, error
    matching = [
        row
        for row in rows
        if row.get("event") == "stage-start"
        and str(row.get("run_id") or "") == run_id
        and str(row.get("stage") or "") == stage
    ]
    if not matching:
        return None, "stage-start-missing"
    return matching[-1], None


def _resolve_manifest_path(workspace: Path, manifest: Path | None) -> Path:
    if manifest is None:
        return workspace / DEFAULT_MANIFEST
    if manifest.is_absolute():
        return manifest
    return workspace / manifest


def _workspace_matches(report_workspace: Any, workspace: Path) -> bool:
    text = str(report_workspace or "").strip()
    if not text:
        return False
    if text == str(workspace):
        return True
    try:
        candidate = Path(text)
        if candidate.is_absolute():
            return candidate.resolve(strict=False) == workspace.resolve(strict=False)
    except OSError:
        return False
    return False


def _count_value(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, list):
        return len(value)
    return 0


def _requires_current_exploit_queue(stage: str) -> bool:
    return stage == "post-coverage-chain-synth"


def _exploit_queue_fingerprint_exists(report: dict[str, Any]) -> bool:
    fingerprints = report.get("input_fingerprints")
    if not isinstance(fingerprints, dict):
        return False
    exploit_queue = fingerprints.get("exploit_queue")
    if not isinstance(exploit_queue, dict):
        return False
    return exploit_queue.get("exists") is True


def _current_queue_lead_count(report: dict[str, Any]) -> int:
    input_counts = report.get("input_counts")
    if not isinstance(input_counts, dict):
        return 0
    return _count_value(input_counts.get("current_queue_leads"))


def _matched_template_count(report: dict[str, Any]) -> int:
    top_level = _count_value(report.get("matched_templates"))
    if top_level:
        return top_level
    input_counts = report.get("input_counts")
    if isinstance(input_counts, dict):
        count = _count_value(input_counts.get("matched_templates"))
        if count:
            return count
    template_match = report.get("template_match")
    if isinstance(template_match, dict):
        return _count_value(template_match.get("matched_templates"))
    return 0


def _proof_obligation_count(report: dict[str, Any]) -> int:
    top_level = _count_value(report.get("proof_obligations"))
    if top_level:
        return top_level
    input_counts = report.get("input_counts")
    if isinstance(input_counts, dict):
        count = _count_value(input_counts.get("proof_obligations"))
        if count:
            return count
    advancement = report.get("advancement")
    if isinstance(advancement, dict):
        return _count_value(advancement.get("proof_obligations"))
    return 0


def _broken_invariant_count(report: dict[str, Any]) -> int:
    top_level = _count_value(report.get("broken_invariant_ids"))
    if top_level:
        return top_level
    input_counts = report.get("input_counts")
    if isinstance(input_counts, dict):
        count = _count_value(input_counts.get("broken_invariant_ids"))
        if count:
            return count
    template_match = report.get("template_match")
    if isinstance(template_match, dict):
        return _count_value(template_match.get("broken_invariant_ids"))
    return 0


def _blocked_chain_support_tokens(report: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    blocked = report.get("blocked_chains")
    if not isinstance(blocked, list):
        return tokens
    for row in blocked:
        if not isinstance(row, dict):
            continue
        support = row.get("composition_support")
        if isinstance(support, list):
            for item in support:
                if isinstance(item, str) and item.strip():
                    tokens.add(item.strip())
    return tokens


def _status_token(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _has_explicit_non_applicable_verdict(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in STATUS_KEYS and _status_token(child) in NON_APPLICABLE_TOKENS:
                return True
            if _has_explicit_non_applicable_verdict(child):
                return True
        return False
    if isinstance(value, list):
        return any(_has_explicit_non_applicable_verdict(item) for item in value)
    return False


def _failure(
    verdict: str,
    reason: str,
    *,
    workspace: Path,
    run_id: str,
    stage: str,
    manifest_path: Path,
    report: LoadedReport | None = None,
    stage_start: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "ok": False,
        "verdict": verdict,
        "reason": reason,
        "workspace": str(workspace),
        "run_id": run_id,
        "stage": stage,
        "manifest_path": str(manifest_path),
        "checked_at": _utc_now(),
    }
    if report is not None:
        payload.update(
            {
                "report_path": str(report.path),
                "report_status": (
                    str(report.payload.get("status"))
                    if isinstance(report.payload, dict)
                    else None
                ),
                "report_generated_at": _timestamp_text(report.generated_at),
                "report_error": report.error,
            }
        )
    if stage_start is not None:
        payload["stage_start_timestamp_utc"] = stage_start.get("timestamp_utc")
    return payload


def _success(
    *,
    workspace: Path,
    run_id: str,
    stage: str,
    manifest_path: Path,
    report: LoadedReport,
    stage_started_at: datetime,
) -> dict[str, Any]:
    assert report.payload is not None
    status = str(report.payload.get("status") or "")
    return {
        "schema": SCHEMA,
        "ok": True,
        "verdict": PASS_VERDICT,
        "reason": f"chain-synthesis report status {status} is valid for current run",
        "workspace": str(workspace),
        "run_id": run_id,
        "stage": stage,
        "manifest_path": str(manifest_path),
        "report_path": str(report.path),
        "report_status": status,
        "report_generated_at": _timestamp_text(report.generated_at),
        "stage_start_timestamp_utc": _timestamp_text(stage_started_at),
        "matched_templates": _matched_template_count(report.payload),
        "broken_invariant_ids": _broken_invariant_count(report.payload),
        "input_counts": report.payload.get("input_counts"),
        "input_fingerprints": report.payload.get("input_fingerprints"),
        "checked_at": _utc_now(),
    }


def validate(
    *,
    workspace: Path,
    run_id: str,
    stage: str,
    manifest_path: Path,
) -> dict[str, Any]:
    workspace = workspace.resolve(strict=False)
    manifest_path = manifest_path.resolve(strict=False)

    if not workspace.is_dir():
        return _failure(
            "error-workspace-missing",
            "workspace does not exist or is not a directory",
            workspace=workspace,
            run_id=run_id,
            stage=stage,
            manifest_path=manifest_path,
        )

    stage_start, manifest_error = _latest_stage_start(
        manifest_path,
        run_id=run_id,
        stage=stage,
    )
    if manifest_error:
        verdict = (
            "fail-no-stage-start"
            if manifest_error == "stage-start-missing"
            else "fail-manifest-invalid"
        )
        return _failure(
            verdict,
            manifest_error,
            workspace=workspace,
            run_id=run_id,
            stage=stage,
            manifest_path=manifest_path,
        )

    assert stage_start is not None
    stage_started_at = _parse_timestamp(stage_start.get("timestamp_utc"))
    if stage_started_at is None:
        return _failure(
            "fail-stage-start-timestamp-invalid",
            "stage-start row lacks a valid timestamp_utc",
            workspace=workspace,
            run_id=run_id,
            stage=stage,
            manifest_path=manifest_path,
            stage_start=stage_start,
        )

    report = _latest_report(workspace)
    if report is None:
        return _failure(
            "fail-missing-report",
            "no .auditooor/chain_synthesis_*.json report exists",
            workspace=workspace,
            run_id=run_id,
            stage=stage,
            manifest_path=manifest_path,
            stage_start=stage_start,
        )
    if report.error:
        return _failure(
            "fail-report-invalid",
            report.error,
            workspace=workspace,
            run_id=run_id,
            stage=stage,
            manifest_path=manifest_path,
            report=report,
            stage_start=stage_start,
        )
    assert report.payload is not None

    if report.payload.get("schema") != CHAIN_SYNTHESIS_SCHEMA:
        return _failure(
            "fail-schema-mismatch",
            "chain report schema does not match auditooor.chain_synthesis_report.v1",
            workspace=workspace,
            run_id=run_id,
            stage=stage,
            manifest_path=manifest_path,
            report=report,
            stage_start=stage_start,
        )
    if not _workspace_matches(report.payload.get("workspace"), workspace):
        return _failure(
            "fail-workspace-mismatch",
            "chain report workspace does not match requested workspace",
            workspace=workspace,
            run_id=run_id,
            stage=stage,
            manifest_path=manifest_path,
            report=report,
            stage_start=stage_start,
        )
    if str(report.payload.get("audit_run_id") or "") != run_id:
        return _failure(
            "fail-run-id-mismatch",
            "chain report audit_run_id does not match requested run id",
            workspace=workspace,
            run_id=run_id,
            stage=stage,
            manifest_path=manifest_path,
            report=report,
            stage_start=stage_start,
        )
    if str(report.payload.get("stage") or "") != stage:
        return _failure(
            "fail-stage-mismatch",
            "chain report stage does not match requested stage",
            workspace=workspace,
            run_id=run_id,
            stage=stage,
            manifest_path=manifest_path,
            report=report,
            stage_start=stage_start,
        )

    if (
        not isinstance(report.payload.get("input_counts"), dict)
        or not report.payload.get("input_counts")
    ):
        return _failure(
            "fail-missing-input-counts",
            "chain report lacks non-empty input_counts",
            workspace=workspace,
            run_id=run_id,
            stage=stage,
            manifest_path=manifest_path,
            report=report,
            stage_start=stage_start,
        )
    if (
        not isinstance(report.payload.get("input_fingerprints"), dict)
        or not report.payload.get("input_fingerprints")
    ):
        return _failure(
            "fail-missing-input-fingerprints",
            "chain report lacks non-empty input_fingerprints",
            workspace=workspace,
            run_id=run_id,
            stage=stage,
            manifest_path=manifest_path,
            report=report,
            stage_start=stage_start,
        )

    if _requires_current_exploit_queue(stage):
        if not _exploit_queue_fingerprint_exists(report.payload):
            return _failure(
                "fail-missing-current-exploit-queue",
                "post-coverage-chain-synth requires input_fingerprints.exploit_queue.exists=true",
                workspace=workspace,
                run_id=run_id,
                stage=stage,
                manifest_path=manifest_path,
                report=report,
                stage_start=stage_start,
            )
        if _current_queue_lead_count(report.payload) <= 0:
            return _failure(
                "fail-empty-current-exploit-queue",
                "post-coverage-chain-synth requires input_counts.current_queue_leads > 0",
                workspace=workspace,
                run_id=run_id,
                stage=stage,
                manifest_path=manifest_path,
                report=report,
                stage_start=stage_start,
            )

    if report.generated_at is None:
        return _failure(
            "fail-report-timestamp-invalid",
            "chain report lacks a valid generated_at timestamp",
            workspace=workspace,
            run_id=run_id,
            stage=stage,
            manifest_path=manifest_path,
            report=report,
            stage_start=stage_start,
        )
    if report.generated_at < stage_started_at:
        return _failure(
            "fail-stale-report",
            "chain report was generated before the manifest stage-start row",
            workspace=workspace,
            run_id=run_id,
            stage=stage,
            manifest_path=manifest_path,
            report=report,
            stage_start=stage_start,
        )

    status = str(report.payload.get("status") or "")
    if status in PASS_STATUSES:
        if _proof_obligation_count(report.payload) <= 0:
            return _failure(
                "fail-complete-without-proof-obligations",
                f"{status} requires proof_obligations > 0",
                workspace=workspace,
                run_id=run_id,
                stage=stage,
                manifest_path=manifest_path,
                report=report,
                stage_start=stage_start,
            )
        return _success(
            workspace=workspace,
            run_id=run_id,
            stage=stage,
            manifest_path=manifest_path,
            report=report,
            stage_started_at=stage_started_at,
        )
    if status == "blocked-missing-hop-evidence":
        if "single-detector-restatement" in _blocked_chain_support_tokens(report.payload):
            return _failure(
                "fail-single-detector-restatement",
                "blocked-missing-hop-evidence is not acceptable when every surviving path is a single-detector restatement",
                workspace=workspace,
                run_id=run_id,
                stage=stage,
                manifest_path=manifest_path,
                report=report,
                stage_start=stage_start,
            )
        if _matched_template_count(report.payload) > 0:
            if (
                _proof_obligation_count(report.payload) > 0
                or _has_explicit_non_applicable_verdict(report.payload)
            ):
                return _success(
                    workspace=workspace,
                    run_id=run_id,
                    stage=stage,
                    manifest_path=manifest_path,
                    report=report,
                    stage_started_at=stage_started_at,
                )
            return _failure(
                "fail-blocked-without-proof-obligations",
                "blocked-missing-hop-evidence requires proof_obligations > 0 or an explicit non-applicable verdict",
                workspace=workspace,
                run_id=run_id,
                stage=stage,
                manifest_path=manifest_path,
                report=report,
                stage_start=stage_start,
            )
        return _failure(
            "fail-blocked-without-template-match",
            "blocked-missing-hop-evidence requires matched_templates > 0",
            workspace=workspace,
            run_id=run_id,
            stage=stage,
            manifest_path=manifest_path,
            report=report,
            stage_start=stage_start,
        )
    if status == "no-template-matches":
        if _broken_invariant_count(report.payload) > 0:
            return _success(
                workspace=workspace,
                run_id=run_id,
                stage=stage,
                manifest_path=manifest_path,
                report=report,
                stage_started_at=stage_started_at,
            )
        return _failure(
            "fail-no-template-matches-without-invariants",
            "no-template-matches requires broken_invariant_ids > 0",
            workspace=workspace,
            run_id=run_id,
            stage=stage,
            manifest_path=manifest_path,
            report=report,
            stage_start=stage_start,
        )
    if status in FAIL_STATUSES:
        return _failure(
            f"fail-status-{status}",
            f"chain report terminal status {status} is not accepted for certification",
            workspace=workspace,
            run_id=run_id,
            stage=stage,
            manifest_path=manifest_path,
            report=report,
            stage_start=stage_start,
        )
    return _failure(
        "fail-status-not-accepted",
        f"chain report terminal status {status or '<missing>'} is not accepted",
        workspace=workspace,
        run_id=run_id,
        stage=stage,
        manifest_path=manifest_path,
        report=report,
        stage_start=stage_start,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    manifest_path = _resolve_manifest_path(args.workspace, args.manifest)
    try:
        result = validate(
            workspace=args.workspace,
            run_id=args.run_id,
            stage=args.stage,
            manifest_path=manifest_path,
        )
    except Exception as exc:
        result = {
            "schema": SCHEMA,
            "ok": False,
            "verdict": "error",
            "reason": f"internal error: {exc.__class__.__name__}: {exc}",
            "workspace": str(args.workspace),
            "run_id": args.run_id,
            "stage": args.stage,
            "manifest_path": str(manifest_path),
            "checked_at": _utc_now(),
        }

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        status = "PASS" if result.get("ok") else "FAIL"
        print(f"{status}: {result.get('verdict')} - {result.get('reason')}")
    if result.get("ok") is True:
        return 0
    return 2 if str(result.get("verdict") or "").startswith("error") else 1


if __name__ == "__main__":
    sys.exit(main())
