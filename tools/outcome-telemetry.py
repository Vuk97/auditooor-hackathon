#!/usr/bin/env python3
"""Build engagement outcome telemetry from workspace submission ledgers.

Phase A needs a ground-truth dashboard before more infrastructure is added.
This tool reads active SUBMISSIONS.md ledgers, normalizes outcomes, and emits
both a human dashboard and optional JSON/JSONL records for trend tracking.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from outcome_semantics import derive_outcome_semantics, normalize_outcome as normalize_outcome_value
from submission_ledger import load_submission_entries
from submission_paths import find_submission_file

# PR 210 — optional integration with cost-telemetry. Loaded via importlib
# because the source file uses a hyphenated name.
_HERE = Path(__file__).resolve().parent
try:
    _ct_spec = importlib.util.spec_from_file_location(
        "cost_telemetry", _HERE / "cost-telemetry.py"
    )
    if _ct_spec and _ct_spec.loader:
        _cost_telemetry = importlib.util.module_from_spec(_ct_spec)
        _ct_spec.loader.exec_module(_cost_telemetry)
    else:
        _cost_telemetry = None
except Exception:
    _cost_telemetry = None


RESOLVED_OUTCOMES = {"accepted", "duplicate", "rejected"}
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info", "Unknown")

# P0-4 burn-down: required scoreboard linkage fields. Mirrors the source-of-
# truth list in tools/track-submissions.py (REQUIRED_LINKAGE_FIELDS) — kept
# duplicated here on purpose: outcome-telemetry must not import the hyphenated
# track-submissions.py module (importlib gymnastics in a hot path) and the
# field set is short enough that drift is caught by the cross-tool tests.
LINKAGE_REQUIRED_FIELDS = (
    "lane",
    "model_route",
    "proof_artifact",
    "production_path_blockers_cleared",
)
LINKAGE_FINAL_TRIAGER_FIELD = "final_triager_outcome"
LINKAGE_MANIFEST_FILENAME = "outcome_linkage_manifest.json"
LINKAGE_MANIFEST_DIR = ".auditooor"
LINKAGE_MANIFEST_VERSION = 1


@dataclass(frozen=True)
class OutcomeRecord:
    workspace: str
    workspace_path: str
    source: str
    finding_id: str
    title: str
    severity: str
    status: str
    outcome: str
    date: str
    outcome_row_present: bool = False
    rejection_reason: str = ""
    learning_scope: str = "full"
    base_rate_only_rejection: bool = False
    lane: str = ""
    model_route: str = ""
    proof_artifact: str = ""
    production_path_status: str = ""
    production_path_blockers_cleared: str = ""
    final_triager_outcome: str = ""
    has_final_triager_field: bool = False


def normalize_severity(value: str) -> str:
    lowered = value.lower()
    for severity in SEVERITIES:
        if severity.lower() in lowered:
            return severity
    return "Unknown"


def normalize_outcome(status: str) -> str:
    return normalize_outcome_value(status)


def _iter_outcome_rows(workspace: Path) -> list[dict[str, object]]:
    path = workspace / "reference" / "outcomes.jsonl"
    if not path.is_file():
        return []
    rows: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            row = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def latest_outcome_rows_by_report_id(workspace: Path) -> dict[str, dict[str, object]]:
    latest: dict[str, dict[str, object]] = {}
    for row in _iter_outcome_rows(workspace):
        report_id = str(row.get("report_id") or "").strip()
        if report_id:
            latest[report_id] = row
    return latest


def _linkage_value(row: dict[str, object] | None, key: str) -> str:
    if not row:
        return ""
    value = row.get(key)
    return str(value).strip() if value is not None else ""


def discover_workspaces(audits_dir: Path) -> list[Path]:
    if not audits_dir.exists():
        return []
    workspaces: list[Path] = []
    for child in sorted(audits_dir.iterdir()):
        if child.is_dir() and find_submission_file(child):
            workspaces.append(child)
    return workspaces


def load_workspace_records(workspace: Path) -> list[OutcomeRecord]:
    tracker = find_submission_file(workspace)
    if tracker is None:
        return []
    workspace_display = portable_path(workspace)
    tracker_display = portable_path(tracker)
    outcome_rows = latest_outcome_rows_by_report_id(workspace)
    records: list[OutcomeRecord] = []
    for entry in load_submission_entries(tracker):
        status = entry.get("status", "")
        finding_id = entry.get("id", "")
        outcome_row = outcome_rows.get(finding_id)
        semantics = derive_outcome_semantics({
            "outcome": outcome_row.get("outcome") if outcome_row else "",
            "outcome_class": outcome_row.get("outcome_class") if outcome_row else "",
            "status": (
                outcome_row.get("status")
                if outcome_row and outcome_row.get("status")
                else status
            ),
            "rejection_reason": outcome_row.get("rejection_reason") if outcome_row else "",
            LINKAGE_FINAL_TRIAGER_FIELD: (
                outcome_row.get(LINKAGE_FINAL_TRIAGER_FIELD) if outcome_row else ""
            ),
        })
        records.append(
            OutcomeRecord(
                workspace=workspace.name,
                workspace_path=workspace_display,
                source=tracker_display,
                finding_id=finding_id,
                title=entry.get("title", ""),
                severity=normalize_severity(entry.get("severity", "")),
                status=status,
                outcome=semantics.outcome,
                date=entry.get("date", ""),
                outcome_row_present=outcome_row is not None,
                rejection_reason=semantics.rejection_reason,
                learning_scope=semantics.learning_scope,
                base_rate_only_rejection=semantics.base_rate_only_rejection,
                lane=_linkage_value(outcome_row, "lane"),
                model_route=_linkage_value(outcome_row, "model_route"),
                proof_artifact=_linkage_value(outcome_row, "proof_artifact"),
                production_path_status=_linkage_value(outcome_row, "production_path_status"),
                production_path_blockers_cleared=_linkage_value(
                    outcome_row, "production_path_blockers_cleared"
                ),
                final_triager_outcome=_linkage_value(
                    outcome_row, LINKAGE_FINAL_TRIAGER_FIELD
                ),
                has_final_triager_field=(
                    outcome_row is not None
                    and LINKAGE_FINAL_TRIAGER_FIELD in outcome_row
                ),
            )
        )
    return records


def portable_path(path: Path) -> str:
    """Prefer repo-relative paths when possible so committed ledgers are stable."""
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def load_records(workspaces: Iterable[Path]) -> list[OutcomeRecord]:
    records: list[OutcomeRecord] = []
    for workspace in workspaces:
        records.extend(load_workspace_records(workspace.expanduser().resolve()))
    return records


def summarize(records: list[OutcomeRecord]) -> dict[str, object]:
    by_workspace: dict[str, Counter[str]] = defaultdict(Counter)
    severity_mix: Counter[str] = Counter()
    aggregate: Counter[str] = Counter()
    linkage_records = [record for record in records if not record.base_rate_only_rejection]

    for record in records:
        aggregate[record.outcome] += 1
        by_workspace[record.workspace][record.outcome] += 1
        severity_mix[record.severity] += 1

    linkage = {
        "records_with_outcome_row": sum(1 for r in linkage_records if r.outcome_row_present),
        "missing_outcome_row": sum(1 for r in linkage_records if not r.outcome_row_present),
        "missing_lane": sum(1 for r in linkage_records if not r.lane),
        "missing_model_route": sum(1 for r in linkage_records if not r.model_route),
        "missing_proof_artifact": sum(1 for r in linkage_records if not r.proof_artifact),
        "missing_production_path_status": sum(1 for r in linkage_records if not r.production_path_status),
        # P0-4 required-field counters. ``missing_production_path_blockers_cleared``
        # is the new required scoreboard field; ``missing_final_triager_field``
        # tracks rows where the FIELD itself is absent (vs. value == "unknown").
        "missing_production_path_blockers_cleared": sum(
            1 for r in linkage_records if not r.production_path_blockers_cleared
        ),
        "missing_final_triager_field": sum(
            1 for r in linkage_records if not r.has_final_triager_field
        ),
        "linkage_required_rows": len(linkage_records),
        "base_rate_only_rejections": sum(
            1 for r in records if r.base_rate_only_rejection
        ),
    }

    resolved = sum(aggregate[outcome] for outcome in RESOLVED_OUTCOMES)
    accepted = aggregate["accepted"]
    acceptance_rate = accepted / resolved if resolved else None
    dupe_rate = aggregate["duplicate"] / resolved if resolved else None
    rejection_rate = aggregate["rejected"] / resolved if resolved else None

    return {
        "total_records": len(records),
        "workspace_count": len(by_workspace),
        "outcomes": dict(sorted(aggregate.items())),
        "severity_mix": {severity: severity_mix[severity] for severity in SEVERITIES if severity_mix[severity]},
        "resolved_count": resolved,
        "acceptance_rate": acceptance_rate,
        "dupe_rate": dupe_rate,
        "rejection_rate": rejection_rate,
        "by_workspace": {name: dict(sorted(counts.items())) for name, counts in sorted(by_workspace.items())},
        "outcome_linkage": linkage,
    }


def pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def render_markdown(records: list[OutcomeRecord], summary: dict[str, object]) -> str:
    lines = [
        "# Outcome Telemetry",
        "",
        f"- Workspaces: {summary['workspace_count']}",
        f"- Findings tracked: {summary['total_records']}",
        f"- Resolved outcomes: {summary['resolved_count']}",
        f"- Acceptance rate: {pct(summary['acceptance_rate'])}",
        f"- Duplicate rate: {pct(summary['dupe_rate'])}",
        f"- Rejection rate: {pct(summary['rejection_rate'])}",
        "",
        "## Outcomes",
        "",
        "| Outcome | Count |",
        "|---|---:|",
    ]
    for outcome, count in summary["outcomes"].items():  # type: ignore[union-attr]
        lines.append(f"| {outcome} | {count} |")

    lines.extend(["", "## Severity Mix", "", "| Severity | Count |", "|---|---:|"])
    for severity, count in summary["severity_mix"].items():  # type: ignore[union-attr]
        lines.append(f"| {severity} | {count} |")

    linkage = summary["outcome_linkage"]  # type: ignore[assignment]
    lines.extend(
        [
            "",
            "## Outcome Linkage",
            "",
            "| Linkage check | Missing / Count |",
            "|---|---:|",
            f"| Records with `reference/outcomes.jsonl` row | {linkage['records_with_outcome_row']} |",  # type: ignore[index]
            f"| Missing outcome row | {linkage['missing_outcome_row']} |",  # type: ignore[index]
            f"| Missing `lane` | {linkage['missing_lane']} |",  # type: ignore[index]
            f"| Missing `model_route` | {linkage['missing_model_route']} |",  # type: ignore[index]
            f"| Missing `proof_artifact` | {linkage['missing_proof_artifact']} |",  # type: ignore[index]
            f"| Missing `production_path_status` | {linkage['missing_production_path_status']} |",  # type: ignore[index]
            f"| Missing `production_path_blockers_cleared` | {linkage['missing_production_path_blockers_cleared']} |",  # type: ignore[index]
            f"| Missing `final_triager_outcome` field | {linkage['missing_final_triager_field']} |",  # type: ignore[index]
            f"| Base-rate-only rejected rows | {linkage['base_rate_only_rejections']} |",  # type: ignore[index]
        ]
    )

    lines.extend(
        [
            "",
            "## Workspace Breakdown",
            "",
            "| Workspace | Accepted | Duplicate | Rejected | In Review | Pending | Unknown | Total |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    by_workspace = summary["by_workspace"]  # type: ignore[assignment]
    for workspace, counts in by_workspace.items():  # type: ignore[union-attr]
        total = sum(counts.values())
        lines.append(
            "| {workspace} | {accepted} | {duplicate} | {rejected} | {in_review} | {pending} | {unknown} | {total} |".format(
                workspace=workspace,
                accepted=counts.get("accepted", 0),
                duplicate=counts.get("duplicate", 0),
                rejected=counts.get("rejected", 0),
                in_review=counts.get("in_review", 0),
                pending=counts.get("pending", 0),
                unknown=counts.get("unknown", 0),
                total=total,
            )
        )

    if records:
        lines.extend(["", "## Records", "", "| Workspace | ID | Severity | Outcome | Lane | Model Route | Proof Artifact | Production Path | Status | Title |", "|---|---:|---|---|---|---|---|---|---|---|"])
        for record in sorted(records, key=lambda r: (r.workspace, r.finding_id or "zzzz", r.title)):
            title = record.title.replace("|", "\\|")
            proof = record.proof_artifact.replace("|", "\\|") or "-"
            lines.append(
                f"| {record.workspace} | {record.finding_id or '-'} | {record.severity} | {record.outcome} | {record.lane or '-'} | {record.model_route or '-'} | {proof} | {record.production_path_status or '-'} | {record.status} | {title} |"
            )

    return "\n".join(lines) + "\n"


def build_cost_sections(
    workspaces: Iterable[Path],
    records: list[OutcomeRecord],
) -> tuple[str, dict[str, object]]:
    """PR 210 integration: for each workspace with a cost_runs/ dir, render
    a 'Cost Summary' Markdown section and collect the JSON-safe payload.

    Cost telemetry is advisory; this section is skipped entirely when no
    workspace has cost_runs/. Never raises."""
    if _cost_telemetry is None:
        return "", {}

    markdown_parts: list[str] = []
    payloads: dict[str, object] = {}

    # Map workspace -> filed-finding count (accepted or resolved, if present).
    filed_by_ws: dict[str, int] = defaultdict(int)
    for record in records:
        if record.outcome in ("accepted", "duplicate", "rejected",
                              "in_review", "pending"):
            filed_by_ws[record.workspace] += 1

    for ws in workspaces:
        cost_runs_dir = ws / "cost_runs"
        if not cost_runs_dir.exists() or not cost_runs_dir.is_dir():
            continue
        try:
            summary = _cost_telemetry.summarize_workspace(ws)
        except Exception:
            continue
        if summary.get("stage_count", 0) == 0:
            continue

        filed_n = filed_by_ws.get(ws.name, 0)
        total_cost = float(summary.get("total_est_cost_usd") or 0.0)
        cpf = (total_cost / filed_n) if filed_n > 0 else None

        try:
            md = _cost_telemetry.render_summary_markdown(
                summary, cost_per_finding=cpf, filed_findings=filed_n,
            )
        except Exception:
            md = ""
        if md.strip():
            markdown_parts.append(f"### {ws.name}\n\n{md}")

        payloads[ws.name] = {
            "summary": summary,
            "filed_findings": filed_n,
            "est_cost_per_filed_finding_usd": cpf,
        }

    if not markdown_parts:
        return "", payloads

    header = ("\n## Cost Summary (PR 210)\n\n"
              "_Advisory telemetry. `est_cost_usd` is derived from a "
              "hard-coded rate card; do NOT cite as proof inside a "
              "finding._\n\n")
    return header + "\n".join(markdown_parts), payloads


def write_jsonl(records: list[OutcomeRecord], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(asdict(record), sort_keys=True) for record in records]
    path.write_text("\n".join(lines) + ("\n" if lines else ""))


def _record_linkage_audit(record: OutcomeRecord) -> dict[str, object]:
    """Per-record linkage audit shape consumed by the manifest writer.

    ``missing_required_fields`` is the ordered subset of LINKAGE_REQUIRED_FIELDS
    whose value is empty on this record. ``has_final_triager_field`` mirrors
    the P0-4 distinction between "field is absent" and "field exists with
    value 'unknown'". ``complete`` is true iff no required field is missing
    AND the final-triager field is present (regardless of its value).
    """
    if record.base_rate_only_rejection:
        return {
            "workspace": record.workspace,
            "finding_id": record.finding_id,
            "outcome": record.outcome,
            "outcome_row_present": record.outcome_row_present,
            "learning_scope": record.learning_scope,
            "base_rate_only_rejection": record.base_rate_only_rejection,
            "linkage_required": False,
            "linkage_skip_reason": "platform_base_rate_only_decline",
            "lane": record.lane,
            "model_route": record.model_route,
            "proof_artifact": record.proof_artifact,
            "production_path_blockers_cleared": record.production_path_blockers_cleared,
            "final_triager_outcome": record.final_triager_outcome,
            "has_final_triager_field": record.has_final_triager_field,
            "missing_required_fields": [],
            "complete": True,
        }
    missing: list[str] = []
    field_values = {
        "lane": record.lane,
        "model_route": record.model_route,
        "proof_artifact": record.proof_artifact,
        "production_path_blockers_cleared": record.production_path_blockers_cleared,
    }
    for key in LINKAGE_REQUIRED_FIELDS:
        if not field_values.get(key, ""):
            missing.append(key)
    return {
        "workspace": record.workspace,
        "finding_id": record.finding_id,
        "outcome": record.outcome,
        "outcome_row_present": record.outcome_row_present,
        "learning_scope": record.learning_scope,
        "base_rate_only_rejection": record.base_rate_only_rejection,
        "linkage_required": True,
        "linkage_skip_reason": "",
        "lane": record.lane,
        "model_route": record.model_route,
        "proof_artifact": record.proof_artifact,
        "production_path_blockers_cleared": record.production_path_blockers_cleared,
        "final_triager_outcome": record.final_triager_outcome,
        "has_final_triager_field": record.has_final_triager_field,
        "missing_required_fields": missing,
        "complete": (not missing) and record.has_final_triager_field,
    }


def build_linkage_manifest(
    workspace: Path,
    records: list[OutcomeRecord],
    *,
    generated_at: str | None = None,
) -> dict[str, object]:
    """Build the JSON manifest payload for one workspace.

    Includes a stable ``manifest_version`` integer so downstream readers can
    branch safely when the schema evolves. ``rows`` preserves source order
    from ``load_workspace_records`` (which mirrors SUBMISSIONS.md ordering),
    so manifest diffs read like ledger diffs.
    """
    ws_records = [r for r in records if r.workspace == workspace.name]
    rows = [_record_linkage_audit(r) for r in ws_records]
    required_rows = [row for row in rows if row.get("linkage_required", True)]
    missing_per_field = {key: 0 for key in LINKAGE_REQUIRED_FIELDS}
    missing_final_triager_field = 0
    complete = 0
    for row in required_rows:
        if row["complete"]:
            complete += 1
        for key in row["missing_required_fields"]:  # type: ignore[union-attr]
            missing_per_field[key] = missing_per_field.get(key, 0) + 1
        if not row["has_final_triager_field"]:
            missing_final_triager_field += 1
    summary = {
        "total_rows": len(rows),
        "linkage_required_rows": len(required_rows),
        "base_rate_only_rows": len(rows) - len(required_rows),
        "complete_rows": complete,
        "incomplete_rows": len(required_rows) - complete,
        "missing_per_field": missing_per_field,
        "missing_final_triager_field": missing_final_triager_field,
    }
    return {
        "manifest_version": LINKAGE_MANIFEST_VERSION,
        "workspace": workspace.name,
        "workspace_path": portable_path(workspace),
        "generated_at": generated_at or "",
        "required_fields": list(LINKAGE_REQUIRED_FIELDS),
        "final_triager_field": LINKAGE_FINAL_TRIAGER_FIELD,
        "summary": summary,
        "rows": rows,
    }


def write_linkage_manifest(workspace: Path, manifest: dict[str, object]) -> Path:
    """Persist ``manifest`` to ``<workspace>/.auditooor/<filename>``.

    The directory is created if missing. Returns the resolved path so callers
    can log it.
    """
    out_dir = workspace / LINKAGE_MANIFEST_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / LINKAGE_MANIFEST_FILENAME
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return path


def emit_linkage_manifests(
    workspaces: Iterable[Path],
    records: list[OutcomeRecord],
    *,
    generated_at: str | None = None,
) -> dict[str, Path]:
    """Write a manifest for each workspace, return ``{ws_name: path}``."""
    written: dict[str, Path] = {}
    for ws in workspaces:
        manifest = build_linkage_manifest(ws, records, generated_at=generated_at)
        path = write_linkage_manifest(ws, manifest)
        written[ws.name] = path
    return written


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize accepted/duplicate/rejected/pending telemetry across audit workspaces."
    )
    parser.add_argument("workspaces", nargs="*", help="Workspace directories. Defaults to --audits-dir discovery.")
    parser.add_argument("--audits-dir", default="~/audits", help="Directory containing audit workspaces")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown")
    parser.add_argument("--out", help="Write dashboard output to this path")
    parser.add_argument("--write-jsonl", help="Write normalized finding records to this JSONL path")
    parser.add_argument(
        "--no-linkage-manifest",
        dest="write_linkage_manifest",
        action="store_false",
        default=True,
        help=(
            "Disable the per-workspace `<ws>/.auditooor/"
            f"{LINKAGE_MANIFEST_FILENAME}` write. The manifest is on by "
            "default so closeout / dashboards always have a fresh "
            "machine-readable view of P0-4 scoreboard linkage coverage."
        ),
    )
    args = parser.parse_args()

    if args.workspaces:
        workspaces = [Path(path).expanduser().resolve() for path in args.workspaces]
    else:
        workspaces = discover_workspaces(Path(args.audits_dir).expanduser().resolve())

    missing = [str(path) for path in workspaces if not path.exists()]
    if missing:
        print(f"[outcome-telemetry] workspace not found: {missing[0]}", file=sys.stderr)
        return 1

    records = load_records(workspaces)
    summary = summarize(records)

    if args.write_jsonl:
        write_jsonl(records, Path(args.write_jsonl).expanduser().resolve())

    # P0-4: persist a per-workspace linkage manifest so closeout / dashboards
    # can read the machine-readable scoreboard coverage without re-parsing
    # outcomes.jsonl. ISO-8601 generated_at lives on the manifest so stale
    # consumers can detect freshness.
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest_paths: dict[str, Path] = {}
    if getattr(args, "write_linkage_manifest", True):
        manifest_paths = emit_linkage_manifests(
            workspaces, records, generated_at=generated_at
        )

    # PR 210: append Cost Summary telemetry when any workspace has cost_runs/.
    cost_md, cost_payloads = build_cost_sections(workspaces, records)

    if args.json:
        out_obj = {
            "summary": summary,
            "records": [asdict(record) for record in records],
        }
        if cost_payloads:
            out_obj["cost_telemetry"] = cost_payloads
        if manifest_paths:
            out_obj["linkage_manifest_paths"] = {
                name: str(path) for name, path in sorted(manifest_paths.items())
            }
        rendered = json.dumps(out_obj, indent=2, sort_keys=True)
    else:
        rendered = render_markdown(records, summary)
        if cost_md:
            rendered = rendered.rstrip() + "\n" + cost_md + "\n"
        if manifest_paths:
            rendered = rendered.rstrip() + "\n\n## Linkage Manifest\n\n"
            for name, path in sorted(manifest_paths.items()):
                rendered += f"- `{name}` -> `{path}`\n"

    if args.out:
        Path(args.out).expanduser().resolve().write_text(rendered)
    else:
        print(rendered, end="")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
