#!/usr/bin/env python3
"""outcome-ledger-gate.py - Gate: enforce new_rule_codified field population.

WIRING-COMPLETENESS-V3 GAP-10 + LEARNING-LOOP GAP-3:
outcomes.jsonl supports new_rule_codified metadata field (Phase I.10 LANDED)
but NO gate enforces field population. The feedback loop
"triager rejection -> new R-rule codified" exists in schema but operators
don't fill it in.

This gate scans all workspaces' outcomes.jsonl files (or a single workspace).
For each row where outcome/outcome_class is in the rejected family
(rejected, declined, oos_rejected, duplicate_of_rejected, withdrawn):

  REQUIRE: new_rule_codified field set to one of:
    - "none"       : operator explicitly says no rule needed for this rejection
    - "deferred"   : operator deferred classification (requires new_rule_codified_reason)
    - "<rule-id>"  : e.g. "R56-RUBRIC-FIT-PROGRAM-LEVEL" (the codified rule)

  Legacy boolean:
    - True  -> WARN (acknowledged but no rule-id; migrate to string form)
    - False -> FAIL (unclassified; must be filled in)
    - None  -> FAIL (missing; must be filled in)

Update path:
  python3 tools/track-submissions.py record-outcome <ws> \\
    --report-id <id> --state rejected \\
    --new-rule-codified  [sets bool True; then edit JSONL to string form]

  OR direct JSONL edit: set new_rule_codified to "none"/"deferred"/"<rule-id>"
  and optionally new_rule_codified_reason to the reason.

Usage:
    python3 tools/outcome-ledger-gate.py [--workspace <ws>] [--strict] [--json]
    python3 tools/outcome-ledger-gate.py --outcomes <path> [--strict] [--json]
    python3 tools/outcome-ledger-gate.py --all-workspaces [--strict] [--json]

Exit codes:
    0 - PASS or WARN (no strict failures)
    1 - FAIL in --strict mode (unclassified rejections found)
    2 - ERROR (file not found / parse failure)

Schema: auditooor.outcome_ledger_gate.v1
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA = "auditooor.outcome_ledger_gate.v1"
TOOL_VERSION = "1.1.0"

# Outcome string values that classify a row as rejected
REJECTED_OUTCOMES = frozenset({
    "rejected",
    "declined",
    "oos_rejected",
    "duplicate_of_rejected",
    "withdrawn",
    "closed",
})

# outcome_class values from outcome-ledger.py that qualify
REJECTED_OUTCOME_CLASSES = frozenset({
    "rejected",
    "dupe",
    "duplicate",
})

# Status field keywords that indicate rejection (free-form)
REJECTED_STATUS_KEYWORDS = [
    "rejected",
    "declined",
    "out of scope",
    "oos",
    "wont fix",
    "won't fix",
]

# Valid string values for new_rule_codified (gate passes)
VALID_NRC_KEYWORDS = frozenset({"none", "deferred"})

# Default workspace roots to search when --all-workspaces
DEFAULT_WORKSPACE_ROOTS = [
    "~/audits",
    "~/auditooor-mcp",
]

# Paths that are test fixtures (skip them)
FIXTURE_SKIP_PARTS = {"fixtures", "fixture", "test_data"}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class RowVerdict:
    workspace: str
    row_id: str
    title: str
    outcome: str
    outcome_class: str
    nrc_value: Any
    nrc_reason: str
    verdict: str  # "pass" | "warn" | "fail" | "skip"
    note: str


@dataclass
class WorkspaceReport:
    outcomes_path: str
    workspace: str
    total_rows: int
    rejected_rows: int
    pass_rows: int    # valid string classification
    warn_rows: int    # legacy bool True
    fail_rows: int    # False / None / missing / empty string
    skip_rows: int    # not in rejected family
    row_verdicts: list[RowVerdict] = field(default_factory=list)

    @property
    def classification_rate(self) -> float:
        if self.rejected_rows == 0:
            return 1.0
        return self.pass_rows / self.rejected_rows

    @property
    def verdict(self) -> str:
        if self.fail_rows > 0:
            return "fail"
        if self.warn_rows > 0:
            return "warn"
        return "pass"


@dataclass
class GateReport:
    schema: str
    generated_at: str
    tool_version: str
    workspaces_scanned: int
    total_rejected: int
    total_classified: int   # pass
    total_warn: int         # legacy bool True
    total_unclassified: int # fail
    fail_rate: float        # unclassified / total_rejected
    overall_verdict: str    # "pass" | "warn" | "fail"
    workspace_reports: list[WorkspaceReport] = field(default_factory=list)
    operator_checklist: list[dict[str, str]] = field(default_factory=list)
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# JSONL I/O
# ---------------------------------------------------------------------------


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                rows.append(obj)
        except json.JSONDecodeError:
            pass
    return rows


# ---------------------------------------------------------------------------
# Row-level classification
# ---------------------------------------------------------------------------


def _is_rejected(row: dict[str, Any]) -> bool:
    """Return True if this row is in the rejected/declined family."""
    def _lc(key: str) -> str:
        return str(row.get(key) or "").lower().strip()

    for field_name in ("outcome", "outcome_class", "state", "final_triager_outcome"):
        val = _lc(field_name)
        if val in REJECTED_OUTCOMES or val in REJECTED_OUTCOME_CLASSES:
            return True

    status = _lc("status")
    for kw in REJECTED_STATUS_KEYWORDS:
        if kw in status:
            return True

    return False


def _row_id(row: dict[str, Any]) -> str:
    for key in ("finding_id", "submission_id", "report_id", "id"):
        v = row.get(key)
        if v:
            return str(v)
    return "(unknown)"


def _classify_nrc(nrc_value: Any, nrc_reason: str) -> tuple[str, str]:
    """Classify new_rule_codified value. Returns (verdict, note)."""
    if nrc_value is None:
        return "fail", "new_rule_codified not set (null/missing)"

    if isinstance(nrc_value, bool):
        if nrc_value:
            return (
                "warn",
                "new_rule_codified=True (legacy bool); migrate to string: "
                "'none' | 'deferred' | '<rule-id>'",
            )
        return "fail", "new_rule_codified=False (unclassified); must be classified"

    val_str = str(nrc_value).strip()
    if not val_str:
        return "fail", "new_rule_codified is empty string"

    if val_str == "deferred":
        if not nrc_reason.strip():
            return (
                "fail",
                "new_rule_codified='deferred' but new_rule_codified_reason is empty; "
                "add a reason for deferral",
            )
        return "pass", f"classified as 'deferred' (reason: {nrc_reason[:60]})"

    if val_str == "none":
        return "pass", "classified as 'none' (operator: no rule needed)"

    # Any other non-empty string is a rule-id
    return "pass", f"classified as rule-id '{val_str}'"


# ---------------------------------------------------------------------------
# Per-file scanning
# ---------------------------------------------------------------------------


def scan_outcomes_file(outcomes_path: Path, workspace_name: str = "") -> WorkspaceReport:
    rows = _load_jsonl(outcomes_path)
    ws = workspace_name or outcomes_path.parent.parent.name

    report = WorkspaceReport(
        outcomes_path=str(outcomes_path),
        workspace=ws,
        total_rows=len(rows),
        rejected_rows=0,
        pass_rows=0,
        warn_rows=0,
        fail_rows=0,
        skip_rows=0,
    )

    for row in rows:
        rid = _row_id(row)
        title = str(row.get("title") or "")[:80]
        outcome = str(row.get("outcome") or "").lower()
        outcome_class = str(row.get("outcome_class") or "").lower()

        if not _is_rejected(row):
            report.skip_rows += 1
            continue

        report.rejected_rows += 1
        nrc = row.get("new_rule_codified")
        nrc_reason = str(row.get("new_rule_codified_reason") or "").strip()
        verdict, note = _classify_nrc(nrc, nrc_reason)

        if verdict == "pass":
            report.pass_rows += 1
        elif verdict == "warn":
            report.warn_rows += 1
        else:
            report.fail_rows += 1

        report.row_verdicts.append(RowVerdict(
            workspace=ws,
            row_id=rid,
            title=title,
            outcome=outcome,
            outcome_class=outcome_class,
            nrc_value=nrc,
            nrc_reason=nrc_reason,
            verdict=verdict,
            note=note,
        ))

    return report


# ---------------------------------------------------------------------------
# Workspace discovery
# ---------------------------------------------------------------------------


def discover_workspace_outcomes(roots: list[str]) -> list[Path]:
    found: list[Path] = []
    for root_str in roots:
        root = Path(os.path.expanduser(root_str))
        if not root.is_dir():
            continue
        for p in root.rglob("outcomes.jsonl"):
            parts_set = {part.lower() for part in p.parts}
            if parts_set & FIXTURE_SKIP_PARTS:
                continue
            found.append(p)
    return sorted(set(found))


# ---------------------------------------------------------------------------
# Operator checklist
# ---------------------------------------------------------------------------


def build_operator_checklist(reports: list[WorkspaceReport]) -> list[dict[str, str]]:
    checklist: list[dict[str, str]] = []
    for ws_report in reports:
        ws_dir = str(Path(ws_report.outcomes_path).parent.parent)
        for rv in ws_report.row_verdicts:
            if rv.verdict not in ("fail", "warn"):
                continue
            if rv.verdict == "fail":
                action = (
                    f"Edit {ws_report.outcomes_path}: set new_rule_codified to "
                    f"'none' | 'deferred' (+ new_rule_codified_reason) | '<rule-id>'"
                )
            else:
                action = (
                    f"Migrate {ws_report.outcomes_path}: change new_rule_codified "
                    f"from True (bool) to string 'none' | 'deferred' | '<rule-id>'"
                )
            checklist.append({
                "workspace": rv.workspace,
                "workspace_dir": ws_dir,
                "row_id": rv.row_id,
                "title": rv.title,
                "outcome": rv.outcome or rv.outcome_class,
                "nrc_current": str(rv.nrc_value),
                "verdict": rv.verdict,
                "action": action,
                "note": rv.note,
            })
    return checklist


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------


def build_gate_report(reports: list[WorkspaceReport], now_str: str) -> GateReport:
    total_rejected = sum(r.rejected_rows for r in reports)
    total_classified = sum(r.pass_rows for r in reports)
    total_warn = sum(r.warn_rows for r in reports)
    total_unclassified = sum(r.fail_rows for r in reports)
    fail_rate = (total_unclassified / total_rejected) if total_rejected > 0 else 0.0

    if total_unclassified > 0:
        overall = "fail"
    elif total_warn > 0:
        overall = "warn"
    else:
        overall = "pass"

    return GateReport(
        schema=SCHEMA,
        generated_at=now_str,
        tool_version=TOOL_VERSION,
        workspaces_scanned=len(reports),
        total_rejected=total_rejected,
        total_classified=total_classified,
        total_warn=total_warn,
        total_unclassified=total_unclassified,
        fail_rate=fail_rate,
        overall_verdict=overall,
        workspace_reports=reports,
        operator_checklist=build_operator_checklist(reports),
    )


def _serialize(report: GateReport) -> dict[str, Any]:
    ws_list = []
    for ws in report.workspace_reports:
        ws_list.append({
            "outcomes_path": ws.outcomes_path,
            "workspace": ws.workspace,
            "total_rows": ws.total_rows,
            "rejected_rows": ws.rejected_rows,
            "pass_rows": ws.pass_rows,
            "warn_rows": ws.warn_rows,
            "fail_rows": ws.fail_rows,
            "skip_rows": ws.skip_rows,
            "classification_rate": round(ws.classification_rate, 4),
            "verdict": ws.verdict,
            "failing_rows": [
                asdict(rv)
                for rv in ws.row_verdicts
                if rv.verdict in ("fail", "warn")
            ],
        })
    return {
        "schema": report.schema,
        "generated_at": report.generated_at,
        "tool_version": report.tool_version,
        "workspaces_scanned": report.workspaces_scanned,
        "total_rejected": report.total_rejected,
        "total_classified": report.total_classified,
        "total_warn": report.total_warn,
        "total_unclassified": report.total_unclassified,
        "fail_rate": round(report.fail_rate, 4),
        "overall_verdict": report.overall_verdict,
        "workspace_reports": ws_list,
        "operator_checklist": report.operator_checklist,
        "error": report.error,
    }


# ---------------------------------------------------------------------------
# Human-readable output
# ---------------------------------------------------------------------------


def print_human(report: GateReport) -> None:
    print(f"[outcome-ledger-gate] schema={report.schema} tool_version={report.tool_version}")
    print(f"[outcome-ledger-gate] workspaces_scanned={report.workspaces_scanned}")
    print(
        f"[outcome-ledger-gate] total_rejected={report.total_rejected}  "
        f"classified={report.total_classified}  "
        f"warn={report.total_warn}  "
        f"unclassified={report.total_unclassified}  "
        f"fail_rate={report.fail_rate:.1%}"
    )
    print(f"[outcome-ledger-gate] overall_verdict={report.overall_verdict}")
    print()

    for ws in report.workspace_reports:
        if ws.rejected_rows == 0:
            continue
        icon = {"pass": "OK", "warn": "WARN", "fail": "FAIL"}.get(ws.verdict, ws.verdict)
        print(
            f"  [{icon}] {ws.workspace}  "
            f"rejected={ws.rejected_rows}  "
            f"pass={ws.pass_rows}  warn={ws.warn_rows}  fail={ws.fail_rows}  "
            f"({ws.classification_rate:.0%} classified)"
        )
        for rv in ws.row_verdicts:
            if rv.verdict in ("fail", "warn"):
                print(f"         {rv.verdict.upper()} id={rv.row_id!r}  '{rv.title:.55}'")
                print(f"               {rv.note}")
    print()

    if report.operator_checklist:
        n = len(report.operator_checklist)
        print(f"Operator checklist: {n} rejection(s) need new_rule_codified classification")
        for item in report.operator_checklist[:15]:
            title_trunc = item['title'][:50]
            print(
                f"  [{item['verdict'].upper()}] [{item['workspace']}] "
                f"id={item['row_id']!r}: {title_trunc!r}"
            )
            print(f"    -> {item['action']}")
        if n > 15:
            print(f"  ... and {n - 15} more. Run with --json to get full list.")
    else:
        print("Operator checklist: all rejection rows are classified.")

    print()
    verdict_msgs = {
        "pass": "PASS: all rejection rows carry a new_rule_codified classification",
        "warn": "WARN: legacy bool new_rule_codified=True rows exist; migrate to string form",
        "fail": "FAIL: unclassified rejection rows found - run make outcome-ledger-gate-check",
    }
    print(f"[outcome-ledger-gate] {verdict_msgs.get(report.overall_verdict, report.overall_verdict)}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Gate: enforce new_rule_codified population on rejected outcomes. "
            "(WIRING-COMPLETENESS-V3 GAP-10 / LEARNING-LOOP GAP-3)"
        )
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="Single workspace directory (scans <ws>/reference/outcomes.jsonl)",
    )
    src.add_argument(
        "--outcomes",
        type=Path,
        default=None,
        help="Direct path to a specific outcomes.jsonl file",
    )
    src.add_argument(
        "--all-workspaces",
        action="store_true",
        help=f"Discover all outcomes.jsonl under {DEFAULT_WORKSPACE_ROOTS}",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 on any unclassified (fail) rejection rows",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_out",
        help="Emit JSON to stdout instead of human-readable text",
    )
    parser.add_argument(
        "--out-json",
        type=Path,
        default=None,
        help="Write JSON report to this file (human text still to stdout)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Resolve outcomes paths
    outcomes_paths: list[Path] = []
    error_msg: Optional[str] = None

    if args.outcomes is not None:
        if not args.outcomes.is_file():
            error_msg = f"outcomes file not found: {args.outcomes}"
        else:
            outcomes_paths = [args.outcomes]

    elif args.workspace is not None:
        ws = args.workspace
        if not ws.is_dir():
            error_msg = f"workspace not found: {ws}"
        else:
            candidate = ws / "reference" / "outcomes.jsonl"
            if not candidate.is_file():
                candidate = ws / "outcomes.jsonl"
            if not candidate.is_file():
                error_msg = f"no outcomes.jsonl found under {ws}"
            else:
                outcomes_paths = [candidate]

    elif args.all_workspaces:
        outcomes_paths = discover_workspace_outcomes(DEFAULT_WORKSPACE_ROOTS)
        if not outcomes_paths:
            print("[outcome-ledger-gate] WARN: no outcomes.jsonl discovered", file=sys.stderr)

    else:
        # Default: local repo reference/outcomes.jsonl
        repo_root = Path(__file__).resolve().parent.parent
        default_path = repo_root / "reference" / "outcomes.jsonl"
        if default_path.is_file():
            outcomes_paths = [default_path]
        else:
            print(
                f"[outcome-ledger-gate] no default outcomes.jsonl at {default_path}; "
                "pass --workspace <ws>, --outcomes <path>, or --all-workspaces",
                file=sys.stderr,
            )

    if error_msg:
        print(f"[outcome-ledger-gate] ERROR: {error_msg}", file=sys.stderr)
        return 2

    # Scan files
    ws_reports: list[WorkspaceReport] = []
    for p in outcomes_paths:
        ws_name = p.parent.parent.name
        ws_reports.append(scan_outcomes_file(p, workspace_name=ws_name))

    gate_report = build_gate_report(ws_reports, now_str)

    # Write JSON file if requested
    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(
            json.dumps(_serialize(gate_report), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"[outcome-ledger-gate] report written to {args.out_json}", file=sys.stderr)

    # Stdout output
    if args.json_out:
        print(json.dumps(_serialize(gate_report), indent=2, sort_keys=True))
    else:
        print_human(gate_report)

    # Exit code
    if args.strict and gate_report.overall_verdict == "fail":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
