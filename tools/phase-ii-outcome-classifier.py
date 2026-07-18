#!/usr/bin/env python3
"""Classify FIX-PHASE-I.10 outcome rows into ``none`` / ``deferred`` / rule-id.

This is a narrow, report-oriented classifier for the Phase II.20 lane.
It reads the existing outcome-ledger gate report, joins rows against local
workspace ledgers when available, and emits a conservative classification
report that can be checked into ``reports/v3_iter_2026-05-25``.

The tool is intentionally small and conservative:
* it never mutates ``reference/outcomes.jsonl``;
* rows with no decline reason or non-terminal state are marked ``deferred``;
* rows that match a clear codified-rule lesson are mapped to a rule id;
* everything else falls back to ``none``.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.phase_ii_outcome_classification.v1"
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GATE_REPORT = REPO_ROOT / "reports" / "v3_iter_2026-05-25" / "lane_FIX_I10_OUTCOME_LEDGER_GATE" / "gate_report.json"
DEFAULT_OUT_DIR = REPO_ROOT / "reports" / "v3_iter_2026-05-25" / "lane_II20_OUTCOME_CLASSIFICATION"
DEFAULT_OUT_JSON = DEFAULT_OUT_DIR / "classification_report.json"
DEFAULT_OUT_MD = DEFAULT_OUT_DIR / "results.md"


@dataclass(frozen=True)
class Classification:
    classification: str
    reason: str
    evidence: str


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _ledger_path_for_workspace(workspace: str, workspace_dir: str | None = None) -> Path | None:
    if workspace_dir:
        candidate = Path(workspace_dir) / "reference" / "outcomes.jsonl"
        if candidate.is_file():
            return candidate
    if workspace == "auditooor-mcp":
        return REPO_ROOT / "reference" / "outcomes.jsonl"
    candidate = Path("/Users/wolf/audits") / workspace / "reference" / "outcomes.jsonl"
    return candidate if candidate.is_file() else None


def _load_ledger_rows(workspace: str, workspace_dir: str | None = None) -> list[dict[str, Any]]:
    path = _ledger_path_for_workspace(workspace, workspace_dir)
    if path is None:
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _row_lookup(row: dict[str, Any], ledgers: dict[str, list[dict[str, Any]]]) -> dict[str, Any] | None:
    workspace = str(row.get("workspace") or "")
    if not workspace:
        return None
    candidates = ledgers.get(workspace, [])
    if not candidates:
        return None
    row_id = str(row.get("row_id") or "")
    title = str(row.get("title") or "")
    def _relevance(entry: dict[str, Any]) -> tuple[int, int]:
        outcome = str(entry.get("outcome") or entry.get("status") or "").lower()
        has_reason = any(
            str(entry.get(field) or "").strip()
            for field in ("rejection_reason", "rejection_class", "fp_reason", "note", "notes")
        )
        rejection_score = 1 if outcome in {"rejected", "declined", "duplicate_of_rejected"} else 0
        reason_score = 1 if has_reason else 0
        return (rejection_score, reason_score)

    for entry in sorted(candidates, key=_relevance, reverse=True):
        ids = {
            str(entry.get("finding_id") or ""),
            str(entry.get("submission_id") or ""),
            str(entry.get("report_id") or ""),
            str(entry.get("draft_id") or ""),
            str(entry.get("id") or ""),
        }
        if row_id and row_id in ids:
            return entry
        if title and title == str(entry.get("title") or ""):
            return entry
    return None


def _join_text(*parts: Any) -> str:
    joined = " ".join(str(part or "") for part in parts).lower()
    return f"{joined} {joined.replace('_', ' ')}"


def _matches(text: str, *patterns: str) -> bool:
    return any(re.search(pattern, text, re.I) for pattern in patterns)


def _display_path(path: Path, *, repo_root: Path = REPO_ROOT) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def classify_row(row: dict[str, Any], ledger_row: dict[str, Any] | None = None) -> Classification:
    """Return the conservative classification for one gate-report row."""
    text = _join_text(
        row.get("workspace"),
        row.get("row_id"),
        row.get("title"),
        row.get("note"),
        row.get("status"),
        row.get("outcome"),
        ledger_row.get("status") if ledger_row else "",
        ledger_row.get("note") if ledger_row else "",
        ledger_row.get("rejection_reason") if ledger_row else "",
        ledger_row.get("rejection_class") if ledger_row else "",
        ledger_row.get("fp_reason") if ledger_row else "",
        ledger_row.get("notes") if ledger_row else "",
        ledger_row.get("final_triager_outcome") if ledger_row else "",
    )

    # Strong explicit rule matches.
    if row.get("workspace") == "dydx" and _matches(text, r"feegrant", r"program-level"):
        return Classification(
            "R56-RUBRIC-FIT-PROGRAM-LEVEL",
            "workspace-specific program-level fit failure",
            "dydx ledger + gate report title",
        )
    if row.get("workspace") == "dydx" and _matches(text, r"codec subcall cap", r"generic dos", r"\bdos\b", r"rate[- ]limit", r"rpc pressure"):
        return Classification(
            "R35-DOS-CLASS-REFRAME",
            "generic DoS / rate-limit framing requires reframe",
            "dydx ledger + gate report title",
        )
    if row.get("workspace") == "dydx" and _matches(text, r"iavl", r"memdb", r"pebbledb", r"goleveldb", r"slowbatchdb", r"production[- ]profile", r"restart"):
        # The cache race row is a production-config issue; the rest are
        # production-profile proof mismatches.
        if _matches(text, r"fast[- ]node", r"disablefastnode", r"cache race"):
            return Classification(
                "R14-PRODUCTION-CONFIG-DISABLES-CLAIMED-IMPACT-SURFACE",
                "claimed surface depends on a production-disabled fast-node path",
                "dydx fast-node cache row",
            )
        return Classification(
            "R30-PRODUCTION-PROFILE-PREFLIGHT",
            "production-profile or backend mismatch needs real backend evidence",
            "dydx ledger + gate report title",
        )
    if _matches(text, r"withdrawn after precondition check", r"prerequisite", r"poisoned state creation"):
        return Classification(
            "R11-SEVERE-IMPACT-WITHOUT-IN-SCOPE-EXPLOIT-PREREQUISITE",
            "high-impact claim needs the in-scope prerequisite spelled out",
            "withdrawn-after-precondition-check lesson",
        )
    if _matches(text, r"panic", r"timeout", r"teardown", r"shutdown", r"closed db", r"cancelled context"):
        return Classification(
            "R15-TEARDOWN-CONTAMINATED-PANIC-OR-LIVENESS-EVIDENCE",
            "liveness evidence is contaminated by teardown signals",
            "panic / teardown keywords",
        )
    if _matches(text, r"share accounting", r"module-account", r"protocol-owned", r"recoverable", r"residual", r"prior residua"):
        return Classification(
            "R16-SEVERITY-OVERCLAIM-ON-INTERNAL-OR-RECOVERABLE-ACCOUNTING",
            "internal or recoverable accounting should not be framed as direct user theft",
            "accounting / residual keywords",
        )
    if _matches(text, r"keeper", r"finalizeblock", r"commit", r"advanceto") and _matches(text, r"direct", r"internal"):
        return Classification(
            "R13-KEEPER-DIRECT-PROOF-FOR-PRODUCTION-PATH-CLAIM",
            "production-path claim needs a real handler / block-execution path",
            "keeper-direct keywords",
        )
    if _matches(text, r"user attribution", r"counterparty", r"user error", r"receiver must verify"):
        return Classification(
            "R17-ACTOR-MODEL-OR-USER-ERROR-FRAMING-GAP",
            "actor separation or non-self-impact proof is missing",
            "actor-model keywords",
        )
    if _matches(text, r"does not halt", r"missing .*check", r"no flag gate", r"pausetrading", r"should pause", r"should halt"):
        # This is conservative: the pause-domain rows in the current ledger are
        # by-design / no-extraction cases, so we do not mint a new rule unless a
        # concrete user impact is present.
        if _matches(text, r"no value extraction", r"independent pause domains", r"architectural[- ]domain[- ]separation[- ]by[- ]design"):
            return Classification(
                "none",
                "by-design pause/domain split with no new rule to codify",
                "architectural/by-design rejection reason",
            )
        return Classification(
            "R45-DESIGNED-AS-INTENDED-PRECHECK",
            "omission-style claim needs a precheck or stronger proof",
            "pause / omission keywords",
        )

    # Conservative non-rule classifications.
    if _matches(text, r"unknown:no decline reason", r"no decline reason provided", r"declined by cantina \(no decline reason"):
        return Classification(
            "deferred",
            "platform supplied no decline reason; defer rather than invent a rule",
            "unknown decline reason",
        )
    if ledger_row and not any(
        str(ledger_row.get(field) or "").strip()
        for field in ("rejection_reason", "rejection_class", "fp_reason", "note", "notes")
    ) and _matches(text, r"\brejected\b", r"\bdeclined\b"):
        return Classification(
            "deferred",
            "rejected row has no platform or triager decline reason",
            "missing decline reason",
        )
    if _matches(text, r"pending", r"in review", r"escalated"):
        return Classification(
            "deferred",
            "non-terminal outcome; classification stays deferred",
            "non-terminal status",
        )
    if _matches(text, r"event-only", r"no functional impact", r"topic indexes wrong address", r"misusing the admin-indexed topic"):
        return Classification(
            "none",
            "event/log only or equivalent cosmetic issue",
            "event-only lesson",
        )
    if _matches(text, r"unrealistic bounds", r"extreme value", r"2\^248", r"uint248", r"no realistic order", r"not economically feasible"):
        return Classification(
            "none",
            "extreme-value trigger has no realistic path",
            "extreme value lesson",
        )
    if _matches(text, r"duplicate", r"same underlying pattern", r"same bug class", r"duplicate of rejected original", r"duplicate of other submission"):
        return Classification(
            "none",
            "duplicate / near-duplicate does not need a new rule",
            "duplicate lesson",
        )
    if _matches(text, r"reconstructible", r"attribution reconstructible", r"same-tx erc1155\.transferbatch"):
        return Classification(
            "none",
            "downstream event reconstruction defeats the proposed bug class",
            "reconstructible-from-batch-event lesson",
        )
    if _matches(text, r"architectural[- ]by[- ]design", r"separate contracts", r"no value extraction", r"independent pause domains"):
        return Classification(
            "none",
            "architectural/by-design rejection does not codify a new rule",
            "architectural by design lesson",
        )
    if _matches(text, r"operator_killed_pre_submit", r"self_assessed_not_a_vulnerability", r"centralization_weighted"):
        return Classification(
            "none",
            "operator-controlled withdrawal or explicit no-vulnerability note",
            "operator-driven withdrawal",
        )

    # Final fallback.
    return Classification(
        "none",
        "no explicit codified rule matched",
        "fallback",
    )


def build_report(
    gate_report: dict[str, Any], *, repo_root: Path = REPO_ROOT, source_gate_report: str | None = None
) -> dict[str, Any]:
    ledgers: dict[str, list[dict[str, Any]]] = {}
    workspace_dirs: dict[str, str] = {}
    for row in gate_report.get("operator_checklist", []):
        ws = str(row.get("workspace") or "")
        if ws and ws not in ledgers:
            workspace_dir = str(row.get("workspace_dir") or "")
            if workspace_dir:
                workspace_dirs[ws] = workspace_dir
            ledgers[ws] = _load_ledger_rows(ws, workspace_dirs.get(ws))

    rows: list[dict[str, Any]] = []
    counts: dict[str, int] = {"none": 0, "deferred": 0}
    rule_counts: dict[str, int] = {}

    for row in gate_report.get("operator_checklist", []):
        ledger_row = _row_lookup(row, ledgers)
        classification = classify_row(row, ledger_row)
        if classification.classification in {"none", "deferred"}:
            counts[classification.classification] = counts.get(classification.classification, 0) + 1
        else:
            rule_counts[classification.classification] = rule_counts.get(classification.classification, 0) + 1
        rows.append(
            {
                "workspace": row.get("workspace"),
                "row_id": row.get("row_id"),
                "title": row.get("title"),
                "status": row.get("verdict"),
                "classification": classification.classification,
                "reason": classification.reason,
                "evidence": classification.evidence,
            }
        )

    summary = {
        "rows": len(rows),
        "none": counts.get("none", 0),
        "deferred": counts.get("deferred", 0),
        "rule_ids": sum(rule_counts.values()),
        "unique_rule_ids": len(rule_counts),
        "rule_counts": dict(sorted(rule_counts.items())),
    }
    return {
        "schema": SCHEMA,
        "generated_at": gate_report.get("generated_at"),
        "source_gate_report": str(
            source_gate_report
            or _display_path(
                DEFAULT_GATE_REPORT.relative_to(repo_root) if DEFAULT_GATE_REPORT.exists() else DEFAULT_GATE_REPORT,
                repo_root=repo_root,
            )
        ),
        "source_inventory": "reports/v3_iter_2026-05-25/lane_AUDIT_DEEP_WIRING_INVENTORY/results.md",
        "summary": summary,
        "rows": rows,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Phase II.20 Outcome Classification",
        "",
        f"- Schema: `{report['schema']}`",
        f"- Rows: {report['summary']['rows']}",
        f"- None: {report['summary']['none']}",
        f"- Deferred: {report['summary']['deferred']}",
        f"- Rule-id classifications: {report['summary']['rule_ids']}",
        f"- Unique rule IDs: {report['summary']['unique_rule_ids']}",
        f"- Source gate report: `{report['source_gate_report']}`",
        f"- Source audit-deep inventory: `{report['source_inventory']}`",
        "",
        "| Workspace | Row | Classification | Reason |",
        "|---|---|---|---|",
    ]
    for row in report["rows"]:
        reason = str(row["reason"]).replace("|", "\\|")
        lines.append(
            f"| `{row['workspace']}` | `{row['row_id']}` | `{row['classification']}` | {reason} |"
        )
    lines.append("")
    if report["summary"]["rule_counts"]:
        lines.append("## Rule IDs")
        lines.append("")
        for rule_id, count in report["summary"]["rule_counts"].items():
            lines.append(f"- `{rule_id}`: {count}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate-report", type=Path, default=DEFAULT_GATE_REPORT)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    parser.add_argument("--stdout-format", choices=("json", "markdown"), default="markdown")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    gate_report = _read_json(args.gate_report)
    report = build_report(gate_report, source_gate_report=_display_path(args.gate_report))

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    args.out_md.write_text(render_markdown(report), encoding="utf-8")

    if args.stdout_format == "json":
        print(json.dumps(report, indent=2, sort_keys=False))
    else:
        print(render_markdown(report), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
