#!/usr/bin/env python3
"""Hunter-packet outcome join (B9 - HACKERMAN V3 capability plan).

Joins corpus records, triager outcomes, OOS lessons, agent artifacts, and
proof mappings into a bounded lesson/outcome/triager block for hunter
context. Each joined row carries an ``evidence_scope`` field from the
canonical vocabulary so a worker sees not only 'similar bug exists' but
whether similar reports were confirmed, downgraded, duplicate, OOS,
unprofitable, documented-mechanics, or proof-deficient.

Evidence scope vocabulary (exact):
    proof           - runtime-proven PoC or artifact accepted for promotion
    OOS             - filed/tested finding was rejected as out-of-scope
    dupe            - finding was marked duplicate on the platform
    economics       - rejected / downgraded on economic / unprofitability grounds
    severity_cap    - downgraded / capped by triager (not OOS, not dupe)
    team_position   - team-acknowledged / by-design / won't-fix
    context_only    - informational context (no outcome signal - corpus/lesson only)

Schema: auditooor.hunter_packet_outcome_join.v1
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.hunter_packet_outcome_join.v1"
DEFAULT_ROW_CAP = 25

# Canonical evidence_scope vocabulary
EVIDENCE_SCOPE_VOCAB = frozenset(
    {"proof", "OOS", "dupe", "economics", "severity_cap", "team_position", "context_only"}
)

# Outcome string -> evidence_scope mapping (from outcomes.jsonl `outcome` field)
OUTCOME_TO_SCOPE: dict[str, str] = {
    "confirmed": "proof",
    "accepted": "proof",
    "paid": "proof",
    "valid": "proof",
    "downgraded": "severity_cap",
    "severity_reduced": "severity_cap",
    "capped": "severity_cap",
    "duplicate": "dupe",
    "dupe": "dupe",
    "oos": "OOS",
    "out_of_scope": "OOS",
    "rejected": "OOS",
    "by_design": "team_position",
    "acknowledged": "team_position",
    "wont_fix": "team_position",
    "unprofitable": "economics",
    "economics": "economics",
    "proof_deficient": "severity_cap",
    "pending": "context_only",
}

# Triager pattern rejection id -> evidence_scope
REJECTION_SCOPE_MAP: dict[str, str] = {
    "R1": "context_only",    # Event-Only Finding
    "R2": "OOS",             # Extreme Value / Theoretical Overflow
    "R3": "dupe",            # Self-Dupe
    "R4": "team_position",   # Acknowledged Design Choice
    "R5": "OOS",             # Spec-compliant behavior
    "R6": "severity_cap",    # Missing proof of impact
    "R7": "economics",       # Economics not viable
}


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _safe_read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read a JSONL file defensively; return empty list if absent/broken."""
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    rows.append(obj)
            except json.JSONDecodeError:
                pass
    except OSError:
        pass
    return rows


def _safe_read_json(path: Path) -> Any:
    """Read a JSON file defensively; return None if absent/broken."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def _safe_read_yaml_fields(path: Path, target_fields: list[str]) -> dict[str, Any]:
    """Extract specific fields from a YAML file without full yaml dependency."""
    if not path.exists():
        return {}
    result: dict[str, Any] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            for field in target_fields:
                if line.startswith(f"{field}:"):
                    val = line[len(field) + 1:].strip().strip('"').strip("'")
                    result[field] = val
                    break
    except OSError:
        pass
    return result


def _infer_scope_from_outcome_str(outcome: str | None) -> str:
    """Map a free-text outcome string to an evidence_scope value."""
    if not outcome:
        return "context_only"
    key = outcome.lower().strip().replace("-", "_").replace(" ", "_")
    return OUTCOME_TO_SCOPE.get(key, "context_only")


def _matches_filter(row: dict[str, Any], attack_class: str | None, bug_class: str | None) -> bool:
    """Return True if row matches optional attack_class / bug_class filters."""
    if attack_class:
        ac = str(row.get("attack_class", "")).lower()
        if attack_class.lower() not in ac:
            return False
    if bug_class:
        bc = str(row.get("bug_class", "")).lower()
        if bug_class.lower() not in bc:
            return False
    return True


# ---------------------------------------------------------------------------
# Source loaders
# ---------------------------------------------------------------------------

def load_outcomes(reference_dir: Path, attack_class: str | None, bug_class: str | None) -> list[dict[str, Any]]:
    """Load rows from reference/outcomes.jsonl and classify evidence scope."""
    rows = _safe_read_jsonl(reference_dir / "outcomes.jsonl")
    result = []
    for row in rows:
        scope = _infer_scope_from_outcome_str(row.get("outcome"))
        result.append({
            "source": "outcomes.jsonl",
            "finding_id": row.get("finding_id", ""),
            "title": row.get("title", ""),
            "severity": row.get("severity", ""),
            "outcome": row.get("outcome", ""),
            "workspace": row.get("workspace", ""),
            "date": row.get("date", ""),
            "evidence_scope": scope,
            "attack_class": row.get("attack_class", ""),
            "bug_class": row.get("bug_class", ""),
            "_raw": row,
        })
    # filter if requested
    if attack_class or bug_class:
        result = [r for r in result if _matches_filter(r, attack_class, bug_class)]
    return result


def load_triager_patterns(reference_dir: Path) -> list[dict[str, Any]]:
    """Load triager rejection/acceptance patterns as context_only rows."""
    patterns = _safe_read_json(reference_dir / "triager_patterns.json")
    if not isinstance(patterns, dict):
        return []
    result = []
    for kind, items in patterns.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            rid = item.get("id", "")
            if kind == "rejections":
                scope = REJECTION_SCOPE_MAP.get(rid, "severity_cap")
                outcome = "triager_rejection_pattern"
            elif kind == "acceptances":
                scope = "proof"
                outcome = "triager_acceptance_pattern"
            else:
                scope = "context_only"
                outcome = "triager_in_review_risk"
            result.append({
                "source": "triager_patterns.json",
                "pattern_id": rid,
                "name": item.get("name", ""),
                "description": item.get("description", "")[:200],
                "outcome": outcome,
                "triager_language": item.get("triager_language", []),
                "evidence_scope": scope,
                "attack_class": "",
                "bug_class": "",
                "_raw": item,
            })
    return result


def load_oos_lessons(workspace_path: Path | None) -> list[dict[str, Any]]:
    """Load OOS check files from workspace .auditooor/ directory."""
    if workspace_path is None:
        return []
    auditooor_dir = workspace_path / ".auditooor"
    if not auditooor_dir.is_dir():
        return []
    result = []
    try:
        for oos_file in auditooor_dir.glob("oos_check_*.json"):
            data = _safe_read_json(oos_file)
            if not isinstance(data, dict):
                continue
            # Determine scope: any matched clause -> OOS; else context_only
            clauses = data.get("clauses_checked", [])
            matched = [c for c in clauses if isinstance(c, dict) and c.get("verdict") == "MATCH"]
            scope = "OOS" if matched else "context_only"
            finding = data.get("finding", "")
            result.append({
                "source": f".auditooor/{oos_file.name}",
                "finding": finding,
                "date": data.get("date", ""),
                "workspace": str(workspace_path),
                "matched_clauses": [c.get("id") for c in matched],
                "outcome": "oos_check",
                "evidence_scope": scope,
                "attack_class": "",
                "bug_class": "",
                "_raw": data,
            })
    except OSError:
        pass
    return result


def load_agent_artifacts(workspace_path: Path | None, attack_class: str | None, bug_class: str | None) -> list[dict[str, Any]]:
    """Load learning_ledger.jsonl from workspace .auditooor/agent_artifacts/."""
    if workspace_path is None:
        return []
    ledger_path = workspace_path / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
    rows = _safe_read_jsonl(ledger_path)
    result = []
    for row in rows:
        terminal_kind = row.get("terminal_kind", "")
        # Map terminal_kind to evidence_scope
        if terminal_kind == "proof_artifact":
            scope = "proof"
        elif terminal_kind in ("kill_reason",):
            scope = "severity_cap"
        elif terminal_kind in ("triager_objection",):
            scope = "team_position"
        elif terminal_kind in ("hacker_question", "detector_hypothesis", "workflow_gap", "proof_obligation"):
            scope = "context_only"
        else:
            scope = "context_only"

        r = {
            "source": "learning_ledger.jsonl",
            "task_id": row.get("task_id", ""),
            "terminal_kind": terminal_kind,
            "status": row.get("status", ""),
            "ts": row.get("ts", ""),
            "quarantine": row.get("quarantine", False),
            "outcome": row.get("status", ""),
            "evidence_scope": scope,
            "attack_class": row.get("attack_class", ""),
            "bug_class": row.get("bug_class", ""),
            "_raw": row,
        }
        if _matches_filter(r, attack_class, bug_class):
            result.append(r)
    return result


def load_proof_mappings(repo_root: Path, workspace_path: Path | None, attack_class: str | None, bug_class: str | None) -> list[dict[str, Any]]:
    """Load proof_artifact_index.jsonl and proof_artifact_accepted_writeback.jsonl."""
    derived_dir = repo_root / "audit" / "corpus_tags" / "derived"
    result = []

    for fname, outcome_label in [
        ("proof_artifact_index.jsonl", "proof_indexed"),
        ("proof_artifact_accepted_writeback.jsonl", "proof_accepted"),
    ]:
        rows = _safe_read_jsonl(derived_dir / fname)
        for row in rows:
            promotion_ready = row.get("promotion_ready", False)
            scope = "proof" if promotion_ready or outcome_label == "proof_accepted" else "severity_cap"
            r = {
                "source": fname,
                "engagement": row.get("engagement", ""),
                "submission_title": row.get("submission_title", ""),
                "candidate_proof_path": row.get("candidate_proof_path", ""),
                "promotion_ready": promotion_ready,
                "promotion_review_status": row.get("promotion_review_status", ""),
                "outcome": outcome_label,
                "evidence_scope": scope,
                "attack_class": row.get("attack_class", ""),
                "bug_class": row.get("bug_class", ""),
                "_raw": row,
            }
            if _matches_filter(r, attack_class, bug_class):
                result.append(r)

    # Also look in workspace for proof sidecars if provided
    if workspace_path:
        ws_derived = workspace_path / "audit" / "corpus_tags" / "derived"
        if ws_derived.is_dir():
            for fname in ("proof_artifact_index.jsonl", "proof_artifact_accepted_writeback.jsonl"):
                rows = _safe_read_jsonl(ws_derived / fname)
                for row in rows:
                    r = {
                        "source": f"workspace/{fname}",
                        "engagement": row.get("engagement", ""),
                        "submission_title": row.get("submission_title", ""),
                        "promotion_ready": row.get("promotion_ready", False),
                        "outcome": "proof_workspace",
                        "evidence_scope": "proof" if row.get("promotion_ready") else "severity_cap",
                        "attack_class": row.get("attack_class", ""),
                        "bug_class": row.get("bug_class", ""),
                        "_raw": row,
                    }
                    if _matches_filter(r, attack_class, bug_class):
                        result.append(r)

    return result


# ---------------------------------------------------------------------------
# Join + emit
# ---------------------------------------------------------------------------

def _strip_raw(row: dict[str, Any]) -> dict[str, Any]:
    """Return a row without the internal _raw key."""
    return {k: v for k, v in row.items() if k != "_raw"}


def build_join(
    repo_root: Path,
    workspace_path: Path | None,
    attack_class: str | None,
    bug_class: str | None,
    row_cap: int = DEFAULT_ROW_CAP,
) -> dict[str, Any]:
    """Build the joined hunter packet outcome block."""
    missing_sources: list[str] = []
    all_rows: list[dict[str, Any]] = []

    # --- outcomes.jsonl ---
    outcomes_path = repo_root / "reference" / "outcomes.jsonl"
    if not outcomes_path.exists():
        missing_sources.append("reference/outcomes.jsonl")
    else:
        all_rows.extend(load_outcomes(repo_root / "reference", attack_class, bug_class))

    # --- triager_patterns.json ---
    tp_path = repo_root / "reference" / "triager_patterns.json"
    if not tp_path.exists():
        missing_sources.append("reference/triager_patterns.json")
    else:
        all_rows.extend(load_triager_patterns(repo_root / "reference"))

    # --- OOS lessons (workspace) ---
    if workspace_path is not None:
        auditooor_dir = workspace_path / ".auditooor"
        if not auditooor_dir.is_dir():
            missing_sources.append(f"{workspace_path}/.auditooor/ (workspace OOS dir absent)")
        else:
            all_rows.extend(load_oos_lessons(workspace_path))

    # --- agent artifacts (workspace) ---
    if workspace_path is not None:
        ledger = workspace_path / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
        if not ledger.exists():
            missing_sources.append(str(ledger))
        else:
            all_rows.extend(load_agent_artifacts(workspace_path, attack_class, bug_class))

    # --- proof mappings ---
    derived = repo_root / "audit" / "corpus_tags" / "derived"
    if not derived.is_dir():
        missing_sources.append("audit/corpus_tags/derived/")
    else:
        all_rows.extend(load_proof_mappings(repo_root, workspace_path, attack_class, bug_class))

    # Scope priority ordering for bounded output: proof first, then OOS/dupe,
    # then severity_cap/economics/team_position, then context_only
    SCOPE_ORDER = {
        "proof": 0,
        "OOS": 1,
        "dupe": 2,
        "economics": 3,
        "severity_cap": 4,
        "team_position": 5,
        "context_only": 6,
    }
    all_rows.sort(key=lambda r: SCOPE_ORDER.get(r.get("evidence_scope", "context_only"), 7))

    # Apply bounded cap
    capped = len(all_rows) > row_cap
    emitted = all_rows[:row_cap]

    # Scope summary
    scope_counts: dict[str, int] = {}
    for r in emitted:
        s = r.get("evidence_scope", "context_only")
        scope_counts[s] = scope_counts.get(s, 0) + 1

    return {
        "schema": SCHEMA,
        "generated_at": _utc_now(),
        "workspace": str(workspace_path) if workspace_path else None,
        "filters": {
            "attack_class": attack_class,
            "bug_class": bug_class,
        },
        "row_cap": row_cap,
        "total_rows_before_cap": len(all_rows),
        "rows_emitted": len(emitted),
        "capped": capped,
        "missing_sources": missing_sources,
        "scope_summary": scope_counts,
        "rows": [_strip_raw(r) for r in emitted],
    }


def _human_format(packet: dict[str, Any]) -> str:
    """Render a human-readable summary of the join packet."""
    lines: list[str] = [
        f"Hunter Packet Outcome Join ({packet['schema']})",
        f"Generated: {packet['generated_at']}",
        f"Workspace: {packet['workspace'] or '(none)'}",
        f"Filters: attack_class={packet['filters']['attack_class']!r}  bug_class={packet['filters']['bug_class']!r}",
        f"Rows emitted: {packet['rows_emitted']} / {packet['total_rows_before_cap']} total (cap={packet['row_cap']}, capped={packet['capped']})",
        "",
    ]
    if packet["missing_sources"]:
        lines.append("Missing sources (defensive - no crash):")
        for ms in packet["missing_sources"]:
            lines.append(f"  - {ms}")
        lines.append("")

    lines.append("Scope summary:")
    for scope, count in sorted(packet["scope_summary"].items()):
        lines.append(f"  {scope:16s} {count:4d}")
    lines.append("")

    lines.append("Rows (bounded, priority-sorted):")
    for i, row in enumerate(packet["rows"], 1):
        scope = row.get("evidence_scope", "?")
        src = row.get("source", "?")
        # pick best title field
        title = (
            row.get("title")
            or row.get("name")
            or row.get("submission_title")
            or row.get("task_id")
            or row.get("finding")
            or "(no title)"
        )
        outcome = row.get("outcome", "")
        lines.append(f"  [{i:2d}] [{scope:13s}] [{src}] {title!r}")
        if outcome:
            lines.append(f"       outcome={outcome!r}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Join corpus records, triager outcomes, OOS lessons, "
                    "agent artifacts, and proof mappings into a bounded hunter "
                    "packet (B9 - HACKERMAN V3 capability plan)."
    )
    parser.add_argument(
        "--workspace", "-w",
        default=None,
        help="Path to the workspace root (e.g. /Users/wolf/audits/nuva). "
             "Used to load .auditooor/ agent artifacts and OOS check files.",
    )
    parser.add_argument(
        "--attack-class",
        default=None,
        help="Optional filter: only include rows whose attack_class contains this string (case-insensitive).",
    )
    parser.add_argument(
        "--bug-class",
        default=None,
        help="Optional filter: only include rows whose bug_class contains this string (case-insensitive).",
    )
    parser.add_argument(
        "--cap",
        type=int,
        default=DEFAULT_ROW_CAP,
        help=f"Maximum rows to emit (default: {DEFAULT_ROW_CAP}).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Emit compact JSON output (schema auditooor.hunter_packet_outcome_join.v1).",
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Path to the auditooor-mcp repo root. Auto-detected from this script's location if omitted.",
    )
    args = parser.parse_args()

    # Resolve repo root
    if args.repo_root:
        repo_root = Path(args.repo_root).resolve()
    else:
        repo_root = Path(__file__).resolve().parent.parent

    workspace_path = Path(args.workspace).resolve() if args.workspace else None

    packet = build_join(
        repo_root=repo_root,
        workspace_path=workspace_path,
        attack_class=args.attack_class,
        bug_class=args.bug_class,
        row_cap=args.cap,
    )

    if args.json_output:
        print(json.dumps(packet, indent=2, ensure_ascii=False))
    else:
        print(_human_format(packet))


if __name__ == "__main__":
    main()
