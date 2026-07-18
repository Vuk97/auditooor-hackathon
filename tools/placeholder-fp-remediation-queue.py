#!/usr/bin/env python3
"""placeholder-fp-remediation-queue.py — indexed reversible remediation queue.

Burn-down item #9 (handover plan): generated DSL drafts under
``detectors/_specs/drafts_*/`` still reference placeholder FP-guard fields
(``guarded_helper_name: "_accrue"``, generic regex placeholders, etc.).
Tier-S/A promotion already fails closed (``detector-lint.py
--fail-high-tier-placeholder-fp-guards``), but the legacy generated backlog
(~19,500 rows) cannot be hand-edited safely.

This tool builds an INDEXED, REVERSIBLE, TESTED remediation queue:

  --scan       Walk the placeholder hits (uses the same field/needle table
               as ``detector-lint.py`` Check 4b) and emit one JSONL row per
               hit at ``<workspace>/.auditooor/placeholder_fp_queue.jsonl``.
               Re-running ``--scan`` is idempotent: existing applied/rolled
               rows are preserved; only new hits are appended.
  --worker     Pop ``--limit N`` queued rows and emit a unified-diff
               PROPOSAL per row at
               ``<workspace>/.auditooor/placeholder_fp_proposals/<sha>.diff``
               with a clear ``OPERATOR REVIEW REQUIRED`` header. Never auto-
               applies. Each proposal is identified by a deterministic
               ``sha`` derived from the queue row.
  --apply <sha>      Apply the named proposal (the operator opts in by sha).
                     Records the original bytes inside the proposal sidecar
                     so ``--rollback`` can restore byte-equal state.
  --rollback <sha>   Revert a previously applied proposal.
  --list-proposals   Print the proposal table (sha, path, status).
  --status           Summarize queue state (pending, proposed, applied,
                     rolled-back).

Suggested-action heuristics (per placeholder field, fall back to
``flag-as-todo``):

  * ``guarded_helper_name`` placeholder ``_accrue`` / ``_guard``  →
        suggest grep-discovery of a real accrual / guard helper name in the
        target source family.
  * ``guard_require_line`` placeholder                            →
        suggest tightening with a class-specific bound require line.
  * ``guard_var_regex`` generic ``balance|amount|total|...``     →
        suggest a pattern-specific anchor matching the draft's
        ``fn_name_regex`` / ``read_var_regex``.

The queue is RESUMABLE. Workspace state lives at
``<workspace>/.auditooor/placeholder_fp_queue_state.json`` so an interrupted
worker run can be re-attempted without losing applied/rolled telemetry.

This tool is **stdlib-only** and never imports detector-lint.py at module
import time (we copy the placeholder field table to keep the contract
explicit; ``detector-lint.py`` is the canonical source-of-truth, and a
divergence test in ``tools/tests/test_placeholder_fp_queue.py`` keeps the
two tables in sync).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import difflib
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKSPACE = ROOT
DEFAULT_SPEC_GLOB = "detectors/_specs/drafts_*"

# ---------------------------------------------------------------------------
# Placeholder field table — kept in sync with detector-lint.py Check 4b.
# A test (``test_placeholder_fp_queue::test_field_table_matches_detector_lint``)
# fails closed if the two diverge, so future detector-lint additions don't
# silently get missed by the queue.
# ---------------------------------------------------------------------------

PLACEHOLDER_FP_GUARD_FIELDS: dict[str, tuple[str, ...]] = {
    "guarded_helper_name": ("_accrue", "_guard"),
    "guard_require_line": ("require(newVal <= 10000",),
    "guard_var_regex": (
        ".*(balance|amount|total|supply|reserve).*",
        ".*(admin|owner|balance|amount).*",
    ),
}

_YAML_SCALAR_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?)\s*(?:#.*)?$")

# Status constants
ST_PENDING = "pending"
ST_PROPOSED = "proposed"
ST_APPLIED = "applied"
ST_ROLLED_BACK = "rolled_back"
ALLOWED_STATUSES = (ST_PENDING, ST_PROPOSED, ST_APPLIED, ST_ROLLED_BACK)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _strip_yaml_scalar(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return value.strip()


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _row_sha(row: dict[str, Any]) -> str:
    """Deterministic short sha for a queue row.

    Uses (path, lineno, field, value) so re-scans don't change the sha for
    the same hit, which keeps applied/rolled telemetry stable across reruns.
    """
    payload = json.dumps(
        {
            "path": row["path"],
            "lineno": row["lineno"],
            "field": row["field"],
            "value": row["value"],
        },
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:12]


def _workspace_dir(workspace: Path) -> Path:
    return workspace / ".auditooor"


def _queue_path(workspace: Path) -> Path:
    return _workspace_dir(workspace) / "placeholder_fp_queue.jsonl"


def _state_path(workspace: Path) -> Path:
    return _workspace_dir(workspace) / "placeholder_fp_queue_state.json"


def _proposals_dir(workspace: Path) -> Path:
    return _workspace_dir(workspace) / "placeholder_fp_proposals"


# ---------------------------------------------------------------------------
# Scan: discover placeholder hits across draft spec dirs
# ---------------------------------------------------------------------------

def discover_hits(spec_dirs: Iterable[Path]) -> list[dict[str, Any]]:
    """Return placeholder hits in deterministic order (sorted by path, line)."""
    hits: list[dict[str, Any]] = []
    for spec_dir in spec_dirs:
        if not spec_dir.is_dir():
            continue
        for yaml_path in sorted(spec_dir.rglob("*.yaml")):
            text = _read_text(yaml_path)
            if not text:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                m = _YAML_SCALAR_RE.match(line)
                if not m:
                    continue
                field, raw_value = m.group(1), m.group(2)
                needles = PLACEHOLDER_FP_GUARD_FIELDS.get(field)
                if not needles:
                    continue
                value = _strip_yaml_scalar(raw_value)
                for needle in needles:
                    if needle in value:
                        hits.append(
                            {
                                "path": str(yaml_path),
                                "lineno": lineno,
                                "field": field,
                                "value": value,
                                "needle": needle,
                            }
                        )
                        break
    return hits


def suggest_action(field: str, value: str) -> dict[str, str]:
    """Return suggested-action metadata for a placeholder hit.

    Heuristic-only — never authoritative. Operators must inspect the proposal
    diff before applying.
    """
    if field == "guarded_helper_name" and value in {"_accrue", "_guard"}:
        verb = "accrual" if value == "_accrue" else "guard"
        return {
            "action": "grep-discover-helper",
            "hint": (
                f"grep the target source family for a real {verb} helper name "
                f"and replace `{value}`; if no real helper exists, demote the "
                "detector below Tier-A or remove the guard requirement."
            ),
        }
    if field == "guard_require_line":
        return {
            "action": "tighten-require-line",
            "hint": (
                "replace the generic `require(newVal <= 10000` placeholder "
                "with a class-specific bound require pinned to the draft's "
                "actual upper-bound variable."
            ),
        }
    if field == "guard_var_regex":
        return {
            "action": "tighten-regex-anchor",
            "hint": (
                "replace the generic balance|amount|total|... placeholder "
                "with an anchor matching the draft's actual fn_name_regex / "
                "read_var_regex semantics."
            ),
        }
    return {
        "action": "flag-as-todo",
        "hint": "no heuristic match — record TODO comment and demote.",
    }


# ---------------------------------------------------------------------------
# Queue I/O
# ---------------------------------------------------------------------------

def load_queue(queue_path: Path) -> list[dict[str, Any]]:
    if not queue_path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in queue_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def write_queue(queue_path: Path, rows: list[dict[str, Any]]) -> None:
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    with queue_path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


def load_state(state_path: Path) -> dict[str, Any]:
    if not state_path.is_file():
        return {"schema": "placeholder_fp_queue_state.v1", "rows": {}}
    data = json.loads(state_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("state file is not a JSON object")
    data.setdefault("schema", "placeholder_fp_queue_state.v1")
    data.setdefault("rows", {})
    return data


def write_state(state_path: Path, state: dict[str, Any]) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(state, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Scan command
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    spec_root = Path(args.spec_root).resolve()
    spec_dirs = [
        p for p in sorted(spec_root.glob(args.spec_glob_suffix)) if p.is_dir()
    ]
    hits = discover_hits(spec_dirs)

    queue_path = _queue_path(workspace)
    state_path = _state_path(workspace)
    state = load_state(state_path)
    rows_by_sha: dict[str, dict[str, Any]] = state["rows"]

    new_rows: list[dict[str, Any]] = []
    appended = 0
    refreshed = 0
    for hit in hits:
        sha = _row_sha(hit)
        suggestion = suggest_action(hit["field"], hit["value"])
        existing = rows_by_sha.get(sha)
        row = {
            "sha": sha,
            "path": hit["path"],
            "lineno": hit["lineno"],
            "field": hit["field"],
            "value": hit["value"],
            "needle": hit["needle"],
            "action": suggestion["action"],
            "hint": suggestion["hint"],
            "status": existing["status"] if existing else ST_PENDING,
            "first_seen": existing["first_seen"] if existing else _now_iso(),
            "last_seen": _now_iso(),
        }
        if existing:
            row["history"] = existing.get("history", [])
            refreshed += 1
        else:
            row["history"] = [
                {"ts": row["first_seen"], "event": "discovered"},
            ]
            appended += 1
        rows_by_sha[sha] = row
        new_rows.append(row)

    write_queue(queue_path, new_rows)
    state["rows"] = rows_by_sha
    state["last_scan"] = _now_iso()
    state["last_scan_summary"] = {
        "spec_dirs": [str(p) for p in spec_dirs],
        "hits": len(hits),
        "new": appended,
        "refreshed": refreshed,
    }
    write_state(state_path, state)

    summary = {
        "queue": str(queue_path),
        "state": str(state_path),
        "hits": len(hits),
        "new": appended,
        "refreshed": refreshed,
        "spec_dirs_scanned": len(spec_dirs),
    }
    print(json.dumps(summary, indent=2))
    return 0


# ---------------------------------------------------------------------------
# Diff / proposal helpers
# ---------------------------------------------------------------------------

def _build_proposal_diff(row: dict[str, Any], original_text: str, new_text: str) -> str:
    """Return a unified-diff string with a clear operator-review header."""
    rel_path = row["path"]
    header_lines = [
        "# OPERATOR REVIEW REQUIRED",
        f"# Proposal SHA : {row['sha']}",
        f"# Target file  : {rel_path}",
        f"# Line         : {row['lineno']}",
        f"# Field        : {row['field']}",
        f"# Placeholder  : {row['value']}",
        f"# Action       : {row['action']}",
        f"# Hint         : {row['hint']}",
        "# Apply with   : "
        f"python3 tools/placeholder-fp-remediation-queue.py --apply {row['sha']}",
        "# Rollback     : "
        f"python3 tools/placeholder-fp-remediation-queue.py --rollback {row['sha']}",
        "#",
        "# This proposal is heuristic. Inspect the diff before applying.",
        "",
    ]
    diff_lines = list(
        difflib.unified_diff(
            original_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
            n=3,
        )
    )
    return "\n".join(header_lines) + "".join(diff_lines)


def _propose_new_text(row: dict[str, Any], original_text: str) -> str:
    """Return the new file body that the proposal would produce.

    The proposal is conservative: we never silently delete the placeholder
    line. We append a TODO comment marker on the offending line so the
    operator's downstream review surfaces it loudly.
    """
    lines = original_text.splitlines(keepends=True)
    idx = row["lineno"] - 1
    if idx < 0 or idx >= len(lines):
        return original_text
    target = lines[idx]
    # Already annotated — no-op.
    if "# TODO(placeholder-fp-burndown" in target:
        return original_text
    # Preserve trailing newline shape.
    if target.endswith("\n"):
        body = target[:-1]
        nl = "\n"
    else:
        body = target
        nl = ""
    annotated = (
        f"{body}  "
        f"# TODO(placeholder-fp-burndown sha={row['sha']} action={row['action']})"
        f"{nl}"
    )
    lines[idx] = annotated
    return "".join(lines)


# ---------------------------------------------------------------------------
# Worker command — emit proposals
# ---------------------------------------------------------------------------

def cmd_worker(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    state_path = _state_path(workspace)
    queue_path = _queue_path(workspace)
    proposals_dir = _proposals_dir(workspace)
    proposals_dir.mkdir(parents=True, exist_ok=True)

    if not state_path.is_file():
        print(
            json.dumps(
                {
                    "error": "state-missing",
                    "hint": "run --scan first",
                    "state_path": str(state_path),
                },
                indent=2,
            ),
            file=sys.stderr,
        )
        return 2

    state = load_state(state_path)
    rows_by_sha: dict[str, dict[str, Any]] = state["rows"]

    # Pop pending rows (deterministic order: sorted by sha).
    pending = [
        row for row in sorted(rows_by_sha.values(), key=lambda r: r["sha"])
        if row["status"] == ST_PENDING
    ]
    if not pending:
        print(json.dumps({"emitted": 0, "remaining_pending": 0}, indent=2))
        return 0

    limit = max(1, args.limit)
    selected = pending[:limit]
    emitted: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for row in selected:
        target_path = Path(row["path"])
        original_text = _read_text(target_path)
        if not original_text:
            row["status"] = ST_PENDING
            row.setdefault("history", []).append(
                {"ts": _now_iso(), "event": "skipped-empty-source"}
            )
            skipped.append({"sha": row["sha"], "reason": "empty-source"})
            continue
        new_text = _propose_new_text(row, original_text)
        if new_text == original_text:
            row["status"] = ST_PENDING
            row.setdefault("history", []).append(
                {"ts": _now_iso(), "event": "skipped-already-annotated"}
            )
            skipped.append({"sha": row["sha"], "reason": "already-annotated"})
            continue
        diff_body = _build_proposal_diff(row, original_text, new_text)
        proposal_path = proposals_dir / f"{row['sha']}.diff"
        proposal_path.write_text(diff_body, encoding="utf-8")
        # Sidecar with original bytes so rollback can restore byte-equal.
        sidecar_path = proposals_dir / f"{row['sha']}.sidecar.json"
        sidecar = {
            "schema": "placeholder_fp_proposal.v1",
            "sha": row["sha"],
            "path": row["path"],
            "lineno": row["lineno"],
            "field": row["field"],
            "value": row["value"],
            "action": row["action"],
            "hint": row["hint"],
            "original_text": original_text,
            "proposed_text": new_text,
            "created_at": _now_iso(),
        }
        sidecar_path.write_text(
            json.dumps(sidecar, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        row["status"] = ST_PROPOSED
        row["proposal_path"] = str(proposal_path)
        row["sidecar_path"] = str(sidecar_path)
        row.setdefault("history", []).append(
            {"ts": _now_iso(), "event": "proposed"}
        )
        emitted.append(
            {
                "sha": row["sha"],
                "path": row["path"],
                "proposal": str(proposal_path),
            }
        )

    state["rows"] = rows_by_sha
    write_state(state_path, state)
    # Refresh queue file for human inspection.
    write_queue(queue_path, sorted(rows_by_sha.values(), key=lambda r: r["sha"]))

    summary = {
        "emitted": len(emitted),
        "skipped": skipped,
        "proposals": emitted,
        "remaining_pending": sum(
            1 for r in rows_by_sha.values() if r["status"] == ST_PENDING
        ),
    }
    print(json.dumps(summary, indent=2))
    return 0


# ---------------------------------------------------------------------------
# Apply command — write proposed_text back to disk
# ---------------------------------------------------------------------------

def cmd_apply(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    state_path = _state_path(workspace)
    proposals_dir = _proposals_dir(workspace)

    state = load_state(state_path)
    rows_by_sha: dict[str, dict[str, Any]] = state["rows"]

    sha = args.apply
    row = rows_by_sha.get(sha)
    if row is None:
        print(
            json.dumps({"error": "unknown-sha", "sha": sha}, indent=2),
            file=sys.stderr,
        )
        return 2
    if row["status"] not in (ST_PROPOSED, ST_ROLLED_BACK):
        print(
            json.dumps(
                {
                    "error": "invalid-state",
                    "sha": sha,
                    "current_status": row["status"],
                    "hint": "row must be proposed or rolled_back to apply",
                },
                indent=2,
            ),
            file=sys.stderr,
        )
        return 2
    sidecar_path = proposals_dir / f"{sha}.sidecar.json"
    if not sidecar_path.is_file():
        print(
            json.dumps(
                {"error": "sidecar-missing", "sha": sha, "path": str(sidecar_path)},
                indent=2,
            ),
            file=sys.stderr,
        )
        return 2
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    target_path = Path(sidecar["path"])
    current_text = _read_text(target_path)
    if current_text != sidecar["original_text"]:
        print(
            json.dumps(
                {
                    "error": "source-drift",
                    "sha": sha,
                    "hint": (
                        "target file changed since proposal was generated; "
                        "regenerate the proposal with --worker"
                    ),
                },
                indent=2,
            ),
            file=sys.stderr,
        )
        return 2
    target_path.write_text(sidecar["proposed_text"], encoding="utf-8")
    row["status"] = ST_APPLIED
    row.setdefault("history", []).append(
        {"ts": _now_iso(), "event": "applied"}
    )
    state["rows"] = rows_by_sha
    write_state(state_path, state)
    write_queue(_queue_path(workspace), sorted(rows_by_sha.values(), key=lambda r: r["sha"]))
    print(
        json.dumps(
            {"applied": sha, "path": str(target_path)}, indent=2
        )
    )
    return 0


# ---------------------------------------------------------------------------
# Rollback command — restore byte-equal original text
# ---------------------------------------------------------------------------

def cmd_rollback(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    state_path = _state_path(workspace)
    proposals_dir = _proposals_dir(workspace)

    state = load_state(state_path)
    rows_by_sha: dict[str, dict[str, Any]] = state["rows"]

    sha = args.rollback
    row = rows_by_sha.get(sha)
    if row is None:
        print(
            json.dumps({"error": "unknown-sha", "sha": sha}, indent=2),
            file=sys.stderr,
        )
        return 2
    if row["status"] != ST_APPLIED:
        print(
            json.dumps(
                {
                    "error": "invalid-state",
                    "sha": sha,
                    "current_status": row["status"],
                    "hint": "only applied rows can be rolled back",
                },
                indent=2,
            ),
            file=sys.stderr,
        )
        return 2
    sidecar_path = proposals_dir / f"{sha}.sidecar.json"
    if not sidecar_path.is_file():
        print(
            json.dumps(
                {"error": "sidecar-missing", "sha": sha, "path": str(sidecar_path)},
                indent=2,
            ),
            file=sys.stderr,
        )
        return 2
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    target_path = Path(sidecar["path"])
    target_path.write_text(sidecar["original_text"], encoding="utf-8")
    row["status"] = ST_ROLLED_BACK
    row.setdefault("history", []).append(
        {"ts": _now_iso(), "event": "rolled_back"}
    )
    state["rows"] = rows_by_sha
    write_state(state_path, state)
    write_queue(_queue_path(workspace), sorted(rows_by_sha.values(), key=lambda r: r["sha"]))
    print(
        json.dumps(
            {"rolled_back": sha, "path": str(target_path)}, indent=2
        )
    )
    return 0


# ---------------------------------------------------------------------------
# Status / list-proposals
# ---------------------------------------------------------------------------

def cmd_status(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    state_path = _state_path(workspace)
    if not state_path.is_file():
        print(json.dumps({"state": "missing", "workspace": str(workspace)}, indent=2))
        return 0
    state = load_state(state_path)
    rows = list(state["rows"].values())
    counts = {status: 0 for status in ALLOWED_STATUSES}
    for row in rows:
        counts[row.get("status", ST_PENDING)] = counts.get(row.get("status", ST_PENDING), 0) + 1
    print(
        json.dumps(
            {
                "workspace": str(workspace),
                "queue": str(_queue_path(workspace)),
                "state": str(state_path),
                "total": len(rows),
                "counts": counts,
                "last_scan": state.get("last_scan"),
            },
            indent=2,
        )
    )
    return 0


def cmd_list_proposals(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    state_path = _state_path(workspace)
    if not state_path.is_file():
        print(json.dumps({"state": "missing", "workspace": str(workspace)}, indent=2))
        return 0
    state = load_state(state_path)
    rows = sorted(state["rows"].values(), key=lambda r: r["sha"])
    table = [
        {
            "sha": row["sha"],
            "status": row["status"],
            "path": row["path"],
            "field": row["field"],
            "action": row["action"],
        }
        for row in rows
        if row["status"] in (ST_PROPOSED, ST_APPLIED, ST_ROLLED_BACK)
    ]
    print(json.dumps({"proposals": table, "count": len(table)}, indent=2))
    return 0


# ---------------------------------------------------------------------------
# Argparse + dispatch
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="placeholder-fp-remediation-queue.py",
        description=(
            "Indexed reversible remediation queue for placeholder FP-guard "
            "fields in generated DSL drafts (burn-down item #9)."
        ),
    )
    parser.add_argument(
        "--workspace",
        default=str(DEFAULT_WORKSPACE),
        help=(
            "Workspace root (queue + state live at "
            "<workspace>/.auditooor/...). Default: repo root."
        ),
    )
    parser.add_argument(
        "--spec-root",
        default=str(DEFAULT_WORKSPACE),
        help=(
            "Root containing the spec drafts (default: repo root). "
            "Combined with --spec-glob-suffix to enumerate draft cohorts."
        ),
    )
    parser.add_argument(
        "--spec-glob-suffix",
        default=DEFAULT_SPEC_GLOB,
        help=(
            "Glob (relative to --spec-root) used to enumerate draft cohorts. "
            f"Default: {DEFAULT_SPEC_GLOB}"
        ),
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--scan",
        action="store_true",
        help="Discover placeholder hits and refresh the queue (default).",
    )
    group.add_argument(
        "--worker",
        action="store_true",
        help="Pop pending rows and emit unified-diff proposals (no auto-apply).",
    )
    group.add_argument(
        "--apply",
        metavar="SHA",
        help="Apply the proposal identified by SHA (operator opt-in).",
    )
    group.add_argument(
        "--rollback",
        metavar="SHA",
        help="Revert a previously applied proposal by SHA.",
    )
    group.add_argument(
        "--status",
        action="store_true",
        help="Summarize queue state by status bucket.",
    )
    group.add_argument(
        "--list-proposals",
        action="store_true",
        help="List proposals (sha, status, path, field, action).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Worker batch size (default: 10).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.apply:
        return cmd_apply(args)
    if args.rollback:
        return cmd_rollback(args)
    if args.worker:
        return cmd_worker(args)
    if args.status:
        return cmd_status(args)
    if args.list_proposals:
        return cmd_list_proposals(args)
    # Default: scan
    return cmd_scan(args)


if __name__ == "__main__":
    sys.exit(main())
