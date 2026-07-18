#!/usr/bin/env python3
"""track-submissions.py — Manual Submission Ledger.

The operator-side half of the outcome-telemetry loop. Replaces PR 209's
dropped automated HackenProof/Cantina/Sherlock API adapter with a thin
human-in-the-loop tool that has zero network and zero API calls.

Workflow:

  1. Operator manually files a report on HackenProof / Cantina / Sherlock /
     Immunefi, copies the URL + report ID.
  2. `tools/track-submissions.py record <workspace> --platform <name>
     --report-url <url> --report-id <id> [--title <t>] [--severity <s>]`
     appends a *pending* row to `<ws>/submissions/SUBMISSIONS.md` and a
     pending record to `<ws>/reference/outcomes.jsonl`.
     P0-4 fields (`--lane`, `--model-route`, `--proof-artifact`,
     `--production-path-blockers-cleared`, `--final-triager-outcome`) tie
     the filed report back to the pipeline lane, model route, proof
     artifact, and triager outcome. Without them, `record` warns; with
     `--strict-linkage` (or env `AUDITOOOR_OUTCOME_REQUIRE_LINKAGE=1`) it
     fails closed (exit 2). The legacy `--production-path-status` flag is
     still accepted for back-compat, but the burn-down required field is
     `--production-path-blockers-cleared`.
  3. Days/weeks later, the triager decides. Operator runs
     `make record-outcome ID=<report-id> STATE=<accepted|paid|duplicate|
     rejected> WS=<ws>` — this tool appends an *updated* record to the
     same JSONL and updates the Status column in SUBMISSIONS.md.
  4. `tools/outcome_reweight.py` (PR 112) already reads the LAST matching
     record per class, so the update is honoured without rewriting history.

Artifacts layout
----------------

    <workspace>/
        submissions/
            SUBMISSIONS.md             # human-readable ledger table
        reference/
            outcomes.jsonl             # append-only telemetry stream

Append-only convention
----------------------

`reference/outcomes.jsonl` is an APPEND-ONLY stream. Never rewrite an
existing line. When an outcome transitions (pending -> accepted, etc.),
write a NEW line with the same `report_id` and a fresh `resolved_at`
stamp. Readers — especially `tools/outcome_reweight.py` — take the LAST
matching record per class as authoritative. Keeping history intact lets
us audit the ledger for "who changed what when" without a database.

Truth audit
-----------

  1. Overclaim risk: a freshly-recorded row still says `pending` and
     explicitly surfaces `Status: pending`. It is a local operator note,
     NOT proof of submission — the URL/report-ID are whatever the operator
     pasted in.
  2. Status vocabulary: exactly `pending | accepted | paid | duplicate |
     rejected`. These match the outcomes.jsonl vocabulary consumed by
     `outcome_reweight.py` (which buckets `paid` + `accepted` together,
     per Codex PR-102 non-blocker 1).
  3. Artifact classification: SUBMISSIONS.md + outcomes.jsonl are
     telemetry, not proof. Operator is responsible for the URL being real.
  4. Cannot-judge behaviour: `list` on a workspace with no ledger prints
     "no submissions recorded" and exits 0.
  5. Duplicate guard: attempting to `record` a report-ID already present
     in this workspace exits 2 with a clear error, preventing double-
     submit telemetry inflation.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

VALID_PLATFORMS = {"hackenproof", "cantina", "sherlock", "immunefi", "code4rena", "other"}

# Pending is the only state that `record` will ever write. The other values
# are reserved for `record-outcome` transitions.
PENDING = "pending"
TERMINAL_STATES = {"accepted", "paid", "duplicate", "rejected"}
ALL_STATES = {PENDING} | TERMINAL_STATES

# PR 9 (wave 8) — duplicate-root semantics. When a submission is marked
# "duplicate" but the original report is hidden (the operator has no
# permission to read it), we MUST classify based on the visible parent state
# without claiming victory or defeat unilaterally:
#
#   * `duplicate_of_accepted` — visible parent state is paid/accepted/in_review
#     trending toward acceptance. The dup row inherits the parent's positive
#     outcome learning signal.
#   * `duplicate_of_rejected` — visible parent state is rejected. The dup row
#     inherits the parent's negative learning signal.
#   * `withdrawn` — operator (or LLM-assisted reply) withdrew the
#     exploitability claim before final triage. Captured separately so the
#     scoreboard does not bucket withdrawals into the rejected lane.
#
# These extend TERMINAL_STATES for `record-outcome` transitions and
# `final_triager_outcome` capture, but readers that only care about
# accepted/rejected/duplicate can collapse them via
# `collapse_duplicate_root()` below.
DUPLICATE_OF_ACCEPTED = "duplicate_of_accepted"
DUPLICATE_OF_REJECTED = "duplicate_of_rejected"
WITHDRAWN = "withdrawn"
EXTENDED_STATES = {DUPLICATE_OF_ACCEPTED, DUPLICATE_OF_REJECTED, WITHDRAWN}
ALL_STATES = ALL_STATES | EXTENDED_STATES

# Field captured alongside `final_triager_outcome` whenever the original
# duplicate parent is not readable (Cantina / Immunefi / HackenProof private
# original). Allowed values: `hidden`, `visible`, `unknown`.
ORIGINAL_VISIBILITY_FIELD = "original_visibility"
ORIGINAL_VISIBILITY_HIDDEN = "hidden"
ORIGINAL_VISIBILITY_VISIBLE = "visible"
ORIGINAL_VISIBILITY_UNKNOWN = "unknown"
ORIGINAL_VISIBILITY_VALUES = {
    ORIGINAL_VISIBILITY_HIDDEN,
    ORIGINAL_VISIBILITY_VISIBLE,
    ORIGINAL_VISIBILITY_UNKNOWN,
}


def collapse_duplicate_root(outcome: str) -> str:
    """Collapse hidden-duplicate-root states into the simpler bucket.

    Used by readers (paste-ready / adversarial-review / outcome_reweight)
    that only care about accepted/rejected/duplicate — but the underlying
    JSONL still preserves the richer `duplicate_of_<accepted|rejected>`
    label so we don't lose the parent-visibility nuance.
    """
    if outcome == DUPLICATE_OF_ACCEPTED:
        return "accepted"
    if outcome == DUPLICATE_OF_REJECTED:
        return "rejected"
    if outcome == WITHDRAWN:
        return "rejected"
    return outcome


def is_duplicate_root(outcome: str) -> bool:
    """Return True iff outcome carries hidden-duplicate-root semantics."""
    return outcome in (DUPLICATE_OF_ACCEPTED, DUPLICATE_OF_REJECTED)

# P0-4 burn-down: scoreboard linkage required-field set. New rows MUST carry
# every key in REQUIRED_LINKAGE_FIELDS so outcome learning can trace the win
# back to the lane / model-route / proof artifact / production-path dossier
# that produced it. `final_triager_outcome` is special: the FIELD must exist
# but its value is "unknown" until the triager decides — that flips later via
# `record-outcome`. Operators preserve back-compat by default (advisory warn);
# strict mode (env `AUDITOOOR_OUTCOME_REQUIRE_LINKAGE=1` or `--strict-linkage`)
# fails closed with exit code 2 when any required field is missing.
REQUIRED_LINKAGE_FIELDS = (
    "lane",
    "model_route",
    "proof_artifact",
    "production_path_blockers_cleared",
)
FINAL_TRIAGER_FIELD = "final_triager_outcome"
FINAL_TRIAGER_DEFAULT = "unknown"
NEW_RULE_CODIFIED_FIELD = "new_rule_codified"
STRICT_LINKAGE_ENV = "AUDITOOOR_OUTCOME_REQUIRE_LINKAGE"

# Human-readable status labels used in the markdown Status column. We keep
# this mapping explicit so the table column never drifts out of sync with
# the JSONL outcome vocabulary.
STATUS_LABEL = {
    "pending": "Pending",
    "accepted": "Accepted",
    "paid": "Paid",
    "duplicate": "Duplicate",
    "rejected": "Rejected",
    DUPLICATE_OF_ACCEPTED: "Duplicate (root accepted)",
    DUPLICATE_OF_REJECTED: "Duplicate (root rejected)",
    WITHDRAWN: "Withdrawn",
}

SUBMISSIONS_HEADER = (
    "| Date | Report-ID | Platform | URL | Severity | Title | Status |\n"
    "|---|---|---|---|---|---|---|"
)

SUBMISSIONS_PREAMBLE = (
    "# Manual Submission Ledger\n"
    "\n"
    "This ledger is maintained by `tools/track-submissions.py`. Each row is a\n"
    "manually-filed report. Status starts as `Pending` and moves to\n"
    "`Accepted | Paid | Duplicate | Rejected` when the triager decides\n"
    "(via `make record-outcome`).\n"
    "\n"
    "Rows here are operator notes, not proof of submission — verify the URL.\n"
    "See `reference/outcomes.jsonl` for the append-only machine-readable stream.\n"
    "\n"
)


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------

def _workspace(path: str) -> Path:
    ws = Path(path).expanduser().resolve()
    if not ws.exists():
        raise SystemExit(f"[track-submissions] workspace not found: {ws}")
    if not ws.is_dir():
        raise SystemExit(f"[track-submissions] not a directory: {ws}")
    return ws


def _submissions_md(ws: Path) -> Path:
    return ws / "submissions" / "SUBMISSIONS.md"


def _outcomes_jsonl(ws: Path) -> Path:
    return ws / "reference" / "outcomes.jsonl"


def _pending_filed_without_platform_id_jsonl(ws: Path) -> Path:
    return ws / "reference" / "pending_filed_without_platform_id.jsonl"


def _utc_now_iso() -> str:
    # ISO 8601 UTC with trailing 'Z' and second precision. Deterministic for
    # tests that want to freeze the clock.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# outcomes.jsonl — append-only stream
# ---------------------------------------------------------------------------

def _iter_outcomes(path: Path) -> List[Dict[str, Any]]:
    """Read all rows from outcomes.jsonl. Skip malformed lines silently.

    Returns rows in file order. Callers who want authoritative state
    per report_id should take the LAST matching row.
    """
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _latest_by_report_id(
    rows: List[Dict[str, Any]], report_id: str
) -> Optional[Dict[str, Any]]:
    match: Optional[Dict[str, Any]] = None
    for row in rows:
        if str(row.get("report_id") or "") == report_id:
            match = row
    return match


def _latest_rows_by_report_id(
    rows: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Collapse rows to the last record per report_id."""
    latest: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        rid = str(row.get("report_id") or "")
        if rid:
            latest[rid] = row
    return latest


def _append_outcome(path: Path, row: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(row, sort_keys=True)
    # Open in append mode — never rewrite history.
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _append_jsonl(path: Path, row: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _copy_linkage_fields(src: Dict[str, Any], dst: Dict[str, Any]) -> None:
    """Preserve optional P0-4 scoreboard linkage metadata across transitions.

    Includes the legacy ``production_path_status`` key (kept for back-compat
    with rows recorded before the P0-4 required-field landed) and the new
    P0-4 required keys: ``production_path_blockers_cleared`` plus
    ``final_triager_outcome``.
    """
    carry_keys = (
        "lane",
        "model_route",
        "proof_artifact",
        "production_path_status",
        "production_path_blockers_cleared",
        FINAL_TRIAGER_FIELD,
        # PR 9 (wave 8) extensions
        ORIGINAL_VISIBILITY_FIELD,
        "outcome_evidence_path",
        "severity_filed",
        "severity_accepted",
        "draft_id",
        NEW_RULE_CODIFIED_FIELD,
    )
    for key in carry_keys:
        value = src.get(key)
        if value not in (None, ""):
            dst[key] = value


def _add_linkage_args(row: Dict[str, Any], args: argparse.Namespace) -> None:
    """Map argparse linkage args onto the outcome row.

    Both legacy ``--production-path-status`` and the new strict-mode
    ``--production-path-blockers-cleared`` are persisted when present.
    ``--final-triager-outcome`` defaults to ``"unknown"`` so the FIELD always
    exists on every newly-recorded row, per P0-4 stop condition.
    """
    arg_to_key = (
        ("lane", "lane"),
        ("model_route", "model_route"),
        ("proof_artifact", "proof_artifact"),
        ("production_path_status", "production_path_status"),
        ("production_path_blockers_cleared", "production_path_blockers_cleared"),
        ("final_triager_outcome", FINAL_TRIAGER_FIELD),
    )
    for arg_name, key in arg_to_key:
        value = getattr(args, arg_name, None)
        if value:
            row[key] = str(value).strip()
    # P0-4: the FIELD must exist on every newly-recorded row. Default to
    # "unknown" so downstream consumers can rely on the key being present.
    row.setdefault(FINAL_TRIAGER_FIELD, FINAL_TRIAGER_DEFAULT)


def _strict_linkage_enabled(args: argparse.Namespace) -> bool:
    """Return True iff strict-linkage gating is requested.

    Resolution order: explicit ``--strict-linkage`` flag wins; otherwise the
    ``AUDITOOOR_OUTCOME_REQUIRE_LINKAGE`` env var promotes warnings to fatal.
    Any non-empty / non-zero value enables strict mode (matches the rest of
    the auditooor ergonomics — see ``AUDITOOOR_LLM_NETWORK_CONSENT``).
    """
    if getattr(args, "strict_linkage", False):
        return True
    raw = os.environ.get(STRICT_LINKAGE_ENV, "")
    return raw.strip() not in ("", "0", "false", "False", "no", "NO", "off", "OFF")


def _missing_linkage_keys(row: Dict[str, Any]) -> List[str]:
    """Return the subset of REQUIRED_LINKAGE_FIELDS that are missing/empty."""
    missing: List[str] = []
    for key in REQUIRED_LINKAGE_FIELDS:
        value = row.get(key)
        if value is None or str(value).strip() == "":
            missing.append(key)
    return missing


# ---------------------------------------------------------------------------
# SUBMISSIONS.md — human-readable table
# ---------------------------------------------------------------------------

def _split_ledger_table(text: str) -> Tuple[str, List[str], str]:
    """Split the markdown into (preamble, data_rows, trailing).

    We look for the canonical header `| Date | Report-ID | ...`. If the
    file exists but doesn't have our header, we treat the whole file as
    preamble and append a new table at the bottom.
    """
    lines = text.splitlines()
    header_idx = -1
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("|") and "Report-ID" in stripped and "Platform" in stripped:
            header_idx = i
            break
    if header_idx == -1:
        return text, [], ""

    # Separator row follows the header.
    sep_idx = header_idx + 1
    if sep_idx >= len(lines) or "---" not in lines[sep_idx]:
        # Header without separator — unusual. Treat as no table.
        return text, [], ""

    data_start = sep_idx + 1
    data_end = data_start
    while data_end < len(lines):
        line = lines[data_end].rstrip()
        if not line.startswith("|"):
            break
        data_end += 1

    preamble = "\n".join(lines[:header_idx]).rstrip()
    data_rows = [lines[i] for i in range(data_start, data_end) if lines[i].strip()]
    trailing_parts = lines[data_end:]
    trailing = "\n".join(trailing_parts).lstrip("\n")
    return preamble, data_rows, trailing


def _escape_md_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()


def _render_row(entry: Dict[str, Any]) -> str:
    cells = [
        entry.get("date", ""),
        entry.get("report_id", ""),
        entry.get("platform", ""),
        entry.get("url", ""),
        entry.get("severity", ""),
        entry.get("title", ""),
        entry.get("status_label", ""),
    ]
    return "| " + " | ".join(_escape_md_cell(str(c)) for c in cells) + " |"


def _parse_row(line: str) -> Optional[Dict[str, str]]:
    if not line.startswith("|"):
        return None
    # Split and trim cells, drop leading/trailing empties caused by '|' edges.
    cells = [c.strip() for c in line.split("|")]
    if cells and cells[0] == "":
        cells = cells[1:]
    if cells and cells[-1] == "":
        cells = cells[:-1]
    if len(cells) < 7:
        return None
    return {
        "date": cells[0],
        "report_id": cells[1],
        "platform": cells[2],
        "url": cells[3],
        "severity": cells[4],
        "title": cells[5],
        "status_label": cells[6],
    }


def _write_ledger(path: Path, preamble: str, rows: List[Dict[str, Any]], trailing: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not preamble.strip():
        preamble = SUBMISSIONS_PREAMBLE.rstrip()
    body_lines = [preamble.rstrip(), "", SUBMISSIONS_HEADER]
    for row in rows:
        body_lines.append(_render_row(row))
    text = "\n".join(body_lines)
    if trailing.strip():
        text += "\n\n" + trailing.rstrip() + "\n"
    else:
        text += "\n"
    path.write_text(text)


def _read_ledger_rows(path: Path) -> Tuple[str, List[Dict[str, str]], str]:
    if not path.exists():
        return SUBMISSIONS_PREAMBLE.rstrip(), [], ""
    text = path.read_text()
    preamble, data_lines, trailing = _split_ledger_table(text)
    if not preamble.strip():
        preamble = SUBMISSIONS_PREAMBLE.rstrip()
    rows: List[Dict[str, str]] = []
    for line in data_lines:
        parsed = _parse_row(line)
        if parsed:
            rows.append(parsed)
    return preamble, rows, trailing


# ---------------------------------------------------------------------------
# Subcommand: record
# ---------------------------------------------------------------------------

def cmd_record(args: argparse.Namespace) -> int:
    ws = _workspace(args.workspace)
    platform = args.platform.strip().lower()
    if platform not in VALID_PLATFORMS:
        print(
            f"[track-submissions] invalid --platform '{platform}'. "
            f"Must be one of: {sorted(VALID_PLATFORMS)}",
            file=sys.stderr,
        )
        return 2

    report_id = args.report_id.strip()
    if not report_id:
        print("[track-submissions] --report-id must not be empty", file=sys.stderr)
        return 2

    outcomes_path = _outcomes_jsonl(ws)
    existing = _iter_outcomes(outcomes_path)
    # Duplicate guard — any prior record with the same report_id blocks this one.
    # We do NOT look at outcome state: even a pending-then-accepted pair counts
    # as "the operator already tracked this report".
    if _latest_by_report_id(existing, report_id) is not None:
        print(
            f"[track-submissions] report_id '{report_id}' already tracked in "
            f"{outcomes_path}. Refusing to double-record. Use 'make record-outcome' "
            f"to update an existing row.",
            file=sys.stderr,
        )
        return 2

    now_iso = _utc_now_iso()
    title = (args.title or "").strip()
    severity = (args.severity or "").strip()
    url = (args.report_url or "").strip()

    outcome_row: Dict[str, Any] = {
        "title": title,
        "outcome": PENDING,
        "status": STATUS_LABEL[PENDING],
        "workspace": ws.name,
        "report_id": report_id,
        "platform": platform,
        "url": url,
        "severity": severity,
        "recorded_at": now_iso,
        NEW_RULE_CODIFIED_FIELD: _coerce_bool(getattr(args, "new_rule_codified", False)),
    }
    _add_linkage_args(outcome_row, args)

    # P0-4: scoreboard linkage gate. When any of the four required fields is
    # missing we either FAIL CLOSED (strict mode) or emit a stderr warning
    # (advisory default). The advisory path preserves back-compat with every
    # existing operator script that does not yet pass linkage flags; once the
    # team migrates, flip strict via env or `--strict-linkage`.
    missing = _missing_linkage_keys(outcome_row)
    strict = _strict_linkage_enabled(args)
    if missing:
        if strict:
            print(
                "[track-submissions] strict-linkage: refusing to record row "
                f"missing required fields: {missing}. "
                f"Pass --{REQUIRED_LINKAGE_FIELDS[0].replace('_', '-')} etc., "
                "or unset --strict-linkage / "
                f"{STRICT_LINKAGE_ENV} to fall back to advisory mode.",
                file=sys.stderr,
            )
            return 2
        print(
            "[track-submissions] WARN: outcome row is missing P0-4 linkage "
            f"fields: {missing}. Required for scoreboard learning. "
            f"Set {STRICT_LINKAGE_ENV}=1 or pass --strict-linkage to fail "
            "closed.",
            file=sys.stderr,
        )

    _append_outcome(outcomes_path, outcome_row)

    submissions_md = _submissions_md(ws)
    preamble, rows, trailing = _read_ledger_rows(submissions_md)
    rows.append(
        {
            "date": now_iso,
            "report_id": report_id,
            "platform": platform,
            "url": url,
            "severity": severity,
            "title": title,
            "status_label": STATUS_LABEL[PENDING],
        }
    )
    _write_ledger(submissions_md, preamble, rows, trailing)

    print(
        f"[track-submissions] recorded pending {platform}:{report_id} in "
        f"{ws.name} -> {submissions_md}"
    )
    return 0


# ---------------------------------------------------------------------------
# Subcommand: record-pending-filed-without-platform-id
# ---------------------------------------------------------------------------

def cmd_record_pending_filed_without_platform_id(args: argparse.Namespace) -> int:
    """Record an operator-reported filing that lacks a platform ID/URL.

    This deliberately writes to a separate local tracker, not outcomes.jsonl and
    not SUBMISSIONS.md. It exists so field-validation can surface the row as a
    pending triage-survival artifact without treating it as submission evidence
    or fabricating the platform identifiers required by ``record``.
    """
    ws = _workspace(args.workspace)
    platform = (args.platform or "").strip().lower()
    if platform and platform not in VALID_PLATFORMS:
        print(
            f"[track-submissions] invalid --platform '{platform}'. "
            f"Must be one of: {sorted(VALID_PLATFORMS)}",
            file=sys.stderr,
        )
        return 2

    local_id = (args.local_id or "").strip()
    if not local_id:
        print("[track-submissions] --local-id must not be empty", file=sys.stderr)
        return 2

    tracker_path = _pending_filed_without_platform_id_jsonl(ws)
    existing = _iter_outcomes(tracker_path)
    if _latest_by_report_id(existing, local_id) is not None:
        print(
            f"[track-submissions] local_id '{local_id}' already tracked in "
            f"{tracker_path}. Refusing to double-record.",
            file=sys.stderr,
        )
        return 2

    row: Dict[str, Any] = {
        "schema": "auditooor.pending_filed_without_platform_id.v1",
        "workspace": ws.name,
        "local_id": local_id,
        # Mirror into report_id so the existing duplicate helper can be reused,
        # while making the non-platform nature explicit.
        "report_id": local_id,
        "platform": platform or "unknown",
        "title": (args.title or "").strip(),
        "severity": (args.severity or "").strip(),
        "source_path": (args.source_path or "submissions/SUBMISSIONS.md").strip(),
        "operator_note": (args.operator_note or "").strip(),
        "recorded_at": _utc_now_iso(),
        "status": "artifact_present_pending",
        "outcome": "pending_without_platform_id",
        "counts_as_outcome_evidence": False,
        "counts_as_submission_evidence": False,
        "requires_platform_id_backfill": True,
    }
    _append_jsonl(tracker_path, row)

    print(
        "[track-submissions] recorded pending filed-without-platform-id "
        f"{local_id} in {ws.name} -> {tracker_path}"
    )
    return 0


# ---------------------------------------------------------------------------
# Subcommand: record-outcome
# ---------------------------------------------------------------------------

def cmd_record_outcome(args: argparse.Namespace) -> int:
    ws = _workspace(args.workspace)
    state = args.state.strip().lower()
    accepted_states = TERMINAL_STATES | EXTENDED_STATES
    if state not in accepted_states:
        print(
            f"[track-submissions] invalid --state '{state}'. "
            f"Must be one of: {sorted(accepted_states)}",
            file=sys.stderr,
        )
        return 2

    # PR 9 (wave 8): when the operator passes a `duplicate_of_<x>` state we
    # require an explicit --original-visibility flag so the row never silently
    # claims hidden-parent semantics. If it's just a legacy `duplicate`, the
    # field is optional (defaults to unknown).
    visibility = (getattr(args, "original_visibility", "") or "").strip().lower()
    if state in (DUPLICATE_OF_ACCEPTED, DUPLICATE_OF_REJECTED):
        if visibility not in ORIGINAL_VISIBILITY_VALUES:
            print(
                f"[track-submissions] state '{state}' requires "
                "--original-visibility=hidden|visible|unknown so the dup-root "
                "row records whether the parent was readable.",
                file=sys.stderr,
            )
            return 2
    elif visibility and visibility not in ORIGINAL_VISIBILITY_VALUES:
        print(
            f"[track-submissions] invalid --original-visibility '{visibility}'. "
            f"Must be one of: {sorted(ORIGINAL_VISIBILITY_VALUES)}",
            file=sys.stderr,
        )
        return 2

    report_id = args.report_id.strip()
    if not report_id:
        print("[track-submissions] --report-id must not be empty", file=sys.stderr)
        return 2

    outcomes_path = _outcomes_jsonl(ws)
    existing = _iter_outcomes(outcomes_path)
    prior = _latest_by_report_id(existing, report_id)
    if prior is None:
        print(
            f"[track-submissions] report_id '{report_id}' not found in "
            f"{outcomes_path}. Run 'record' first.",
            file=sys.stderr,
        )
        return 2

    now_iso = _utc_now_iso()
    # Append — never rewrite — a new line carrying the terminal state.
    new_row: Dict[str, Any] = {
        "title": prior.get("title", ""),
        "outcome": state,
        "status": STATUS_LABEL[state],
        "workspace": ws.name,
        "report_id": report_id,
        "platform": prior.get("platform", ""),
        "url": prior.get("url", ""),
        "severity": prior.get("severity", ""),
        # Preserve the original recorded_at so readers can compute time-to-
        # resolution without needing to scan all prior rows for the same ID.
        "recorded_at": prior.get("recorded_at", now_iso),
        "resolved_at": now_iso,
        NEW_RULE_CODIFIED_FIELD: _coerce_bool(prior.get(NEW_RULE_CODIFIED_FIELD)),
    }
    _copy_linkage_fields(prior, new_row)
    if getattr(args, "new_rule_codified", False):
        new_row[NEW_RULE_CODIFIED_FIELD] = True
    # PR 9 (wave 8) extensions: visibility + evidence_path + severity capture.
    if visibility:
        new_row[ORIGINAL_VISIBILITY_FIELD] = visibility
    elif state in (DUPLICATE_OF_ACCEPTED, DUPLICATE_OF_REJECTED):
        # Defensive: the gate above forces a value, but make sure JSON is sane
        # on every path.
        new_row[ORIGINAL_VISIBILITY_FIELD] = ORIGINAL_VISIBILITY_UNKNOWN
    evidence_path = (getattr(args, "outcome_evidence_path", "") or "").strip()
    if evidence_path:
        new_row["outcome_evidence_path"] = evidence_path
    severity_filed = (getattr(args, "severity_filed", "") or "").strip()
    if severity_filed:
        new_row["severity_filed"] = severity_filed
    severity_accepted = (getattr(args, "severity_accepted", "") or "").strip()
    if severity_accepted:
        new_row["severity_accepted"] = severity_accepted
    # Mirror final_triager_outcome from the chosen state so downstream
    # consumers can grep one canonical key.
    new_row[FINAL_TRIAGER_FIELD] = state
    _append_outcome(outcomes_path, new_row)

    # Update the Status column in SUBMISSIONS.md. If the row doesn't exist
    # (someone edited the markdown by hand), add it at the bottom so the
    # markdown never silently lies about resolved outcomes.
    submissions_md = _submissions_md(ws)
    preamble, rows, trailing = _read_ledger_rows(submissions_md)
    label = STATUS_LABEL[state]
    updated = False
    for row in rows:
        if row.get("report_id") == report_id:
            row["status_label"] = label
            updated = True
    if not updated:
        rows.append(
            {
                "date": prior.get("recorded_at", now_iso),
                "report_id": report_id,
                "platform": prior.get("platform", ""),
                "url": prior.get("url", ""),
                "severity": prior.get("severity", ""),
                "title": prior.get("title", ""),
                "status_label": label,
            }
        )
    _write_ledger(submissions_md, preamble, rows, trailing)

    print(
        f"[track-submissions] resolved {report_id} -> {state} in "
        f"{ws.name} ({submissions_md})"
    )
    return 0


# ---------------------------------------------------------------------------
# Subcommand: list
# ---------------------------------------------------------------------------

def cmd_list(args: argparse.Namespace) -> int:
    ws = _workspace(args.workspace)
    outcomes_path = _outcomes_jsonl(ws)
    rows = _iter_outcomes(outcomes_path)
    if not rows:
        print("no submissions recorded")
        return 0

    # Collapse to the LAST record per report_id — this is the authoritative
    # state and matches how `outcome_reweight.load_outcome_history` reads
    # the file.
    latest = _latest_rows_by_report_id(rows)
    want = args.outcome.lower() if args.outcome else PENDING
    filtered: List[Dict[str, Any]] = []
    for rid, row in latest.items():
        outcome = str(row.get("outcome") or "").lower()
        if want == "all" or outcome == want:
            filtered.append(row)

    if not filtered:
        print(f"no submissions with outcome='{want}'")
        return 0

    # Sort by recorded_at for stable output.
    filtered.sort(key=lambda r: str(r.get("recorded_at") or ""))
    for row in filtered:
        rid = row.get("report_id", "")
        platform = row.get("platform", "")
        outcome = row.get("outcome", "")
        title = row.get("title", "") or "(no title)"
        url = row.get("url", "")
        recorded = row.get("recorded_at", "")
        resolved = row.get("resolved_at", "")
        line = f"{outcome:<10} {platform:<12} {rid:<20} {recorded}"
        if resolved:
            line += f" -> {resolved}"
        line += f"  {title}"
        if url:
            line += f"  <{url}>"
        print(line)
    return 0


# ---------------------------------------------------------------------------
# Subcommand: validate-ledger (P0-4)
# ---------------------------------------------------------------------------

def _row_linkage_audit(row: Dict[str, Any]) -> Dict[str, Any]:
    """Produce a per-row linkage audit dict.

    The shape is intentionally machine-readable so closeout / dashboards can
    consume it without re-parsing the ledger. ``has_final_triager_field``
    captures the P0-4 nuance that the FIELD must exist even when its value
    is "unknown".
    """
    missing = _missing_linkage_keys(row)
    return {
        "report_id": str(row.get("report_id") or ""),
        "outcome": str(row.get("outcome") or ""),
        "missing_required_fields": missing,
        "complete": not missing and (FINAL_TRIAGER_FIELD in row),
        "has_final_triager_field": FINAL_TRIAGER_FIELD in row,
        "final_triager_outcome": str(row.get(FINAL_TRIAGER_FIELD) or ""),
    }


def _summarize_audits(audits: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(audits)
    complete = sum(1 for a in audits if a["complete"])
    missing_per_field: Dict[str, int] = {key: 0 for key in REQUIRED_LINKAGE_FIELDS}
    missing_final_triager_field = 0
    for audit in audits:
        for key in audit["missing_required_fields"]:
            missing_per_field[key] = missing_per_field.get(key, 0) + 1
        if not audit["has_final_triager_field"]:
            missing_final_triager_field += 1
    return {
        "total_rows": total,
        "complete_rows": complete,
        "incomplete_rows": total - complete,
        "missing_per_field": missing_per_field,
        "missing_final_triager_field": missing_final_triager_field,
    }


def cmd_validate_ledger(args: argparse.Namespace) -> int:
    """Scan ``reference/outcomes.jsonl`` and report missing-required-field rows.

    Operators run this against an established workspace to discover which
    rows still need backfill. Exit code mirrors strict-mode contract:

      * Default (advisory): exit 0 even with incomplete rows — surfaces a
        report so operators can plan backfill without breaking automation.
      * ``--strict-linkage`` (or env ``AUDITOOOR_OUTCOME_REQUIRE_LINKAGE=1``):
        exit 1 if any row is incomplete, so CI gates can fail closed.

    Output: a stable Markdown summary on stdout, plus an optional
    ``--json`` flag for machine consumers and ``--out`` to persist to disk.
    """
    ws = _workspace(args.workspace)
    outcomes_path = _outcomes_jsonl(ws)
    rows = _iter_outcomes(outcomes_path)

    # Authoritative state per report_id is the LAST line — same convention as
    # `outcome_reweight.load_outcome_history`. We audit the LATEST row per
    # report_id so backfill on a later transition (record-outcome) clears the
    # warning even though the original pending row predated strict mode.
    if args.all_rows:
        target_rows = rows
    else:
        target_rows = list(_latest_rows_by_report_id(rows).values())

    audits = [_row_linkage_audit(row) for row in target_rows]
    summary = _summarize_audits(audits)

    payload: Dict[str, Any] = {
        "workspace": ws.name,
        "outcomes_path": str(outcomes_path),
        "scope": "all-rows" if args.all_rows else "latest-per-report-id",
        "summary": summary,
        "incomplete": [a for a in audits if not a["complete"]],
    }

    if args.json:
        rendered = json.dumps(payload, indent=2, sort_keys=True)
    else:
        lines = [
            f"# Outcome Ledger Linkage Audit ({ws.name})",
            "",
            f"- Source: `{outcomes_path}`",
            f"- Scope: {payload['scope']}",
            f"- Total rows: {summary['total_rows']}",
            f"- Complete rows: {summary['complete_rows']}",
            f"- Incomplete rows: {summary['incomplete_rows']}",
            "",
            "## Missing per required field",
            "",
            "| Field | Missing count |",
            "|---|---:|",
        ]
        for key in REQUIRED_LINKAGE_FIELDS:
            lines.append(f"| {key} | {summary['missing_per_field'].get(key, 0)} |")
        lines.append(
            f"| {FINAL_TRIAGER_FIELD} (field absent) | "
            f"{summary['missing_final_triager_field']} |"
        )
        if payload["incomplete"]:
            lines.extend(["", "## Rows needing backfill", "", "| Report ID | Outcome | Missing fields |", "|---|---|---|"])
            for audit in payload["incomplete"]:
                missing_repr = ", ".join(audit["missing_required_fields"]) or "-"
                rid = audit["report_id"] or "-"
                outcome = audit["outcome"] or "-"
                lines.append(f"| {rid} | {outcome} | {missing_repr} |")
        rendered = "\n".join(lines) + "\n"

    if args.out:
        out_path = Path(args.out).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered)
    else:
        print(rendered, end="")

    if _strict_linkage_enabled(args) and summary["incomplete_rows"] > 0:
        print(
            f"[track-submissions] strict-linkage: {summary['incomplete_rows']} "
            "incomplete row(s) — exit 1.",
            file=sys.stderr,
        )
        return 1
    return 0


# ---------------------------------------------------------------------------
# Subcommand: backfill (PR 9, wave 8)
# ---------------------------------------------------------------------------

# Keys that constitute a valid PR 9 backfill spec line. We do not require URL
# or platform — back-filled rows often reference findings filed before PR 9
# landed and the URLs may have been omitted from the original telemetry.
BACKFILL_REQUIRED_KEYS = (
    "draft_id",
    "lane",
    "model_route",
    "proof_artifact",
    "production_path_blockers_cleared",
    "final_triager_outcome",
    "outcome_evidence_path",
    "severity_filed",
)
BACKFILL_OPTIONAL_KEYS = (
    "platform",
    "url",
    "title",
    "severity_accepted",
    "original_visibility",
    "report_id",
    "recorded_at",
    "resolved_at",
    "workspace",
    "notes",
    NEW_RULE_CODIFIED_FIELD,
)


def _validate_backfill_record(record: Dict[str, Any]) -> List[str]:
    """Return a list of validation errors for a single backfill record.

    Keep this stdlib-only; the spec file is JSONL so each line is independently
    parseable.
    """
    errors: List[str] = []
    for key in BACKFILL_REQUIRED_KEYS:
        value = record.get(key)
        if value is None or str(value).strip() == "":
            errors.append(f"missing required key: {key}")
    outcome = str(record.get("final_triager_outcome", "")).strip().lower()
    if outcome and outcome not in (
        ALL_STATES | {"in_review", "unknown"}
    ):
        errors.append(
            f"final_triager_outcome '{outcome}' not in "
            f"{sorted(ALL_STATES | {'in_review', 'unknown'})}"
        )
    if outcome in (DUPLICATE_OF_ACCEPTED, DUPLICATE_OF_REJECTED):
        visibility = str(record.get(ORIGINAL_VISIBILITY_FIELD, "")).strip().lower()
        if visibility not in ORIGINAL_VISIBILITY_VALUES:
            errors.append(
                f"final_triager_outcome '{outcome}' requires "
                f"{ORIGINAL_VISIBILITY_FIELD} ∈ "
                f"{sorted(ORIGINAL_VISIBILITY_VALUES)} "
                f"(got '{record.get(ORIGINAL_VISIBILITY_FIELD, '')}')"
            )
    if NEW_RULE_CODIFIED_FIELD in record and not isinstance(record.get(NEW_RULE_CODIFIED_FIELD), bool):
        errors.append(f"{NEW_RULE_CODIFIED_FIELD} must be a JSON boolean")
    return errors


def _materialize_backfill_record(
    record: Dict[str, Any], default_workspace: str
) -> Dict[str, Any]:
    """Build a full outcome row from a backfill spec record.

    The spec records carry the rich PR 9 fields (draft_id, lane, model_route,
    etc.). The ``outcome`` field on the materialized row mirrors the spec's
    ``final_triager_outcome`` so existing readers (outcome_reweight,
    outcome-telemetry) continue to work without code changes.
    """
    outcome = str(record.get("final_triager_outcome", "")).strip().lower()
    workspace = str(record.get("workspace") or default_workspace).strip()
    report_id = str(
        record.get("report_id") or record.get("draft_id") or ""
    ).strip()
    row: Dict[str, Any] = {
        "title": str(record.get("title", "") or "").strip(),
        "outcome": outcome,
        "status": STATUS_LABEL.get(outcome, outcome.replace("_", " ").title()),
        "workspace": workspace,
        "report_id": report_id,
        "draft_id": str(record.get("draft_id", "") or "").strip(),
        "platform": str(record.get("platform", "") or "").strip(),
        "url": str(record.get("url", "") or "").strip(),
        "severity": str(record.get("severity_filed", "") or "").strip(),
        "severity_filed": str(record.get("severity_filed", "") or "").strip(),
        "lane": str(record.get("lane", "") or "").strip(),
        "model_route": str(record.get("model_route", "") or "").strip(),
        "proof_artifact": str(record.get("proof_artifact", "") or "").strip(),
        "production_path_blockers_cleared": str(
            record.get("production_path_blockers_cleared", "") or ""
        ).strip(),
        FINAL_TRIAGER_FIELD: outcome,
        "outcome_evidence_path": str(
            record.get("outcome_evidence_path", "") or ""
        ).strip(),
        "recorded_at": str(record.get("recorded_at") or _utc_now_iso()).strip(),
        "backfilled_at": _utc_now_iso(),
        "backfill_source": "PR 9 (wave 8) outcome+duplicate learning backfill",
        NEW_RULE_CODIFIED_FIELD: _coerce_bool(record.get(NEW_RULE_CODIFIED_FIELD)),
    }
    severity_accepted = str(record.get("severity_accepted", "") or "").strip()
    if severity_accepted:
        row["severity_accepted"] = severity_accepted
    visibility = str(record.get(ORIGINAL_VISIBILITY_FIELD, "") or "").strip().lower()
    if visibility:
        row[ORIGINAL_VISIBILITY_FIELD] = visibility
    elif outcome in (DUPLICATE_OF_ACCEPTED, DUPLICATE_OF_REJECTED):
        row[ORIGINAL_VISIBILITY_FIELD] = ORIGINAL_VISIBILITY_UNKNOWN
    notes = str(record.get("notes", "") or "").strip()
    if notes:
        row["notes"] = notes
    resolved_at = str(record.get("resolved_at", "") or "").strip()
    if resolved_at:
        row["resolved_at"] = resolved_at
    return row


def _read_backfill_spec(path: Path) -> List[Dict[str, Any]]:
    """Parse a JSONL backfill spec file. Skip blank lines + `#` comments."""
    if not path.exists():
        raise SystemExit(
            f"[track-submissions] backfill spec not found: {path}"
        )
    records: List[Dict[str, Any]] = []
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(
                f"[track-submissions] invalid JSONL line in {path}: {exc}"
            ) from exc
        if not isinstance(obj, dict):
            raise SystemExit(
                f"[track-submissions] non-object record in {path}: {obj!r}"
            )
        records.append(obj)
    return records


def cmd_backfill(args: argparse.Namespace) -> int:
    """PR 9: bulk-append outcome rows from a JSONL spec.

    Each spec record MUST include the PR 9 fields. The materialized rows are
    written append-only to ``--ledger-path`` (defaults to
    ``reference/outcomes.jsonl`` at the repo root). Duplicates against the
    existing latest-by-report_id stream are skipped unless ``--allow-duplicate``
    is set — that lets operators re-issue a row after a triager-state change.
    """
    spec_path = Path(args.spec).expanduser().resolve()
    records = _read_backfill_spec(spec_path)
    if args.ledger_path:
        ledger_path = Path(args.ledger_path).expanduser().resolve()
    else:
        # Repo-relative default. Walk up until we find `reference/`.
        here = Path(__file__).resolve().parent
        for candidate in (here.parent, here.parent.parent):
            if (candidate / "reference").is_dir():
                ledger_path = candidate / "reference" / "outcomes.jsonl"
                break
        else:
            raise SystemExit(
                "[track-submissions] could not auto-locate reference/outcomes.jsonl. "
                "Pass --ledger-path explicitly."
            )

    default_workspace = (args.default_workspace or "").strip() or "unknown"

    # Validate first; refuse the whole batch if any row is bad. This avoids
    # the half-applied state where some rows landed and others didn't.
    all_errors: List[Tuple[int, List[str]]] = []
    for idx, record in enumerate(records, start=1):
        errors = _validate_backfill_record(record)
        if errors:
            all_errors.append((idx, errors))
    if all_errors:
        print(
            f"[track-submissions] backfill validation failed for {len(all_errors)} "
            f"of {len(records)} records:",
            file=sys.stderr,
        )
        for idx, errs in all_errors:
            for err in errs:
                print(f"  record #{idx}: {err}", file=sys.stderr)
        return 2

    # De-dup against the existing ledger.
    existing_rows = _iter_outcomes(ledger_path)
    existing_ids = {
        str(row.get("draft_id") or row.get("report_id") or ""): row
        for row in existing_rows
    }

    written = 0
    skipped = 0
    by_outcome: Counter = Counter()
    by_workspace: Dict[str, int] = {}
    duplicate_root_count = 0

    for record in records:
        materialized = _materialize_backfill_record(record, default_workspace)
        key = str(materialized.get("draft_id") or materialized.get("report_id") or "")
        if key and key in existing_ids and not args.allow_duplicate:
            skipped += 1
            continue
        _append_outcome(ledger_path, materialized)
        written += 1
        outcome = str(materialized.get("outcome") or "")
        by_outcome[outcome] += 1
        ws_key = str(materialized.get("workspace") or default_workspace)
        by_workspace[ws_key] = by_workspace.get(ws_key, 0) + 1
        if is_duplicate_root(outcome):
            duplicate_root_count += 1

    summary = {
        "spec": str(spec_path),
        "ledger": str(ledger_path),
        "records": len(records),
        "written": written,
        "skipped": skipped,
        "duplicate_root_rows": duplicate_root_count,
        "by_outcome": dict(by_outcome.items()),
        "by_workspace": by_workspace,
    }

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"[track-submissions] backfill: {written} written, {skipped} skipped")
        print(f"  spec    : {spec_path}")
        print(f"  ledger  : {ledger_path}")
        print(f"  dup-root: {duplicate_root_count}")
        for outcome, count in sorted(by_outcome.items()):
            print(f"  outcome {outcome}: {count}")
        for ws, count in sorted(by_workspace.items()):
            print(f"  workspace {ws}: {count}")

    return 0


# ---------------------------------------------------------------------------
# Subcommand: duplicate-root-status (PR 9)
# ---------------------------------------------------------------------------

def _classify_dup_root(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return a per-row dup-root descriptor, or None for plain rows.

    Used by paste-ready and adversarial-review integrations to surface the
    hidden-duplicate-root status without claiming a unilateral acceptance or
    rejection.
    """
    outcome = str(row.get("outcome") or row.get(FINAL_TRIAGER_FIELD) or "").lower()
    if not is_duplicate_root(outcome):
        return None
    visibility = str(row.get(ORIGINAL_VISIBILITY_FIELD) or "").lower() or ORIGINAL_VISIBILITY_UNKNOWN
    inherited = collapse_duplicate_root(outcome)
    return {
        "report_id": str(row.get("report_id") or row.get("draft_id") or ""),
        "title": str(row.get("title") or ""),
        "outcome": outcome,
        "inherited_outcome": inherited,
        "original_visibility": visibility,
        "evidence_path": str(row.get("outcome_evidence_path") or ""),
    }


def render_duplicate_root_summary(rows: List[Dict[str, Any]]) -> str:
    """Render the dup-root surfacing block for paste-ready / adversarial.

    Stable, deterministic markdown. Empty string when there are no dup-root
    rows so callers can append unconditionally without an extra branch.
    """
    descs = [d for d in (_classify_dup_root(row) for row in rows) if d]
    if not descs:
        return ""
    lines = [
        "## Duplicate-Root Status (PR 9 hidden-parent semantics)",
        "",
        "Rows below were classified as duplicate-of-<accepted|rejected> when the",
        "operator could not read the original parent report. The dup row inherits",
        "the visible parent's learning signal but does NOT claim victory or",
        "defeat unilaterally.",
        "",
        "| Report ID | Outcome | Inherited | Original visible? | Evidence |",
        "|---|---|---|---|---|",
    ]
    for desc in descs:
        evidence = desc["evidence_path"] or "-"
        lines.append(
            f"| {desc['report_id'] or '-'} | {desc['outcome']} | "
            f"{desc['inherited_outcome']} | {desc['original_visibility']} | "
            f"{evidence} |"
        )
    return "\n".join(lines) + "\n"


def cmd_duplicate_root_status(args: argparse.Namespace) -> int:
    """Surface dup-root rows. Used by paste-ready/adversarial-review hooks.

    Reads either the workspace-local ``reference/outcomes.jsonl`` or
    ``--ledger-path``. Prints the rendered markdown block on stdout. Exits 0
    even when there are no dup-root rows (the empty block is a valid result).
    """
    if args.ledger_path:
        ledger_path = Path(args.ledger_path).expanduser().resolve()
        if not ledger_path.exists():
            print(f"[track-submissions] ledger not found: {ledger_path}", file=sys.stderr)
            return 2
    else:
        ws = _workspace(args.workspace)
        ledger_path = _outcomes_jsonl(ws)
    rows = _iter_outcomes(ledger_path)
    if args.report_id:
        rid = args.report_id.strip()
        rows = [
            r for r in rows
            if str(r.get("report_id") or r.get("draft_id") or "") == rid
        ]
    # Collapse to latest-per-report_id so we don't surface stale dup-root
    # rows superseded by a real triager outcome later.
    latest = _latest_rows_by_report_id(rows)
    rendered = render_duplicate_root_summary(list(latest.values()))
    if args.json:
        descs = [d for d in (_classify_dup_root(r) for r in latest.values()) if d]
        print(json.dumps({"duplicate_root_rows": descs}, indent=2, sort_keys=True))
        return 0
    if rendered:
        print(rendered, end="")
    else:
        print("(no duplicate-root rows surfaced)")
    return 0


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="track-submissions.py",
        description="Manual Submission Ledger (replaces PR 209 API adapter).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_record = sub.add_parser(
        "record",
        help="Append a pending row after manually filing a report.",
    )
    p_record.add_argument("workspace", help="Workspace directory (e.g. ~/audits/foo)")
    p_record.add_argument("--platform", required=True,
                          help=f"One of {sorted(VALID_PLATFORMS)}")
    p_record.add_argument("--report-url", required=True, help="URL of the submitted report")
    p_record.add_argument("--report-id", required=True, help="Platform-assigned report ID")
    p_record.add_argument("--title", default="", help="Finding title")
    p_record.add_argument("--severity", default="", help="Severity label (Critical/High/...)")
    p_record.add_argument("--lane", default="", help="Pipeline lane that produced the finding (e.g. source-mine, audit-deep)")
    p_record.add_argument("--model-route", default="", help="Model route used before Codex/operator verification")
    p_record.add_argument("--proof-artifact", default="", help="Path or identifier for the proof artifact/package")
    p_record.add_argument("--production-path-status", default="", help="Production-path dossier status or blocker summary (legacy)")
    p_record.add_argument(
        "--production-path-blockers-cleared",
        default="",
        help=(
            "P0-4 scoreboard required field. Free-form value such as 'yes', "
            "'no', 'partial:<note>'. The cleared-state of production-path "
            "blockers when the row is filed."
        ),
    )
    p_record.add_argument(
        "--final-triager-outcome",
        default="",
        help=(
            "P0-4 scoreboard required field. Defaults to 'unknown' until "
            "`record-outcome` flips it. The FIELD must always exist on a "
            "fresh row so downstream consumers can iterate without KeyError."
        ),
    )
    p_record.add_argument(
        "--strict-linkage",
        action="store_true",
        default=False,
        help=(
            "P0-4 scoreboard fail-closed gate. With this flag (or env "
            f"{STRICT_LINKAGE_ENV}=1), missing lane/model_route/"
            "proof_artifact/production_path_blockers_cleared exits 2."
        ),
    )
    p_record.add_argument(
        "--new-rule-codified",
        action="store_true",
        default=False,
        help=(
            "Persist new_rule_codified=true when this outcome record already "
            "resulted in a durable codified rule. Defaults to false."
        ),
    )
    p_record.set_defaults(func=cmd_record)

    p_pending = sub.add_parser(
        "record-pending-filed-without-platform-id",
        help=(
            "Record an operator-reported filed row that has no platform "
            "report ID/URL yet. Writes reference/pending_filed_without_platform_id.jsonl "
            "only; does not write outcomes.jsonl."
        ),
    )
    p_pending.add_argument("workspace", help="Workspace directory")
    p_pending.add_argument(
        "--local-id",
        required=True,
        help="Stable local row/draft identifier. This is not a platform report ID.",
    )
    p_pending.add_argument(
        "--platform",
        default="",
        help=f"Optional expected platform, one of {sorted(VALID_PLATFORMS)}.",
    )
    p_pending.add_argument("--title", default="")
    p_pending.add_argument("--severity", default="")
    p_pending.add_argument(
        "--source-path",
        default="submissions/SUBMISSIONS.md",
        help="Local artifact containing the operator-reported row.",
    )
    p_pending.add_argument(
        "--operator-note",
        default="",
        help="Short note explaining why the platform ID/URL is not available.",
    )
    p_pending.set_defaults(func=cmd_record_pending_filed_without_platform_id)

    p_record_outcome = sub.add_parser(
        "record-outcome",
        help="Append an outcome transition for an existing report_id.",
    )
    p_record_outcome.add_argument("workspace", help="Workspace directory")
    p_record_outcome.add_argument("--report-id", required=True)
    p_record_outcome.add_argument(
        "--state",
        required=True,
        help=(
            f"One of {sorted(TERMINAL_STATES | EXTENDED_STATES)}. "
            "PR 9 (wave 8) adds duplicate_of_accepted / duplicate_of_rejected "
            "/ withdrawn — duplicate_of_* requires --original-visibility."
        ),
    )
    p_record_outcome.add_argument(
        "--original-visibility",
        default="",
        help=(
            "PR 9 hidden-duplicate-root semantics. One of "
            f"{sorted(ORIGINAL_VISIBILITY_VALUES)}. REQUIRED when --state is "
            "duplicate_of_accepted or duplicate_of_rejected so the row "
            "records whether the original parent was readable to the "
            "operator. Optional otherwise."
        ),
    )
    p_record_outcome.add_argument(
        "--outcome-evidence-path",
        default="",
        help=(
            "PR 9 outcome row field. Path (relative to repo root) of the "
            "operator-readable evidence that justifies the transition (e.g. "
            "triager reply, rejection forensic note, OOS analysis)."
        ),
    )
    p_record_outcome.add_argument(
        "--severity-filed",
        default="",
        help="PR 9 outcome row field. Severity claimed in the original filing.",
    )
    p_record_outcome.add_argument(
        "--severity-accepted",
        default="",
        help=(
            "PR 9 outcome row field. Severity actually awarded by the "
            "triager. Empty / absent if downgraded-to-rejected or still "
            "in-review."
        ),
    )
    p_record_outcome.add_argument(
        "--new-rule-codified",
        action="store_true",
        default=False,
        help=(
            "Persist new_rule_codified=true on the appended outcome transition "
            "when this result produced a durable codified rule. Omitted means false."
        ),
    )
    p_record_outcome.set_defaults(func=cmd_record_outcome)

    p_validate = sub.add_parser(
        "validate-ledger",
        help=(
            "P0-4: scan reference/outcomes.jsonl for rows missing required "
            "scoreboard linkage fields. Default exits 0 (advisory); pass "
            "--strict-linkage / set "
            f"{STRICT_LINKAGE_ENV}=1 to exit 1 on any incomplete row."
        ),
    )
    p_validate.add_argument("workspace", help="Workspace directory")
    p_validate.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit JSON instead of Markdown.",
    )
    p_validate.add_argument(
        "--out",
        default="",
        help="Persist report to this path instead of stdout.",
    )
    p_validate.add_argument(
        "--all-rows",
        action="store_true",
        default=False,
        help=(
            "Audit every line in the append-only stream. By default the "
            "scanner only inspects the LAST row per report_id (matches the "
            "authoritative-state convention used by outcome_reweight)."
        ),
    )
    p_validate.add_argument(
        "--strict-linkage",
        action="store_true",
        default=False,
        help=(
            "Exit 1 instead of 0 when any audited row is missing required "
            f"linkage fields. Equivalent to {STRICT_LINKAGE_ENV}=1."
        ),
    )
    p_validate.set_defaults(func=cmd_validate_ledger)

    p_list = sub.add_parser("list", help="List ledger rows filtered by outcome.")
    p_list.add_argument("--workspace", required=True, help="Workspace directory")
    p_list.add_argument(
        "--outcome",
        default=None,
        help=(
            "Filter by outcome (pending|accepted|paid|duplicate|rejected|"
            "duplicate_of_accepted|duplicate_of_rejected|withdrawn|all). "
            "Default: pending — so the operator sees what's outstanding."
        ),
    )
    p_list.set_defaults(func=cmd_list)

    p_backfill = sub.add_parser(
        "backfill",
        help=(
            "PR 9 (wave 8): bulk-append outcome rows from a JSONL spec. Each "
            "line is a record with the rich PR 9 fields (draft_id, lane, "
            "model_route, proof_artifact, production_path_blockers_cleared, "
            "final_triager_outcome, outcome_evidence_path, severity_filed, "
            "severity_accepted, original_visibility)."
        ),
    )
    p_backfill.add_argument("--spec", required=True, help="Path to JSONL spec file")
    p_backfill.add_argument(
        "--ledger-path",
        default="",
        help=(
            "Path to outcomes.jsonl (default: auto-detect "
            "<repo>/reference/outcomes.jsonl)"
        ),
    )
    p_backfill.add_argument(
        "--default-workspace",
        default="",
        help="Workspace name to apply when a spec record omits 'workspace'.",
    )
    p_backfill.add_argument(
        "--allow-duplicate",
        action="store_true",
        default=False,
        help=(
            "Append even if a row with the same draft_id/report_id already "
            "exists. Default: skip duplicates."
        ),
    )
    p_backfill.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit a JSON summary instead of plain-text counts.",
    )
    p_backfill.set_defaults(func=cmd_backfill)

    p_dup_root = sub.add_parser(
        "duplicate-root-status",
        help=(
            "PR 9 (wave 8): surface hidden-duplicate-root rows for paste-ready "
            "/ adversarial-review pipelines. Reads the workspace ledger or a "
            "specific --ledger-path."
        ),
    )
    p_dup_root.add_argument(
        "workspace",
        nargs="?",
        default=".",
        help=(
            "Workspace directory (used when --ledger-path is omitted). "
            "Defaults to the current directory."
        ),
    )
    p_dup_root.add_argument(
        "--ledger-path",
        default="",
        help="Override the ledger path (e.g. repo-root reference/outcomes.jsonl).",
    )
    p_dup_root.add_argument(
        "--report-id",
        default="",
        help="Filter to a single report_id (or draft_id).",
    )
    p_dup_root.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit a JSON list instead of the markdown surfacing block.",
    )
    p_dup_root.set_defaults(func=cmd_duplicate_root_status)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
