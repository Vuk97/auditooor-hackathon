#!/usr/bin/env python3
"""campaign-telemetry.py — link campaigns to model usage, submitted findings,
and triager outcomes (V5 PR 6).

Background
----------
Per ``docs/ROADMAP_10_OF_10_V5_CAMPAIGNS.md`` Section 6 ("Submission And
Outcome Telemetry") and Section 8 ("PR 6 - Telemetry and budget guard
integration"), the V5 campaign machinery already lays down per-campaign
config + summary + per-campaign ``telemetry.jsonl`` files (PR 2,
``tools/campaign-state.py``). What was still missing — and what this
module ships — is:

1. A repo-level append-only ledger that links every LLM dispatch back to
   the campaign that triggered it.
2. A separate ledger ("Was Opus worth it?") for every Opus escalation,
   so the team can review whether the spend produced accepted findings.
3. A submission-metadata schema that captures the exact fields Codex
   listed: source/fuzz/symbolic/deep campaign id, models + role played,
   tests run, scope verdict + OOS clauses checked, prior-art result, and
   the eventual triager outcome.
4. A ``report`` subcommand that aggregates the three ledgers to answer
   the four questions from Section 6:

     a. Which lanes produce accepted findings?
     b. Which models create too many false positives?
     c. Which gates catch the most dangerous mistakes?
     d. Which workspaces need more source mining vs more fuzzing?

Design contract
---------------
- **Stdlib only.** No new pip dependencies.
- **Append-only ledgers.** The two campaign-level ledgers
  (``tools/calibration/campaign_dispatch_log.jsonl`` and
  ``tools/calibration/opus_escalations.jsonl``) and the submission ledger
  (``tools/calibration/campaign_submissions.jsonl``) are all append-only.
  ``record_triager_outcome`` writes a NEW line — it never rewrites prior
  rows. ``aggregate`` keeps the latest per ``finding_id`` so amendments
  win.
- **Library + CLI.** Other tools (e.g. ``llm-dispatch.py``) import
  ``record_dispatch`` via ``importlib.util`` because the file name
  contains a hyphen. The CLI is for ad-hoc querying and the
  Section 6 report.
- **Defensive against orphaned ledger entries.** Codex's required
  metadata list calls out "triager outcome after response", which lands
  *after* the submission was filed and possibly after the campaign that
  produced it has been closed. The module never re-opens a closed
  campaign — it simply appends a follow-up ``triager_outcome`` row
  keyed by ``finding_id`` so aggregation remains stable.
- **No secrets in the ledger.** The dispatch hook records provider name,
  model id, token counts, and audit-trail file path. It NEVER records
  prompt or response content (the audit trail itself already enforces
  this rule).

Hooks (for callers)
-------------------
``llm-dispatch.py`` reads ``AUDITOOOR_CAMPAIGN_ID`` (and optionally
``AUDITOOOR_CAMPAIGN_LANE``, ``AUDITOOOR_CAMPAIGN_ROLE``,
``AUDITOOOR_CAMPAIGN_WORKSPACE``) from the environment when present, and
calls :func:`record_dispatch` from this module after the audit trail is
written. Off-path dispatchers (anything that does NOT shell through
``llm-dispatch.py``) must call this hook themselves; we cannot intercept
provider HTTP calls we never see.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

THIS_FILE = Path(__file__).resolve()
TOOLS_DIR = THIS_FILE.parent
CALIBRATION_DIR = TOOLS_DIR / "calibration"

DISPATCH_LOG_DEFAULT = CALIBRATION_DIR / "campaign_dispatch_log.jsonl"
OPUS_LOG_DEFAULT = CALIBRATION_DIR / "opus_escalations.jsonl"
SUBMISSION_LOG_DEFAULT = CALIBRATION_DIR / "campaign_submissions.jsonl"

DISPATCH_SCHEMA_VERSION = "campaign-dispatch.v1"
OPUS_SCHEMA_VERSION = "opus-escalation.v1"
SUBMISSION_SCHEMA_VERSION = "campaign-submission.v1"

OPUS_PROVIDERS = frozenset({"anthropic"})
OPUS_MODEL_PREFIX = "claude-opus"

VALID_TRIAGER_OUTCOMES = (
    "pending",
    "accepted",
    "rejected",
    "duplicate",
    "in_review",
)
VALID_SCOPE_VERDICTS = ("in-scope", "out-of-scope", "borderline", "unknown")

EXIT_OK = 0
EXIT_USER_ERROR = 1
EXIT_INTERNAL = 2

# Submission-metadata required field set, mirroring Codex Section 6.
SUBMISSION_REQUIRED_FIELDS = (
    "schema_version",
    "ts",
    "finding_id",
    "workspace",
    "source_campaign_id",
    "fuzz_campaign_id",
    "symbolic_campaign_id",
    "deep_campaign_id",
    "models_used",
    "tests_run",
    "scope_verdict",
    "oos_clauses_checked",
    "prior_art_result",
    "triager_outcome",
)


# ---------------------------------------------------------------------------
# Time helper (single source so tests can monkeypatch)
# ---------------------------------------------------------------------------

def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> _dt.datetime:
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    return _dt.datetime.fromisoformat(raw).astimezone(_dt.timezone.utc)


# ---------------------------------------------------------------------------
# Append-only writer (shared across the three ledgers)
# ---------------------------------------------------------------------------

def _append_jsonl(path: Path, entry: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, sort_keys=True, separators=(",", ": "))
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    return path


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.is_file():
        return []
    out: List[Dict[str, Any]] = []
    text = path.read_text(encoding="utf-8")
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{path}:{line_no}: invalid JSON: {exc}"
            ) from exc
        if not isinstance(entry, dict):
            raise ValueError(f"{path}:{line_no}: line is not a JSON object")
        out.append(entry)
    return out


# ---------------------------------------------------------------------------
# Library API: record_dispatch
# ---------------------------------------------------------------------------

def record_dispatch(
    *,
    campaign_id: str,
    provider: str,
    model: str,
    tokens_used: int,
    outcome: str,
    audit_path: Optional[str] = None,
    role: Optional[str] = None,
    workspace: Optional[str] = None,
    lane: Optional[str] = None,
    budget_guard_disabled: bool = False,
    log_path: Optional[Path] = None,
    opus_log_path: Optional[Path] = None,
    now_fn=None,
) -> Dict[str, Any]:
    """Append a campaign-dispatch record. Stdlib-only.

    The hook must NEVER raise on writer failure inside dispatch, so
    callers should catch a broad ``Exception`` around this call and emit
    a structured stderr ``warn`` instead. The library still validates the
    inputs strictly so silent corruption never enters the ledger.
    """
    if not isinstance(campaign_id, str) or not campaign_id.strip():
        raise ValueError("campaign_id must be a non-empty string")
    if not isinstance(provider, str) or not provider.strip():
        raise ValueError("provider must be a non-empty string")
    if not isinstance(model, str) or not model.strip():
        raise ValueError("model must be a non-empty string")
    if (isinstance(tokens_used, bool) or not isinstance(tokens_used, int)
            or tokens_used < 0):
        raise ValueError("tokens_used must be int >= 0")
    if not isinstance(outcome, str) or not outcome.strip():
        raise ValueError("outcome must be a non-empty string")

    ts = (now_fn or _utcnow)() if callable(now_fn) else _utcnow()
    entry = {
        "schema_version": DISPATCH_SCHEMA_VERSION,
        "ts": ts,
        "campaign_id": campaign_id.strip(),
        "lane": (lane or None),
        "workspace": (workspace or None),
        "provider": provider.strip(),
        "model": model.strip(),
        "role": (role or None),
        "tokens_used": int(tokens_used),
        "outcome": outcome.strip(),
        "audit_path": (audit_path or None),
        "budget_guard_disabled": bool(budget_guard_disabled),
    }
    _append_jsonl(log_path or DISPATCH_LOG_DEFAULT, entry)

    # If the dispatch was an Opus call, also append to the
    # opus_escalations ledger as a side-effect with a placeholder
    # follow_up_outcome. The auto-stub guarantees that an Opus dispatch
    # is NEVER missed by the "was it worth it?" ledger, even when the
    # wrapper script forgets to record one explicitly. Aggregation keeps
    # the latest per audit_path, so multiple rows for the same dispatch
    # are fine.
    if _is_opus(provider, model):
        _append_jsonl(opus_log_path or OPUS_LOG_DEFAULT, {
            "schema_version": OPUS_SCHEMA_VERSION,
            "ts": ts,
            "campaign_id": entry["campaign_id"],
            "escalation_reason": "auto-recorded-from-dispatch",
            "scope_of_question": (role or "unknown"),
            "decision_returned": entry["outcome"],
            "follow_up_outcome": "pending",
            "tokens_used": int(tokens_used),
            "audit_path": entry["audit_path"],
            "auto_stub": True,
        })
    return entry


def _is_opus(provider: str, model: str) -> bool:
    p = (provider or "").strip().lower()
    m = (model or "").strip().lower()
    if p in OPUS_PROVIDERS and m.startswith(OPUS_MODEL_PREFIX):
        return True
    # Allow override for symmetric routing where operators tag the
    # provider as "claude_opus" directly (campaign.v1 uses this label).
    return p == "claude_opus"


# ---------------------------------------------------------------------------
# Library API: record_opus_escalation
# ---------------------------------------------------------------------------

def record_opus_escalation(
    *,
    escalation_reason: str,
    scope_of_question: str,
    decision_returned: str,
    tokens_used: int,
    campaign_id: Optional[str] = None,
    audit_path: Optional[str] = None,
    follow_up_outcome: str = "pending",
    log_path: Optional[Path] = None,
    now_fn=None,
) -> Dict[str, Any]:
    """Append an Opus escalation row.

    ``follow_up_outcome`` defaults to ``pending``; the operator (or a
    later automated pass that links to the campaign-submission ledger)
    refines it to one of accepted/rejected/duplicate via the same
    function with a different ``follow_up_outcome`` value, OR by
    appending via :func:`record_triager_outcome` keyed by ``finding_id``
    so the "was Opus worth it?" report can join Opus rows to triager
    outcomes through the submission ledger.
    """
    if not isinstance(escalation_reason, str) or not escalation_reason.strip():
        raise ValueError("escalation_reason must be a non-empty string")
    if not isinstance(scope_of_question, str) or not scope_of_question.strip():
        raise ValueError("scope_of_question must be a non-empty string")
    if not isinstance(decision_returned, str) or not decision_returned.strip():
        raise ValueError("decision_returned must be a non-empty string")
    if (isinstance(tokens_used, bool) or not isinstance(tokens_used, int)
            or tokens_used < 0):
        raise ValueError("tokens_used must be int >= 0")
    if follow_up_outcome not in VALID_TRIAGER_OUTCOMES:
        raise ValueError(
            f"follow_up_outcome must be one of "
            f"{VALID_TRIAGER_OUTCOMES}, got {follow_up_outcome!r}"
        )

    ts = (now_fn or _utcnow)() if callable(now_fn) else _utcnow()
    entry = {
        "schema_version": OPUS_SCHEMA_VERSION,
        "ts": ts,
        "campaign_id": (campaign_id or None),
        "escalation_reason": escalation_reason.strip(),
        "scope_of_question": scope_of_question.strip(),
        "decision_returned": decision_returned.strip(),
        "follow_up_outcome": follow_up_outcome,
        "tokens_used": int(tokens_used),
        "audit_path": (audit_path or None),
    }
    _append_jsonl(log_path or OPUS_LOG_DEFAULT, entry)
    return entry


# ---------------------------------------------------------------------------
# Library API: record_submission
# ---------------------------------------------------------------------------

def record_submission(
    metadata: Dict[str, Any],
    *,
    log_path: Optional[Path] = None,
    now_fn=None,
) -> Dict[str, Any]:
    """Append a campaign-submission row built from an operator-supplied
    metadata dict.

    The dict must conform to the Section 6 schema. Validation is strict:
    missing required fields, unknown campaign-id types, and bad enum
    values all raise. The function fills defaults for ``schema_version``
    and ``ts`` if omitted so callers can pass minimal payloads.
    """
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be a JSON object")

    md = dict(metadata)  # shallow copy — never mutate caller's dict
    md.setdefault("schema_version", SUBMISSION_SCHEMA_VERSION)
    md.setdefault(
        "ts",
        ((now_fn or _utcnow)() if callable(now_fn) else _utcnow()),
    )
    md.setdefault("triager_outcome", "pending")

    errors = validate_submission_metadata(md)
    if errors:
        raise ValueError(
            "submission metadata invalid: " + "; ".join(errors)
        )

    _append_jsonl(log_path or SUBMISSION_LOG_DEFAULT, md)
    return md


def validate_submission_metadata(md: Dict[str, Any]) -> List[str]:
    """Return a list of human-readable validation errors (empty == valid)."""
    errors: List[str] = []
    for field in SUBMISSION_REQUIRED_FIELDS:
        if field not in md:
            errors.append(f"missing required field: {field}")
    if errors:
        return errors

    if md.get("schema_version") != SUBMISSION_SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {SUBMISSION_SCHEMA_VERSION!r}, "
            f"got {md.get('schema_version')!r}"
        )

    fid = md.get("finding_id")
    if not isinstance(fid, str) or not fid.strip():
        errors.append("finding_id must be a non-empty string")

    ws = md.get("workspace")
    if not isinstance(ws, str) or not ws.strip():
        errors.append("workspace must be a non-empty string")

    for cid_field in (
        "source_campaign_id",
        "fuzz_campaign_id",
        "symbolic_campaign_id",
        "deep_campaign_id",
    ):
        v = md.get(cid_field)
        if v is None:
            continue
        if not isinstance(v, str) or not v.strip():
            errors.append(
                f"{cid_field} must be either null or a non-empty string"
            )

    models_used = md.get("models_used")
    if not isinstance(models_used, list):
        errors.append("models_used must be a list")
    else:
        for entry in models_used:
            if not isinstance(entry, dict):
                errors.append("models_used[*] must be a JSON object")
                break
            if "model" not in entry or "role" not in entry:
                errors.append(
                    "models_used[*] requires {model, role} keys"
                )
                break
            if (not isinstance(entry["model"], str)
                    or not isinstance(entry["role"], str)):
                errors.append(
                    "models_used[*].model and .role must both be strings"
                )
                break

    tests_run = md.get("tests_run")
    if not isinstance(tests_run, list):
        errors.append("tests_run must be a list")
    else:
        for entry in tests_run:
            if not isinstance(entry, dict):
                errors.append("tests_run[*] must be a JSON object")
                break
            if "command" not in entry:
                errors.append("tests_run[*] requires a 'command' key")
                break
            if not isinstance(entry["command"], str):
                errors.append("tests_run[*].command must be a string")
                break

    scope_verdict = md.get("scope_verdict")
    if scope_verdict not in VALID_SCOPE_VERDICTS:
        errors.append(
            f"scope_verdict must be one of {VALID_SCOPE_VERDICTS}, "
            f"got {scope_verdict!r}"
        )

    oos = md.get("oos_clauses_checked")
    if not isinstance(oos, list):
        errors.append("oos_clauses_checked must be a list")
    else:
        for clause in oos:
            if not isinstance(clause, str):
                errors.append(
                    "oos_clauses_checked[*] must be strings"
                )
                break

    prior_art = md.get("prior_art_result")
    if prior_art not in ("novel", "duplicate", "unknown"):
        errors.append(
            "prior_art_result must be one of "
            "{novel, duplicate, unknown}, got "
            f"{prior_art!r}"
        )

    triager = md.get("triager_outcome")
    if triager not in VALID_TRIAGER_OUTCOMES:
        errors.append(
            f"triager_outcome must be one of "
            f"{VALID_TRIAGER_OUTCOMES}, got {triager!r}"
        )

    return errors


# ---------------------------------------------------------------------------
# Library API: record_triager_outcome
# ---------------------------------------------------------------------------

def record_triager_outcome(
    *,
    finding_id: str,
    outcome: str,
    log_path: Optional[Path] = None,
    opus_log_path: Optional[Path] = None,
    now_fn=None,
) -> Dict[str, Any]:
    """Append a follow-up row to the submission ledger that updates the
    triager outcome for ``finding_id``.

    The submission ledger is append-only; aggregation keeps the latest
    per ``finding_id`` so the most recent triager outcome wins. Earlier
    rows for the same id are preserved on disk for audit.

    Side-effect: when the most recent submission row for ``finding_id``
    is found, we ALSO append a follow-up row to the opus_escalations
    ledger setting ``follow_up_outcome = outcome`` so the
    "was Opus worth it?" aggregator never has to join across files.
    This closes the "Opus row could orphan" path called out in the
    Kimi pre-review.
    """
    if not isinstance(finding_id, str) or not finding_id.strip():
        raise ValueError("finding_id must be a non-empty string")
    if outcome not in VALID_TRIAGER_OUTCOMES:
        raise ValueError(
            f"outcome must be one of {VALID_TRIAGER_OUTCOMES}, "
            f"got {outcome!r}"
        )

    ts = (now_fn or _utcnow)() if callable(now_fn) else _utcnow()
    sub_path = log_path or SUBMISSION_LOG_DEFAULT
    opus_path = opus_log_path or OPUS_LOG_DEFAULT

    # Load the most recent submission row for this finding_id (if any)
    # so we can mirror campaign_id / workspace into the follow-up.
    parent = _latest_submission_for(finding_id, sub_path)

    follow_up = {
        "schema_version": SUBMISSION_SCHEMA_VERSION + ".follow-up",
        "ts": ts,
        "finding_id": finding_id.strip(),
        "triager_outcome": outcome,
        "follow_up": True,
    }
    if parent is not None:
        follow_up["source_campaign_id"] = parent.get("source_campaign_id")
        follow_up["fuzz_campaign_id"] = parent.get("fuzz_campaign_id")
        follow_up["symbolic_campaign_id"] = parent.get("symbolic_campaign_id")
        follow_up["deep_campaign_id"] = parent.get("deep_campaign_id")
        follow_up["workspace"] = parent.get("workspace")
    _append_jsonl(sub_path, follow_up)

    # Mirror to the Opus ledger so "was Opus worth it?" rows do not
    # orphan when a finding lands. We append a follow-up row keyed by
    # the parent's campaign_id and finding_id.
    if parent is not None:
        _append_jsonl(opus_path, {
            "schema_version": OPUS_SCHEMA_VERSION + ".follow-up",
            "ts": ts,
            "campaign_id": (
                parent.get("source_campaign_id")
                or parent.get("fuzz_campaign_id")
                or parent.get("symbolic_campaign_id")
                or parent.get("deep_campaign_id")
            ),
            "finding_id": finding_id.strip(),
            "follow_up_outcome": outcome,
            "follow_up": True,
        })

    return follow_up


def _latest_submission_for(
    finding_id: str, sub_path: Path
) -> Optional[Dict[str, Any]]:
    if not sub_path.is_file():
        return None
    rows = _read_jsonl(sub_path)
    latest: Optional[Dict[str, Any]] = None
    latest_ts: Optional[_dt.datetime] = None
    for row in rows:
        if row.get("finding_id") != finding_id:
            continue
        if row.get("follow_up"):
            continue  # we want the canonical row, not earlier follow-ups
        ts = row.get("ts")
        try:
            ts_dt = _parse_iso(ts) if isinstance(ts, str) else None
        except ValueError:
            ts_dt = None
        if ts_dt is None:
            continue
        if latest_ts is None or ts_dt > latest_ts:
            latest = row
            latest_ts = ts_dt
    return latest


# ---------------------------------------------------------------------------
# Aggregation: report
# ---------------------------------------------------------------------------

def aggregate(
    *,
    since: Optional[str] = None,
    dispatch_log: Optional[Path] = None,
    opus_log: Optional[Path] = None,
    submission_log: Optional[Path] = None,
) -> Dict[str, Any]:
    """Build the Section 6 report. Returns a dict with these slices:

    - ``by_lane``: lane -> {dispatches, tokens, accepted, rejected,
      submitted, accept_rate}
    - ``by_model``: model -> {dispatches, tokens, ok_dispatches,
      hold_dispatches, budget_skips, hold_rate}
    - ``by_workspace``: workspace -> {source_mine_dispatches,
      fuzz_dispatches, accepted, mining_share}
    - ``opus_value``: counts + accepted/rejected/pending split per
      campaign — answers "was Opus worth it?"
    - ``totals``: top-level counts.

    ``since`` is an ISO date or datetime; rows with ``ts`` strictly older
    are excluded. Malformed ``ts`` rows are kept but marked under
    ``totals.malformed_ts``.
    """
    cutoff_dt: Optional[_dt.datetime] = None
    if since:
        try:
            cutoff_dt = _parse_iso(since)
        except ValueError as exc:
            raise ValueError(f"--since must be ISO-8601: {exc}") from exc

    dispatches = _read_jsonl(dispatch_log or DISPATCH_LOG_DEFAULT)
    opus_rows = _read_jsonl(opus_log or OPUS_LOG_DEFAULT)
    submissions = _read_jsonl(submission_log or SUBMISSION_LOG_DEFAULT)

    def _in_window(row: Dict[str, Any]) -> Optional[bool]:
        if cutoff_dt is None:
            return True
        ts = row.get("ts")
        if not isinstance(ts, str):
            return None
        try:
            return _parse_iso(ts) >= cutoff_dt
        except ValueError:
            return None

    malformed = 0

    # Latest-per-finding for triager outcomes.
    finding_outcome: Dict[str, str] = {}
    finding_workspace: Dict[str, str] = {}
    finding_source_lane: Dict[str, List[str]] = defaultdict(list)
    canonical_subs: List[Dict[str, Any]] = []

    for row in submissions:
        keep = _in_window(row)
        if keep is None:
            malformed += 1
            continue
        if not keep:
            continue
        fid = row.get("finding_id")
        if not isinstance(fid, str):
            continue
        outcome = row.get("triager_outcome")
        if isinstance(outcome, str) and outcome in VALID_TRIAGER_OUTCOMES:
            # Latest wins.
            finding_outcome[fid] = outcome
        if not row.get("follow_up"):
            ws = row.get("workspace")
            if isinstance(ws, str):
                finding_workspace[fid] = ws
            for cid_key, lane in (
                ("source_campaign_id", "source_mine"),
                ("fuzz_campaign_id", "fuzz"),
                ("symbolic_campaign_id", "symbolic"),
                ("deep_campaign_id", "deep"),
            ):
                if isinstance(row.get(cid_key), str):
                    finding_source_lane[fid].append(lane)
            canonical_subs.append(row)

    # By-lane aggregation: dispatches keyed by their declared lane;
    # acceptance is joined through the submission ledger's lane fields.
    by_lane: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "dispatches": 0,
            "tokens_used": 0,
            "submitted": 0,
            "accepted": 0,
            "rejected": 0,
            "duplicate": 0,
            "pending": 0,
        }
    )
    by_model: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "dispatches": 0,
            "tokens_used": 0,
            "ok_dispatches": 0,
            "hold_dispatches": 0,
            "budget_skips": 0,
        }
    )
    by_workspace: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "source_mine_dispatches": 0,
            "fuzz_dispatches": 0,
            "other_dispatches": 0,
            "submitted": 0,
            "accepted": 0,
            "rejected": 0,
        }
    )

    for row in dispatches:
        keep = _in_window(row)
        if keep is None:
            malformed += 1
            continue
        if not keep:
            continue
        lane = row.get("lane") or "unknown"
        ws = row.get("workspace") or "unknown"
        provider = row.get("provider") or "unknown"
        model = row.get("model") or "unknown"
        outcome = (row.get("outcome") or "").strip()
        tokens = int(row.get("tokens_used") or 0)

        slot_lane = by_lane[lane]
        slot_lane["dispatches"] += 1
        slot_lane["tokens_used"] += tokens

        slot_model = by_model[f"{provider}:{model}"]
        slot_model["dispatches"] += 1
        slot_model["tokens_used"] += tokens
        if outcome == "ok":
            slot_model["ok_dispatches"] += 1
        elif outcome.startswith("budget-skip"):
            slot_model["budget_skips"] += 1
        else:
            slot_model["hold_dispatches"] += 1

        slot_ws = by_workspace[ws]
        if lane == "source_mine":
            slot_ws["source_mine_dispatches"] += 1
        elif lane == "fuzz":
            slot_ws["fuzz_dispatches"] += 1
        else:
            slot_ws["other_dispatches"] += 1

    # Project triager outcomes onto by_lane / by_workspace.
    for sub in canonical_subs:
        fid = sub.get("finding_id")
        if not isinstance(fid, str):
            continue
        ws = finding_workspace.get(fid) or "unknown"
        outcome = finding_outcome.get(fid, "pending")
        for lane in finding_source_lane.get(fid, ["unknown"]):
            slot = by_lane[lane]
            slot["submitted"] += 1
            if outcome in slot:
                slot[outcome] += 1
        slot_ws = by_workspace[ws]
        slot_ws["submitted"] += 1
        if outcome == "accepted":
            slot_ws["accepted"] += 1
        elif outcome == "rejected":
            slot_ws["rejected"] += 1

    # Compute derived ratios (best effort; division-by-zero guarded).
    for lane, slot in by_lane.items():
        sub = slot["submitted"]
        slot["accept_rate"] = (
            (slot["accepted"] / sub) if sub > 0 else None
        )
    for key, slot in by_model.items():
        d = slot["dispatches"]
        slot["hold_rate"] = (
            (slot["hold_dispatches"] / d) if d > 0 else None
        )
    for ws, slot in by_workspace.items():
        s = slot["source_mine_dispatches"]
        f = slot["fuzz_dispatches"]
        if (s + f) == 0:
            slot["mining_share"] = None
            slot["fuzz_share"] = None
        else:
            slot["mining_share"] = s / (s + f)
            slot["fuzz_share"] = f / (s + f)

    # Opus value: how many escalations -> accepted vs rejected vs pending.
    opus_by_campaign: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {
            "escalations": 0,
            "tokens_used": 0,
            "accepted": 0,
            "rejected": 0,
            "duplicate": 0,
            "pending": 0,
            "in_review": 0,
        }
    )

    for row in opus_rows:
        keep = _in_window(row)
        if keep is None:
            malformed += 1
            continue
        if not keep:
            continue
        cid = row.get("campaign_id") or "no-campaign"
        slot = opus_by_campaign[cid]
        if not row.get("follow_up"):
            slot["escalations"] += 1
            slot["tokens_used"] += int(row.get("tokens_used") or 0)
        outcome = row.get("follow_up_outcome", "pending")
        if (
            outcome in slot
            and outcome != "escalations"
            and outcome != "tokens_used"
        ):
            slot[outcome] += 1

    return {
        "totals": {
            "dispatches": sum(b["dispatches"] for b in by_lane.values()),
            "tokens_used": sum(b["tokens_used"] for b in by_lane.values()),
            "submissions": len(canonical_subs),
            "opus_escalations": sum(
                v["escalations"] for v in opus_by_campaign.values()
            ),
            "malformed_ts": malformed,
        },
        "by_lane": dict(by_lane),
        "by_model": dict(by_model),
        "by_workspace": dict(by_workspace),
        "opus_value": dict(opus_by_campaign),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_record_dispatch(args: argparse.Namespace) -> int:
    try:
        record_dispatch(
            campaign_id=args.campaign_id,
            provider=args.provider,
            model=args.model,
            tokens_used=int(args.tokens),
            outcome=args.outcome,
            audit_path=args.audit_path,
            role=args.role,
            workspace=args.workspace,
            lane=args.lane,
            budget_guard_disabled=args.budget_guard_disabled,
        )
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return EXIT_USER_ERROR
    print(json.dumps({"action": "record-dispatch", "ok": True}))
    return EXIT_OK


def cmd_record_opus(args: argparse.Namespace) -> int:
    try:
        record_opus_escalation(
            escalation_reason=args.escalation_reason,
            scope_of_question=args.scope_of_question,
            decision_returned=args.decision,
            tokens_used=int(args.tokens),
            campaign_id=args.campaign_id,
            audit_path=args.audit_path,
            follow_up_outcome=args.follow_up_outcome,
        )
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return EXIT_USER_ERROR
    print(json.dumps({"action": "record-opus", "ok": True}))
    return EXIT_OK


def cmd_record_submission(args: argparse.Namespace) -> int:
    p = Path(args.metadata_file)
    if not p.is_file():
        print(json.dumps({"error": f"metadata-file not found: {p}"}),
              file=sys.stderr)
        return EXIT_USER_ERROR
    try:
        md = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"invalid JSON: {exc}"}),
              file=sys.stderr)
        return EXIT_USER_ERROR
    try:
        entry = record_submission(md)
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return EXIT_USER_ERROR
    print(json.dumps(
        {"action": "record-submission", "ok": True,
         "finding_id": entry.get("finding_id")},
        sort_keys=True,
    ))
    return EXIT_OK


def cmd_record_triager(args: argparse.Namespace) -> int:
    try:
        record_triager_outcome(
            finding_id=args.finding_id,
            outcome=args.outcome,
        )
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return EXIT_USER_ERROR
    print(json.dumps({"action": "record-triager", "ok": True}))
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    try:
        report = aggregate(since=args.since)
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return EXIT_USER_ERROR

    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2))
        return EXIT_OK

    # Plain-text report — one section per Section 6 question.
    totals = report["totals"]
    print(
        f"Campaign telemetry report (since={args.since or 'all-time'})"
    )
    print(
        f"  totals: dispatches={totals['dispatches']}, "
        f"tokens={totals['tokens_used']}, "
        f"submissions={totals['submissions']}, "
        f"opus_escalations={totals['opus_escalations']}"
    )
    if totals.get("malformed_ts"):
        print(f"  malformed-ts rows: {totals['malformed_ts']}")
    print()
    print("Q1: Which lanes produce accepted findings?")
    for lane, slot in sorted(report["by_lane"].items()):
        rate = slot.get("accept_rate")
        rate_str = (
            f"{rate:.0%}" if isinstance(rate, float) else "n/a"
        )
        print(
            f"  {lane:14s} dispatches={slot['dispatches']:>4} "
            f"submitted={slot['submitted']:>3} "
            f"accepted={slot['accepted']:>3} "
            f"accept_rate={rate_str}"
        )
    print()
    print("Q2: Which models are noisy (high hold-rate / low ok-rate)?")
    for model, slot in sorted(report["by_model"].items()):
        rate = slot.get("hold_rate")
        rate_str = (
            f"{rate:.0%}" if isinstance(rate, float) else "n/a"
        )
        print(
            f"  {model:32s} dispatches={slot['dispatches']:>4} "
            f"ok={slot['ok_dispatches']:>3} "
            f"hold={slot['hold_dispatches']:>3} "
            f"budget_skips={slot['budget_skips']:>2} "
            f"hold_rate={rate_str}"
        )
    print()
    print(
        "Q3 (proxy): Which dispatches were prevented by gates "
        "(budget-skip / strategic refusals)?"
    )
    print(
        f"  total_budget_skips: "
        f"{sum(s['budget_skips'] for s in report['by_model'].values())}"
    )
    print()
    print(
        "Q4: Which workspaces need more source mining vs more fuzzing?"
    )
    for ws, slot in sorted(report["by_workspace"].items()):
        ms = slot.get("mining_share")
        fs = slot.get("fuzz_share")
        if ms is None:
            share = "no source/fuzz dispatches"
        else:
            share = f"mining={ms:.0%} fuzz={fs:.0%}"
        print(
            f"  {ws:32s} source={slot['source_mine_dispatches']:>3} "
            f"fuzz={slot['fuzz_dispatches']:>3} "
            f"submitted={slot['submitted']:>3} "
            f"accepted={slot['accepted']:>3} "
            f"({share})"
        )
    print()
    print("Was Opus worth it? (per campaign)")
    for cid, slot in sorted(report["opus_value"].items()):
        print(
            f"  {cid:32s} escalations={slot['escalations']:>3} "
            f"tokens={slot['tokens_used']:>6} "
            f"accepted={slot['accepted']:>3} "
            f"rejected={slot['rejected']:>3} "
            f"pending={slot['pending']:>3}"
        )
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="campaign-telemetry",
        description=(
            "V5 PR 6: link campaigns to model usage, submitted findings, "
            "and triager outcomes. Stdlib-only library + CLI."
        ),
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser(
        "record-dispatch",
        help="Append a campaign-tied LLM dispatch row.",
    )
    p1.add_argument("--campaign-id", required=True)
    p1.add_argument("--provider", required=True)
    p1.add_argument("--model", required=True)
    p1.add_argument("--tokens", type=int, required=True)
    p1.add_argument("--outcome", required=True)
    p1.add_argument("--audit-path", default=None)
    p1.add_argument("--role", default=None)
    p1.add_argument("--workspace", default=None)
    p1.add_argument("--lane", default=None)
    p1.add_argument(
        "--budget-guard-disabled", action="store_true",
    )
    p1.set_defaults(func=cmd_record_dispatch)

    p2 = sub.add_parser(
        "record-opus",
        help="Append a 'was Opus worth it?' escalation row.",
    )
    p2.add_argument("--escalation-reason", required=True)
    p2.add_argument("--scope-of-question", required=True)
    p2.add_argument("--decision", required=True)
    p2.add_argument("--tokens", type=int, required=True)
    p2.add_argument("--campaign-id", default=None)
    p2.add_argument("--audit-path", default=None)
    p2.add_argument(
        "--follow-up-outcome", default="pending",
        choices=VALID_TRIAGER_OUTCOMES,
    )
    p2.set_defaults(func=cmd_record_opus)

    p3 = sub.add_parser(
        "record-submission",
        help="Append a campaign-submission row from a metadata JSON file.",
    )
    p3.add_argument("--metadata-file", required=True)
    p3.set_defaults(func=cmd_record_submission)

    p4 = sub.add_parser(
        "record-triager",
        help="Append a follow-up triager outcome for a previously filed finding.",
    )
    p4.add_argument("--finding-id", required=True)
    p4.add_argument(
        "--outcome", required=True, choices=VALID_TRIAGER_OUTCOMES,
    )
    p4.set_defaults(func=cmd_record_triager)

    p5 = sub.add_parser(
        "report",
        help="Aggregate the three ledgers into Section 6's question-answers.",
    )
    p5.add_argument("--since", default=None)
    p5.add_argument("--json", action="store_true")
    p5.set_defaults(func=cmd_report)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print(json.dumps({"error": "interrupted"}), file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(main())
