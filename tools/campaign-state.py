#!/usr/bin/env python3
"""campaign-state.py — V5 campaign state foundation (stdlib-only).

Implements the campaign-state helper described in
``docs/ROADMAP_10_OF_10_V5_CAMPAIGNS.md`` Section 2.

Workspace layout (always created under ``<workspace>/.auditooor/``):

    .auditooor/
      campaigns/
        <campaign_id>/
          config.json       # persisted campaign state (campaign.v1)
          summary.json      # written on `complete`
          telemetry.jsonl   # append-only state-transition log
          artifacts/        # per-campaign artifact directory

Subcommands::

    init      Create a new campaign (idempotent; re-init is a no-op).
    resume    Mark an existing campaign ``running`` and emit its config.
    complete  Mark an existing campaign ``completed`` + write summary.json.
    list      List all campaigns in a workspace.
    validate  Re-validate config.json against the campaign.v1 schema rules.

This PR ships only the state foundation — no source-mining or fuzzing
logic. PRs 3-6 wire concrete lanes on top of these helpers.

Design notes
------------

* **Idempotent init.** Codex acceptance test #1: a campaign init'd twice
  must not duplicate state. We re-read config.json if it already exists,
  return the same campaign_id, and append a single ``init-noop`` line to
  telemetry. We never overwrite ``created_at``.

* **Resume preserves telemetry.** Codex acceptance test #2: a partial
  campaign must resume cleanly. ``resume`` opens telemetry in append-mode
  (never truncates), validates the existing config, and appends a
  ``resume`` line. Foot-gun guard: a missing telemetry file is recreated
  empty rather than treated as fatal so an interrupted init can still
  resume.

* **Complete writes summary.** Codex acceptance test #3: completion must
  emit summary.json with inputs, outputs, verdicts, tests. The ``--summary``
  flag accepts a path to a pre-built summary; otherwise we synthesize a
  minimum-viable summary from the campaign config (lane, status, models,
  inputs, artifacts, survivors, rejections, tests, next_action).

* **Schema validation is internal** (no jsonschema dependency). The
  validator enforces the conditional rules from campaign.v1.json:
  - status==completed requires completed_at + summary_path
  - status in {running, blocked} requires non-empty next_action
  - all required fields present, enum values respected, types correct.
  Schema-shape errors return classification ``schema-violation``; missing
  files return ``not-found``; corrupted JSON returns ``corrupt-state``.

* **Stdlib only.** No third-party imports. Tested under ``python3 -m
  unittest tools.tests.test_campaign_state``.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Constants and classification codes
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "campaign.v1"
FINDING_SCHEMA_VERSION = "finding.v1"

LANES = (
    "source_mine",
    "fuzz",
    "symbolic",
    "deep",
    "math",
    "crypto",
    "econ",
)
STATUSES = ("created", "running", "blocked", "completed", "rejected")
FINDING_STATUSES = ("candidate", "investigate", "hold", "rejected", "promoted")
SEVERITIES = ("informational", "low", "medium", "high", "critical", "unknown")

# Allowed top-level keys on the campaign state (additionalProperties:false
# parity with campaign.v1.json). Extra keys are surfaced as schema errors so
# operator typos and stray extension fields don't go silent.
CAMPAIGN_ALLOWED_KEYS = frozenset({
    "schema_version",
    "campaign_id",
    "workspace",
    "lane",
    "status",
    "models",
    "inputs",
    "artifacts",
    "survivors",
    "rejections",
    "tests",
    "next_action",
    "created_at",
    "updated_at",
    "completed_at",
    "summary_path",
    "notes",
    "rejection_reason",
    "lane_config",
})

# Allowed top-level keys on a finding state (additionalProperties:false
# parity with finding.v1.json). Mirror enforcement when PR 5 wires the
# finding store on top of this helper.
FINDING_ALLOWED_KEYS = frozenset({
    "schema_version",
    "finding_id",
    "campaign_id",
    "workspace",
    "lane",
    "status",
    "title",
    "severity",
    "files",
    "claim",
    "trigger",
    "impact",
    "reproduction_plan",
    "source_only_or_pre_deployment",
    "models_used",
    "tests_run",
    "scope_check",
    "prior_art_check",
    "blocking_questions",
    "rejection_reason",
    "created_at",
    "updated_at",
    "promoted_at",
})
ALLOWED_MODELS = (
    "kimi",
    "minimax",
    "claude",
    "claude_sonnet",
    "claude_opus",
    "codex",
)

# Filesystem constants
CAMPAIGN_DIRNAME = ".auditooor"
CAMPAIGNS_SUBDIR = "campaigns"
CONFIG_FILENAME = "config.json"
SUMMARY_FILENAME = "summary.json"
TELEMETRY_FILENAME = "telemetry.jsonl"
ARTIFACTS_DIRNAME = "artifacts"

# Classification labels (mirrored in tests for stable contracts)
CLS_OK = "ok"
CLS_SCHEMA_VIOLATION = "schema-violation"
CLS_NOT_FOUND = "not-found"
CLS_CORRUPT = "corrupt-state"
CLS_ALREADY_COMPLETED = "already-completed"
CLS_INTERNAL = "internal-error"
CLS_BAD_INPUT = "bad-input"

# Identifier hardening: campaign_id and finding_id share this regex.
ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# Exit codes
EXIT_OK = 0
EXIT_USER_ERROR = 1
EXIT_INTERNAL = 2


# ---------------------------------------------------------------------------
# Time helper (single source so tests can monkeypatch)
# ---------------------------------------------------------------------------

def _utcnow() -> str:
    """RFC 3339 UTC timestamp with seconds precision and trailing ``Z``."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _campaigns_root(workspace: Path) -> Path:
    return workspace / CAMPAIGN_DIRNAME / CAMPAIGNS_SUBDIR


def _campaign_dir(workspace: Path, campaign_id: str) -> Path:
    return _campaigns_root(workspace) / campaign_id


def _config_path(workspace: Path, campaign_id: str) -> Path:
    return _campaign_dir(workspace, campaign_id) / CONFIG_FILENAME


def _summary_path(workspace: Path, campaign_id: str) -> Path:
    return _campaign_dir(workspace, campaign_id) / SUMMARY_FILENAME


def _telemetry_path(workspace: Path, campaign_id: str) -> Path:
    return _campaign_dir(workspace, campaign_id) / TELEMETRY_FILENAME


def _artifacts_dir(workspace: Path, campaign_id: str) -> Path:
    return _campaign_dir(workspace, campaign_id) / ARTIFACTS_DIRNAME


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _err(classification: str, message: str, **extra: Any) -> dict[str, Any]:
    payload = {"classification": classification, "message": message}
    payload.update(extra)
    return payload


def _validate_campaign(state: dict[str, Any]) -> list[str]:
    """Return a list of human-readable validation errors (empty == valid).

    Mirrors campaign.v1.json's required-fields, enum, type, and
    conditional-required rules. We do not depend on jsonschema; this is
    cheaper to read and avoids adding a third-party dep to the audit tree.
    """
    errors: list[str] = []

    if not isinstance(state, dict):
        return ["state must be a JSON object"]

    if state.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {SCHEMA_VERSION!r}, got "
            f"{state.get('schema_version')!r}"
        )

    required = (
        "campaign_id",
        "workspace",
        "lane",
        "status",
        "models",
        "inputs",
        "artifacts",
        "survivors",
        "rejections",
        "tests",
        "next_action",
        "created_at",
        "updated_at",
    )
    for field in required:
        if field not in state:
            errors.append(f"missing required field: {field}")

    # Type/enum checks — only when fields are present.
    cid = state.get("campaign_id")
    if isinstance(cid, str) and not ID_RE.match(cid):
        errors.append(
            f"campaign_id must match {ID_RE.pattern!r}, got {cid!r}"
        )

    ws = state.get("workspace")
    if "workspace" in state and (not isinstance(ws, str) or not ws):
        errors.append("workspace must be a non-empty string")

    lane = state.get("lane")
    if "lane" in state and lane not in LANES:
        errors.append(f"lane must be one of {LANES}, got {lane!r}")

    status = state.get("status")
    if "status" in state and status not in STATUSES:
        errors.append(f"status must be one of {STATUSES}, got {status!r}")

    models = state.get("models")
    if "models" in state:
        if not isinstance(models, list):
            errors.append("models must be a list")
        else:
            for m in models:
                if m not in ALLOWED_MODELS:
                    errors.append(
                        f"models[*] must be one of {ALLOWED_MODELS}, got {m!r}"
                    )
            if len(set(models)) != len(models):
                errors.append("models must contain unique entries")

    for list_field in ("inputs", "artifacts", "survivors", "rejections", "tests"):
        if list_field in state and not isinstance(state[list_field], list):
            errors.append(f"{list_field} must be a list")
        elif list_field in state:
            for entry in state[list_field]:
                if not isinstance(entry, str) or not entry:
                    errors.append(
                        f"{list_field}[*] must be non-empty strings"
                    )
                    break

    if "next_action" in state and not isinstance(state["next_action"], str):
        errors.append("next_action must be a string (may be empty)")

    # additionalProperties:false parity — surface unknown top-level keys so
    # operator typos and forward-compat extensions don't silently slip past
    # the gate (Minimax M-3, low severity).
    extras = sorted(set(state.keys()) - CAMPAIGN_ALLOWED_KEYS)
    if extras:
        errors.append(f"unknown fields rejected by schema: {extras}")

    # Conditional rules
    if status == "completed":
        if not state.get("completed_at"):
            errors.append("status==completed requires completed_at")
        if not state.get("summary_path"):
            errors.append("status==completed requires summary_path")

    if status in ("running", "blocked"):
        na = state.get("next_action") or ""
        if not na.strip():
            errors.append(
                f"status=={status} requires non-empty next_action "
                "(would orphan campaign per Codex acceptance #1/#3)"
            )

    # Rejection parity with finding.v1.json: a rejected campaign must
    # carry a rejection_reason. Otherwise nothing in the workspace
    # explains why the lane stopped (Minimax M-1).
    if status == "rejected":
        rr = state.get("rejection_reason") or ""
        if not isinstance(rr, str) or not rr.strip():
            errors.append(
                "status==rejected requires non-empty rejection_reason"
            )

    return errors


def _validate_finding(state: Any) -> list[str]:
    """Validate a finding.v1 object. Exposed as a helper so PR 5 can call
    it from the source-mining and fuzz wrappers without duplicating the
    rules. Mirrors finding.v1.json including the promoted-without-proof
    guard (Codex acceptance test #4)."""
    errors: list[str] = []
    if not isinstance(state, dict):
        return ["finding state must be a JSON object"]

    if state.get("schema_version") != FINDING_SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {FINDING_SCHEMA_VERSION!r}, got "
            f"{state.get('schema_version')!r}"
        )

    required = (
        "finding_id",
        "campaign_id",
        "workspace",
        "lane",
        "status",
        "title",
        "files",
        "claim",
        "created_at",
        "updated_at",
    )
    for field in required:
        if field not in state:
            errors.append(f"missing required field: {field}")

    fid = state.get("finding_id")
    if isinstance(fid, str) and not ID_RE.match(fid):
        errors.append(f"finding_id must match {ID_RE.pattern!r}, got {fid!r}")
    cid = state.get("campaign_id")
    if isinstance(cid, str) and not ID_RE.match(cid):
        errors.append(f"campaign_id must match {ID_RE.pattern!r}, got {cid!r}")

    lane = state.get("lane")
    if "lane" in state and lane not in LANES:
        errors.append(f"lane must be one of {LANES}, got {lane!r}")

    status = state.get("status")
    if "status" in state and status not in FINDING_STATUSES:
        errors.append(f"status must be one of {FINDING_STATUSES}, got {status!r}")

    sev = state.get("severity")
    if "severity" in state and sev not in SEVERITIES:
        errors.append(f"severity must be one of {SEVERITIES}, got {sev!r}")

    files = state.get("files")
    if "files" in state:
        if not isinstance(files, list) or not files:
            errors.append("files must be a non-empty list")
        else:
            for entry in files:
                if not isinstance(entry, str) or not entry:
                    errors.append("files[*] must be non-empty strings")
                    break

    title = state.get("title")
    if "title" in state and (not isinstance(title, str) or not title):
        errors.append("title must be a non-empty string")
    claim = state.get("claim")
    if "claim" in state and (not isinstance(claim, str) or not claim):
        errors.append("claim must be a non-empty string")

    extras = sorted(set(state.keys()) - FINDING_ALLOWED_KEYS)
    if extras:
        errors.append(f"unknown fields rejected by schema: {extras}")

    # Promotion gate: status==promoted requires reproduction_plan OR
    # explicit source_only_or_pre_deployment flag. This is the V5 PR 2
    # half of Codex acceptance test #4 — the campaign-state helper now
    # owns the rule even though only PRs 5+ will exercise it.
    if status == "promoted":
        has_plan = bool((state.get("reproduction_plan") or "").strip()) \
            if isinstance(state.get("reproduction_plan"), str) else False
        source_only = state.get("source_only_or_pre_deployment") is True
        if not (has_plan or source_only):
            errors.append(
                "status==promoted requires either a non-empty "
                "reproduction_plan OR explicit "
                "source_only_or_pre_deployment=true (Codex acceptance #4)"
            )
        if not state.get("promoted_at"):
            errors.append("status==promoted requires promoted_at")

    if status == "rejected":
        rr = state.get("rejection_reason") or ""
        if not isinstance(rr, str) or not rr.strip():
            errors.append("status==rejected requires non-empty rejection_reason")

    return errors


# ---------------------------------------------------------------------------
# Telemetry append helper
# ---------------------------------------------------------------------------

def _append_telemetry(workspace: Path, campaign_id: str, event: str,
                      **extra: Any) -> None:
    """Append a single JSONL line to telemetry.jsonl. Open-append-only.
    Resume must never truncate this file."""
    line = {
        "ts": _utcnow(),
        "event": event,
        "campaign_id": campaign_id,
    }
    line.update(extra)
    path = _telemetry_path(workspace, campaign_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(line, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# Read / write helpers (atomic write to avoid mid-write resume)
# ---------------------------------------------------------------------------

def _read_state(workspace: Path, campaign_id: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Return ``(state, error)``. ``error`` is a dict with classification."""
    path = _config_path(workspace, campaign_id)
    if not path.exists():
        return None, _err(CLS_NOT_FOUND, f"no campaign at {path}", path=str(path))
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        return None, _err(CLS_CORRUPT, f"invalid JSON: {exc}", path=str(path))
    except OSError as exc:
        return None, _err(CLS_INTERNAL, f"I/O error reading {path}: {exc}")
    if not isinstance(data, dict):
        return None, _err(CLS_CORRUPT, "config.json root must be an object")
    return data, None


def _write_state_atomic(path: Path, state: dict[str, Any]) -> None:
    """Atomic write so a crash mid-update can still resume from prior config."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------

def _default_campaign_id(lane: str) -> str:
    """Deterministic-ish id based on lane + day + counter. Tests pass --id."""
    today = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    return f"{lane.replace('_', '-')}-{today}-001"


def cmd_init(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser()
    if not workspace.exists():
        workspace.mkdir(parents=True, exist_ok=True)

    if args.lane not in LANES:
        _emit_json(_err(CLS_BAD_INPUT,
                        f"--lane must be one of {LANES}, got {args.lane!r}"))
        return EXIT_USER_ERROR

    campaign_id = args.id or _default_campaign_id(args.lane)
    if not ID_RE.match(campaign_id):
        _emit_json(_err(CLS_BAD_INPUT,
                        f"--id must match {ID_RE.pattern!r}, got {campaign_id!r}"))
        return EXIT_USER_ERROR

    cfg_path = _config_path(workspace, campaign_id)

    # Idempotent re-init: if config exists, validate & emit existing state.
    if cfg_path.exists():
        state, err = _read_state(workspace, campaign_id)
        if err is not None:
            _emit_json(err)
            return EXIT_INTERNAL
        # Re-validate so a prior corrupt write surfaces here.
        problems = _validate_campaign(state)  # type: ignore[arg-type]
        if problems:
            _emit_json(_err(CLS_SCHEMA_VIOLATION,
                            "existing config.json fails schema validation",
                            errors=problems, path=str(cfg_path)))
            return EXIT_INTERNAL
        # K-4 fix: if the prior init was interrupted between config write
        # and telemetry creation, recreate telemetry empty so an init-noop
        # event can be appended without raising.
        tel_path = _telemetry_path(workspace, campaign_id)
        if not tel_path.exists():
            tel_path.parent.mkdir(parents=True, exist_ok=True)
            tel_path.touch()
        _append_telemetry(workspace, campaign_id, "init-noop",
                          reason="campaign already initialized")
        _emit_json({
            "classification": CLS_OK,
            "action": "init-noop",
            "campaign_id": campaign_id,
            "config_path": str(cfg_path),
            "state": state,
        })
        return EXIT_OK

    now = _utcnow()
    models = [m.strip() for m in (args.models or "").split(",") if m.strip()]
    if not models:
        models = ["kimi", "minimax", "claude"]
    for m in models:
        if m not in ALLOWED_MODELS:
            _emit_json(_err(CLS_BAD_INPUT,
                            f"--models contains unknown model {m!r}; "
                            f"allowed: {ALLOWED_MODELS}"))
            return EXIT_USER_ERROR

    state = {
        "schema_version": SCHEMA_VERSION,
        "campaign_id": campaign_id,
        "workspace": str(workspace.resolve()),
        "lane": args.lane,
        "status": "created",
        "models": models,
        "inputs": [],
        "artifacts": [],
        "survivors": [],
        "rejections": [],
        "tests": [],
        "next_action": (
            args.next_action.strip() if args.next_action else "resume to start"
        ),
        "created_at": now,
        "updated_at": now,
    }
    problems = _validate_campaign(state)
    if problems:
        # Should not happen — internal contract violation.
        _emit_json(_err(CLS_SCHEMA_VIOLATION,
                        "init produced an invalid campaign (internal bug)",
                        errors=problems))
        return EXIT_INTERNAL

    # K-5/K-6 fix: write config FIRST, then artifacts dir + telemetry.
    # This way a crash between config-write and telemetry-touch leaves a
    # campaign that init-noop or resume can recover (resume already
    # recreates missing telemetry; init-noop now does too).
    _write_state_atomic(cfg_path, state)
    _artifacts_dir(workspace, campaign_id).mkdir(parents=True, exist_ok=True)
    _telemetry_path(workspace, campaign_id).touch(exist_ok=True)
    _append_telemetry(workspace, campaign_id, "init",
                      lane=args.lane, models=models)

    _emit_json({
        "classification": CLS_OK,
        "action": "init",
        "campaign_id": campaign_id,
        "config_path": str(cfg_path),
        "state": state,
    })
    return EXIT_OK


def cmd_resume(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser()
    state, err = _read_state(workspace, args.id)
    if err is not None:
        _emit_json(err)
        return EXIT_USER_ERROR if err["classification"] == CLS_NOT_FOUND else EXIT_INTERNAL

    problems = _validate_campaign(state)  # type: ignore[arg-type]
    if problems:
        _emit_json(_err(CLS_SCHEMA_VIOLATION,
                        "config.json fails schema validation; refusing to resume",
                        errors=problems))
        return EXIT_INTERNAL

    if state["status"] == "completed":
        # Don't silently re-open completed campaigns.
        _emit_json(_err(CLS_ALREADY_COMPLETED,
                        f"campaign {args.id} already completed",
                        completed_at=state.get("completed_at")))
        return EXIT_USER_ERROR

    state["status"] = "running"
    state["updated_at"] = _utcnow()
    if args.next_action:
        state["next_action"] = args.next_action
    elif not state.get("next_action"):
        state["next_action"] = "operator must set --next-action on resume"

    # Re-validate after mutation so running w/ empty next_action is rejected.
    problems = _validate_campaign(state)
    if problems:
        _emit_json(_err(CLS_SCHEMA_VIOLATION,
                        "resume produced invalid state",
                        errors=problems))
        return EXIT_INTERNAL

    _write_state_atomic(_config_path(workspace, args.id), state)
    # Ensure the telemetry file exists even if the prior init was interrupted
    # before laying it down; this preserves Codex acceptance test #2.
    _telemetry_path(workspace, args.id).parent.mkdir(parents=True, exist_ok=True)
    if not _telemetry_path(workspace, args.id).exists():
        _telemetry_path(workspace, args.id).touch()
    _append_telemetry(workspace, args.id, "resume",
                      next_action=state["next_action"])

    _emit_json({
        "classification": CLS_OK,
        "action": "resume",
        "campaign_id": args.id,
        "state": state,
    })
    return EXIT_OK


def cmd_complete(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser()
    state, err = _read_state(workspace, args.id)
    if err is not None:
        _emit_json(err)
        return EXIT_USER_ERROR if err["classification"] == CLS_NOT_FOUND else EXIT_INTERNAL

    if state["status"] == "completed":
        _emit_json(_err(CLS_ALREADY_COMPLETED,
                        f"campaign {args.id} already completed",
                        completed_at=state.get("completed_at")))
        return EXIT_USER_ERROR

    summary_obj: dict[str, Any]
    summary_path = _summary_path(workspace, args.id)

    if args.summary:
        src = Path(args.summary).expanduser()
        if not src.exists():
            _emit_json(_err(CLS_NOT_FOUND, f"--summary file missing: {src}"))
            return EXIT_USER_ERROR
        try:
            with src.open("r", encoding="utf-8") as fh:
                summary_obj = json.load(fh)
        except json.JSONDecodeError as exc:
            _emit_json(_err(CLS_CORRUPT, f"--summary not valid JSON: {exc}"))
            return EXIT_USER_ERROR
        if not isinstance(summary_obj, dict):
            _emit_json(_err(CLS_CORRUPT, "--summary root must be an object"))
            return EXIT_USER_ERROR
    else:
        summary_obj = {}

    # Synthesize required fields from the campaign so summary.json always
    # carries inputs / outputs / verdicts / tests (Codex acceptance #3).
    synthesized = {
        "schema_version": "summary.v1",
        "campaign_id": state["campaign_id"],
        "lane": state["lane"],
        "workspace": state["workspace"],
        "models": state["models"],
        "inputs": state["inputs"],
        "artifacts": state["artifacts"],
        "survivors": state["survivors"],
        "rejections": state["rejections"],
        "tests": state["tests"],
        "verdicts": {
            "survivors": len(state["survivors"]),
            "rejections": len(state["rejections"]),
        },
        "next_action": state.get("next_action", ""),
        "completed_at": _utcnow(),
    }
    # Operator-supplied summary wins on collision but must keep id / lane.
    for key, val in synthesized.items():
        summary_obj.setdefault(key, val)
    # Always pin the campaign back-link.
    summary_obj["campaign_id"] = state["campaign_id"]
    summary_obj["lane"] = state["lane"]

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    _write_state_atomic(summary_path, summary_obj)

    state["status"] = "completed"
    state["completed_at"] = summary_obj["completed_at"]
    state["updated_at"] = state["completed_at"]
    state["summary_path"] = str(summary_path.relative_to(workspace))
    # Completion implies no next action by definition; allow empty.
    if state.get("next_action"):
        state["next_action"] = ""

    problems = _validate_campaign(state)
    if problems:
        _emit_json(_err(CLS_SCHEMA_VIOLATION,
                        "complete produced invalid state",
                        errors=problems))
        return EXIT_INTERNAL

    _write_state_atomic(_config_path(workspace, args.id), state)
    _append_telemetry(workspace, args.id, "complete",
                      summary_path=state["summary_path"])

    _emit_json({
        "classification": CLS_OK,
        "action": "complete",
        "campaign_id": args.id,
        "summary_path": str(summary_path),
        "state": state,
    })
    return EXIT_OK


def cmd_list(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser()
    root = _campaigns_root(workspace)
    items: list[dict[str, Any]] = []
    if root.exists():
        for entry in sorted(root.iterdir()):
            if not entry.is_dir():
                continue
            cfg = entry / CONFIG_FILENAME
            if not cfg.exists():
                continue
            try:
                with cfg.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except (json.JSONDecodeError, OSError):
                items.append({
                    "campaign_id": entry.name,
                    "status": "corrupt",
                    "config_path": str(cfg),
                })
                continue
            items.append({
                "campaign_id": data.get("campaign_id", entry.name),
                "lane": data.get("lane"),
                "status": data.get("status"),
                "updated_at": data.get("updated_at"),
                "config_path": str(cfg),
            })

    if args.json:
        _emit_json({"classification": CLS_OK, "campaigns": items})
    else:
        if not items:
            print(f"no campaigns under {root}")
        for item in items:
            print(
                f"{item.get('campaign_id'):40s} "
                f"lane={item.get('lane')!s:12s} "
                f"status={item.get('status')!s:10s} "
                f"updated={item.get('updated_at')}"
            )
    return EXIT_OK


def cmd_validate(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser()
    state, err = _read_state(workspace, args.id)
    if err is not None:
        _emit_json(err)
        return EXIT_USER_ERROR if err["classification"] == CLS_NOT_FOUND else EXIT_INTERNAL
    problems = _validate_campaign(state)  # type: ignore[arg-type]
    if problems:
        _emit_json(_err(CLS_SCHEMA_VIOLATION, "validation failed", errors=problems))
        return EXIT_INTERNAL
    _emit_json({
        "classification": CLS_OK,
        "action": "validate",
        "campaign_id": args.id,
    })
    return EXIT_OK


def cmd_validate_finding(args: argparse.Namespace) -> int:
    """Validate a finding.v1 JSON file. PR 2 ships the gate; PR 5 wires
    it into the source-mining/fuzz wrappers. The CLI surface keeps the
    Codex acceptance #4 contract callable from CI without spinning up
    the full lane plumbing."""
    path = Path(args.path).expanduser()
    if not path.exists():
        _emit_json(_err(CLS_NOT_FOUND, f"finding file missing: {path}"))
        return EXIT_USER_ERROR
    try:
        with path.open("r", encoding="utf-8") as fh:
            state = json.load(fh)
    except json.JSONDecodeError as exc:
        _emit_json(_err(CLS_CORRUPT, f"finding not valid JSON: {exc}"))
        return EXIT_INTERNAL

    problems = _validate_finding(state)
    if problems:
        _emit_json(_err(CLS_SCHEMA_VIOLATION, "finding validation failed",
                        errors=problems, path=str(path)))
        return EXIT_INTERNAL
    _emit_json({
        "classification": CLS_OK,
        "action": "validate-finding",
        "path": str(path),
        "finding_id": state.get("finding_id"),
        "status": state.get("status"),
    })
    return EXIT_OK


def cmd_reject(args: argparse.Namespace) -> int:
    """Mark a campaign rejected with a required rejection_reason. Without
    this transition a lane that decides 'no bug, kill it' has no way to
    set status=rejected and would leave the campaign stuck (Minimax M-1)."""
    workspace = Path(args.workspace).expanduser()
    state, err = _read_state(workspace, args.id)
    if err is not None:
        _emit_json(err)
        return EXIT_USER_ERROR if err["classification"] == CLS_NOT_FOUND else EXIT_INTERNAL

    if state["status"] in ("completed", "rejected"):
        _emit_json(_err(CLS_BAD_INPUT,
                        f"campaign {args.id} already in terminal status "
                        f"{state['status']!r}"))
        return EXIT_USER_ERROR

    state["status"] = "rejected"
    state["updated_at"] = _utcnow()
    state["rejection_reason"] = args.reason
    state["next_action"] = ""

    problems = _validate_campaign(state)
    if problems:
        _emit_json(_err(CLS_SCHEMA_VIOLATION,
                        "reject produced invalid state", errors=problems))
        return EXIT_INTERNAL

    _write_state_atomic(_config_path(workspace, args.id), state)
    _append_telemetry(workspace, args.id, "reject", reason=args.reason)
    _emit_json({
        "classification": CLS_OK,
        "action": "reject",
        "campaign_id": args.id,
        "state": state,
    })
    return EXIT_OK


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------

def _emit_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="campaign-state",
        description="V5 campaign state foundation (init/resume/complete/list/validate).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="Create a new campaign (idempotent).")
    pi.add_argument("--workspace", required=True)
    pi.add_argument("--lane", required=True, choices=LANES)
    pi.add_argument("--id", default=None,
                    help="Override campaign_id (default: <lane>-<utc-date>-001).")
    pi.add_argument("--models", default=None,
                    help=f"Comma-separated models. Allowed: {','.join(ALLOWED_MODELS)}.")
    pi.add_argument("--next-action", default=None,
                    help="Initial next_action string (defaults to 'resume to start').")
    pi.set_defaults(func=cmd_init)

    pr = sub.add_parser("resume", help="Resume an existing campaign.")
    pr.add_argument("--workspace", required=True)
    pr.add_argument("--id", required=True)
    pr.add_argument("--next-action", default=None)
    pr.set_defaults(func=cmd_resume)

    pc = sub.add_parser("complete", help="Mark a campaign completed and write summary.json.")
    pc.add_argument("--workspace", required=True)
    pc.add_argument("--id", required=True)
    pc.add_argument("--summary", default=None,
                    help="Path to a pre-built summary.json (merged with synthesized fields).")
    pc.set_defaults(func=cmd_complete)

    pl = sub.add_parser("list", help="List campaigns in a workspace.")
    pl.add_argument("--workspace", required=True)
    pl.add_argument("--json", action="store_true")
    pl.set_defaults(func=cmd_list)

    pv = sub.add_parser("validate", help="Validate a campaign's config.json.")
    pv.add_argument("--workspace", required=True)
    pv.add_argument("--id", required=True)
    pv.set_defaults(func=cmd_validate)

    pj = sub.add_parser("reject",
                        help="Mark a campaign rejected with a required reason.")
    pj.add_argument("--workspace", required=True)
    pj.add_argument("--id", required=True)
    pj.add_argument("--reason", required=True,
                    help="Required: why this lane was killed (mirrors finding.v1 rule).")
    pj.set_defaults(func=cmd_reject)

    pf = sub.add_parser("validate-finding",
                        help="Validate a finding.v1 JSON file (PR 5 will wire this).")
    pf.add_argument("--path", required=True)
    pf.set_defaults(func=cmd_validate_finding)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        _emit_json(_err(CLS_INTERNAL, "interrupted"))
        return EXIT_INTERNAL
    except Exception as exc:  # noqa: BLE001 - last-resort guard
        _emit_json(_err(CLS_INTERNAL, f"unexpected: {exc}",
                        exception=type(exc).__name__))
        return EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(main())
