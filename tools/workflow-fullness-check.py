#!/usr/bin/env python3
# r36-rebuttal: lane pathspec registered via tools/agent-pathspec-register.py to agent_pathspec.json
"""Gap #39 — workflow-fullness-required-or-flag-cheap.

For ANY draft (LOW+) before promotion to `paste_ready/` or `filed/` that
claims a "full audit complete" / "exhausted" / "comprehensive review" /
"all engines run" wording, the cited workflow invocation MUST have run
the FULL toolset OR the draft MUST explicitly flag the cheap path with
`--cheap-path-acknowledged` / `<!-- gap39-rebuttal: ... -->`.

The gate consumes:
  - the draft markdown body (scanned for fullness-claim phrases)
  - the workspace's `.auditooor/workflow_invocation_log.jsonl` if present
    (per-invocation rows that record which engines were actually run)
  - any audit-deep report path cited by the draft

Schema: ``auditooor.gap39_workflow_fullness.v1``

Verdict vocabulary
==================

- ``pass-out-of-scope`` - draft does not contain any fullness-claim phrase
  (the gate only fires when the draft makes a fullness claim).
- ``pass-cheap-path-acknowledged`` - draft contains the cheap-path
  acknowledgement marker.
- ``pass-full-workflow-evidence`` - draft cites a workflow log that proves
  the full toolset ran.
- ``ok-rebuttal`` - draft contains a valid ``gap39-rebuttal`` (<=200
  chars, non-empty).
- ``fail-workflow-cheap-default-without-acknowledgement`` - draft claims
  "full" without evidence and without acknowledgement.
- ``error`` - input shape error (e.g. draft path does not exist).

CLI
===

    workflow-fullness-check.py <draft.md> [--workspace <ws>]
        [--strict] [--json]

By default writes a human-readable verdict to stdout. ``--json`` emits a
single JSON object matching the schema above. Exit codes:

- ``0`` - pass / ok-rebuttal verdict.
- ``1`` - fail verdict.
- ``2`` - error verdict (input shape).

Empirical anchor
================

Operator anchor 2026-05-26: "analyze explained workflows in github readme,
like make audit, audit fast, audit deep etc and fix it. This needs to be
default behavior. whatever we analyze and audit, we do it full". Current
workflows ship with cheap-default-skipped tools (halmos/medusa/echidna
behind ``--live`` flag; mythril/manticore/kontrol detected but never
invoked; ``make hunt`` runs zero formal verification / fuzz / symbolic
execution). The gate prevents future drafts from claiming "full audit"
without proving the full toolset actually ran.

Hard gate
=========

Wired as ``pre-submit-check.sh`` Check #110
(``GAP39-WORKFLOW-FULLNESS``). Fail-closed when the draft makes a
fullness claim without evidence and without acknowledgement. Override
marker: visible bounded line ``gap39-rebuttal: <reason>`` (<=200 chars)
or HTML-comment form ``<!-- gap39-rebuttal: <reason> -->``. Empty or
oversized reason is ignored.

Generalisation
==============

Target-agnostic and platform-agnostic. Works on any bounty engagement
where the operator wants to enforce "no fake-fullness" discipline. The
fullness-phrase catalogue and full-engine catalogue are env-tunable:

- ``AUDITOOOR_GAP39_FULLNESS_PHRASES`` newline-separated regex list of
  fullness-claim phrases beyond the defaults
- ``AUDITOOOR_GAP39_FULL_ENGINES`` newline-separated list of engine
  names that MUST appear in the workflow log as ``status=success`` or
  ``status=ran`` to count as full
- ``AUDITOOOR_GAP39_WORKFLOW_LOG`` override the default workflow log
  path (default: ``<workspace>/.auditooor/workflow_invocation_log.jsonl``)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.gap39_workflow_fullness.v1"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# Fullness-claim phrases that trigger the gate. Word-boundary regex.
# Each phrase says "the workflow ran the full toolset" implicitly.
DEFAULT_FULLNESS_PHRASES = [
    r"full audit complete",
    r"full audit performed",
    r"comprehensive audit",
    r"comprehensive review",
    r"comprehensive analysis",
    r"exhaustive review",
    r"exhaustively reviewed",
    r"exhausted the (?:toolset|engines|surface|analysis)",
    r"all engines (?:ran|run|executed|fired)",
    r"all (?:depth )?tools (?:ran|run|executed|fired)",
    r"full toolset (?:ran|executed|fired)",
    r"deep audit complete",
    r"fully audited",
    r"thoroughly audited",
]

# Engines that MUST appear in workflow_invocation_log.jsonl as a
# successful invocation row to count as "full". These names match the
# step names emitted by tools/audit-deep.sh and audit-deep-solidity.
DEFAULT_FULL_ENGINES = [
    "halmos-runner",
    "medusa-fuzz",
    "echidna-campaign",
]

# Cheap-path acknowledgement marker. When the draft body or referenced
# workflow log carries this marker, the gate passes regardless of
# engine evidence.
CHEAP_PATH_ACKNOWLEDGED_MARKER = "--cheap-path-acknowledged"

# Rebuttal marker patterns.
REBUTTAL_VISIBLE_RE = re.compile(
    r"^[ \t]*gap39-rebuttal:[ \t]*(.+?)[ \t]*$", re.MULTILINE
)
REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*gap39-rebuttal:\s*(.+?)\s*-->", re.DOTALL
)
REBUTTAL_MAX_CHARS = 200


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class WorkflowEvidence:
    """Outcome of scanning a workflow log."""

    log_path: str = ""
    log_exists: bool = False
    engines_seen: list[str] = field(default_factory=list)
    engines_success: list[str] = field(default_factory=list)
    missing_engines: list[str] = field(default_factory=list)
    cheap_path_acknowledged: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "log_path": self.log_path,
            "log_exists": self.log_exists,
            "engines_seen": sorted(self.engines_seen),
            "engines_success": sorted(self.engines_success),
            "missing_engines": sorted(self.missing_engines),
            "cheap_path_acknowledged": self.cheap_path_acknowledged,
        }


@dataclass
class DraftEvidence:
    fullness_phrases_hit: list[str] = field(default_factory=list)
    cheap_path_acknowledged: bool = False
    rebuttal: str | None = None
    rebuttal_oversized: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "fullness_phrases_hit": self.fullness_phrases_hit,
            "cheap_path_acknowledged": self.cheap_path_acknowledged,
            "rebuttal": self.rebuttal,
            "rebuttal_oversized": self.rebuttal_oversized,
        }


@dataclass
class Verdict:
    verdict: str
    reason: str
    schema: str = SCHEMA
    draft: DraftEvidence = field(default_factory=DraftEvidence)
    workflow: WorkflowEvidence = field(default_factory=WorkflowEvidence)
    full_engines_required: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "verdict": self.verdict,
            "reason": self.reason,
            "evidence": {
                "draft": self.draft.to_dict(),
                "workflow": self.workflow.to_dict(),
                "full_engines_required": sorted(self.full_engines_required),
            },
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _env_list(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    if not raw:
        return []
    return [line.strip() for line in raw.splitlines() if line.strip()]


def _fullness_phrase_regexes() -> list[re.Pattern[str]]:
    patterns = list(DEFAULT_FULLNESS_PHRASES) + _env_list(
        "AUDITOOOR_GAP39_FULLNESS_PHRASES"
    )
    return [
        re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns
    ]


def _full_engines() -> list[str]:
    env = _env_list("AUDITOOOR_GAP39_FULL_ENGINES")
    if env:
        return env
    return list(DEFAULT_FULL_ENGINES)


def _extract_rebuttal(body: str) -> tuple[str | None, bool]:
    """Return (rebuttal_text_or_None, oversized_flag)."""
    for m in REBUTTAL_HTML_RE.finditer(body):
        text = m.group(1).strip()
        if not text:
            continue
        if len(text) > REBUTTAL_MAX_CHARS:
            return text, True
        return text, False
    for m in REBUTTAL_VISIBLE_RE.finditer(body):
        text = m.group(1).strip()
        if not text:
            continue
        if len(text) > REBUTTAL_MAX_CHARS:
            return text, True
        return text, False
    return None, False


def _scan_draft(body: str) -> DraftEvidence:
    ev = DraftEvidence()
    for rx in _fullness_phrase_regexes():
        for m in rx.finditer(body):
            phrase = m.group(0)
            if phrase not in ev.fullness_phrases_hit:
                ev.fullness_phrases_hit.append(phrase)
    if CHEAP_PATH_ACKNOWLEDGED_MARKER in body:
        ev.cheap_path_acknowledged = True
    rebuttal, oversized = _extract_rebuttal(body)
    ev.rebuttal = rebuttal
    ev.rebuttal_oversized = oversized
    return ev


def _scan_workflow_log(log_path: Path, required_engines: list[str]) -> WorkflowEvidence:
    ev = WorkflowEvidence(log_path=str(log_path))
    if not log_path.exists():
        ev.missing_engines = list(required_engines)
        return ev
    ev.log_exists = True
    seen: set[str] = set()
    success: set[str] = set()
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        ev.missing_engines = list(required_engines)
        return ev
    if CHEAP_PATH_ACKNOWLEDGED_MARKER in text:
        ev.cheap_path_acknowledged = True
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        step = row.get("tool") or row.get("step") or row.get("name")
        if not isinstance(step, str):
            continue
        seen.add(step)
        status = row.get("status", "")
        if isinstance(status, str) and status.lower() in {
            "ok",
            "success",
            "ran",
            "completed",
        }:
            success.add(step)
    ev.engines_seen = sorted(seen)
    ev.engines_success = sorted(success)
    ev.missing_engines = [eng for eng in required_engines if eng not in success]
    return ev


def _resolve_workflow_log(workspace: Path | None) -> Path:
    override = os.environ.get("AUDITOOOR_GAP39_WORKFLOW_LOG", "").strip()
    if override:
        return Path(override).expanduser()
    if workspace is not None:
        return workspace / ".auditooor" / "workflow_invocation_log.jsonl"
    # Fallback: nonexistent path so the gate reports missing engines.
    return Path("/dev/null/workflow_invocation_log.jsonl")


def evaluate(
    draft_path: Path,
    workspace: Path | None = None,
    strict: bool = False,
) -> Verdict:
    if not draft_path.exists():
        v = Verdict(
            verdict="error",
            reason=f"draft path does not exist: {draft_path}",
        )
        v.full_engines_required = _full_engines()
        return v

    try:
        body = draft_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        v = Verdict(verdict="error", reason=f"could not read draft: {exc}")
        v.full_engines_required = _full_engines()
        return v

    draft_ev = _scan_draft(body)

    required = _full_engines()
    log_path = _resolve_workflow_log(workspace)
    wf_ev = _scan_workflow_log(log_path, required)

    verdict = Verdict(
        verdict="pass-out-of-scope",
        reason="draft makes no fullness claim",
        draft=draft_ev,
        workflow=wf_ev,
        full_engines_required=required,
    )

    # Rebuttal trumps when the draft has a non-oversized rebuttal AND
    # there is something to rebut (a fullness phrase hit). An oversized
    # rebuttal is ignored.
    if draft_ev.fullness_phrases_hit:
        if draft_ev.rebuttal and not draft_ev.rebuttal_oversized:
            verdict.verdict = "ok-rebuttal"
            verdict.reason = (
                f"gap39-rebuttal accepted: {draft_ev.rebuttal[:80]}"
            )
            return verdict
        if draft_ev.cheap_path_acknowledged or wf_ev.cheap_path_acknowledged:
            verdict.verdict = "pass-cheap-path-acknowledged"
            verdict.reason = (
                "cheap-path acknowledgement marker present"
            )
            return verdict
        if not wf_ev.missing_engines and wf_ev.log_exists:
            verdict.verdict = "pass-full-workflow-evidence"
            verdict.reason = (
                "workflow log shows all required engines ran successfully"
            )
            return verdict
        # Failure.
        verdict.verdict = "fail-workflow-cheap-default-without-acknowledgement"
        if not wf_ev.log_exists:
            verdict.reason = (
                "fullness claim made but workflow log not found at "
                f"{wf_ev.log_path}; cite an audit-deep run or acknowledge cheap path"
            )
        else:
            verdict.reason = (
                "fullness claim made but workflow log shows missing engines: "
                + ", ".join(wf_ev.missing_engines)
            )
        return verdict

    # No fullness phrase hit -> pass-out-of-scope. Strict mode does not
    # promote this; the gate is opt-in by phrase trigger.
    return verdict


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _verdict_exit_code(verdict: str) -> int:
    if verdict.startswith("fail"):
        return 1
    if verdict == "error":
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="workflow-fullness-check.py",
        description=(
            "Gap #39 mechanical gate: refuse fullness claims that lack "
            "full-workflow evidence or cheap-path acknowledgement."
        ),
    )
    parser.add_argument("draft", help="path to draft markdown")
    parser.add_argument(
        "--workspace",
        default=None,
        help=(
            "workspace path (defaults to draft's nearest ancestor with "
            ".auditooor/)"
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="reserved; the gate is already fail-closed on phrase hits.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit JSON verdict instead of human-readable text",
    )
    args = parser.parse_args(argv)

    draft_path = Path(args.draft).expanduser()
    workspace: Path | None = None
    if args.workspace:
        workspace = Path(args.workspace).expanduser()
    else:
        # Walk up from draft_path to find a .auditooor/ ancestor.
        cur = draft_path.resolve().parent if draft_path.exists() else None
        while cur is not None:
            if (cur / ".auditooor").is_dir():
                workspace = cur
                break
            if cur == cur.parent:
                break
            cur = cur.parent

    v = evaluate(draft_path, workspace=workspace, strict=args.strict)

    if args.json:
        print(json.dumps(v.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"verdict: {v.verdict}")
        print(f"reason: {v.reason}")
        if v.draft.fullness_phrases_hit:
            print("fullness phrases hit:")
            for p in v.draft.fullness_phrases_hit:
                print(f"  - {p}")
        if v.workflow.log_exists:
            print(
                f"workflow log: {v.workflow.log_path} "
                f"(engines_seen={len(v.workflow.engines_seen)}, "
                f"engines_success={len(v.workflow.engines_success)}, "
                f"missing={len(v.workflow.missing_engines)})"
            )
        else:
            print(f"workflow log: {v.workflow.log_path} (NOT FOUND)")
        if v.workflow.missing_engines:
            print("missing engines:")
            for eng in v.workflow.missing_engines:
                print(f"  - {eng}")
        if v.draft.rebuttal is not None:
            if v.draft.rebuttal_oversized:
                print(
                    "gap39-rebuttal: OVERSIZED "
                    f"({len(v.draft.rebuttal)} > {REBUTTAL_MAX_CHARS} chars) "
                    "- ignored"
                )
            else:
                print(f"gap39-rebuttal: {v.draft.rebuttal}")
    return _verdict_exit_code(v.verdict)


if __name__ == "__main__":
    sys.exit(main())
