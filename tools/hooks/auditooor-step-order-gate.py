#!/usr/bin/env python3
"""PreToolUse hook (Bash): block running a canonical README audit step OUT OF ORDER.

The README runbook is strictly ordered (step-1 -> 1c -> 2 -> 2c -> 3 -> 4 -> 4b -> 5).
``readme-step-integrity.py`` (wired into ``audit-done-guard``, wired into the Stop
hook) already catches a SKIPPED/DEGRADED step - but only at the DONE boundary, at the
end of a turn. Nothing stopped a tick from executing a LATER work-step before an
EARLIER step's verify-artifact exists (e.g. ``make audit-depth`` (step-4 depth cert)
before any step-3 hunt sidecars exist). It self-corrects eventually (the later
artifact won't validate), but the work is wasted and the failure is opaque.

This hook makes step-ORDER mechanical at EXECUTION time: when a Bash command invokes a
gated work-step's make-target for an audit workspace, it asserts that the step's
required PRIOR-step artifacts exist on disk. If a prerequisite is entirely absent, the
call is DENIED with the missing step's README ``what_must_be_done`` quoted, so the
operator/loop runs the steps in order.

DATA-DRIVEN (2026-07-02, generic/all-language/all-workspace):
- The gated (step -> immediate-required-predecessor) map is DERIVED from
  ``readme_runbook_steps.json`` ORDERING, not a hardcoded 2-entry list. Each gated
  work-step maps to its immediate PRIOR ``required`` step(s) that declare an on-disk
  verify-artifact. So step-2 requires step-1c+step-1, step-2c requires step-2, step-4b
  requires step-4, etc. - a NEW manifest step is auto-covered without editing this hook.
- Only steps with a known, unambiguous PRIMARY driver make-target are candidates; that
  mapping (``_STEP_DRIVER_TARGET``) is intentionally curated (the README ``what_must_be_done``
  free-text mentions several helper targets per step - ``make audit-prep`` under step-1,
  ``make mimo-corpus-mine`` under step-3 - and scraping it would over-gate). Adding a
  driver target here is the only manual touch; the PREREQ set for it is manifest-derived.

Deliberately CONSERVATIVE (no false-positives, no wedging):
- ``audit-complete`` / ``audit-run-full`` are NEVER gated - they are the status-tellers
  that REPORT which gates are red; blocking them would hide the very gaps the operator
  needs to see (and contradicts done-discipline: a failing audit-complete is work, run it).
  The manifest's terminal step (step-5, ``make audit-complete``) is therefore excluded from
  driver-target gating by construction.
- A prereq counts as satisfied if ANY of its artifacts exist (file present, or dir
  non-empty). "Present-but-degraded" is left to step-integrity at done-time; this hook
  only blocks a GROSS skip (prereq wholly absent). A prereq step that declares NO on-disk
  artifact is skipped as a gate (it can't be the thing that was grossly skipped).
- ADVISORY-FIRST for any newly-covered transition: by default this hook only HARD-DENIES
  the two historically-gated transitions (hunt-scoped/step-3, audit-depth/step-4) so it
  can never retroactively brick a prior audit's tick. Set AUDITOOOR_STEP_ORDER_STRICT=1 to
  hard-deny EVERY manifest-derived transition (the newer ones warn on stderr otherwise).
- Override: AUDITOOOR_STEP_ORDER_OK=1 (audit-logged). Fails OPEN on any parse error or
  missing runbook (never wedges a non-audit session).

Decision protocol (Claude Code PreToolUse): print JSON
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":...}}
to block; exit 0 silently to allow.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

# Primary driver make-target -> canonical step_id, for the work-steps whose out-of-order
# execution wastes real work. This is the ONLY curated join (README free-text mentions
# several helper targets per step, so it can't be scraped safely). audit-complete /
# audit-run-full are intentionally ABSENT - status-tellers are never gated. The PREREQ
# set for each of these is derived from the manifest ordering below, not hardcoded.
_STEP_DRIVER_TARGET = {
    "make audit-deep": "step-2",
    "make hunt-scoped": "step-3",
    "make audit-depth": "step-4",
}

# Transitions that this hook HARD-DENIES by default (backward-compatible with the prior
# 2-entry behavior). Every OTHER manifest-derived transition is ADVISORY (warns on
# stderr, allows) unless AUDITOOOR_STEP_ORDER_STRICT=1 is set. This keeps a NEW manifest
# step / newly-covered driver from retroactively bricking a prior audit's tick.
_DEFAULT_HARD_DENY_STEPS = {"step-3", "step-4"}

_WS_RE = re.compile(r"\bWS\s*=\s*([^\s;|&]+)")
_RUNBOOK = Path(__file__).resolve().parents[1] / "readme_runbook_steps.json"

# Match a driver target as an actual make invocation, e.g. `make audit-depth`.
_TARGET_RES = {
    tgt: re.compile(r"\bmake\s+" + re.escape(tgt.split(None, 1)[1]) + r"\b")
    for tgt in _STEP_DRIVER_TARGET
}

# Commands that CARRY text (a make-target named inside a commit message / echo / doc
# string is a mention, not an invocation). If the command's lead verb is one of these,
# do not gate - we would otherwise trip on `git commit -m "...make audit-depth..."`.
_MESSAGE_VERBS = re.compile(
    r"^\s*(git\s+commit|git\s+tag|echo|printf|cat|grep|sed|awk|less|head|tail|"
    r"python3?\s+-c|jq)\b")
# Heredoc body: everything from `<<['\"]?TAG` to a line that is just TAG. Stripping it
# removes embedded message/script text that merely MENTIONS a make-target.
_HEREDOC = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?\n.*?^\s*\1\b", re.DOTALL | re.MULTILINE)


def _strip_noninvocation(cmd: str) -> str:
    """Remove heredoc bodies so a make-target mentioned in a commit message / doc
    text is not mistaken for an invocation."""
    return _HEREDOC.sub("", cmd)


def _load_ordered_steps() -> list[dict]:
    """Return the manifest steps as an ordered list of dicts (canonical run order).

    Preserves the on-disk array order; that ORDER is the source of truth for
    'immediate required predecessor'."""
    try:
        d = json.loads(_RUNBOOK.read_text(encoding="utf-8"))
    except Exception:
        return []
    steps = d.get("steps") if isinstance(d, dict) else d
    if isinstance(steps, dict):
        # dict form: values in insertion order (py3.7+ preserves it)
        steps = list(steps.values())
    out = []
    for x in steps or []:
        if isinstance(x, dict) and (x.get("step_id") or x.get("id")):
            out.append(x)
    return out


def _sid(step: dict) -> str:
    return step.get("step_id") or step.get("id") or ""


def _artifact_paths(step: dict) -> list[str]:
    hvd = step.get("how_to_verify_done") or {}
    paths: list[str] = []
    if isinstance(hvd, dict):
        for c in hvd.get("artifact_checks", []) or []:
            if not isinstance(c, dict):
                continue
            if c.get("path"):
                paths.append(str(c["path"]))
            for p in c.get("paths", []) or []:
                paths.append(str(p))
    return paths


def _immediate_required_predecessors(steps: list[dict], target_sid: str) -> list[dict]:
    """The immediate required-predecessor step of ``target_sid`` in manifest order.

    Walk backwards from the target step and return the FIRST step that is a real on-disk
    anchor: ``required``, artifact-bearing, and NOT language-filtered. Everything else is
    transparent and skipped:
      - non-``required`` (advisory) steps carry no ordering obligation;
      - required steps with NO on-disk artifact (manual attestation-only) cannot be the
        thing that was grossly skipped on disk;
      - LANGUAGE-FILTERED steps (e.g. solidity-only step-1c/step-2c) are skipped because
        this hook cannot know the workspace language and must never wedge a non-matching
        workspace by demanding a language-specific artifact.

    This yields, from the current manifest:
      step-2  -> [step-1]     (skips solidity-only step-1c and advisory step-1b)
      step-2c -> [step-2]
      step-3  -> [step-2]     (skips solidity/evm-only step-2c) - matches the historical
                               hunt-scoped requires step-2 gate exactly
      step-4  -> [step-3]     - matches the historical audit-depth requires step-3 gate
      step-4b -> [step-4]
    A NEW manifest step is covered automatically by the same single-anchor walk. Returning
    the SINGLE nearest anchor (not the whole contiguous run) keeps the gate GROSS-skip-only
    and backward-compatible: it never demands more prior artifacts than the prior hardcoded
    pair did."""
    idx = next((i for i, s in enumerate(steps) if _sid(s) == target_sid), None)
    if idx is None:
        return []
    for j in range(idx - 1, -1, -1):
        s = steps[j]
        if not s.get("required"):
            continue
        if s.get("language_filter"):
            continue
        if not _artifact_paths(s):
            continue
        return [s]
    return []


def _present(ws: Path, rel: str) -> bool:
    """True iff the artifact exists: a non-empty file, or a non-empty directory."""
    p = (ws / rel) if not os.path.isabs(rel) else Path(rel)
    if p.is_dir():
        try:
            return any(p.iterdir())
        except OSError:
            return False
    if p.is_file():
        try:
            return p.stat().st_size > 0
        except OSError:
            return False
    return False


def _prereq_satisfied(ws: Path, step: dict) -> bool:
    """A prereq step is satisfied if ANY of its verify-artifacts is present.

    A step that declares NO artifacts (manual/judgment step) is treated as satisfied -
    it carries no on-disk gate, so it can't be the thing that was skipped."""
    paths = _artifact_paths(step)
    if not paths:
        return True
    return any(_present(ws, rel) for rel in paths)


def main() -> int:
    if os.environ.get("AUDITOOOR_STEP_ORDER_OK") == "1":
        return 0
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    if payload.get("tool_name") != "Bash":
        return 0
    cmd = (payload.get("tool_input") or {}).get("command") or ""
    if not cmd or "make " not in cmd:
        return 0
    if _MESSAGE_VERBS.match(cmd):
        return 0  # message/doc-bearing command; a named target is a mention, not a run
    cmd = _strip_noninvocation(cmd)
    if "make " not in cmd:
        return 0

    # Which gated driver target (if any) does this command invoke?
    hit = next(
        ((tgt, _STEP_DRIVER_TARGET[tgt]) for tgt, rx in _TARGET_RES.items() if rx.search(cmd)),
        None,
    )
    if not hit:
        return 0
    _target, step_id = hit

    m = _WS_RE.search(cmd)
    if not m:
        return 0  # no explicit workspace -> can't reason about artifacts; allow
    ws = Path(m.group(1)).expanduser()
    if not ws.is_dir():
        return 0

    steps = _load_ordered_steps()
    if not steps:
        return 0  # runbook unreadable -> fail open

    prereq_steps = _immediate_required_predecessors(steps, step_id)
    if not prereq_steps:
        return 0  # no artifact-bearing required predecessor -> nothing to gate

    missing = []
    for st in prereq_steps:
        if not _prereq_satisfied(ws, st):
            wmb = str(st.get("what_must_be_done", "")).strip()
            wmb = re.sub(r"\s+", " ", wmb)[:200]
            missing.append((_sid(st), wmb, _artifact_paths(st)))

    if not missing:
        return 0

    # ADVISORY-FIRST: only the historically-gated transitions hard-deny by default. Any
    # newly manifest-covered transition warns (allow) unless STRICT is set, so this hook
    # can never retroactively brick a prior audit's in-order tick.
    hard_deny = (
        step_id in _DEFAULT_HARD_DENY_STEPS
        or os.environ.get("AUDITOOOR_STEP_ORDER_STRICT") == "1"
    )

    lines = [
        f"STEP-ORDER VIOLATION: `{step_id}` ({cmd.split('make', 1)[1].strip().split()[0]}) "
        f"requires a prior step whose verify-artifact is absent in {ws}:",
    ]
    for pid, wmb, paths in missing:
        lines.append(f"  - {pid} NOT done. Required artifact(s) absent: {paths}")
        if wmb:
            lines.append(f"    README {pid}: {wmb}")
    lines.append(
        "Run the missing step IN ORDER first. If this is intentional "
        "(e.g. re-running with an external artifact), set AUDITOOOR_STEP_ORDER_OK=1."
    )
    reason = "\n".join(lines)

    if not hard_deny:
        # Advisory: warn to stderr, allow the call (exit 0, no deny JSON).
        sys.stderr.write(
            "[step-order-gate ADVISORY] " + reason
            + "\n(advisory-only; set AUDITOOOR_STEP_ORDER_STRICT=1 to hard-deny)\n"
        )
        return 0

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
