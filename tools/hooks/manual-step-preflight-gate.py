#!/usr/bin/env python3
"""PreToolUse hook: block WRITING a manual-step attestation that was not preceded
by a full-text read-ack (and, for Write, that is not grounded).

This is the automatic, non-bypassable TRIGGER for the manual-step-preflight ENGINE
(tools/manual-step-preflight.py). Mechanical steps have hard gates; manual steps had
only a post-hoc presence check. This hook fires the moment the agent tries to Write
`.auditooor/attestations/step-<id>.json` for a MANUAL attest-required step and denies
it unless:
  (1) a preflight read-ack marker exists whose step_text_sha == the CURRENT step text
      (i.e. `manual-step-preflight.py render` was run this cycle - forces reading the
      WHOLE step, and re-forces it when the README step drifts), AND
  (2) (Write only, when the content parses as JSON) the attestation carries
      read_ack == that sha and >=1 evidence_ref that exists under the workspace.

Precondition (1) used to require a SEPARATE prior manual CLI invocation of `render`;
in practice nobody ran it, so the hook either blanket-denied every manual attestation
or got disabled outright. Now, the FIRST time this hook sees an attestation write with
no current marker, it self-heals by calling the engine's `auto_render_if_missing()`
inline (same marker content `render()` would have written) and re-checks, instead of
denying forever. This only removes the "you must have separately run render" friction
- it does NOT relax precondition (2): the attestation content still must independently
carry a matching read_ack and >=1 real evidence_ref. Set
AUDITOOOR_MANUAL_STEP_AUTORENDER=0 to disable the self-heal and restore the old
blanket-deny-until-manually-rendered behavior (e.g. to reproduce a prior audit's exact
enforcement posture).

I/O: PreToolUse hook contract. Reads the tool-call JSON on stdin; emits
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
"permissionDecisionReason":...}} to block, or exits 0 silently to allow.

FAIL-OPEN on any error / unknown shape: an enforcement hook must never brick an
unrelated tool call. Only a clearly-manual attestation write with a missing/stale
read-ack is denied.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from pathlib import Path

_ENGINE = Path(__file__).resolve().parent.parent / "manual-step-preflight.py"
_ATT_RE = re.compile(r"(?P<ws>.*)/\.auditooor/attestations/(?P<step>step-[0-9a-z]+)\.json$")


def _load_engine():
    spec = importlib.util.spec_from_file_location("_msp_engine", _ENGINE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _deny(reason: str) -> None:
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason}}))
    sys.exit(0)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0  # unparseable -> allow
    tool = payload.get("tool_name") or payload.get("tool") or ""
    if tool not in ("Write", "Edit"):
        return 0
    ti = payload.get("tool_input") or payload.get("input") or {}
    fp = str(ti.get("file_path") or ti.get("path") or "")
    m = _ATT_RE.search(fp.replace("\\", "/"))
    if not m:
        return 0  # not an attestation write
    ws = Path(m.group("ws"))
    step_id = m.group("step")

    try:
        eng = _load_engine()
        manifest = eng._load_manifest(None)
        if not manifest:
            return 0
        step = eng._canonical_step(manifest, step_id)
        # only enforce for MANUAL attest-required steps
        if not step or not (eng._is_manual(step) and eng._attest_required(step)):
            return 0
        cur_sha = eng._step_text_sha(step)
        marker = eng._load_json(eng._preflight_marker(ws, step_id))
        marker_missing_or_stale = not isinstance(marker, dict) or marker.get("step_text_sha") != cur_sha
        if marker_missing_or_stale and os.environ.get("AUDITOOOR_MANUAL_STEP_AUTORENDER", "1") != "0":
            # Self-heal: produce the same read-ack marker `render` would have
            # written, so a human/agent forgetting to run render as a SEPARATE
            # step doesn't blanket-deny forever. This does NOT weaken grounding:
            # the attestation CONTENT (read_ack + evidence_refs) is still checked
            # below - auto-render only supplies precondition (1), never (2).
            ar = eng.auto_render_if_missing(ws, step_id, manifest)
            if ar.get("auto_rendered"):
                print(
                    f"[manual-step-preflight-gate] auto-rendered read-ack marker for "
                    f"{step_id} (no prior `render` run this cycle) - self-healed instead "
                    "of blanket-denying; content grounding is still enforced.",
                    file=sys.stderr,
                )
            marker = eng._load_json(eng._preflight_marker(ws, step_id))
            marker_missing_or_stale = not isinstance(marker, dict) or marker.get("step_text_sha") != cur_sha
        if marker_missing_or_stale:
            _deny(
                f"Manual step {step_id} attestation blocked: no current read-ack marker. "
                f"Run `python3 tools/manual-step-preflight.py render --ws {ws} --step {step_id}` "
                "FIRST (reads the whole step; re-required when the README step text drifts), "
                "then write the attestation with read_ack + evidence_refs.")
        # Write: validate the content being written is grounded
        if tool == "Write":
            content = ti.get("content")
            if isinstance(content, str) and content.strip():
                try:
                    att = json.loads(content)
                except ValueError:
                    att = None
                if isinstance(att, dict):
                    if str(att.get("read_ack") or "") != cur_sha:
                        _deny(
                            f"Manual step {step_id} attestation blocked: read_ack must equal the "
                            f"current step-text sha {cur_sha} (read the whole step via "
                            "manual-step-preflight render).")
                    ev = att.get("evidence_refs")
                    grounded = [r for r in (ev or []) if isinstance(r, str) and (ws / r).exists()]
                    if not grounded:
                        _deny(
                            f"Manual step {step_id} attestation blocked: evidence_refs must cite >=1 "
                            "artifact that exists under the workspace (no ungrounded attestation).")
    except SystemExit:
        raise
    except Exception:
        return 0  # fail-open
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        sys.exit(0)
