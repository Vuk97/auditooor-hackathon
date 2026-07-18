#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FEAT-README-ATTESTATION-GATE registered in .auditooor/agent_pathspec.json -->
"""readme-attestation-check.py - forced per-step README attestation gate.

The standing failure mode: an agent declares a workspace audited without ever
reading the canonical runbook, so a step "runs" by side effect (an artifact
happens to exist) while the agent never internalised what that step is FOR or
how to verify it is genuinely done. readme-conformance-check.py already gates on
the *artifacts* and a thin JSON attestation; this gate goes further and forces
the agent to write back a FAITHFUL VERBATIM quote of each executed step's
canonical ``what_must_be_done`` + ``how_to_verify_done`` text. A paraphrase that
does not match the canonical manifest FAILS - so a green here is evidence the
agent actually read the runbook, not just that an artifact landed on disk.

DESIGN (mirrors the codified-rules rebuttal pattern + the existing conformance
"step-ran" signal):

  * STEP-RAN SIGNAL (reused, NOT reinvented): a step "executed" iff
    readme-conformance-check._evaluate_step returns status == "done" for it -
    i.e. all its artifact_checks pass and any required thin attestation exists.
    We do NOT invent a new notion of "ran"; we layer the verbatim-quote
    requirement on top of the SAME signal the conformance gate already uses.
    (A "waived" / "n/a-for-language" / "red" step did NOT execute for our
    purposes, so it needs NO verbatim attestation - this is what keeps the gate
    BOUNDED: a fresh workspace with zero executed steps never false-fails.)

  * VERBATIM ATTESTATION: for every executed step there must be a row in
    <ws>/.auditooor/readme_step_attestations.jsonl whose
    ``attested_what_must_be_done`` and ``attested_how_to_verify_done`` each
    NORMALIZE-MATCH (whitespace+case normalized; >= 0.95 similarity ratio OR a
    canonical-substring containment) the canonical text from
    tools/readme_runbook_steps.json. Missing row OR paraphrase-mismatch ->
    failure for that step.

  * WAIVER (never weaken silently): if
    <ws>/.auditooor/readme_attestation_rebuttal.md exists with a non-empty
    reason, the verify is DOWNGRADED to warn (rc 0) and the waiver text is
    printed - exactly the codified-rules ``<rule>-rebuttal`` escape hatch.

MODES:
  --verify  --ws <ws>            (default) gate every executed step. rc 1 if any
                                 executed step lacks a faithful verbatim
                                 attestation (unless waived).
  --attest  --ws <ws> --step <id> --what <text> --how <text>
                                 append a faithful attestation row. The agent
                                 MUST supply the quoted text it read for that
                                 step via --what / --how (or --what-file /
                                 --how-file). The writer VALIDATES that the
                                 supplied text faithfully reproduces the canonical
                                 manifest text and REFUSES to write otherwise - it
                                 never auto-copies the canonical text on the
                                 agent's behalf, so a green here is evidence the
                                 agent actually reproduced the runbook text, not
                                 that a writer copied it. (Defeats the "attest
                                 without reading" bypass.)

Exit codes: 0 = all executed steps attested (or waived, or none executed);
            1 = an executed step lacks a faithful verbatim attestation;
            2 = usage / workspace / manifest error.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
_MANIFEST_REL = Path("tools") / "readme_runbook_steps.json"
_ATTEST_REL = Path(".auditooor") / "readme_step_attestations.jsonl"
_WAIVER_REL = Path(".auditooor") / "readme_attestation_rebuttal.md"
_SCHEMA = "auditooor.readme_step_attestation.v1"
_MATCH_RATIO = 0.95


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def _load_json(p: Path) -> Any:
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _manifest_path(explicit: str | None) -> Path:
    return Path(explicit) if explicit else (_REPO_ROOT / _MANIFEST_REL)


def _load_manifest(explicit: str | None) -> dict | None:
    m = _load_json(_manifest_path(explicit))
    if isinstance(m, dict) and isinstance(m.get("steps"), list):
        return m
    return None


def _canonical_step(manifest: dict, step_id: str) -> dict | None:
    for s in manifest.get("steps", []):
        if s.get("step_id") == step_id:
            return s
    return None


def _canonical_how_to_verify_text(step: dict) -> str:
    """Render the canonical how_to_verify_done block to a stable text form.

    how_to_verify_done is structured JSON (artifact_checks + flags), so we
    serialise it deterministically (sorted keys) so an attestation can quote it
    verbatim and the match is reproducible. The agent attests the canonical
    rendering, which forces it to look at the actual verification spec.
    """
    how = step.get("how_to_verify_done", {})
    return json.dumps(how, sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Normalisation + match
# ---------------------------------------------------------------------------

def _normalize(text: str) -> str:
    """Whitespace + case normalised form for tolerant verbatim matching."""
    return re.sub(r"\s+", " ", str(text or "")).strip().lower()


def _faithful_match(attested: str, canonical: str) -> bool:
    """True iff the attested text faithfully reproduces the canonical text.

    Faithful = NORMALIZE-MATCH by either:
      (a) FULL canonical-substring containment - the attestation contains the
          WHOLE canonical text after normalisation (``nc in na``). This is the
          ONLY containment direction allowed: it lets the agent legitimately wrap
          the canonical text in surrounding quotes / prose, but it does NOT let a
          TRUNCATED quote pass. (The reverse direction ``na in nc`` is rejected
          precisely because it would let a short substring of a long canonical -
          e.g. just "Run python3" - pass as if faithful.) OR
      (b) similarity ratio >= _MATCH_RATIO (tolerates trivial whitespace/case
          drift the normaliser did not already collapse). A SequenceMatcher ratio
          is length-sensitive, so a truncated quote (much shorter than the
          canonical) scores well below the threshold and is correctly rejected.
    A reworded paraphrase AND a truncated quote both satisfy NEITHER, so they
    FAIL - which is the whole point of this gate.
    """
    na = _normalize(attested)
    nc = _normalize(canonical)
    if not nc:
        # Defensive: an empty canonical (should not happen for a real step)
        # cannot meaningfully be attested; treat as non-match so it is visible.
        return False
    if not na:
        return False
    if nc in na:  # FULL canonical present (only this direction; no truncation pass)
        return True
    return SequenceMatcher(None, na, nc).ratio() >= _MATCH_RATIO


# ---------------------------------------------------------------------------
# Reused "step-ran" signal
# ---------------------------------------------------------------------------

def _load_conformance_module():
    """Load readme-conformance-check.py as a module so we reuse its EXACT
    per-step "did it run" signal (status=='done') rather than inventing our own.
    Python 3.14: set sys.modules[name] before exec_module."""
    import importlib.util as _ilu
    p = Path(__file__).resolve().with_name("readme-conformance-check.py")
    spec = _ilu.spec_from_file_location("_rcc_attest", str(p))
    mod = _ilu.module_from_spec(spec)
    sys.modules["_rcc_attest"] = mod
    spec.loader.exec_module(mod)
    return mod


def _executed_step_ids(ws: Path, manifest_path: str | None) -> tuple[set[str], dict]:
    """Return (set_of_executed_step_ids, raw_conformance_result).

    A step is "executed" iff readme-conformance-check reports it status=='done'.
    That status is True exactly when the step's artifact_checks pass and its thin
    attestation (if required) exists - i.e. the step genuinely ran and produced
    its artifacts. We do NOT add a separate notion of execution. waived / red /
    n/a-for-language steps are NOT counted as executed, which bounds the gate so
    a fresh workspace (no executed steps) never false-fails.
    """
    mod = _load_conformance_module()
    mpath = Path(manifest_path) if manifest_path else None
    conf = mod.evaluate(ws, manifest_path=mpath)
    executed: set[str] = set()
    for sr in conf.get("steps", []):
        if sr.get("status") == "done":
            executed.add(sr["step_id"])
    return executed, conf


# ---------------------------------------------------------------------------
# Attestation store
# ---------------------------------------------------------------------------

def _read_attestations(ws: Path) -> dict[str, dict]:
    """Return {step_id: latest_attestation_row} from the jsonl store.

    Later rows for the same step_id override earlier ones (append-only writer,
    last write wins) so re-attesting after a manifest text change is honoured.
    """
    p = ws / _ATTEST_REL
    out: dict[str, dict] = {}
    try:
        txt = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in txt.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict) and obj.get("step_id"):
            out[str(obj["step_id"])] = obj
    return out


def _waiver_reason(ws: Path) -> str | None:
    """Return the non-empty waiver reason from readme_attestation_rebuttal.md, or
    None. An empty/whitespace-only file is treated as ABSENT (no free pass)."""
    p = ws / _WAIVER_REL
    try:
        txt = p.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    return txt or None


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

def verify(ws: Path, manifest_path: str | None = None) -> dict:
    """Gate result. attestation_pass=True iff every executed step has a faithful
    verbatim attestation (or the gate is waived, or no step executed)."""
    ws = ws.resolve()
    result: dict[str, Any] = {
        "tool": "readme-attestation-check",
        "workspace": str(ws),
        "checked_at": int(time.time()),
        "attestation_pass": False,
        "executed_step_ids": [],
        "failing_step_ids": [],
        "per_step": [],
        "waived": False,
        "waiver_reason": None,
    }
    if not ws.is_dir():
        result["error"] = f"workspace not found: {ws}"
        return result

    manifest = _load_manifest(manifest_path)
    if manifest is None:
        result["error"] = f"manifest not found or invalid: {_manifest_path(manifest_path)}"
        return result

    executed, _conf = _executed_step_ids(ws, manifest_path)
    result["executed_step_ids"] = sorted(executed)

    attestations = _read_attestations(ws)
    failing: list[str] = []

    for step_id in sorted(executed):
        step = _canonical_step(manifest, step_id)
        if step is None:
            # An executed step with no manifest entry cannot be attested against
            # a canonical text; record it but do NOT fail-closed on a manifest
            # gap (the conformance gate owns manifest membership).
            result["per_step"].append({
                "step_id": step_id, "status": "no-manifest-entry", "detail": "skipped",
            })
            continue
        canon_what = str(step.get("what_must_be_done", ""))
        canon_how = _canonical_how_to_verify_text(step)
        row = attestations.get(step_id)
        if row is None:
            result["per_step"].append({
                "step_id": step_id, "status": "missing",
                "detail": "executed step has NO attestation row",
            })
            failing.append(step_id)
            continue
        att_what = str(row.get("attested_what_must_be_done", ""))
        att_how = str(row.get("attested_how_to_verify_done", ""))
        what_ok = _faithful_match(att_what, canon_what)
        how_ok = _faithful_match(att_how, canon_how)
        if what_ok and how_ok:
            result["per_step"].append({"step_id": step_id, "status": "faithful"})
        else:
            bad = []
            if not what_ok:
                bad.append("what_must_be_done")
            if not how_ok:
                bad.append("how_to_verify_done")
            result["per_step"].append({
                "step_id": step_id, "status": "paraphrase-mismatch",
                "detail": "non-verbatim field(s): " + ", ".join(bad),
            })
            failing.append(step_id)

    result["failing_step_ids"] = failing

    if not failing:
        result["attestation_pass"] = True
        result["verdict"] = "pass-readme-attestation"
        return result

    # Failing steps exist - check for a waiver (downgrade to warn).
    waiver = _waiver_reason(ws)
    if waiver:
        result["waived"] = True
        result["waiver_reason"] = waiver
        result["attestation_pass"] = True  # downgraded to warn
        result["verdict"] = "warn-readme-attestation-waived"
        return result

    result["attestation_pass"] = False
    result["verdict"] = "fail-readme-attestation-missing"
    return result


# ---------------------------------------------------------------------------
# Attest (per-step writer)
# ---------------------------------------------------------------------------

class AttestationError(Exception):
    """Raised when --attest is called without faithful agent-supplied text."""


def attest(
    ws: Path,
    step_id: str,
    attested_what: str | None,
    attested_how: str | None,
    manifest_path: str | None = None,
    extra: dict | None = None,
) -> dict:
    """Append a faithful attestation row for step_id using AGENT-SUPPLIED text.

    The agent MUST pass the text it read for this step (``attested_what`` +
    ``attested_how``). The writer does NOT auto-copy the canonical manifest text -
    that would let an agent "attest" a step it never read, defeating the whole
    gate. Instead it VALIDATES the supplied text against the canonical manifest
    text using the SAME ``_faithful_match`` the verifier uses, and REFUSES
    (AttestationError) to write a missing/paraphrased/truncated quote. A row only
    lands on disk when it would already pass --verify, so the writer cannot
    manufacture a green the verifier would not also grant on the agent's own text.

    The caller may add/overwrite a timestamp; we leave `ts` unset (the row
    carries `ts_unset: true`) so a wrapping loop can stamp it deterministically,
    per the brief. Returns the written row."""
    ws = ws.resolve()
    manifest = _load_manifest(manifest_path)
    if manifest is None:
        raise AttestationError(
            f"manifest not found or invalid: {_manifest_path(manifest_path)}"
        )
    step = _canonical_step(manifest, step_id)
    if step is None:
        raise AttestationError(f"unknown step_id: {step_id} (not in manifest)")

    if attested_what is None or attested_how is None:
        raise AttestationError(
            "refusing to attest: --attest requires the agent-supplied quoted text "
            "via --what/--what-file AND --how/--how-file. The writer does NOT "
            "auto-copy the canonical runbook text - you must reproduce it yourself "
            "(that reproduction IS the proof you read the step). Read the canonical "
            f"text for step '{step_id}' in {_manifest_path(manifest_path)} and pass "
            "it verbatim."
        )

    canon_what = str(step.get("what_must_be_done", ""))
    canon_how = _canonical_how_to_verify_text(step)
    what_ok = _faithful_match(attested_what, canon_what)
    how_ok = _faithful_match(attested_how, canon_how)
    if not (what_ok and how_ok):
        bad = []
        if not what_ok:
            bad.append("--what (what_must_be_done)")
        if not how_ok:
            bad.append("--how (how_to_verify_done)")
        raise AttestationError(
            "refusing to attest: supplied text is not a faithful verbatim "
            "reproduction of the canonical manifest text for non-verbatim field(s): "
            + ", ".join(bad)
            + ". A paraphrase or a truncated quote is rejected here exactly as it "
            "would be by --verify. Re-read the canonical step text and pass it "
            "verbatim."
        )

    row = {
        "schema": _SCHEMA,
        "step_id": step_id,
        "attested_what_must_be_done": str(attested_what),
        "attested_how_to_verify_done": str(attested_how),
        "ts_unset": True,
    }
    if extra:
        row.update(extra)
    apath = ws / _ATTEST_REL
    apath.parent.mkdir(parents=True, exist_ok=True)
    with apath.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return row


def _is_mechanical(step: dict) -> bool:
    """A step is MECHANICAL (self-proving) when its class contains 'mechanical'
    and NOT 'manual'. Such a step lands in executed_step_ids ONLY when its
    artifact_checks pass (the artifact on disk IS the proof it ran), so an
    auto-attestation is sound and unfakeable. manual / manual-judgment steps
    (0b/0c/0d/0e SCOPE/SEVERITY/clone/toolchain, 2c >=1M fuzz, 4b economic
    invariants) are NOT mechanical - they require an explicit agent read, so the
    anti-bypass design is preserved for the steps that actually need judgment."""
    cls = str(step.get("class", "")).lower()
    return "mechanical" in cls and "manual" not in cls


def attest_executed_mechanical(ws: Path, manifest_path: str | None = None) -> dict:
    """Auto-record an attestation row for every EXECUTED mechanical step.

    Closes the Theme-C done-blocker (capability-wiring audit 2026-06-30): the
    README per-step attestation gate fail-closes audit-done-guard, but `--attest`
    was manual-only, so every autonomously-run workspace sat at
    fail-readme-attestation-missing forever. For MECHANICAL steps there is nothing
    for a human to judge - the verify-artifact presence (which is exactly what puts
    the step in executed_step_ids) is the proof. So we auto-attest those, quoting
    the canonical what/how text (the same text --verify checks), and tag the row
    `auto_attested_mechanical: true` for audit transparency. Manual-judgment steps
    are SKIPPED - the operator/agent still attests those explicitly. Idempotent:
    an already-attested step is left alone; an un-executed step is never attested
    (no artifact -> not executed -> not attested)."""
    ws = ws.resolve()
    out = {"verdict": "ok", "attested": [], "skipped_manual": [],
           "already": [], "errors": []}
    manifest = _load_manifest(manifest_path)
    if manifest is None:
        out["verdict"] = "no-manifest"
        return out
    executed, _conf = _executed_step_ids(ws, manifest_path)
    existing = _read_attestations(ws)
    for step_id in sorted(executed):
        step = _canonical_step(manifest, step_id)
        if step is None:
            continue
        if not _is_mechanical(step):
            out["skipped_manual"].append(step_id)
            continue
        if step_id in existing:
            out["already"].append(step_id)
            continue
        try:
            attest(ws, step_id,
                   str(step.get("what_must_be_done", "")),
                   _canonical_how_to_verify_text(step),
                   manifest_path=manifest_path,
                   extra={"auto_attested_mechanical": True})
            out["attested"].append(step_id)
        except AttestationError as e:
            out["errors"].append({"step": step_id, "error": str(e)})
    if out["errors"]:
        out["verdict"] = "partial"
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_human(result: dict) -> None:
    ws = result.get("workspace", "?")
    print(f"readme-attestation-check  workspace: {ws}")
    if result.get("error"):
        print(f"ERROR: {result['error']}")
        return
    print(f"executed steps: {result.get('executed_step_ids', [])}")
    for sr in result.get("per_step", []):
        mark = "OK " if sr["status"] == "faithful" else "!! "
        detail = f"  {sr.get('detail')}" if sr.get("detail") else ""
        print(f"  {mark}{sr['step_id']:10s} {sr['status']}{detail}")
    print()
    if result.get("waived"):
        print(f"WAIVED via {_WAIVER_REL}: {result.get('waiver_reason')}")
    print(result.get("verdict", "(no verdict)"))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--verify", action="store_true", help="(default) gate executed steps")
    ap.add_argument("--attest", action="store_true", help="append a faithful attestation row")
    ap.add_argument("--attest-executed-mechanical", dest="attest_mechanical",
                    action="store_true",
                    help="auto-attest every EXECUTED mechanical step from its canonical "
                         "text + verify-artifact (manual-judgment steps still need explicit "
                         "--attest). Closes the autonomous-loop done-blocker.")
    ap.add_argument("--ws", "--workspace", dest="ws", required=True)
    ap.add_argument("--step", help="step_id (required with --attest)")
    ap.add_argument("--what", default=None,
                    help="(with --attest) the verbatim what_must_be_done text you read")
    ap.add_argument("--how", default=None,
                    help="(with --attest) the verbatim how_to_verify_done text you read")
    ap.add_argument("--what-file", dest="what_file", default=None,
                    help="(with --attest) read --what text from this file")
    ap.add_argument("--how-file", dest="how_file", default=None,
                    help="(with --attest) read --how text from this file")
    ap.add_argument("--manifest", default=None, help="path to readme_runbook_steps.json")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    ws = Path(os.path.expanduser(args.ws)).resolve()

    if args.attest_mechanical:
        if not ws.is_dir():
            print(f"ERROR: workspace not found: {ws}", file=sys.stderr)
            return 2
        res = attest_executed_mechanical(ws, manifest_path=args.manifest)
        if args.json:
            print(json.dumps(res, indent=2, sort_keys=True))
        else:
            print(f"[attest-mechanical] {res['verdict']}: attested {res['attested']}, "
                  f"already {res['already']}, skipped-manual {res['skipped_manual']}")
            for e in res.get("errors", []):
                print(f"  !! {e['step']}: {e['error'][:120]}")
        return 0 if res["verdict"] in ("ok", "no-manifest") else 1

    if args.attest:
        if not args.step:
            print("ERROR: --attest requires --step <id>", file=sys.stderr)
            return 2
        if not ws.is_dir():
            print(f"ERROR: workspace not found: {ws}", file=sys.stderr)
            return 2

        # Resolve the agent-supplied text. --what/--how take precedence; the
        # *-file variants are a convenience for long/multiline canonical text.
        # We do NOT default-fill from the manifest: the agent MUST reproduce the
        # text, and the writer validates that reproduction (concern (5) fix).
        att_what = args.what
        if att_what is None and args.what_file:
            try:
                att_what = Path(os.path.expanduser(args.what_file)).read_text(
                    encoding="utf-8", errors="replace")
            except OSError as exc:
                print(f"ERROR: cannot read --what-file: {exc}", file=sys.stderr)
                return 2
        att_how = args.how
        if att_how is None and args.how_file:
            try:
                att_how = Path(os.path.expanduser(args.how_file)).read_text(
                    encoding="utf-8", errors="replace")
            except OSError as exc:
                print(f"ERROR: cannot read --how-file: {exc}", file=sys.stderr)
                return 2

        try:
            row = attest(ws, args.step, att_what, att_how, manifest_path=args.manifest)
        except AttestationError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(row, indent=2, ensure_ascii=False))
        else:
            print(f"attested {args.step} -> {ws / _ATTEST_REL}")
        return 0

    # default: verify
    result = verify(ws, manifest_path=args.manifest)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        _print_human(result)
    if not ws.is_dir():
        return 2
    if result.get("error"):
        return 2
    return 0 if result.get("attestation_pass") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
