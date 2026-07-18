#!/usr/bin/env python3
"""manual-step-preflight - enforcement for the README runbook's MANUAL steps.

Mechanical steps have hard fail-closed gates. Manual / manual-judgment steps
(0b SCOPE.md, 0c SEVERITY.md, 0d clone+prior_audits, 0e toolchain, 2c invariant
fuzz, 4b economic invariants, ...) only had a POST-HOC attestation-presence gate:
it verified a JSON existed and that it faithfully quoted the canonical verify
spec, but it did NOT (a) force the FULL step text to be surfaced BEFORE the step
was worked, (b) re-force a read when the README step text DRIFTS, or (c) require
the attestation to be GROUNDED in artifacts that exist on disk. This tool closes
those gaps and can fan setup out to subagents.

Three actions:

  render  (default)  Print the ENTIRE what_must_be_done + how_to_verify_done +
                     drift_note for a step (no truncation - the "read the whole
                     thing" enforcement), write a preflight read-ack marker
                     binding the exact step-text hash, and print the grounded
                     attestation template. A later attestation MUST echo that
                     read_ack hash + cite >=1 evidence file that exists.

  check              For every manual attest-required step that HAS an
                     attestation, verify: a preflight marker exists whose
                     step_text_sha == the CURRENT step text (re-forces a read on
                     drift); the attestation carries read_ack == that hash; and
                     evidence_refs lists >=1 path that exists under the ws.
                     ADVISORY by default (warn, rc 0); AUDITOOOR_MANUAL_STEP_STRICT=1
                     makes ungrounded / un-read-acked / drifted attestations FAIL.
                     Legacy attestations with no read_ack are grandfathered under
                     advisory and only fail under strict (clean migration path).

  dispatch-setup     Emit a spawn-worker plan for the PARALLELIZABLE manual setup
                     steps (0d clone+prior_audits per repo; 2c/4b harness authoring)
                     so setup is fanned out instead of hand-done serially.

Generic + language-agnostic: reads only the canonical manifest + the ws
attestation store. Additive - it never rewrites an existing attestation.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
_MANIFEST_REL = "tools/readme_runbook_steps.json"
_ATTEST_DIR_REL = (".auditooor", "attestations")
_PREFLIGHT_DIR_REL = (".auditooor", "attestations", ".preflight")

# G2 (id26): named envs (advisory-first; a bare non-strict caller == byte-identical).
#   AUDITOOOR_ATTEST_SCHEMA_STRICT  -> a schema-required attestation field
#                                      missing/empty HARD-FAILS instead of WARN.
#                                      GRADUATED TO DEFAULT-ON under the L37 strict
#                                      umbrella (operator decision 2026-07-03):
#                                        explicit opt-out : {0,false,no} -> advisory
#                                        explicit opt-in  : truthy       -> hard-fail
#                                        unset (new default): hard-fail iff
#                                          AUDITOOOR_L37_STRICT is truthy (what
#                                          `make audit-complete STRICT=1` exports);
#                                          a bare non-strict / library caller with
#                                          L37 unset stays advisory (never retro-red).
#   AUDITOOOR_ATTEST_SELFHEAL       -> re-stamp a missing `attested_by` from the
#                                      run context (default value below) so a
#                                      regenerated attestation that dropped the
#                                      field is repaired in place, not silently
#                                      accepted. Off by default; never mutates.
_ENV_SCHEMA_STRICT = "AUDITOOOR_ATTEST_SCHEMA_STRICT"
_ENV_SELFHEAL = "AUDITOOOR_ATTEST_SELFHEAL"


def _schema_strict_enabled() -> bool:
    """Uniform gate predicate for AUDITOOOR_ATTEST_SCHEMA_STRICT: explicit
    {0,false,no} opts out; any other explicit value opts in; unset defaults ON
    under AUDITOOOR_L37_STRICT (advisory when L37 is unset/falsey)."""
    v = os.environ.get(_ENV_SCHEMA_STRICT, "").strip().lower()
    if v in ("0", "false", "no"):
        return False                       # explicit opt-out (escape hatch)
    if v:                                   # any other explicit value
        return True                         # explicit opt-in
    # unset -> default-ON under the L37 strict umbrella; advisory otherwise.
    return os.environ.get("AUDITOOOR_L37_STRICT", "").strip().lower() not in (
        "", "0", "false", "no")
# attestation_format.attested_by_values lists the honest values; self-heal uses
# the machine-verified one so a hand-repaired field is honestly labelled.
_SELFHEAL_ATTESTED_BY = "claude-operator-verified"


def _load_schema_helper():
    """Import the reusable attestation-schema helper from readme-conformance-check
    (hyphenated filename -> importlib). Returns the module or None. Reuses the
    SINGLE source of truth for required fields (manifest attestation_format);
    does NOT rebuild the schema constant here."""
    p = _REPO_ROOT / "tools" / "readme-conformance-check.py"
    try:
        spec = importlib.util.spec_from_file_location("_readme_conformance_check", p)
        if spec is None or spec.loader is None:
            return None
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    except (OSError, ImportError, ValueError, SyntaxError):
        return None


def _schema_missing_fields(obj: dict, step: dict, manifest: dict) -> list[str]:
    """Delegate to the shared readme-conformance-check helper; on import failure
    fall back to a local base-field check so the gate never silently no-ops."""
    helper = _load_schema_helper()
    if helper is not None and hasattr(helper, "attestation_schema_missing_fields"):
        return helper.attestation_schema_missing_fields(obj, step, manifest)
    # Fallback (import failed): mirror the manifest attestation_format base set.
    fmt = manifest.get("attestation_format") if isinstance(manifest, dict) else None
    base = (fmt or {}).get("required_fields_always") or ["completed_at", "attested_by", "summary"]
    missing = [f for f in base if not obj.get(f)]
    for f in step.get("how_to_verify_done", {}).get("attestation_fields", []) or []:
        if f not in base and obj.get(f) is None:
            missing.append(f)
    return missing

# steps whose setup is genuinely parallelizable (fan-out candidates)
_PARALLEL_SETUP = {
    "step-0d": "clone each in-scope repo at its audit pin + populate prior_audits/ (one worker per repo)",
    "step-2c": "author one Chimera/Recon invariant harness per value-moving core contract (one worker per contract)",
    "step-4b": "author protocol-specific economic bool invariants (one worker per invariant cluster)",
}


def _load_json(p: Path) -> Any:
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _load_manifest(explicit: str | None) -> dict | None:
    m = _load_json(Path(explicit) if explicit else (_REPO_ROOT / _MANIFEST_REL))
    if isinstance(m, dict) and isinstance(m.get("steps"), list):
        return m
    return None


def _canonical_step(manifest: dict, step_id: str) -> dict | None:
    for s in manifest.get("steps", []):
        if s.get("step_id") == step_id:
            return s
    return None


def _step_text(step: dict) -> str:
    """The canonical, drift-sensitive text of a step: what must be done + the
    deterministically-serialised verification spec + drift note."""
    parts = [
        str(step.get("what_must_be_done") or ""),
        json.dumps(step.get("how_to_verify_done", {}), sort_keys=True, ensure_ascii=False),
        str(step.get("drift_note") or ""),
    ]
    return "\n".join(parts)


def _step_text_sha(step: dict) -> str:
    return hashlib.sha256(_step_text(step).encode("utf-8")).hexdigest()[:16]


def _attest_required(step: dict) -> bool:
    how = step.get("how_to_verify_done", {})
    return bool(isinstance(how, dict) and how.get("attestation_required"))


def _is_manual(step: dict) -> bool:
    return "manual" in str(step.get("class") or "").lower()


def _manual_attest_steps(manifest: dict) -> list[dict]:
    return [s for s in manifest.get("steps", [])
            if _is_manual(s) and _attest_required(s)]


def _preflight_marker(ws: Path, step_id: str) -> Path:
    return ws.joinpath(*_PREFLIGHT_DIR_REL) / f"{step_id}.json"


def _attestation(ws: Path, step_id: str) -> dict | None:
    p = ws.joinpath(*_ATTEST_DIR_REL) / f"{step_id}.json"
    d = _load_json(p)
    return d if isinstance(d, dict) else None


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------

def render(ws: Path, step_id: str, manifest: dict, *, now: str | None = None) -> dict:
    step = _canonical_step(manifest, step_id)
    if not step:
        return {"action": "render", "ok": False, "reason": f"unknown step {step_id!r}"}
    sha = _step_text_sha(step)
    marker_dir = ws.joinpath(*_PREFLIGHT_DIR_REL)
    marker_dir.mkdir(parents=True, exist_ok=True)
    marker = {
        "step_id": step_id,
        "step_text_sha": sha,
        "label": step.get("label", ""),
        "attestation_required": _attest_required(step),
    }
    if now:
        marker["opened_at"] = now
    _preflight_marker(ws, step_id).write_text(json.dumps(marker, indent=2), encoding="utf-8")
    tmpl = {
        "completed_at": now or "<UTC ISO8601>",
        "attested_by": "<who>",
        "summary": "<what you actually did, grounded>",
        "read_ack": sha,
        "evidence_refs": ["<relative/path/to/an/artifact/that/exists>"],
    }
    return {
        "action": "render", "ok": True, "step_id": step_id,
        "label": step.get("label", ""), "class": step.get("class", ""),
        "step_text_sha": sha,
        "what_must_be_done": step.get("what_must_be_done", ""),
        "how_to_verify_done": step.get("how_to_verify_done", {}),
        "drift_note": step.get("drift_note", ""),
        "attestation_template": tmpl,
        "parallelizable": step_id in _PARALLEL_SETUP,
    }


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

def _selfheal_attested_by(ws: Path, sid: str, att: dict, *, now: str | None = None) -> bool:
    """Under AUDITOOOR_ATTEST_SELFHEAL, re-stamp a missing/empty `attested_by`
    on-disk from the run context and return True if the file was repaired. Only
    fires for the `attested_by` base field (the NUVA drop); never overwrites an
    existing truthy value; never touches step-specific fields (those need real
    per-step evidence, not a synthesised stamp)."""
    if att.get("attested_by"):
        return False
    att["attested_by"] = _SELFHEAL_ATTESTED_BY
    if now and not att.get("completed_at"):
        att["completed_at"] = now
    try:
        p = ws.joinpath(*_ATTEST_DIR_REL) / f"{sid}.json"
        p.write_text(json.dumps(att, indent=2), encoding="utf-8")
        return True
    except OSError:
        # revert the in-memory mutation so the caller still flags it
        att.pop("attested_by", None)
        return False


def check(ws: Path, manifest: dict, *, now: str | None = None) -> dict:
    strict = bool(os.environ.get("AUDITOOOR_MANUAL_STEP_STRICT"))
    schema_strict = _schema_strict_enabled()
    selfheal = bool(os.environ.get(_ENV_SELFHEAL))
    findings: list[dict] = []
    schema_findings: list[dict] = []
    healed: list[str] = []
    for step in _manual_attest_steps(manifest):
        sid = step["step_id"]
        att = _attestation(ws, sid)
        if att is None:
            # absence is the EXISTING attestation-presence gate's job, not ours.
            continue

        # --- SCHEMA-VALIDATE BEFORE PREFLIGHT (G2 / id26) ---
        # A regenerated attestation that dropped a schema-required field (e.g.
        # NUVA step-1b.json lost `attested_by`) must be CAUGHT here, not slip
        # through as a mere "legacy" grounding note. Runs before the read-ack /
        # evidence grounding check so a missing required field is never silently
        # accepted by the preflight lane.
        missing = _schema_missing_fields(att, step, manifest)
        if missing and selfheal and missing == ["attested_by"]:
            # self-heal ONLY the attested_by drop (base field), re-read after.
            if _selfheal_attested_by(ws, sid, att, now=now):
                healed.append(sid)
                missing = _schema_missing_fields(att, step, manifest)
        if missing:
            schema_findings.append({
                "step_id": sid, "label": step.get("label", ""),
                "missing_fields": missing,
                "attestation_path": str((ws.joinpath(*_ATTEST_DIR_REL) / f"{sid}.json")),
            })

        cur_sha = _step_text_sha(step)
        marker = _load_json(_preflight_marker(ws, sid))
        read_ack = str(att.get("read_ack") or "")
        ev = att.get("evidence_refs")
        legacy = ("read_ack" not in att and "evidence_refs" not in att)
        problems: list[str] = []
        if legacy:
            problems.append("legacy attestation (no read_ack / evidence_refs) - re-run preflight+attest to ground it")
        else:
            if read_ack != cur_sha:
                problems.append(
                    f"read_ack {read_ack!r} != current step-text sha {cur_sha!r} "
                    "(step text drifted or full text never surfaced - re-read the whole step)")
            if not isinstance(marker, dict) or marker.get("step_text_sha") != cur_sha:
                problems.append("no preflight read-ack marker for the current step text (render was not run this cycle)")
            existing = [r for r in (ev or []) if isinstance(r, str) and (ws / r).exists()]
            if not existing:
                problems.append("evidence_refs cites no artifact that exists under the workspace (ungrounded)")
        if problems:
            findings.append({"step_id": sid, "label": step.get("label", ""),
                             "legacy": legacy, "problems": problems})

    # Verdict precedence (advisory-first + never-false-pass + never-retro-red):
    #  * schema_findings ALWAYS surface in the result dict (never-false-pass - a
    #    missing required field is never silently dropped, even in default mode).
    #  * The top-line `verdict` HARD-FAILS to the schema class ONLY under a named
    #    default-OFF env (AUDITOOOR_ATTEST_SCHEMA_STRICT). This is the ONE knob
    #    that turns the schema gate from advisory into blocking.
    #  * In DEFAULT (both envs unset) mode the top-line verdict is BYTE-IDENTICAL
    #    to the historical grounding-only logic (never-retro-red: a ws does not
    #    silently flip verdict class just because this gate landed). The schema
    #    problem is still exposed in schema_findings + schema_advisory=True so a
    #    caller / the CLI can WARN on it without a retro-red.
    #  * schema_only=True marks the NUVA shape (schema-broken, grounding-clean):
    #    in default mode that yields the advisory warn-attestation-schema-invalid
    #    verdict since there is no historical grounding finding to preserve.
    result: dict[str, Any] = {
        "action": "check", "strict": strict, "schema_strict": schema_strict,
        "selfheal": selfheal, "healed": healed,
        "schema_findings": schema_findings, "findings": findings,
        "schema_advisory": bool(schema_findings),
    }
    schema_bad = bool(schema_findings)
    grounding_bad = bool(findings)

    # 1. named schema-strict env: schema miss blocks (its own hard-fail class).
    if schema_strict and schema_bad:
        result["verdict"] = "fail-attestation-schema-invalid"
        return result

    # 2. historical grounding verdict is preserved verbatim (never-retro-red).
    #    AUDITOOOR_MANUAL_STEP_STRICT keeps its exact prior meaning (grounding).
    if grounding_bad:
        result["verdict"] = "fail-manual-step-ungrounded" if strict else "warn-manual-step-ungrounded"
        return result

    # 3. NUVA shape: schema-broken but grounding-clean. No historical grounding
    #    verdict to preserve, so surface the advisory schema warn (still not a
    #    hard fail without the named env).
    if schema_bad:
        result["verdict"] = "warn-attestation-schema-invalid"
        return result

    result["verdict"] = "pass-manual-steps-grounded"
    return result


# ---------------------------------------------------------------------------
# dispatch-setup
# ---------------------------------------------------------------------------

def auto_render_if_missing(ws: Path, step_id: str, manifest: dict, *, now: str | None = None) -> dict:
    """Idempotent library entrypoint for callers (e.g. the PreToolUse gate hook)
    that need a current read-ack marker to exist WITHOUT a separate manual CLI
    invocation of `render`. If a marker already exists and matches the current
    step text, this is a no-op (auto_rendered=False). Otherwise it calls the
    same render() used by the CLI - same marker content, same hash binding - and
    reports auto_rendered=True so the caller can log that it self-healed.

    This does NOT change what counts as grounded: it only produces the read-ack
    marker step (1) automatically; the attestation content itself still must
    separately carry a matching read_ack + evidence_refs (step (2), still
    enforced by check() / the gate hook after this call returns).
    """
    step = _canonical_step(manifest, step_id)
    if not step:
        return {"ok": False, "auto_rendered": False, "reason": f"unknown step {step_id!r}"}
    cur_sha = _step_text_sha(step)
    existing = _load_json(_preflight_marker(ws, step_id))
    if isinstance(existing, dict) and existing.get("step_text_sha") == cur_sha:
        return {"ok": True, "auto_rendered": False, "step_id": step_id, "step_text_sha": cur_sha}
    r = render(ws, step_id, manifest, now=now)
    r["auto_rendered"] = bool(r.get("ok"))
    return r


def dispatch_setup(ws: Path, manifest: dict) -> dict:
    plans = []
    for step in _manual_attest_steps(manifest):
        sid = step["step_id"]
        if sid not in _PARALLEL_SETUP:
            continue
        plans.append({
            "step_id": sid, "label": step.get("label", ""),
            "fan_out": _PARALLEL_SETUP[sid],
            "spawn_worker_hint": (
                f"bash tools/spawn-worker.sh --lane-id {ws.name}-{sid}-setup "
                f"--lane-type hunt --severity MEDIUM --workspace {ws} "
                f"--prompt-file <per-unit brief>  # then Agent(read the enriched brief)"),
            "preflight_first": f"python3 tools/manual-step-preflight.py render --ws {ws} --step {sid}",
        })
    return {"action": "dispatch-setup", "workspace": str(ws), "parallelizable_steps": plans}


def _print_render(r: dict) -> None:
    if not r.get("ok"):
        print(f"[manual-step-preflight] {r.get('reason')}", file=sys.stderr)
        return
    print(f"===== {r['step_id']}  {r['label']}  (class={r['class']}) =====")
    print(f"step_text_sha: {r['step_text_sha']}  (this is your read_ack)")
    print("\n--- WHAT MUST BE DONE (read the WHOLE thing) ---")
    print(r["what_must_be_done"])
    print("\n--- HOW TO VERIFY DONE ---")
    print(json.dumps(r["how_to_verify_done"], indent=2, ensure_ascii=False))
    if r.get("drift_note"):
        print("\n--- DRIFT NOTE ---")
        print(r["drift_note"])
    print("\n--- ATTESTATION TEMPLATE (write to .auditooor/attestations/%s.json) ---" % r["step_id"])
    print(json.dumps(r["attestation_template"], indent=2))
    if r.get("parallelizable"):
        print("\n[hint] this step's setup is parallelizable: "
              "python3 tools/manual-step-preflight.py dispatch-setup --ws <ws>")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("action", nargs="?", default="render",
                    choices=["render", "check", "dispatch-setup"])
    ap.add_argument("--ws", "--workspace", dest="ws", required=True)
    ap.add_argument("--step", help="step_id (required for render)")
    ap.add_argument("--manifest", default=None)
    ap.add_argument("--now", default=None, help="UTC ISO8601 to stamp the marker (optional)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    manifest = _load_manifest(a.manifest)
    if not manifest:
        print("[manual-step-preflight] cannot load runbook manifest", file=sys.stderr)
        return 2
    ws = Path(a.ws)

    if a.action == "render":
        if not a.step:
            print("--step is required for render", file=sys.stderr)
            return 2
        r = render(ws, a.step, manifest, now=a.now)
        print(json.dumps(r, indent=2) if a.json else "", end="")
        if not a.json:
            _print_render(r)
        return 0 if r.get("ok") else 2

    if a.action == "dispatch-setup":
        r = dispatch_setup(ws, manifest)
        print(json.dumps(r, indent=2))
        return 0

    # check
    r = check(ws, manifest, now=a.now)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"[manual-step-preflight] verdict: {r['verdict']} "
              f"(strict={r['strict']} schema_strict={r.get('schema_strict')})")
        if r.get("healed"):
            print(f"  self-healed attested_by for: {', '.join(r['healed'])}")
        for f in r.get("schema_findings", []):
            print(f"  {f['step_id']} {f['label']}: SCHEMA - missing required field(s): "
                  f"{', '.join(f['missing_fields'])}")
        for f in r["findings"]:
            print(f"  {f['step_id']} {f['label']}:")
            for p in f["problems"]:
                print(f"     - {p}")
    return 1 if r["verdict"].startswith("fail-") else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
