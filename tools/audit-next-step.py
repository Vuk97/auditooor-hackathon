#!/usr/bin/env python3
# <!-- r36-rebuttal: lane L-AUDIT-NEXT-STEP registered via agent-pathspec-register.py -->
"""audit-next-step.py - the single "what is the NEXT required step to work on?" answer.

The 5-minute audit loop drives EVERY README runbook step to done, but nothing
UNIFIED the two existing readers into one "next action" verdict, so a tick could
eyeball progress from memory and silently skip a RED step (NUVA: step-3 per-fn
hunt sat undispatched for several ticks; advisory step-0g / step-1b / step-2c-input
were also RED). The pieces existed:

  - tools/readme-conformance-check.py   -> per-step PASS/RED + the missing artifact
  - tools/audit-done-guard.py           -> the mechanical DONE verdict + FAIL reasons
  - tools/readme_runbook_steps.json     -> per-step what_must_be_done / how_to_verify_done / KIND

This tool REUSES all three (no re-implementation of step-eval or done logic - it
imports the two evaluators as modules so they stay the single source of truth) and
prints, in one call:

  (a) NEXT REQUIRED STEP = the FIRST unmet REQUIRED (not advisory) step in runbook
      order, with its step_id + KIND + verbatim what_must_be_done + how_to_verify_done
      (this mechanically satisfies the loop's "STEP CITATION FIRST" rule);
  (b) the FULL RED list split into REQUIRED vs ADVISORY;
  (c) the audit-done-guard verdict line (DONE / NOT-DONE + the FAIL reasons).

rc 0 = all REQUIRED runbook steps PASS AND the done-guard says DONE.
rc 1 = a required step is RED OR the done-guard is NOT-DONE (a tick/CI can gate on it).
rc 2 = usage / workspace error.

CLI: python3 tools/audit-next-step.py <workspace> [--json] [--ttl-hours N]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Reuse: import the two canonical evaluators as modules (single source of truth).
# Both are hyphenated filenames, so load by path. NO re-implementation of the
# step-eval logic or the done-verdict logic lives here.
# ---------------------------------------------------------------------------

def _load_module(filename: str, mod_name: str):
    path = _TOOLS_DIR / filename
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {filename}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Manifest helpers: KIND derivation + verbatim step-detail lookup.
# ---------------------------------------------------------------------------

def _kind_of(step_class: str) -> str:
    """Map the manifest `class` to a coarse KIND (manual | mechanical | conditional).

    The prompt asks for a manual/mechanical/conditional KIND; the manifest carries
    finer classes. This is a pure presentation mapping - the authoritative class
    string is also surfaced in the JSON so nothing is lost."""
    c = (step_class or "").lower()
    if c.startswith("manual"):
        # manual, manual-judgment, manual-judgment+conditional-mechanical-run
        return "manual"
    if "conditional" in c or c == "step-2c-input":
        # conditional-mechanical, step-2c-input (a conditional input-materialization)
        return "conditional"
    if c.startswith("mechanical") or c == "mechanical":
        return "mechanical"
    return c or "unknown"


def _manifest_index(manifest: dict) -> dict[str, dict]:
    """{step_id: step_dict} preserving manifest order via the returned dict."""
    idx: dict[str, dict] = {}
    for step in manifest.get("steps", []):
        sid = step.get("step_id")
        if sid:
            idx[sid] = step
    return idx


def _verbatim(step: dict) -> dict[str, str]:
    """Verbatim what_must_be_done + how_to_verify_done for a step.

    what_must_be_done is a plain string in the manifest. how_to_verify_done is a
    structured block; we surface a compact but faithful string (the artifact-check
    paths + attestation requirement) so the loop can cite HOW the step is verified
    without re-deriving it."""
    what = step.get("what_must_be_done", "")
    how = step.get("how_to_verify_done", {}) or {}
    parts: list[str] = []
    for chk in (how.get("artifact_checks", []) or []) + (how.get("condition_checks", []) or []):
        ctype = chk.get("type", "?")
        target = (
            chk.get("path")
            or chk.get("path_from_repo_root")
            or (", ".join(chk.get("paths", [])) if chk.get("paths") else "")
            or chk.get("json_pointer", "")
        )
        parts.append(f"{ctype}({target})" if target else ctype)
    if how.get("attestation_required"):
        parts.append(f"attestation:{how.get('attestation_path', '<required>')}")
    verify = "; ".join(parts) if parts else "(no mechanical checks - see class)"
    return {"what": what, "verify": verify}


# ---------------------------------------------------------------------------
# Core evaluation
# ---------------------------------------------------------------------------

def evaluate(
    ws: Path,
    *,
    ttl_hours: float = 6.0,
    manifest_path: Path | None = None,
    conformance_mod: Any = None,
    guard_mod: Any = None,
) -> dict:
    """Unify the conformance per-step eval and the done-guard verdict into one
    "next required step" object. `conformance_mod` / `guard_mod` may be injected
    for testing; otherwise the real hyphenated tools are loaded."""
    ws = ws.resolve()
    result: dict[str, Any] = {
        "workspace": str(ws),
        "next_required_step": None,
        "red_required": [],
        "red_advisory": [],
        "done_guard": {"rc": None, "verdict": "", "fails": []},
        "all_required_pass": False,
        "rc": 1,
    }
    if not ws.is_dir():
        result["error"] = f"workspace not found: {ws}"
        result["rc"] = 2
        return result

    if conformance_mod is None:
        conformance_mod = _load_module("readme-conformance-check.py", "_ans_conformance")
    if guard_mod is None:
        guard_mod = _load_module("audit-done-guard.py", "_ans_done_guard")

    # --- (1) per-step conformance eval (REUSED, single source of truth) ---
    conf = conformance_mod.evaluate(ws, manifest_path=manifest_path)
    if conf.get("error"):
        result["error"] = conf["error"]
        result["rc"] = 2
        return result

    # manifest for KIND + verbatim detail (the conformance eval resolved which
    # manifest it used; read the same file so KIND/what/verify match its steps)
    mpath = Path(conf.get("manifest_path")) if conf.get("manifest_path") else (
        manifest_path or (_TOOLS_DIR / "readme_runbook_steps.json")
    )
    try:
        manifest = json.loads(mpath.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        manifest = {"steps": []}
    step_by_id = _manifest_index(manifest)

    # --- (2) split RED into required vs advisory, in runbook order ---
    # conf["steps"] is already in manifest order; each carries required + status.
    first_unmet_required: dict | None = None
    for sr in conf.get("steps", []):
        if sr.get("status") != "red":
            continue
        sid = sr.get("step_id")
        step = step_by_id.get(sid, {})
        kind = _kind_of(sr.get("class") or step.get("class", ""))
        vb = _verbatim(step)
        row = {
            "id": sid,
            "kind": kind,
            "class": sr.get("class") or step.get("class", ""),
            "label": sr.get("label", sid),
            "missing": sr.get("failures", []),
            "what": vb["what"],
            "verify": vb["verify"],
        }
        if sr.get("required", True):
            result["red_required"].append(row)
            if first_unmet_required is None:
                first_unmet_required = row
        else:
            result["red_advisory"].append(row)

    result["next_required_step"] = first_unmet_required
    result["all_required_pass"] = len(result["red_required"]) == 0

    # --- (3) done-guard verdict (REUSED) ---
    guard = guard_mod.evaluate(ws, ttl_hours=ttl_hours)
    guard_done = bool(guard.get("done"))
    result["done_guard"] = {
        "rc": 0 if guard_done else 1,
        "verdict": ("DONE: " if guard_done else "NOT-DONE: ") + str(guard.get("reason", "")),
        "done": guard_done,
        "fails": list(guard.get("fail_gates", []) or []),
    }

    # --- rc: 0 iff all required steps pass AND the done-guard says DONE ---
    result["rc"] = 0 if (result["all_required_pass"] and guard_done) else 1
    return result


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def _print_human(res: dict) -> None:
    ws = res.get("workspace", "?")
    print(f"audit-next-step  workspace: {ws}")
    print()

    if res.get("error"):
        print(f"ERROR: {res['error']}")
        return

    nxt = res.get("next_required_step")
    print("== NEXT REQUIRED STEP (STEP CITATION FIRST) ==")
    if nxt is None:
        if res.get("done_guard", {}).get("done"):
            print("  (none - all required steps PASS and the workspace is DONE)")
        else:
            print("  (no RED required runbook step - but the workspace is NOT-DONE;")
            print("   the remaining work is a done-guard gate, see below)")
    else:
        print(f"  step_id : {nxt['id']}")
        print(f"  KIND    : {nxt['kind']}  (class: {nxt['class']})")
        print(f"  label   : {nxt['label']}")
        print(f"  what_must_be_done : {nxt['what']}")
        print(f"  how_to_verify_done: {nxt['verify']}")
        if nxt.get("missing"):
            print("  missing:")
            for m in nxt["missing"]:
                print(f"    - {m}")
    print()

    print("== FULL RED LIST ==")
    rr = res.get("red_required", [])
    ra = res.get("red_advisory", [])
    print(f"  REQUIRED RED ({len(rr)}):")
    if rr:
        for r in rr:
            print(f"    [{r['kind']:11s}] {r['id']:12s} {r['label']}")
    else:
        print("    (none)")
    print(f"  ADVISORY RED ({len(ra)}):")
    if ra:
        for r in ra:
            print(f"    [{r['kind']:11s}] {r['id']:12s} {r['label']}")
    else:
        print("    (none)")
    print()

    dg = res.get("done_guard", {})
    print("== AUDIT-DONE-GUARD ==")
    print(f"  {dg.get('verdict', '')}")
    for g in dg.get("fails", []):
        print(f"    FAIL: {g}")
    print()

    print(f"audit-next-step: rc={res.get('rc')} "
          f"({'ready-to-file/DONE' if res.get('rc') == 0 else 'work remaining'})")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("workspace")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--ttl-hours", type=float,
                    default=float(os.environ.get("AUDIT_DONE_TTL_HOURS", "6")))
    args = ap.parse_args(argv)

    ws = Path(os.path.expanduser(args.workspace)).resolve()
    res = evaluate(ws, ttl_hours=args.ttl_hours)

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        _print_human(res)

    return int(res.get("rc", 1))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
