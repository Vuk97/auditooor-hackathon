#!/usr/bin/env python3
"""manual-step-required-check - fail-closed enforcement for pipeline steps that
REQUIRE a MANUAL MODEL ACTION and cannot be safely autorun.

THE operator's key ask (2026-07-04): some pipeline steps must NOT be blindly
autorun - the go-ethereum fork-delta prune is the cautionary tale that "fucked
things up" when it pruned files it had not proven unmodified. For such steps an
autorun is UNSAFE, so the safe design is: the model performs the step by hand,
then ATTESTS it (completed_at + attested_by + summary). This gate detects when a
REQUIRING-MANUAL-MODEL-ACTION step was NOT completed/attested and FAILS CLOSED
under strict (WARN advisory) while printing the EXACT machine-readable
instruction of what the model must do - so a skipped/fumbled manual step is never
silently green.

This is the INVERSE of an autorun gate: it does not run the work (running it is
what is unsafe); it enforces that a human/model DID the work and left a receipt.

Registry: each manual step carries
  id            - stable key (used for the attestation filename)
  label         - human summary
  applies_when  - a predicate over the workspace (a step that is N/A for this
                  workspace is a silent pass; only APPLICABLE unattested steps
                  fail)
  attestation   - .auditooor/manual_step_attestations/<id>.json ; REQUIRED
                  fields completed_at + attested_by + summary (non-empty), plus
                  any step-specific fields
  instruction   - the verbatim instruction string printed on failure

Attestation honesty (mirrors readme_runbook_steps.json attestation_format): an
attestation with attested_by not in the accepted set, or with a blank required
field, is treated as UNATTESTED (RED) - a claude-only rubber-stamp does not
count. A missing attestation file is UNATTESTED.

Advisory-first: WARN + rc 0 by default; an applicable-unattested step returns
ok=False (CLI exit 1) ONLY under strict = AUDITOOOR_L37_STRICT=1 or the per-gate
AUDITOOOR_L37_MANUAL_STEP_STRICT=1. Never green-passes by silently skipping: an
applicable step with no valid attestation is always reported (WARN or FAIL).

Verdicts (per step): attested | unattested-applicable | not-applicable |
attestation-invalid. Top-level: pass-all-manual-steps-attested |
pass-no-applicable-manual-steps | fail-manual-step-unattested.

Exit 0 on pass / WARN-advisory; exit 1 only on a strict fail.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ATTEST_DIR_REL = ".auditooor/manual_step_attestations"

# Accepted attested_by values (a claude-only rubber-stamp is RED - mirrors
# readme_runbook_steps.json attestation_format.attested_by_values).
_ACCEPTED_ATTESTED_BY = {"operator", "claude-operator-verified"}
_REQUIRED_FIELDS = ("completed_at", "attested_by", "summary")


# --------------------------------------------------------------------------
# Workspace predicates (READ-ONLY reuse of the shipped detectors).
# --------------------------------------------------------------------------
def _load_go_entrypoint_surface():
    tool_path = _HERE / "go_entrypoint_surface.py"
    if not tool_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "_go_entrypoint_surface_manual", tool_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_go_entrypoint_surface_manual"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def _is_cosmos_go_intrinsic(ws: Path) -> bool:
    """Kill-switch-INDEPENDENT Cosmos-Go detection (see go-coverage-basis-check).
    Returns False (not applicable) if the detector is unavailable - a manual step
    is only enforced when we can CONFIRM it applies."""
    ges = _load_go_entrypoint_surface()
    if ges is None:
        return False
    try:
        g = getattr(ges, "_has_cosmos_gomod", None)
        l = getattr(ges, "_has_cosmos_layout", None)
        if not callable(g) or not callable(l):
            return False
        return bool(g(ws) or l(ws))
    except Exception:
        return False


def _fork_line_is_negated(line: str) -> bool:
    """A SCOPE.md line that MENTIONS a go-ethereum fork base only to DENY one is
    NOT a fork signal. Without this, a first-party workspace whose SCOPE.md says
    'NOT a fork of ... go-ethereum' false-triggers the fork-delta manual step
    (observed NUVA 2026-07-06: line 'contains NO upstream fork ... not a fork of
    bor / cosmos-sdk / cometbft / go-ethereum' matched the naive substring)."""
    return any(n in line for n in (
        "no upstream fork", "no fork", "not a fork", "isn't a fork", "is not a fork",
        "first-party", "first party", "contains no ", "no vendored", "no vendor",
        "fork-base set is empty", "fork base set is empty", "fork_bases is empty",
        "pass-no-fork", "no-fork-detected", "no fork detected", "not applicable",
    ))


def _has_go_fork(ws: Path) -> bool:
    """A Go L1 that vendors a go-ethereum fork under src/ (bor <- go-ethereum,
    etc.). The fork-delta prune is only relevant when such a fork is present.
    Detection prefers AUTHORITATIVE signals over noisy SCOPE.md free-text:
      (1) a resolved go-ethereum base in .auditooor/fork_bases.json (an EMPTY
          fork_bases.json is an authoritative 'no fork' that suppresses the text
          signal - the prune has no base to verify against, so the step is N/A);
      (2) a vendored fork tree structurally shaped like go-ethereum (core/vm +
          core/state);
      (3) an AFFIRMATIVE (non-negated) SCOPE.md mention, only when fork_bases did
          not already declare the set empty."""
    if not _is_cosmos_go_intrinsic(ws) and not _has_any_go(ws):
        return False
    # (1) authoritative: fork_bases.json.
    fork_bases_authoritative_empty = False
    fb = ws / ".auditooor" / "fork_bases.json"
    try:
        if fb.is_file():
            data = json.loads(fb.read_text(encoding="utf-8", errors="replace") or "null")
            if data:  # non-empty dict/list => a resolved base set
                blob = json.dumps(data).lower()
                if "go-ethereum" in blob or re.search(r"\bgeth\b", blob):
                    return True
            else:
                fork_bases_authoritative_empty = True
    except (OSError, ValueError):
        pass
    # (2) structural: a fork dir whose core/vm + core/state layout matches go-ethereum
    src = ws / "src"
    if src.is_dir():
        try:
            for child in src.iterdir():
                if not child.is_dir():
                    continue
                if (child / "core" / "vm").is_dir() and (child / "core" / "state").is_dir():
                    return True
        except OSError:
            pass
    # (3) SCOPE.md AFFIRMATIVE mention only (skip disclaimer negations), and only
    # when fork_bases did not already authoritatively declare the set empty.
    if not fork_bases_authoritative_empty:
        scope = ws / "SCOPE.md"
        try:
            if scope.is_file():
                for line in scope.read_text(encoding="utf-8", errors="replace").lower().splitlines():
                    if ("go-ethereum" in line or re.search(r"\bgeth\b", line)) \
                            and not _fork_line_is_negated(line):
                        return True
        except OSError:
            pass
    return False


def _has_any_go(ws: Path) -> bool:
    src = ws / "src"
    root = src if src.is_dir() else ws
    try:
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in (
                ".git", "node_modules", "vendor", "third_party", ".auditooor",
                "reference", "docs", "prior_audits") and not d.startswith(".")]
            if any(f.endswith(".go") for f in fns):
                return True
            # bound the walk
            if dp[len(str(root)):].count(os.sep) > 5:
                dns[:] = []
    except OSError:
        return False
    return False


# --------------------------------------------------------------------------
# The registry of REQUIRING-MANUAL-MODEL-ACTION steps.
# --------------------------------------------------------------------------
MANUAL_STEPS = [
    {
        "id": "go-ethereum-fork-delta-prune-verify",
        "label": "go-ethereum fork-delta prune verification (Go L1)",
        "applies_when": _has_go_fork,
        "instruction": (
            "MANUAL MODEL ACTION REQUIRED - go-ethereum fork-delta prune "
            "verification. Do NOT let the fork-delta prune autorun blindly (it "
            "previously pruned files it had not proven unmodified). Confirm BY "
            "HAND that: (1) the fork-base ref for the vendored go-ethereum fork "
            "is resolved (a \"## Fork Bases\" row in SCOPE.md + a resolved "
            ".auditooor/fork_bases.json entry, or an equivalent resolved base "
            "commit); (2) the prune dropped ONLY files PROVEN byte-identical to "
            "that upstream base (whitespace-normalized diff == empty), and KEPT "
            "every file with any local delta plus every file whose base could "
            "not be resolved (fail-open to KEPT, never a silent under-scope); "
            "(3) you spot-checked at least one KEPT modified file and one "
            "PRUNED file against the upstream base. Then write the attestation "
            ".auditooor/manual_step_attestations/go-ethereum-fork-delta-prune-"
            "verify.json with completed_at + attested_by=operator (or "
            "claude-operator-verified) + summary + fields "
            "fork_base_resolved, files_pruned_proven_unmodified, "
            "files_kept_with_delta_or_unresolved. Do NOT hand-green: the "
            "prune must be VERIFIED, not assumed."
        ),
        "extra_fields": [
            "fork_base_resolved",
            "files_pruned_proven_unmodified",
            "files_kept_with_delta_or_unresolved",
        ],
    },
    {
        "id": "entry-point-scoped-hunt-scoping",
        "label": "entry-point-scoped hunt scoping (Go L1)",
        "applies_when": _is_cosmos_go_intrinsic,
        "instruction": (
            "MANUAL MODEL ACTION REQUIRED - entry-point-scoped hunt scoping. For "
            "a Cosmos-SDK / CometBFT Go-L1 the hunt target and coverage "
            "denominator are the external ENTRY-POINT surface "
            "(msg-server / ABCI / precompile / ante / IBC / RPC / "
            "genesis+lifecycle+ValidateBasic), NOT every exported Go helper (a "
            "Go export is the Solidity-internal analog, covered transitively). "
            "Confirm BY HAND that: (1) the fcc result records "
            "go_entry_surface.applied=True (run tools/go-coverage-basis-check.py "
            "and expect pass-entry-point-basis, NOT fail-wrong-basis); (2) the "
            "Step-3 hunt was dispatched against the ENTRY-POINT residual the "
            "coverage gate lists, not the every-exported set (you did not "
            "hand a hunt batch every exported keeper helper). Then write the "
            "attestation .auditooor/manual_step_attestations/entry-point-scoped-"
            "hunt-scoping.json with completed_at + attested_by=operator (or "
            "claude-operator-verified) + summary + fields "
            "go_entry_surface_applied, hunt_scoped_to_entry_point_residual."
        ),
        "extra_fields": [
            "go_entry_surface_applied",
            "hunt_scoped_to_entry_point_residual",
        ],
    },
]


def _load_attestation(ws: Path, step_id: str) -> tuple[dict | None, Path]:
    p = ws / _ATTEST_DIR_REL / f"{step_id}.json"
    if not p.is_file():
        return None, p
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace")), p
    except (OSError, ValueError):
        return None, p


def _attestation_valid(obj: dict | None, extra_fields) -> tuple[bool, str]:
    if not isinstance(obj, dict):
        return False, "attestation file absent or not a JSON object"
    for f in _REQUIRED_FIELDS:
        v = obj.get(f)
        if not isinstance(v, str) or not v.strip():
            return False, f"required field '{f}' missing or blank"
    if str(obj.get("attested_by", "")).strip() not in _ACCEPTED_ATTESTED_BY:
        return False, (f"attested_by='{obj.get('attested_by')}' not in accepted "
                       f"set {sorted(_ACCEPTED_ATTESTED_BY)} (a rubber-stamp is RED)")
    for f in (extra_fields or ()):
        if f not in obj:
            return False, f"step-specific field '{f}' missing"
    return True, "attested"


def _strict() -> bool:
    if os.environ.get("AUDITOOOR_L37_MANUAL_STEP_STRICT", "").strip() == "1":
        return True
    if os.environ.get("AUDITOOOR_L37_STRICT", "").strip() == "1":
        return True
    return False


def evaluate(ws) -> dict:
    ws = Path(ws)
    strict = _strict()
    steps_out = []
    unattested = []
    applicable = 0
    for spec in MANUAL_STEPS:
        try:
            applies = bool(spec["applies_when"](ws))
        except Exception:
            applies = False
        if not applies:
            steps_out.append({
                "id": spec["id"], "label": spec["label"],
                "verdict": "not-applicable", "ok": True,
                "instruction": None})
            continue
        applicable += 1
        obj, path = _load_attestation(ws, spec["id"])
        valid, why = _attestation_valid(obj, spec.get("extra_fields"))
        if valid:
            steps_out.append({
                "id": spec["id"], "label": spec["label"],
                "verdict": "attested", "ok": True,
                "attestation_path": str(path), "instruction": None})
        else:
            verdict = ("attestation-invalid" if obj is not None
                       else "unattested-applicable")
            steps_out.append({
                "id": spec["id"], "label": spec["label"],
                "verdict": verdict, "ok": False,
                "attestation_path": str(path), "reason": why,
                "instruction": spec["instruction"]})
            unattested.append({
                "id": spec["id"], "reason": why,
                "instruction": spec["instruction"]})

    if applicable == 0:
        verdict = "pass-no-applicable-manual-steps"
        ok = True
        reason = ("no REQUIRING-MANUAL-MODEL-ACTION step applies to this "
                  "workspace (all N/A)")
    elif not unattested:
        verdict = "pass-all-manual-steps-attested"
        ok = True
        reason = (f"all {applicable} applicable manual step(s) carry a valid "
                  "attestation")
    else:
        verdict = "fail-manual-step-unattested"
        ok = not strict
        reason = (f"{len(unattested)} applicable manual step(s) NOT completed/"
                  f"attested: {', '.join(u['id'] for u in unattested)}")
        if not strict:
            reason = "WARN: " + reason

    return {
        "gate": "manual-step-required",
        "verdict": verdict,
        "ok": ok,
        "strict": strict,
        "reason": reason,
        "applicable_count": applicable,
        "unattested": unattested,
        "steps": steps_out,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Fail-closed enforcement for REQUIRING-MANUAL-MODEL-ACTION steps.")
    ap.add_argument("workspace", help="path to the audit workspace")
    ap.add_argument("--json", action="store_true", help="emit the verdict dict as JSON")
    args = ap.parse_args(argv)

    res = evaluate(args.workspace)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"manual-step-required  workspace: {args.workspace}")
        print(f"  verdict : {res['verdict']}")
        print(f"  strict  : {res['strict']}")
        print(f"  reason  : {res['reason']}")
        for u in res["unattested"]:
            print(f"\n  [{u['id']}] {u['reason']}")
            print(f"  INSTRUCTION: {u['instruction']}")
    return 0 if res.get("ok", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
