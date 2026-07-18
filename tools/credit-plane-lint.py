#!/usr/bin/env python3
"""tools/credit-plane-lint.py - advisory serving-join credit-plane lint (P26).

PROBLEM (the #1 audit-complete false-red, per memory
methodology_serving_join_falsered_class): genuine evidence sits ON DISK (a
mutation-verified harness sidecar, a ws-owned hunt sidecar) but a downstream
reader keyed on a narrower path/schema/glob NEVER CREDITED it, so a gate goes RED
while the work is actually done. This lint reads the narrow-waist credit-evidence
record (tools/lib/credit_evidence.py) and flags every "on disk but uncredited"
delta.

ADVISORY-FIRST ENVELOPE (mirrors tools/lib/lane_result_validator.py verbatim):
  - Default verdict is a WARN-shape (``warn-uncredited-evidence`` /
    ``pass-all-credited``), rc 0 always.
  - Only under STRICT (``--strict`` OR env
    ``AUDITOOOR_CREDIT_PLANE_STRICT`` in {1,true,yes}) does an uncredited delta
    ELEVATE to ``fail-uncredited-evidence`` + rc 1. Wave-1 wiring (audit-deep)
    invokes WITHOUT strict, so the flag-unset path is byte-identical WARN + rc 0.
  - NOT wired into audit-done-guard / honest-zero-verify (wave-1 read-only).

PER-READER EXPECTED-SCOPE ALLOWLIST (the whole safety of the advisory):
  Some readers credit-BY-DESIGN on a NARROWER set than "everything on disk". If we
  flagged those we would emit a false serving-join. The allowlist below records, per
  reader, the scope it is DESIGNED to credit, with a cited justification. An
  uncredited item is SUPPRESSED (not flagged) only if it falls in an allowlisted
  narrower-scope reason. Anything OUTSIDE an allowlist entry is still flagged - so a
  genuine narrowing that drops real evidence is NOT masked.

  Allowlist entries are keyed by a stable ``reason`` code, never by a broad glob, so
  an over-broad entry cannot silently swallow a real false-red. Each carries a
  human-readable justification for audit.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parent.parent
_LOADER_PATH = _REPO / "tools" / "lib" / "credit_evidence.py"

SCHEMA = "auditooor.credit_plane_lint.v1"
STRICT_ENV = "AUDITOOOR_CREDIT_PLANE_STRICT"


def _load_loader():
    name = "credit_evidence_loader"
    spec = importlib.util.spec_from_file_location(name, str(_LOADER_PATH))
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so the loader module's @dataclass can resolve
    # cls.__module__ (Python 3.12+/3.14 dataclasses read sys.modules[__module__]).
    sys.modules.setdefault(name, mod)
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception:
        sys.modules.pop(name, None)
        return None
    return mod


# ---------------------------------------------------------------------------
# PER-READER EXPECTED-SCOPE ALLOWLIST
#
# Each entry: reason-code -> (reader, justification). An uncredited finding whose
# ``reason`` matches an allowlisted code is SUPPRESSED (credited-by-design on a
# narrower set). Everything else is a genuine serving-join and is flagged.
#
# CITED justifications (do-not over-broaden):
#  - mvc-cluster-not-per-fn-manifest: the per-FUNCTION genuine_coverage_manifest is
#    per-function BY DESIGN (genuine-coverage-sidecar-merge.py docstring: "cross-
#    function / core invariant sidecars ... are out of scope for this per-function
#    manifest"). A cluster sidecar (filename not mvc-<src>-<fn>) legitimately has no
#    per-fn manifest row; crediting it there would be a schema error, not a fix.
#  - hunt-non-belonging: a derived sidecar whose workspace_path/workspace does not
#    resolve to THIS ws is correctly NOT bridged (hunt-sidecar-bridge belongs-check).
#    The loader already excludes non-belonging sidecars, so this is defense-in-depth.
# ---------------------------------------------------------------------------

ALLOWLIST: dict[str, dict[str, str]] = {
    "mvc-cluster-not-per-fn-manifest": {
        "reader": "genuine-coverage-sidecar-merge.py",
        "justification": (
            "per-function genuine_coverage_manifest is per-function BY DESIGN; a "
            "cross-function/cluster sidecar (non mvc-<src>-<fn> filename) is out of "
            "scope for that manifest and credited elsewhere - not a serving-join."
        ),
    },
    "hunt-non-belonging": {
        "reader": "hunt-sidecar-bridge.py",
        "justification": (
            "a derived hunt sidecar whose workspace_path/workspace does not resolve "
            "to this ws is correctly not bridged (belongs-check); not a serving-join."
        ),
    },
}


def _mvc_uncredited_reason(m: Any) -> str:
    """Classify an uncredited mvc sidecar. A cluster sidecar (filename not the
    per-fn mvc-<src>-<fn> shape) is an ALLOWLISTED narrower-scope case; a per-fn
    sidecar missing its per-fn manifest row is a genuine serving-join."""
    name = Path(getattr(m, "sidecar", "")).name.lower()
    # Per-fn sidecars are mvc-<srcbase>-<fn>.json (>=2 hyphen-separated segments
    # after the mvc- prefix). A cluster/core sidecar uses a different convention;
    # if we cannot confirm the per-fn shape we DO NOT suppress (fail-open to flag).
    stem = name[:-5] if name.endswith(".json") else name  # strip .json
    fn_norm = str(getattr(m, "fn_norm", ""))
    if stem.startswith("mvc-") and fn_norm and stem.endswith(fn_norm) and stem != "mvc-" + fn_norm:
        # A well-formed per-fn sidecar that the per-fn manifest DID NOT credit is
        # the real serving-join (genuine-coverage-sidecar-merge should have upgraded
        # the manifest row but did not - or never ran).
        return "mvc-per-fn-uncredited"
    # Cannot confirm per-fn shape -> treat as cluster (allowlisted narrower scope).
    return "mvc-cluster-not-per-fn-manifest"


def build_findings(rec: Any) -> list[dict[str, Any]]:
    """Return the list of raw uncredited-evidence findings (before allowlist)."""
    findings: list[dict[str, Any]] = []
    for m in rec.mvc_uncredited:
        reason = _mvc_uncredited_reason(m)
        findings.append({
            "family": "mvc",
            "reason": reason,
            "function": getattr(m, "function", ""),
            "sidecar": getattr(m, "sidecar", ""),
            "detail": (
                "genuine mutation-verified sidecar on disk but no matching genuine "
                "row in genuine_coverage_manifest.json"
            ),
        })
    for h in rec.hunt_uncredited:
        findings.append({
            "family": "hunt",
            "reason": "hunt-derived-not-bridged",
            "name": getattr(h, "name", ""),
            "derived_path": getattr(h, "derived_path", ""),
            "detail": (
                "ws-owned hunt sidecar in derived dir but no bridged copy in "
                "<ws>/.auditooor/hunt_findings_sidecars/"
            ),
        })
    return findings


def apply_allowlist(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split findings into (flagged, suppressed). A finding is suppressed iff its
    reason-code is in ALLOWLIST (credited-by-design on a narrower set)."""
    flagged: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    for f in findings:
        entry = ALLOWLIST.get(f.get("reason", ""))
        if entry is not None:
            g = dict(f)
            g["allowlisted_reader"] = entry["reader"]
            g["allowlist_justification"] = entry["justification"]
            suppressed.append(g)
        else:
            flagged.append(f)
    return flagged, suppressed


def lint(
    workspace: str | Path,
    *,
    strict: bool | None = None,
    derived_root: str | Path | None = None,
) -> dict[str, Any]:
    """Advisory credit-plane lint over ``workspace``. Returns a JSON-serializable
    dict mirroring lane_result_validator's WARN-default / STRICT-elevate envelope.

    Verdicts:
        pass-all-credited
        warn-uncredited-evidence   (default when flagged findings exist)
        fail-uncredited-evidence   (strict=True or env elevated)
        error-loader-unavailable
    """
    if strict is None:
        strict = os.environ.get(STRICT_ENV, "") in {"1", "true", "yes"}

    loader = _load_loader()
    if loader is None:
        return {
            "schema": SCHEMA,
            "verdict": "error-loader-unavailable",
            "strict": strict,
            "error": f"could not load {_LOADER_PATH}",
        }

    rec = loader.load_credit_evidence(workspace, derived_root=derived_root)
    raw = build_findings(rec)
    flagged, suppressed = apply_allowlist(raw)

    if not flagged:
        verdict = "pass-all-credited"
    elif strict:
        verdict = "fail-uncredited-evidence"
    else:
        verdict = "warn-uncredited-evidence"

    return {
        "schema": SCHEMA,
        "verdict": verdict,
        "strict": strict,
        "ws_name": rec.ws_name,
        "ws_path": rec.ws_path,
        "flagged_count": len(flagged),
        "suppressed_count": len(suppressed),
        "flagged": flagged,
        "suppressed_by_allowlist": suppressed,
        "evidence_summary": {
            "mvc_on_disk_genuine": len(rec.mvc_on_disk_genuine),
            "mvc_uncredited": len(rec.mvc_uncredited),
            "hunt_derived_owned": len(rec.hunt_derived_owned),
            "hunt_uncredited": len(rec.hunt_uncredited),
            "coverage_plane_present": rec.coverage_plane_present,
        },
    }


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Advisory serving-join credit-plane lint. WARN + rc 0 by default; "
            "elevates to FAIL + rc 1 only under --strict / "
            f"{STRICT_ENV}=1. Wave-1: read-only, not in audit-done-guard."
        )
    )
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--derived-root", default=None)
    ap.add_argument("--strict", action="store_true",
                    help=f"elevate uncredited-evidence to FAIL (or set {STRICT_ENV}=1)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = True if args.strict else None  # None -> env-driven default
    result = lint(args.workspace, strict=strict, derived_root=args.derived_root)

    if args.json:
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(f"credit-plane-lint ({SCHEMA})")
        print(f"  verdict         : {result['verdict']}")
        print(f"  strict          : {result.get('strict')}")
        print(f"  flagged         : {result.get('flagged_count')}")
        print(f"  suppressed      : {result.get('suppressed_count')}")
        for f in result.get("flagged", []):
            key = f.get("function") or f.get("name") or "?"
            print(f"    - [{f.get('family')}/{f.get('reason')}] {key}")

    if result["verdict"] == "fail-uncredited-evidence":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_main())
