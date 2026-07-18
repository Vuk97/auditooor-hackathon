#!/usr/bin/env python3
"""closure-health-check.py - closure-degrade (enforcement-gap 2026-07-03): did the
inter-procedural CLOSURE pass actually run, or silently degrade?

THE gap: the D-CONNECT closure-aware `unguarded` correction (dataflow-slice.py) stamps
each path record with `closure_consulted` / `closure_degraded` (R80 honesty - it never
silently claims closure-backed when the predicates module failed to import or the sink
was not navigable). But NO gate read those flags, so a run where the closure DEGRADED on
every record (predicates unimportable, Slither broken) is INDISTINGUISHABLE from a clean
run: the slice-local `unguarded` over-reports on role-gated code, and negative-space /
guard-asymmetry leads are unreliable, yet the audit greens.

This gate reads <ws>/.auditooor/dataflow_paths.jsonl and classifies closure health:
  pass - closure not requested (no closure_* keys) OR consulted with a low degrade fraction
  FLAG - closure WAS requested (>=1 record has a closure_* key) but degraded on all/most
         records (degrade_fraction > threshold, default 0.5), i.e. the closure correction
         silently did not run -> unguarded/negative-space results are unreliable

Advisory by default (rc 0). Under AUDITOOOR_CLOSURE_DEGRADE_STRICT=1 a FLAG is rc 1.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

SCHEMA = "auditooor.closure_health_check.v1"
_DEFAULT_MAX_DEGRADE_FRACTION = 0.5


def check(ws: Path) -> dict:
    ws = Path(ws)
    p = ws / ".auditooor" / "dataflow_paths.jsonl"
    if not p.is_file():
        return {"schema": SCHEMA, "verdict": "pass",
                "reason": "no dataflow_paths.jsonl (closure pass not applicable / not run)"}
    total = consulted = degraded = closure_requested = 0
    try:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if not isinstance(r, dict):
                continue
            total += 1
            has_closure_key = ("closure_consulted" in r) or ("closure_degraded" in r)
            if has_closure_key:
                closure_requested += 1
            if r.get("closure_consulted"):
                consulted += 1
            if r.get("closure_degraded"):
                degraded += 1
    except OSError as exc:
        return {"schema": SCHEMA, "verdict": "error", "reason": f"cannot read dataflow_paths.jsonl: {exc}"}

    if closure_requested == 0:
        return {"schema": SCHEMA, "verdict": "pass", "total_records": total,
                "reason": "closure correction not requested on any record (--closure-unguarded off); nothing to verify"}
    denom = consulted + degraded
    frac = (degraded / denom) if denom else 1.0
    try:
        max_frac = float(os.environ.get("AUDITOOOR_CLOSURE_MAX_DEGRADE_FRACTION", _DEFAULT_MAX_DEGRADE_FRACTION))
    except (TypeError, ValueError):
        max_frac = _DEFAULT_MAX_DEGRADE_FRACTION
    payload = {"schema": SCHEMA, "total_records": total,
               "closure_requested": closure_requested, "closure_consulted": consulted,
               "closure_degraded": degraded, "degrade_fraction": round(frac, 4),
               "max_degrade_fraction": max_frac}
    if consulted == 0 or frac > max_frac:
        payload["verdict"] = "FLAG"
        payload["reason"] = (f"closure pass DEGRADED: {degraded}/{denom} records degraded "
                             f"(fraction {frac:.2f} > {max_frac}); the inter-procedural closure "
                             "correction did not run - unguarded/negative-space results are unreliable "
                             "(predicates unimportable / Slither broken). Fix the closure toolchain + re-slice.")
        return payload
    payload["verdict"] = "pass"
    payload["reason"] = f"closure healthy: {consulted} consulted, {degraded} degraded ({frac:.2f} <= {max_frac})"
    return payload


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("workspace")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    rep = check(Path(a.workspace).expanduser())
    if a.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"[closure-health-check] {rep['verdict']}: {rep.get('reason','')}")
    strict = os.environ.get("AUDITOOOR_CLOSURE_DEGRADE_STRICT", "").strip().lower() in ("1", "true", "yes", "on")
    if rep["verdict"] in ("FLAG", "fail") and strict:
        return 1
    if rep["verdict"] == "error":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
