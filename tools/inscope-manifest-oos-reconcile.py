#!/usr/bin/env python3
"""inscope-manifest-oos-reconcile - drop from inscope_units.jsonl any unit whose
file carries an EXPLICIT, SCOPE.md-cited out-of-scope adjudication.

Why this exists (Strata 2026-07-07, operator-caught): the manifest producer
(workspace-coverage-heatmap.py::write_inscope_manifest) enumerates first-party
code transitively and can pull in files SCOPE.md EXCLUDES - e.g. read-only view
helpers under `lens/` that move no value. On Strata that put 17 CDOLens units in
inscope_units.jsonl even though `contracts/lens/CDOLens.sol` is not among the
in-scope targets. That single manifest/SCOPE.md contradiction (a) trips
inscope-disposition-guard (a valid `verdict:oos` adjudication points at a file the
manifest calls in-scope) and (b) inflates the function-coverage denominator with
units that can never be legitimately covered - so the audit can never reach 100%.

This is a RECONCILIATION, not a scope weakening: it removes a manifest unit ONLY
when an adjudication artifact ALREADY dispositioned that unit's file OOS with a
cited reason. It never invents an OOS verdict, never touches a value-mover that
lacks an OOS adjudication, backs up the original manifest, and logs every dropped
unit + the citing reason so the change is fully auditable. The real producer fix
(teach write_inscope_manifest to honor SCOPE.md carve-outs) is upstream; this
closes the loop deterministically for any workspace where the contradiction exists.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_OOS_VERDICTS = {"oos", "out-of-scope", "out_of_scope", "not-in-scope", "not_in_scope"}


def _oos_adjudicated_files(ws: Path) -> dict:
    """basename -> reason, for every verdict:oos adjudication that cites a reason.
    Scans commit_adjudications.jsonl (+ any *adjudication*.jsonl) for OOS records.
    A record must carry a non-empty reason so a bare 'oos' can never silently drop
    a value-mover."""
    out = {}
    import glob
    for p in glob.glob(str(ws / ".auditooor" / "*adjudication*.jsonl")):
        for line in Path(p).read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(j, dict):
                continue
            v = str(j.get("verdict", "")).lower().replace(" ", "-")
            reason = str(j.get("reason", "")).strip()
            ref = j.get("source_ref") or j.get("file") or ""
            if v in _OOS_VERDICTS and reason and ref:
                # strip any :line suffix, key by basename AND relpath
                base = os.path.basename(str(ref).split(":")[0])
                if base.endswith((".sol", ".rs", ".go", ".vy", ".cairo", ".move", ".nr")):
                    out[base] = reason
    return out


def reconcile(ws: Path, apply: bool) -> dict:
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file():
        return {"verdict": "pass-no-manifest", "dropped": [], "kept": 0}
    oos = _oos_adjudicated_files(ws)
    kept, dropped = [], []
    for line in manifest.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            u = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            kept.append(line)
            continue
        base = os.path.basename(str(u.get("file", "")))
        if base in oos:
            dropped.append({"file": u.get("file"), "function": u.get("function"),
                            "reason": oos[base]})
        else:
            kept.append(line)
    res = {
        "verdict": "reconciled" if dropped else "pass-no-oos-units-in-manifest",
        "oos_adjudicated_files": sorted(oos.keys()),
        "dropped_count": len(dropped),
        "kept_count": len(kept),
        "dropped": dropped,
    }
    if apply and dropped:
        # back up original once, then rewrite + log
        bak = manifest.with_suffix(".jsonl.pre_oos_reconcile")
        if not bak.exists():
            bak.write_text(manifest.read_text(errors="ignore"))
        manifest.write_text("\n".join(kept) + "\n")
        log = ws / ".auditooor" / "inscope_oos_reconcile_log.json"
        log.write_text(json.dumps(res, indent=2))
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("workspace")
    ap.add_argument("--apply", action="store_true",
                    help="rewrite inscope_units.jsonl (default: dry-run report only)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    ws = Path(args.workspace).resolve()
    res = reconcile(ws, args.apply)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"[inscope-oos-reconcile] {res['verdict']}: "
              f"{res.get('dropped_count', 0)} unit(s) dropped "
              f"({'APPLIED' if args.apply else 'dry-run'}), {res.get('kept_count', 0)} kept")
        for d in res.get("dropped", [])[:20]:
            print(f"   DROP {d['file']}::{d['function']}  <- {d['reason'][:70]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
