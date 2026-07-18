#!/usr/bin/env python3
"""mechanism-scan-run - run every applicable mechanism detector on a workspace and
write the common .auditooor/mechanism_scan/<mechanism>.json sidecars the
completeness-matrix v2 mechanism axis consumes.

This is the DRIVER that populates the impact x mechanism plane: without it the
mechanism cells stay 'not-enumerated-unscanned' forever. Each detector is
language-gated (only run on a workspace whose in-scope languages match), imported
by file path, and invoked via its scan_root(root) entrypoint. A detector that
finds nothing writes a clean sidecar (0 findings => the cell is enumerated-clean);
a detector that fires writes its findings (the cell becomes an OPEN obligation the
auditor must verify->paste-ready or refute->mechanism_dispositions.jsonl).

Generic: no workspace/target literal; the detector registry is the single list to
grow as new mechanism detectors ship.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_DET = _HERE / "detectors"

# (module_basename, mechanism, impact, languages, advisory). advisory=True detectors
# are WIRED + runnable but INCLUDED only when AUDITOOOR_MECH_ADVISORY_DETECTORS=1
# (default OFF) - so a NEW mechanism cell cannot retroactively re-open a parked audit
# until the completeness-matrix mechanism axis is taught to consume it under STRICT
# (advisory-first promotion). Legacy 4-tuples default advisory=False.
_REGISTRY = [
    ("go_ast_consensus_hook_unbounded_iteration", "consensus-hook-unbounded-iteration", "chain-halt", ["go"], False),
    ("go_ast_msgserver_missing_authority_sibling_asymmetry", "missing-authority-gate-sibling-asymmetry", "direct-theft", ["go"], False),
    ("sol_ast_unbounded_attacker_growable_iteration", "unbounded-attacker-growable-iteration", "permanent-freeze", ["solidity"], False),
    ("rust_substrate_hook_unbounded_iteration", "consensus-hook-unbounded-iteration", "chain-halt", ["rust"], False),
    ("move_block_callback_unbounded_iteration", "consensus-hook-unbounded-iteration", "chain-halt", ["move"], False),
    # G-4 / G-15 (enforcement-gap 2026-07-03) - advisory-first until the matrix axis consumes them.
    ("sol_reentrancy_callback_surface", "reentrancy-callback-surface", "direct-theft", ["solidity"], True),
    ("sol_upgradeable_storage_collision_surface", "storage-collision-upgradeable", "permanent-freeze", ["solidity"], True),
]
_ADVISORY_DETECTORS_ENV = "AUDITOOOR_MECH_ADVISORY_DETECTORS"

_EXT_LANG = {".go": "go", ".sol": "solidity", ".rs": "rust", ".move": "move",
             ".cairo": "zk", ".circom": "zk", ".vy": "vyper"}


def _ws_languages(ws: Path) -> set[str]:
    """Languages present in the in-scope manifest (falls back to a src walk)."""
    langs: set[str] = set()
    man = ws / ".auditooor" / "inscope_units.jsonl"
    if man.is_file():
        for line in man.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            ext = os.path.splitext(str(r.get("file", "")))[1].lower()
            if ext in _EXT_LANG:
                langs.add(_EXT_LANG[ext])
    if langs:
        return langs
    for dp, dns, fns in os.walk(ws / "src"):
        dns[:] = [d for d in dns if not d.startswith(".") and d not in ("vendor", "node_modules")]
        for fn in fns:
            ext = os.path.splitext(fn)[1].lower()
            if ext in _EXT_LANG:
                langs.add(_EXT_LANG[ext])
    return langs


def _load_detector(module_base: str):
    path = _DET / (module_base + ".py")
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("mech_det_" + module_base, path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod if hasattr(mod, "scan_root") else None


def _src_root(ws: Path) -> Path:
    s = ws / "src"
    return s if s.is_dir() else ws


def run(ws: Path) -> dict:
    langs = _ws_languages(ws)
    out_dir = ws / ".auditooor" / "mechanism_scan"
    out_dir.mkdir(parents=True, exist_ok=True)
    root = _src_root(ws)
    ran, skipped, fired = [], [], []
    _advisory_on = os.environ.get(_ADVISORY_DETECTORS_ENV, "").strip().lower() in ("1", "true", "yes", "on")
    for _row in _REGISTRY:
        module_base, mechanism, impact, det_langs = _row[0], _row[1], _row[2], _row[3]
        _advisory = _row[4] if len(_row) > 4 else False
        if _advisory and not _advisory_on:
            skipped.append({"detector": module_base, "reason": "advisory-detector-not-promoted"})
            continue
        if langs and det_langs and not (langs & set(det_langs)):
            skipped.append({"detector": module_base, "reason": "language-not-in-scope"})
            continue
        mod = _load_detector(module_base)
        if mod is None:
            skipped.append({"detector": module_base, "reason": "detector-unavailable"})
            continue
        try:
            rep = mod.scan_root(str(root))
        except Exception as exc:
            skipped.append({"detector": module_base, "reason": f"scan-error: {exc}"})
            continue
        findings = rep.get("findings", []) if isinstance(rep, dict) else []
        sidecar = {
            "schema": "auditooor.mechanism_scan.v1",
            "detector": module_base,
            "mechanism": mechanism,
            "impact": impact,
            "root": str(root),
            "findings": findings,
            "finding_count": len(findings),
        }
        (out_dir / f"{mechanism}.json").write_text(
            json.dumps(sidecar, indent=2, sort_keys=True), encoding="utf-8")
        ran.append({"detector": module_base, "mechanism": mechanism, "findings": len(findings)})
        if findings:
            fired.append({"detector": module_base, "mechanism": mechanism, "findings": len(findings)})
    return {"schema": "auditooor.mechanism_scan_run.v1", "ws": str(ws),
            "ws_languages": sorted(langs), "ran": ran, "fired": fired,
            "skipped": skipped, "sidecar_dir": str(out_dir)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workspace", "--ws", dest="ws", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    rep = run(Path(args.ws).expanduser().resolve())
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"[mechanism-scan-run] langs={rep['ws_languages']} "
              f"ran={len(rep['ran'])} fired={len(rep['fired'])} skipped={len(rep['skipped'])}")
        for f in rep["fired"]:
            print(f"  FIRED {f['mechanism']} ({f['detector']}): {f['findings']} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
