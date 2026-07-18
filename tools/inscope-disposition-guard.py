#!/usr/bin/env python3
"""inscope-disposition-guard - fail CLOSED when ANY disposition marks an
IN-SCOPE unit out-of-scope (vendored / trusted / OOS / not-in-scope).

THE generic, language-agnostic backstop for the strata 2026-07-01 class: a
disposition tool (unhunted-surface-adjudicate, exploit-class-coverage,
trusted-infra-compromise, per-finding-oos, ...) auto-closed an IN-SCOPE
first-party unit as out-of-scope using a local heuristic that contradicted the
authoritative `inscope_units.jsonl` manifest. The producer fix lives in each
tool; THIS gate is the whole-workspace safety net that catches ANY regression
in ANY tool for ANY language, so a wrongly-scoped closure can never silently
green audit-complete again.

It scans every `.auditooor/*.json(l)` disposition/verdict artifact for records
that BOTH (a) carry an OOS-family class/verdict token AND (b) reference a file
that is IN the in-scope manifest. Any such record is a wrong closure.

Verdicts:
  pass-no-inscope-oos     - no in-scope unit carries an OOS-family disposition
  pass-no-manifest        - inscope_units.jsonl absent/empty (cannot assert;
                            setup not run) - advisory pass, not a false green
  fail-inscope-marked-oos - >=1 in-scope unit closed out-of-scope (listed)

Exit 0 on pass-*, 1 on fail-*. Language-agnostic: keys on file paths + the
manifest, never on extension or contract idiom.
"""
from __future__ import annotations

import argparse
import glob
import importlib.util
import json
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load_scope_authority():
    spec = importlib.util.spec_from_file_location(
        "scope_authority", str(_HERE / "scope_authority.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


SA = _load_scope_authority()

# JSON keys that may carry a disposition class / verdict / status token.
_CLASS_KEYS = ("evidence_class", "verdict", "status", "disposition", "class",
               "evidence_klass", "closure_class", "resolution",
               "disposition_type", "disposition_class")
# JSON keys that may carry the referenced source file.
_REF_KEYS = ("evidence_ref", "file", "file_line", "path", "source_ref",
             "unit", "target", "file_path", "ref")
# artifacts that are NOT dispositions (skip - they legitimately hold OOS text)
_SKIP_NAMES = {
    "inscope_units.jsonl", "scope.md", "severity.md",
    "bug_bounty_oos_index.json", "operator_oos.json",
}


def _iter_records(obj):
    """Yield dict records from a parsed JSON payload (list, dict-of-lists, or
    a top-level dict with a 'verdicts'/'classes'/'records' array)."""
    if isinstance(obj, list):
        for x in obj:
            if isinstance(x, dict):
                yield x
        return
    if isinstance(obj, dict):
        for arr_key in ("verdicts", "classes", "records", "dispositions",
                        "leads", "entries", "items"):
            arr = obj.get(arr_key)
            if isinstance(arr, list):
                for x in arr:
                    if isinstance(x, dict):
                        yield x
        # a dict that is itself one record
        if any(k in obj for k in _CLASS_KEYS):
            yield obj


def _record_class_tokens(rec: dict):
    for k in _CLASS_KEYS:
        v = rec.get(k)
        if isinstance(v, str) and v.strip():
            yield v


def _record_ref(rec: dict) -> str:
    for k in _REF_KEYS:
        v = rec.get(k)
        if isinstance(v, str) and v.strip():
            return v
    # nested function_anchor.file
    fa = rec.get("function_anchor")
    if isinstance(fa, dict):
        f = fa.get("file") or fa.get("file_path") or ""
        if isinstance(f, str) and f.strip():
            return f
    return ""


def evaluate(ws: str) -> dict:
    ws_path = Path(ws)
    ins = SA.load_inscope(ws_path)
    if not ins.present:
        return {"verdict": "pass-no-manifest", "workspace": str(ws_path),
                "violations": [], "note": "inscope_units.jsonl absent/empty; cannot assert scope"}
    adir = ws_path / ".auditooor"
    violations = []
    scanned = 0
    files = glob.glob(str(adir / "*.json")) + glob.glob(str(adir / "*.jsonl"))
    for fp in sorted(files):
        name = Path(fp).name.lower()
        if name in _SKIP_NAMES:
            continue
        try:
            text = Path(fp).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # support both a single JSON doc and JSONL
        payloads = []
        try:
            payloads.append(json.loads(text))
        except ValueError:
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    payloads.append(json.loads(line))
                except ValueError:
                    continue
        for obj in payloads:
            for rec in _iter_records(obj):
                tokens = list(_record_class_tokens(rec))
                if not any(SA.is_oos_family(t) for t in tokens):
                    continue
                ref = _record_ref(rec)
                if not ref:
                    continue
                if SA.is_inscope_file(ws_path, ref):
                    scanned += 1
                    violations.append({
                        "artifact": Path(fp).name,
                        "ref": ref,
                        "oos_class": next((t for t in tokens if SA.is_oos_family(t)), ""),
                        "title": str(rec.get("title", ""))[:120],
                    })
    if violations:
        return {"verdict": "fail-inscope-marked-oos", "workspace": str(ws_path),
                "violations": violations,
                "note": f"{len(violations)} in-scope unit(s) closed out-of-scope - "
                        "an in-scope first-party unit can never be OOS/vendored/trusted"}
    return {"verdict": "pass-no-inscope-oos", "workspace": str(ws_path),
            "violations": [], "inscope_files": len(ins.basenames)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    rep = evaluate(args.workspace)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"[inscope-disposition-guard] verdict: {rep['verdict']}")
        for v in rep.get("violations", []):
            print(f"  WRONG-OOS: {v['ref']}  [{v['oos_class']}]  in {v['artifact']}")
        if rep.get("note"):
            print(f"  {rep['note']}")
    return 0 if rep["verdict"].startswith("pass-") else 1


if __name__ == "__main__":
    sys.exit(main())
