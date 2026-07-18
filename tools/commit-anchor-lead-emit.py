#!/usr/bin/env python3
"""commit-anchor-lead-emit - under PRIMACY-OF-RULES, turn each OUT-OF-SCOPE
security-shaped fix-commit into an IN-SCOPE anchor-hunt lead.

Operator principle (strata 2026-07-02): GitHub mining is UNRESTRICTED even under
primacy-of-rules - you read the whole repo (OOS files, history, parallel
implementations) freely; the rules only bound WHERE a finding may LAND (an in-scope
asset), not what you may MINE as an anchor. So an OOS fix-commit whose bug-pattern
also lives unfixed in an IN-SCOPE twin is an in-scope finding. The commit-adjudication
gate AUTO-CLEARS OOS commits under rules mode (correct for filing) - which silently
drops their ANCHOR value. This tool recovers it: for each OOS-production security-
shaped commit it emits an anchor-hunt lead naming the IN-SCOPE sibling(s) to check for
the same unfixed pattern, so the anchor avenue fires automatically instead of by hand.

A sibling is an in-scope contract that either (a) shares >=1 base interface with the
OOS contract (e.g. OOS DYSAccounting `is IAccounting` <-> in-scope Accounting `is
IAccounting`), or (b) has a matching name-stem (Discrete/DYS/Mock/Abstract prefix or
Lens/Base/Impl/Upgradeable suffix stripped -> common stem).

Output: <ws>/.auditooor/anchor_leads.jsonl - one row per (anchor_sha, oos_file,
in_scope_sibling). Consumed by the step-3 hunt (dispatch one anchor-hunt per lead:
"does the in-scope sibling share the OOS-fixed bug at the pin?"). Language-agnostic
on the git/scope side; the contract-base parse is Solidity-first with a generic
name-stem fallback for other languages.

ONLY emits under primacy-of-RULES (the mode where OOS auto-clears and anchors would
otherwise be lost). Under primacy-of-IMPACT the adjudication gate already forces the
OOS mechanism to be reasoned about, so no separate anchor lead is needed.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _load(mod_file: str, name: str):
    spec = importlib.util.spec_from_file_location(name, _REPO_ROOT / "tools" / mod_file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


CAJ = _load("commit-adjudication-completeness-check.py", "_caj_anchor")
SA = CAJ.SA

# Solidity contract/interface declaration -> its base list.
_DECL_RE = re.compile(
    r"\b(?:abstract\s+contract|contract|interface|library)\s+([A-Za-z_]\w*)"
    r"\s*(?:is\s+([^{]+))?\{", re.MULTILINE)
_STEM_STRIP_PREFIX = ("discrete", "dys", "mock", "abstract", "base", "test", "i")
_STEM_STRIP_SUFFIX = ("lens", "base", "impl", "upgradeable", "lib", "v2", "v3",
                      "mock", "test", "harness")


def _bases_of(text: str) -> dict[str, set]:
    """map declared contract/interface name -> set of base names it inherits."""
    out: dict[str, set] = {}
    for m in _DECL_RE.finditer(text or ""):
        name = m.group(1)
        bases = set()
        if m.group(2):
            for b in re.split(r"[,\s]+", m.group(2).strip()):
                b = b.split("(", 1)[0].strip()
                if b:
                    bases.add(b)
        out[name] = bases
    return out


def _name_stem(basename: str) -> str:
    stem = re.sub(r"\.(sol|rs|go|vy|move)$", "", str(basename or ""), flags=re.I).lower()
    changed = True
    while changed:
        changed = False
        for p in _STEM_STRIP_PREFIX:
            if stem.startswith(p) and len(stem) > len(p) + 2:
                stem = stem[len(p):]; changed = True
        for s in _STEM_STRIP_SUFFIX:
            if stem.endswith(s) and len(stem) > len(s) + 2:
                stem = stem[:-len(s)]; changed = True
    return stem


def _inscope_index(ws: Path, repo: Path | None) -> list[dict]:
    """for each in-scope file: {basename, path, bases, stem}."""
    ins = SA.load_inscope(ws)
    idx = []
    if not ins.present:
        return idx
    for bn in sorted(ins.basenames):
        p = None
        if repo:
            hits = [h for h in repo.rglob(bn) if "/lib/" not in str(h) and "node_modules" not in str(h)]
            p = hits[0] if hits else None
        bases: set = set()
        if p and p.is_file():
            for _n, bs in _bases_of(p.read_text(encoding="utf-8", errors="replace")).items():
                bases |= bs
        idx.append({"basename": bn, "path": str(p) if p else "", "bases": bases,
                    "stem": _name_stem(bn)})
    return idx


def _siblings_for(oos_path: Path, inscope_idx: list[dict]) -> list[dict]:
    try:
        txt = oos_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    oos_bases: set = set()
    for _n, bs in _bases_of(txt).items():
        oos_bases |= bs
    oos_stem = _name_stem(oos_path.name)
    sibs = []
    for e in inscope_idx:
        if e["basename"] == oos_path.name:
            continue
        shared = sorted(oos_bases & e["bases"])
        stem_match = bool(oos_stem) and oos_stem == e["stem"]
        if shared or stem_match:
            sibs.append({"in_scope_file": e["basename"],
                         "match": ("shared-interface:" + ",".join(shared)) if shared
                                  else f"name-stem:{oos_stem}"})
    return sibs


def emit(ws: Path) -> dict:
    mode = CAJ._scope_mode(ws)
    if mode != "rules":
        return {"emitted": 0, "scope_mode": mode, "leads": [],
                "note": "primacy-of-impact: the adjudication gate already forces OOS "
                        "mechanisms to be reasoned about; no separate anchor lead needed"}
    residual = CAJ._residual_security_commits(ws)
    repo = CAJ._find_src_repo(ws)
    inscope_idx = _inscope_index(ws, repo)
    leads = []
    for c in residual:
        sha = c["sha"]
        touched = CAJ._touched_files(repo, sha) if repo else None
        if not touched:
            continue
        for f in touched:
            if not CAJ._is_production_file(f):
                continue
            if SA.is_inscope_file(ws, f):
                continue  # in-scope commit is the adjudication gate's job, not an anchor
            oos_path = (repo / f) if repo else None
            if not (oos_path and oos_path.is_file()):
                # still emit a bare lead (no sibling resolution possible)
                leads.append({"anchor_sha": sha, "oos_file": f, "in_scope_siblings": [],
                              "hint": c["hint"]})
                continue
            sibs = _siblings_for(oos_path, inscope_idx)
            if sibs:
                leads.append({"anchor_sha": sha, "oos_file": f,
                              "in_scope_siblings": sibs, "hint": c["hint"]})
    # dedupe identical (sha, oos_file)
    seen = set(); uniq = []
    for l in leads:
        k = (l["anchor_sha"], l["oos_file"])
        if k in seen:
            continue
        seen.add(k); uniq.append(l)
    out_path = ws / ".auditooor" / "anchor_leads.jsonl"
    if uniq:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(json.dumps(l) for l in uniq) + "\n", encoding="utf-8")
    return {"emitted": len(uniq), "scope_mode": mode,
            "with_siblings": sum(1 for l in uniq if l["in_scope_siblings"]),
            "path": str(out_path), "leads": uniq}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ws", "--workspace", dest="ws", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    rep = emit(Path(a.ws))
    if a.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"[commit-anchor-lead-emit] mode={rep['scope_mode']} emitted={rep['emitted']} "
              f"anchor lead(s) (with in-scope siblings: {rep.get('with_siblings', 0)})")
        for l in rep["leads"][:20]:
            sibs = ", ".join(s["in_scope_file"] for s in l["in_scope_siblings"]) or "(no sibling resolved)"
            print(f"  {l['anchor_sha'][:12]}  {l['oos_file']}  ->  {sibs}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
