#!/usr/bin/env python3
"""CUT-pristine guard: the audited source MUST equal its committed pin before any
baseline/fuzz/mutation-verify result is trusted.

WHY (the 2026-06-23 SSV poison): a coverage-guided campaign's "all invariants
passing" verdict is only meaningful against the PRISTINE audit-pin contract. A
mutation-verify run that mutates source in place restores from an in-memory copy
captured at entry - but when several per-function runs mutate the SAME source
files CONCURRENTLY, each captures a sibling's in-flight mutant as its "original",
and a hard kill (SIGKILL bypasses the SIGTERM/finally restore) leaves mutants on
disk. The workspace tree was thus left with 4 mutation-testing operators in
contracts/modules/{SSVClusters,SSVOperators}.sol; every subsequent echidna
baseline ran against MUTATED code, so its passing/falsifying verdicts were
meaningless (one campaign "found a bug" that was just the seeded mutant). Nothing
flagged it - build-readiness passed (a mutant still COMPILES).

This guard fails closed: it asserts the first-party CUT source has NO uncommitted
edits vs HEAD (or a recorded audit pin). Wire it as a preflight before genuine-
coverage / invariant-fuzz / any baseline campaign. It is GENERIC (any git-tracked
workspace, any language) and cheap (git diff). Test/PoC/harness dirs are EXCLUDED -
authoring a harness or PoC is expected and does not invalidate a baseline; only
edits to the contract/source-under-test do.

Exit 1 (with --check) only when CUT source is dirty. Opt out with
AUDITOOOR_CUT_PRISTINE_BYPASS=1 (audit-logged by the caller).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

# Directories whose edits do NOT invalidate a baseline (authoring is expected).
_EXCLUDE_SEGMENTS = (
    "/test/", "/tests/", "/mock", "/mocks/", "/script/", "/scripts/",
    "/.auditooor/", "/node_modules/", "/lib/", "/out/", "/cache/",
    "/prior_audits/", "/echidna/", "/halmos/", "/certora/", "/fuzz/",
)
# First-party source roots we care about (the CUT). Generic across languages.
_SRC_HINTS = ("contracts/", "src/", "/modules/", "/libraries/")


def _git(ws: Path, *args: str) -> tuple[int, str]:
    try:
        p = subprocess.run(
            ["git", "-C", str(ws), *args],
            capture_output=True, text=True, timeout=60,
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)


def _is_cut_path(rel: str) -> bool:
    low = "/" + rel.replace("\\", "/").lower()
    if any(seg in low for seg in _EXCLUDE_SEGMENTS):
        return False
    # source-ish extensions only
    if not low.endswith((".sol", ".rs", ".go", ".move", ".cairo", ".vy")):
        return False
    return any(h in low for h in _SRC_HINTS) or low.endswith(".sol")


def find_git_root(start: Path) -> Path | None:
    rc, out = _git(start, "rev-parse", "--show-toplevel")
    if rc == 0 and out.strip():
        return Path(out.strip())
    return None


def evaluate(ws: Path, ref: str = "HEAD") -> dict:
    """Return a verdict dict. status in {pristine, dirty, not-a-git-repo, error}."""
    git_root = find_git_root(ws)
    if git_root is None:
        return {"status": "not-a-git-repo", "ws": str(ws),
                "reason": "not inside a git work tree; cannot assert CUT pristine"}
    rc, out = _git(git_root, "diff", "--name-only", ref, "--")
    if rc != 0:
        return {"status": "error", "ws": str(ws), "reason": out.strip()[:300]}
    changed = [l.strip() for l in out.splitlines() if l.strip()]
    cut_dirty = [c for c in changed if _is_cut_path(c)]
    if not cut_dirty:
        return {"status": "pristine", "ws": str(ws), "ref": ref,
                "cut_dirty": [], "non_cut_changed": len(changed)}
    # gather a short per-file diffstat for the dirty CUT files
    rc2, stat = _git(git_root, "diff", "--stat", ref, "--", *cut_dirty)
    return {
        "status": "dirty",
        "ws": str(ws),
        "ref": ref,
        "git_root": str(git_root),
        "cut_dirty": cut_dirty,
        "diffstat": stat.strip().splitlines()[-12:] if rc2 == 0 else [],
        "restore_cmd": "git -C %s checkout %s -- %s"
                       % (git_root, ref, " ".join(cut_dirty)),
        "reason": ("%d audited source file(s) have uncommitted edits vs %s - a "
                   "baseline/fuzz/mutation result against this tree is INVALID "
                   "(likely leftover mutation-test operators from an interrupted "
                   "run). Restore the pin before trusting coverage." )
                  % (len(cut_dirty), ref),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("workspace")
    ap.add_argument("--ref", default="HEAD",
                    help="git ref the CUT must match (default HEAD = audit pin)")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 when CUT source is dirty")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    ws = Path(args.workspace).resolve()

    if os.environ.get("AUDITOOOR_CUT_PRISTINE_BYPASS"):
        rep = {"status": "bypassed", "reason": "AUDITOOOR_CUT_PRISTINE_BYPASS=1"}
        print(json.dumps(rep) if args.json else "[cut-pristine] BYPASSED (env)")
        return 0

    rep = evaluate(ws, ref=args.ref)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        st = rep["status"]
        if st == "pristine":
            print("[cut-pristine] pristine: audited source matches %s" % rep.get("ref"))
        elif st == "dirty":
            print("[cut-pristine] DIRTY: %s" % rep["reason"])
            for f in rep["cut_dirty"]:
                print("    %s" % f)
            print("  restore: %s" % rep["restore_cmd"])
        else:
            print("[cut-pristine] %s: %s" % (st, rep.get("reason", "")))
    if args.check and rep["status"] == "dirty":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
