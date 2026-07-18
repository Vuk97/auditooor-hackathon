#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-FORGE-BUILD-READINESS registered via agent-pathspec-register.py -->
"""Forge build-readiness precheck: assert the Solidity TEST TREE compiles BEFORE
the genuine-coverage / per-fn mutation-verify pass runs.

WHY (SSV loop 2026-06-23, the "0/N silent" class)
--------------------------------------------------
The per-function mutation-verify runs `forge test --match-contract Halmos_<C>_<fn>`.
If `forge` cannot COMPILE the project (broken remappings, a pragma conflict between
a harness and its CUT, a stray/leftover test file with a bad import, etc.), forge
runs 0 tests and exits - which the runner records as `no-execution` per harness ->
the gate reports 0/N genuine and `live-engines`/`hollow` stay red. The build break
is the ROOT cause but it surfaces many steps downstream as a mysterious empty result.

This precheck runs `forge build` once per foundry root and FAILS LOUDLY with the
exact compiler error, so the operator fixes the build BEFORE step-4b instead of
chasing a phantom 0/N. It is offline-safe: if `forge` is not installed it returns a
non-fatal `toolchain-absent` (the genuine-coverage pass is already skipped in that
case).

Verdicts: pass-build-ready | fail-build-broken | toolchain-absent | no-foundry-root
Exit: 0 = pass / toolchain-absent / no-foundry-root (advisory); 1 = fail-build-broken
(only in --check mode).
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

SCHEMA = "auditooor.forge_build_readiness.v1"
_HERE = Path(__file__).resolve().parent
# Dirs that are never a first-party foundry root worth build-checking.
_PRUNE = {".git", "node_modules", "lib", "out", "cache", "artifacts", "broadcast",
          "prior_audits", "reference", "submissions", "agent_outputs", ".auditooor"}


def _forge_bin() -> str | None:
    resolver = _HERE / "lib" / "forge-resolve.sh"
    if resolver.is_file():
        try:
            out = subprocess.run(["bash", str(resolver)], capture_output=True,
                                 text=True, timeout=30)
            for line in (out.stdout or "").splitlines():
                line = line.strip()
                if line and Path(line).name == "forge" and Path(line).exists():
                    return line
        except Exception:  # noqa: BLE001
            pass
    return shutil.which("forge")


def _foundry_roots(ws: Path) -> list[Path]:
    roots: list[Path] = []
    for p in ws.rglob("foundry.toml"):
        if any(seg in _PRUNE for seg in p.relative_to(ws).parts):
            continue
        roots.append(p.parent)
    # de-dupe + stable order
    seen: set[str] = set()
    out: list[Path] = []
    for r in sorted(roots, key=lambda x: len(x.parts)):
        if str(r) not in seen:
            seen.add(str(r))
            out.append(r)
    return out


def _quarantine_engine_reproducers(ws: Path, root: Path) -> list[str]:
    """Move echidna/medusa-generated CORPUS REPRODUCER .sol files out of the
    compiled tree so they cannot poison `forge build`.

    WHY (SSV loop 2026-06-23, second-order poison): when a coverage-guided campaign
    FALSIFIES a property, echidna writes foundry-format reproducers to
    `test/echidna/corpus/<name>/foundry/Test.<n>.sol`. With foundry.toml `test =
    "test"`, `forge build` then tries to COMPILE those malformed reproducer stubs
    (`Identifier not found`), breaking the WHOLE project compile - so every later
    `forge build` / per-fn mutation-verify baseline fails (blocked-by-sibling-compile)
    even though no first-party file changed. The build passes BEFORE the first
    falsification and breaks AFTER it - a baffling, order-dependent symptom. These
    reproducers are regenerable artifacts (the call sequence is in the engine log),
    so we QUARANTINE (not delete) them under .auditooor/ - out of the compiled tree
    but preserved. Generic across any forge workspace that runs echidna/medusa with a
    corpusDir inside test/."""
    moved: list[str] = []
    qroot = ws / ".auditooor" / "engine_reproducer_quarantine"
    try:
        candidates = [
            p for p in root.rglob("*.sol")
            if "/corpus/" in ("/" + str(p.relative_to(root)).replace("\\", "/") + "/")
        ]
    except (OSError, ValueError):
        candidates = []
    for p in candidates:
        try:
            rel = p.relative_to(ws)
        except ValueError:
            rel = p.name
        dest = qroot / rel
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(p), str(dest))
            moved.append(str(rel))
        except (OSError, shutil.Error):
            continue
    return moved


def evaluate(ws: Path, *, timeout: int = 600) -> dict:
    res = {"schema": SCHEMA, "workspace": str(ws), "verdict": "", "roots": []}
    forge = _forge_bin()
    roots = _foundry_roots(ws)
    # Pre-emptively quarantine engine reproducer .sol out of every compiled tree -
    # they are the #1 "build was fine, now it is broken" cause on fuzzed workspaces.
    quarantined: list[str] = []
    for root in roots:
        quarantined.extend(_quarantine_engine_reproducers(ws, root))
    if quarantined:
        res["quarantined_reproducers"] = quarantined
    if not roots:
        res["verdict"] = "no-foundry-root"
        res["reason"] = "no first-party foundry.toml found; nothing to build-check"
        return res
    if not forge:
        res["verdict"] = "toolchain-absent"
        res["reason"] = "forge not installed/resolvable; build-check skipped (offline-safe)"
        return res
    broken = []
    for root in roots:
        try:
            p = subprocess.run([forge, "build"], cwd=str(root), capture_output=True,
                               text=True, timeout=timeout)
            ok = p.returncode == 0
            out = ((p.stdout or "") + "\n" + (p.stderr or "")).strip()
        except subprocess.TimeoutExpired:
            ok, out = False, f"forge build TIMEOUT after {timeout}s"
        except Exception as exc:  # noqa: BLE001
            ok, out = False, f"forge build error: {exc}"
        row = {"root": str(root.relative_to(ws)) if root != ws else ".",
               "ok": ok}
        if not ok:
            # surface the compiler error (last lines are the actionable diagnostic)
            row["error_tail"] = "\n".join(out.splitlines()[-12:])
            broken.append(row)
        res["roots"].append(row)
    if broken:
        res["verdict"] = "fail-build-broken"
        res["reason"] = (f"{len(broken)} of {len(roots)} foundry root(s) FAIL forge "
                         f"build - the per-fn mutation-verify pass would silently "
                         f"record no-execution on every harness. Fix the build first.")
    else:
        res["verdict"] = "pass-build-ready"
        res["reason"] = f"all {len(roots)} foundry root(s) compile (forge build OK)"
    return res


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("workspace")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 on fail-build-broken (gate mode)")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    r = evaluate(Path(args.workspace).expanduser(), timeout=args.timeout)
    if args.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"[forge-build-readiness] {r['verdict']}: {r.get('reason','')}")
        for row in r.get("roots", []):
            if not row.get("ok"):
                print(f"  BROKEN {row['root']}:\n    " +
                      "\n    ".join(str(row.get("error_tail", "")).splitlines()[-6:]))
    if args.check and r["verdict"] == "fail-build-broken":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
