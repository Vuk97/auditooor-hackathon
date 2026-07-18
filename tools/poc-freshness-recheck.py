#!/usr/bin/env python3
"""poc-freshness-recheck.py - re-validate every paste-ready/filed finding's PoC
against the CURRENT pinned source, catching silent source-drift that invalidates
a PoC after it was authored.

Generic gap this closes (NUVA 2026-06-30): a finding's PoC compiles + PASSES at
authoring time (pre-submit-check.sh), but the audited project's source keeps
moving (re-pin each pass). A renamed/removed symbol then breaks the PoC build
WITHOUT anyone re-running it - e.g. the filed marker-NAV finding's PoC referenced
`VaultAccount.FeePeriodStart`, which upstream renamed to `PeriodStart`, so the
shipped zip no longer compiled (`go vet: FeePeriodStart undefined`) even though
the underlying bug is still live. A triager would hit a build failure. README
rule-5 mandates "re-verify it still reproduces each pass"; this automates the
compile-half of that check (cheap, high-signal) so a stale-PoC finding cannot be
declared file-ready.

Per finding under submissions/{paste_ready,filed,staging}/**:
  - Go PoC (*_test.go on disk OR inside a *.zip): resolve the target package
    (`package X[_test]` -> a dir under src/ declaring `package X`), copy the test
    in, `go vet ./<pkg>/` against current src, capture undefined/renamed-symbol
    drift, then REMOVE the temp file (git stays clean).
  - Solidity PoC (loose *.t.sol/*.sol under a finding root, OR an inline ```solidity
    block in the finding .md): resolve each `import "...sol"` path against the current
    source tree. An import whose .sol basename exists NOWHERE under the workspace
    references a renamed/removed source file (Strata 2026-07-07: a paste-ready PoC
    imported `AccountingLib.sol`, which the re-pin restructured away into
    Accounting.sol/DiscreteAccounting.sol, so the PoC no longer compiles). This is the
    Solidity analog of the Go undefined-symbol check - it was documented here but never
    implemented, so the gate vacuously passed every Solidity-only workspace.

Honest + non-destructive: only ever copies a PoC into a package dir and deletes
it again; never edits a finding, never edits src. Reports drift; does not fix it.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from go_toolchain_env import apply_go_toolchain as _apply_go_toolchain
except Exception:  # pragma: no cover - helper must be a sibling in tools/
    def _apply_go_toolchain(env, cwd, **_kw):  # type: ignore
        return ""

_FINDING_ROOTS = ("submissions/paste_ready", "submissions/filed", "submissions/staging")
_PKG_RE = re.compile(r"^\s*package\s+([A-Za-z_][A-Za-z0-9_]*)\s*$", re.M)
# Solidity import forms: `import "X.sol";`, `import {A} from "X.sol";`,
# `import * as N from "X.sol";`, `import X from "X.sol";`. Captures the path literal.
_SOL_IMPORT_RE = re.compile(
    r'^\s*import\s+(?:[^"\';]*\bfrom\s+)?["\']([^"\']+)["\']\s*;', re.M)
# Fenced ```solidity blocks inside a finding .md (inline PoCs that never hit disk as .sol).
_MD_SOL_BLOCK_RE = re.compile(r"```(?:solidity|sol)\s*\n(.*?)```", re.S | re.I)
_SOL_SKIP_DIRS = {".git", "out", "cache", "artifacts", "broadcast"}


def _workspace_sol_basenames(ws: Path) -> set[str]:
    """Every .sol file basename present in the CURRENT source tree (src + lib + vendored
    deps + co-located finding helpers). A PoC import whose basename is absent from this
    set references a source file that was renamed/removed since the PoC was authored -
    the Solidity analog of the Go 'undefined: <symbol>' drift signal. Basename (not full
    path) is used deliberately: it is remapping-agnostic (foundry.toml/remappings.txt
    rewrite import prefixes, so a full-path match would false-flag), catches the
    high-signal whole-file removal case, and mirrors resolve_go_pkg_dir's first-match
    semantics. It will not flag a file that merely MOVED (still low-FP by design)."""
    names: set[str] = set()
    for p in ws.rglob("*.sol"):
        if any(seg in _SOL_SKIP_DIRS for seg in p.parts):
            continue
        names.add(p.name)
    return names


def _sol_import_drift(src: str, sol_file: Path | None, basenames: set[str]) -> list[str]:
    """Imports in `src` whose .sol basename exists nowhere in the current source tree.
    A relative import that resolves on-disk from the PoC's own location is always fresh
    (short-circuits before the basename check) to avoid flagging a co-located helper."""
    drift = []
    for raw in _SOL_IMPORT_RE.findall(src):
        base = os.path.basename(raw.strip())
        if not base.endswith(".sol"):
            continue
        # 1. relative import that resolves directly from the PoC file -> fresh.
        if sol_file is not None and raw.strip().startswith("."):
            cand = (sol_file.parent / raw.strip()).resolve()
            if cand.exists():
                continue
        # 2. basename present anywhere in the current tree -> resolvable, fresh.
        if base in basenames:
            continue
        drift.append(f"import \"{raw.strip()}\" -> {base} not found in current source tree")
    return drift


def recheck_sol_poc(ws: Path, src: str, basenames: set[str],
                    label: str, sol_file: Path | None) -> dict:
    """Freshness-check one Solidity PoC (loose .t.sol/.sol or an inline md block)."""
    rec = {"poc": label, "lang": "solidity", "compiles": None, "drift": [], "note": ""}
    if "import" not in src:
        rec["note"] = "no imports to resolve"
        rec["compiles"] = True
        return rec
    drift = _sol_import_drift(src, sol_file, basenames)
    if drift:
        rec["compiles"] = False
        rec["drift"] = drift
    else:
        rec["compiles"] = True
    return rec


def go_package_of(test_src: str) -> str | None:
    """Return the non-test package name a Go test belongs to (`keeper_test`->`keeper`)."""
    m = _PKG_RE.search(test_src)
    if not m:
        return None
    pkg = m.group(1)
    return pkg[:-5] if pkg.endswith("_test") else pkg


def find_go_module_roots(ws: Path) -> list[Path]:
    """Dirs under <ws>/src containing a go.mod (the audited Go modules)."""
    src = ws / "src"
    if not src.is_dir():
        return []
    return sorted({p.parent for p in src.rglob("go.mod") if p.is_file()})


def resolve_go_pkg_dir(module_root: Path, pkg: str) -> Path | None:
    """First dir under module_root whose non-test .go files declare `package pkg`."""
    try:
        for go in module_root.rglob("*.go"):
            if go.name.endswith("_test.go") or "/vendor/" in str(go):
                continue
            try:
                head = go.read_text(encoding="utf-8", errors="replace")[:4000]
            except OSError:
                continue
            m = _PKG_RE.search(head)
            if m and m.group(1) == pkg:
                return go.parent
    except Exception:  # noqa: BLE001
        pass
    return None


def classify_drift(vet_output: str) -> list[str]:
    """Extract source-drift signals (renamed/removed symbols) from `go vet` output."""
    sigs = []
    for line in vet_output.splitlines():
        low = line.lower()
        if ("undefined:" in low or "has no field or method" in low
                or "undeclared name" in low or "too many arguments" in low
                or "not enough arguments" in low or "cannot use" in low):
            sigs.append(line.strip())
    return sigs


def _go_compile_check(pkg_dir: Path, module_root: Path) -> tuple[bool, str]:
    """Compile the package's TEST binary against current source. Uses `go test -c`
    (the authoritative type-checker) NOT `go vet`: vet adds heuristic LINTs (e.g.
    unkeyed-struct-literal) that fail rc without being compile errors, and vet was
    observed to emit a spurious 'undefined' on an external test package that the
    real compiler did not (NUVA 2026-06-30). `go test -c` fails ONLY on genuine
    compile errors - exactly the source-drift signal we want."""
    env = dict(os.environ)
    # Honor the workspace's PINNED Go toolchain (go.work/go.mod), read generically from the
    # module - NEVER hardcode a version. Only if the ws pins nothing (and GOTOOLCHAIN is unset)
    # fall back to a stable default so an unpinned PoC still type-checks reproducibly.
    if not _apply_go_toolchain(env, module_root, log_prefix="poc-freshness-recheck"):
        env.setdefault("GOTOOLCHAIN", "go1.24.1")
    try:
        rel = "./" + str(pkg_dir.relative_to(module_root)) + "/"
    except ValueError:
        rel = "./..."
    try:
        r = subprocess.run(["go", "test", "-c", "-o", os.devnull, rel],
                           cwd=str(module_root), env=env,
                           capture_output=True, text=True, timeout=600)
        return r.returncode == 0, (r.stdout + r.stderr)
    except Exception as exc:  # noqa: BLE001
        return False, f"compile-invocation-error: {exc}"


def _extract_go_tests_from_zip(zp: Path, into: Path) -> list[Path]:
    out = []
    try:
        with zipfile.ZipFile(zp) as z:
            for n in z.namelist():
                if n.endswith("_test.go"):
                    dst = into / Path(n).name
                    dst.write_bytes(z.read(n))
                    out.append(dst)
    except Exception:  # noqa: BLE001
        pass
    return out


def recheck_go_poc(ws: Path, test_file: Path, modules: list[Path]) -> dict:
    """Copy a Go PoC test into its package dir, vet against current src, clean up."""
    src = test_file.read_text(encoding="utf-8", errors="replace")
    pkg = go_package_of(src)
    rec = {"poc": str(test_file), "lang": "go", "package": pkg,
           "compiles": None, "drift": [], "note": ""}
    if not pkg:
        rec["note"] = "no package declaration"
        return rec
    target = None
    for m in modules:
        target = resolve_go_pkg_dir(m, pkg)
        if target:
            mod_root = m
            break
    if not target:
        rec["note"] = f"package '{pkg}' not found in any src module (cannot place PoC)"
        return rec
    # BASELINE DIFF: `go vet ./pkg/` vets the WHOLE package, so a pre-existing nit
    # in a sibling _test.go (e.g. payout_test.go's unkeyed-struct-literal lint) would
    # false-attribute to the PoC. Vet the package WITHOUT the PoC first, then WITH it,
    # and count ONLY failures the PoC newly introduces. This isolates genuine
    # PoC-vs-source drift (undefined renamed symbol) from ambient package warnings.
    base_ok, base_out = _go_compile_check(target, mod_root)
    base_lines = {ln.strip() for ln in base_out.splitlines() if ln.strip()}
    dst = target / f"_pocfresh_{test_file.stem}.go"
    try:
        dst.write_text(src, encoding="utf-8")
        with_ok, with_out = _go_compile_check(target, mod_root)
        new_lines = [ln.strip() for ln in with_out.splitlines()
                     if ln.strip() and ln.strip() not in base_lines]
        new_drift = classify_drift("\n".join(new_lines))
        # Stale ONLY if the PoC introduces a NEW compile-class failure. If the package
        # was already failing baseline for ambient reasons and the PoC adds nothing
        # compile-breaking, the PoC itself is fresh (not stale).
        if new_drift:
            rec["compiles"] = False
            rec["drift"] = new_drift
        elif new_lines and not with_ok and base_ok:
            # PoC newly broke the build with non-classified errors -> still stale.
            rec["compiles"] = False
            rec["note"] = "PoC introduced a new build failure (non-classified)"
            rec["drift"] = new_lines[:5]
        else:
            rec["compiles"] = True
            if not base_ok:
                rec["note"] = "package has ambient vet warnings (pre-existing, not PoC-attributable)"
    finally:
        try:
            dst.unlink()
        except OSError:
            pass
    return rec


def recheck(ws: Path) -> dict:
    modules = find_go_module_roots(ws)
    sol_basenames = _workspace_sol_basenames(ws)
    results = []
    tmp = Path(tempfile.mkdtemp(prefix="pocfresh_"))
    for root_rel in _FINDING_ROOTS:
        root = ws / root_rel
        if not root.is_dir():
            continue
        # loose *_test.go PoCs
        for tf in root.rglob("*_test.go"):
            results.append(recheck_go_poc(ws, tf, modules))
        # zipped Go PoCs
        for zp in root.rglob("*.zip"):
            for tf in _extract_go_tests_from_zip(zp, tmp):
                r = recheck_go_poc(ws, tf, modules)
                r["poc"] = f"{zp} :: {tf.name}"
                results.append(r)
        # loose Solidity PoCs (*.t.sol / *.sol) - previously UNCHECKED, making the gate
        # a vacuous pass on every Solidity-only workspace (Strata 2026-07-07).
        for sf in root.rglob("*.sol"):
            try:
                src = sf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            results.append(recheck_sol_poc(ws, src, sol_basenames, str(sf), sf))
        # inline ```solidity PoC blocks embedded in a finding .md (no on-disk .sol).
        for md in root.rglob("*.md"):
            try:
                text = md.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for i, block in enumerate(_MD_SOL_BLOCK_RE.findall(text)):
                if "import" not in block:
                    continue
                results.append(
                    recheck_sol_poc(ws, block, sol_basenames,
                                    f"{md} :: solidity-block[{i}]", None))
    stale = [r for r in results if r.get("compiles") is False]
    out = {"workspace": str(ws), "go_modules": [str(m) for m in modules],
           "poc_count": len(results), "stale_count": len(stale),
           "results": results,
           "verdict": "pass-poc-fresh" if not stale else "fail-stale-poc"}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    r = recheck(a.workspace)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"poc-freshness-recheck: {r['verdict']} "
              f"({r['poc_count']} PoC(s), {r['stale_count']} stale)")
        for res in r["results"]:
            if res.get("compiles") is False:
                print(f"  STALE {res['poc']}")
                for d in res["drift"][:3]:
                    print(f"        {d}")
    return 0 if r["verdict"] == "pass-poc-fresh" else 1


if __name__ == "__main__":
    raise SystemExit(main())
