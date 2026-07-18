#!/usr/bin/env python3
# <!-- r36-rebuttal: pathspec declared via tools/agent-pathspec-register.py lane LANE-iter3-B-advisory-dsl; orchestrator commits; disjoint owner -->
"""slither-dep-resolver.py - make a third-party .sol compile under Slither by
resolving its import dependency scopes (the "missing node_modules / unresolved
import" compile-miss that strands advisory .sol cases in the backtest).

WHY THIS TOOL EXISTS
--------------------
``auditor-backtest.py``'s ``_slither_compile`` already tries (1) plain Slither,
(2) Slither with remaps derived from an EXISTING ``node_modules/``, (3) compile
the enclosing tree. It FAILS when the dependency tree is simply not on disk -
a repo checked out without ``npm install`` / ``forge install``. This tool closes
that last gap: it reads the import scopes a target .sol needs (``@openzeppelin``,
``@polytope-labs``, ``solmate``, ``forge-std``, ...), provisions them (npm
install into a scratch ``node_modules`` OR reuse a shared dependency cache OR a
forge-std/solmate lib dir), and emits the exact ``--solc-remaps`` string + a
``remappings.txt`` so Slither (and ``auditor-backtest --corpus-detector-dir``)
can compile the file.

RELATED TOOLS (tool-duplication preflight, per global anchor)
-------------------------------------------------------------
  * tools/fix-remappings.sh   - rewrites `./`-style remappings to absolute
    paths. Does NOT install deps nor synthesize remaps for MISSING scopes.
    Complementary: run fix-remappings.sh AFTER this tool writes remappings.txt.
  * auditor-backtest.py::_slither_compile - tries remaps from an EXISTING
    node_modules. This tool PROVISIONS the node_modules it relies on.
No existing tool installs/provisions the dependency tree. This fills that gap.

Usage
-----
    # Inspect what a file needs (no install):
    python3 tools/slither-dep-resolver.py <file.sol> --dry-run --json

    # Resolve via a shared dependency cache (no network):
    python3 tools/slither-dep-resolver.py <file.sol> \
        --dep-cache ~/.auditooor/sol-deps --emit-remappings

    # Resolve via npm install (network):
    python3 tools/slither-dep-resolver.py <file.sol> --npm-install

Output: prints the resolved --solc-remaps string on the LAST line (so a caller
can `$(...)` it), and writes <dir>/remappings.txt unless --no-write.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Known scope -> npm package (the import root maps to a published package).
_SCOPE_TO_NPM = {
    "@openzeppelin/contracts": "@openzeppelin/contracts",
    "@openzeppelin/contracts-upgradeable": "@openzeppelin/contracts-upgradeable",
    "@polytope-labs/ismp-solidity-abi": "@polytope-labs/ismp-solidity-abi",
    "@polytope-labs/solidity-merkle-trees": "@polytope-labs/solidity-merkle-trees",
    "@uniswap/v3-core": "@uniswap/v3-core",
    "@uniswap/v3-periphery": "@uniswap/v3-periphery",
    "@uniswap/v2-core": "@uniswap/v2-core",
    "solmate": "solmate",
    "forge-std": "forge-std",
    "@chainlink/contracts": "@chainlink/contracts",
}

_IMPORT_RE = re.compile(
    r"""import\s+(?:\{[^}]*\}\s+from\s+)?["']([^"']+)["']""")


def _imports_in_file(sol: Path) -> set[str]:
    try:
        txt = sol.read_text(errors="ignore")
    except Exception:
        return set()
    return set(_IMPORT_RE.findall(txt))


def _imports_in_tree(root: Path) -> set[str]:
    out: set[str] = set()
    for p in root.rglob("*.sol"):
        if any(part in {"node_modules", ".git", "lib", "out", "cache"}
               for part in p.parts):
            continue
        out |= _imports_in_file(p)
    return out


def needed_scopes(imports: set[str]) -> set[str]:
    """Resolve the set of dependency SCOPES (import-root prefixes) an import set
    references. A scope is the longest known prefix; unknown non-relative
    imports are reported as 'unresolved'."""
    scopes: set[str] = set()
    for imp in imports:
        if imp.startswith(".") or imp.startswith("/"):
            continue  # relative / absolute local - resolved by the tree
        # match the longest known scope prefix
        best = None
        for scope in _SCOPE_TO_NPM:
            if imp == scope or imp.startswith(scope + "/"):
                if best is None or len(scope) > len(best):
                    best = scope
        if best:
            scopes.add(best)
        else:
            # bare scope like `@foo/bar/Baz.sol` -> take `@foo/bar`
            parts = imp.split("/")
            if imp.startswith("@") and len(parts) >= 2:
                scopes.add("/".join(parts[:2]))
            elif parts:
                scopes.add(parts[0])
    return scopes


def _have(scope: str, base: Path) -> bool:
    """Is `scope` already present under base/node_modules ?"""
    nm = base / "node_modules" / scope
    return nm.is_dir()


def resolve_from_cache(scopes: set[str], cache: Path, dest: Path) -> dict:
    """Symlink/copy each scope from a shared dep cache into dest/node_modules.
    Returns {scope: status}."""
    out = {}
    (dest / "node_modules").mkdir(parents=True, exist_ok=True)
    for scope in sorted(scopes):
        src = cache / scope
        tgt = dest / "node_modules" / scope
        if tgt.exists():
            out[scope] = "already-present"
            continue
        if src.is_dir():
            tgt.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.symlink(src.resolve(), tgt)
                out[scope] = "linked-from-cache"
            except OSError:
                shutil.copytree(src, tgt)
                out[scope] = "copied-from-cache"
        else:
            out[scope] = "cache-miss"
    return out


def resolve_via_npm(scopes: set[str], dest: Path, timeout=180) -> dict:
    """npm install each scope's package into dest. Returns {scope: status}."""
    out = {}
    npm = shutil.which("npm")
    if not npm:
        return {s: "npm-not-found" for s in scopes}
    pkgs = []
    for scope in sorted(scopes):
        pkg = _SCOPE_TO_NPM.get(scope, scope)
        if _have(scope, dest):
            out[scope] = "already-present"
        else:
            pkgs.append(pkg)
            out[scope] = "queued"
    if not pkgs:
        return out
    dest.mkdir(parents=True, exist_ok=True)
    if not (dest / "package.json").exists():
        (dest / "package.json").write_text('{"name":"slither-dep-resolver-scratch","version":"0.0.0"}\n')
    try:
        r = subprocess.run([npm, "install", "--no-save", "--no-audit",
                            "--no-fund", *pkgs],
                           cwd=str(dest), capture_output=True, text=True,
                           timeout=timeout)
        ok = r.returncode == 0
        for scope in scopes:
            if out.get(scope) == "queued":
                out[scope] = "installed" if (ok and _have(scope, dest)) \
                    else "install-failed"
    except subprocess.TimeoutExpired:
        for scope in scopes:
            if out.get(scope) == "queued":
                out[scope] = "install-timeout"
    return out


def build_remaps(scopes: set[str], dest: Path) -> list[str]:
    """Emit `scope/=<dest>/node_modules/scope/` remap lines for resolved scopes."""
    remaps = []
    nm = dest / "node_modules"
    for scope in sorted(scopes):
        if (nm / scope).exists():
            remaps.append(f"{scope}/={nm / scope}/")
    return remaps


def try_slither_compile(sol: Path, remaps: list[str]) -> dict:
    """Best-effort: confirm the file now compiles with the remaps. Returns
    {compiled: bool, error: str|None}. No-ops gracefully if slither absent."""
    try:
        from slither import Slither  # noqa
    except Exception as e:
        return {"compiled": None, "error": f"slither-unavailable:{e}"}
    try:
        if remaps:
            Slither(str(sol), solc_remaps=" ".join(remaps))
        else:
            Slither(str(sol))
        return {"compiled": True, "error": None}
    except Exception as e:
        return {"compiled": False, "error": f"{type(e).__name__}:{str(e)[:160]}"}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help=".sol file or directory")
    ap.add_argument("--dep-cache", help="shared dependency cache dir "
                    "(scope subdirs); resolve offline by symlink")
    ap.add_argument("--npm-install", action="store_true",
                    help="npm install missing scopes (needs network)")
    ap.add_argument("--dest", help="where to provision node_modules "
                    "(default: target's dir)")
    ap.add_argument("--dry-run", action="store_true",
                    help="report needed scopes; do not provision")
    ap.add_argument("--emit-remappings", action="store_true",
                    help="write <dest>/remappings.txt")
    ap.add_argument("--no-write", action="store_true")
    ap.add_argument("--verify-compile", action="store_true",
                    help="run Slither to confirm the file compiles")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    target = Path(args.target)
    if target.is_dir():
        imports = _imports_in_tree(target)
        primary = next(iter(target.rglob("*.sol")), None)
        dest = Path(args.dest) if args.dest else target
    else:
        imports = _imports_in_file(target)
        primary = target
        dest = Path(args.dest) if args.dest else target.parent

    scopes = needed_scopes(imports)
    report = {
        "target": str(target),
        "imports": sorted(imports),
        "needed_scopes": sorted(scopes),
        "resolution": {},
        "remaps": [],
        "remappings_file": None,
        "compile": None,
    }

    if args.dry_run or not scopes:
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"target={target}")
            print(f"needed_scopes={sorted(scopes)}")
        # still print empty remaps line for $() callers
        print("")
        return 0

    if args.dep_cache:
        report["resolution"] = resolve_from_cache(
            scopes, Path(args.dep_cache).expanduser(), dest)
    if args.npm_install:
        npm_res = resolve_via_npm(scopes, dest)
        # merge (npm wins on a scope the cache missed)
        for k, v in npm_res.items():
            if report["resolution"].get(k) in (None, "cache-miss"):
                report["resolution"][k] = v

    remaps = build_remaps(scopes, dest)
    report["remaps"] = remaps

    if args.emit_remappings and not args.no_write and remaps:
        rpath = dest / "remappings.txt"
        rpath.write_text("\n".join(remaps) + "\n")
        report["remappings_file"] = str(rpath)

    if args.verify_compile and primary:
        report["compile"] = try_slither_compile(primary, remaps)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"target={target}")
        print(f"needed_scopes={sorted(scopes)}")
        print(f"resolution={report['resolution']}")
        if report["remappings_file"]:
            print(f"remappings_file={report['remappings_file']}")
        if report["compile"]:
            print(f"compile={report['compile']}")
    # LAST line: the solc-remaps string (for $() capture)
    print(" ".join(remaps))
    return 0


if __name__ == "__main__":
    sys.exit(main())
