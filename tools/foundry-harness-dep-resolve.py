#!/usr/bin/env python3
"""Resolve the build dependencies of scaffolded Foundry harness roots.

Generic fix for ANY fetched-verified-source / scaffolded-harness EVM workspace
(Polymarket is the anchor). The chimera/recon harnesses and engine-harness roots
this pipeline scaffolds compile their own contracts fine (foundry auto-downloads
solc), but they import external libraries (`forge-std/Test.sol`, `@solady/...`,
`@openzeppelin/...`) with an EMPTY `lib/` and NO remappings -> `forge build` fails
"Source ... not found", so halmos / medusa / echidna report `engine-error` and NO
real symbolic / fuzz execution happens. That is the root cause of "the deep engines
never actually run on fetched-source targets" (verified: Polymarket pocs/ engines
all engine-error because lib/ lacked forge-std + solady + openzeppelin).

This tool walks the workspace for Foundry harness roots, detects which known
external library each one imports, installs the matching dependency into
<root>/lib/<name> (forge install, with an offline copy-fallback from a known-good
sibling on-disk copy), and ensures <root>/remappings.txt carries the right remaps.

Idempotent. Does NOT write harness BODIES (an empty Setup still yields
"No contracts to fuzz"); that is a separate harness-authoring step.

Known deps (extend DEP_REGISTRY for more):
  forge-std, solady (@solady), openzeppelin-contracts (@openzeppelin), solmate
  (@solmate), ds-test.

Usage:
  foundry-harness-dep-resolve.py --workspace <ws> [--check] [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

SCHEMA = "auditooor.foundry_harness_dep_resolve.v1"
HARNESS_PARENT_HINTS = ("chimera_harnesses", "poc-tests", "pocs", "harnesses")

# import-prefix -> dependency spec.
#   probe:   a file (relative to the installed lib dir) that must exist to call it usable
#   repo:    forge install target (owner/name)
#   libname: the lib/<libname> dir
#   remaps:  remappings.txt lines to add
#   sibling: dir name to search for on-disk copy-fallback (must contain `probe`)
DEP_REGISTRY = {
    "forge-std/": {
        "libname": "forge-std", "repo": "foundry-rs/forge-std",
        "probe": "src/Vm.sol", "must_contain": "function skip(bool",
        "remaps": ["forge-std/=lib/forge-std/src/"], "sibling": "forge-std",
    },
    "@solady/": {
        "libname": "solady", "repo": "Vectorized/solady",
        "probe": "src/utils/SafeTransferLib.sol", "must_contain": "",
        "remaps": ["@solady/=lib/solady/", "solady/=lib/solady/"], "sibling": "solady",
    },
    "solady/": {
        "libname": "solady", "repo": "Vectorized/solady",
        "probe": "src/utils/SafeTransferLib.sol", "must_contain": "",
        "remaps": ["solady/=lib/solady/"], "sibling": "solady",
    },
    "@openzeppelin/": {
        "libname": "openzeppelin-contracts", "repo": "OpenZeppelin/openzeppelin-contracts",
        "probe": "contracts/token/ERC20/ERC20.sol", "must_contain": "",
        "remaps": ["@openzeppelin/=lib/openzeppelin-contracts/"], "sibling": "openzeppelin-contracts",
    },
    "openzeppelin-contracts/": {
        "libname": "openzeppelin-contracts", "repo": "OpenZeppelin/openzeppelin-contracts",
        "probe": "contracts/token/ERC20/ERC20.sol", "must_contain": "",
        "remaps": ["openzeppelin-contracts/=lib/openzeppelin-contracts/"], "sibling": "openzeppelin-contracts",
    },
    "@solmate/": {
        "libname": "solmate", "repo": "transmissions11/solmate",
        "probe": "src/tokens/ERC20.sol", "must_contain": "",
        "remaps": ["@solmate/=lib/solmate/src/", "solmate/=lib/solmate/src/"], "sibling": "solmate",
    },
    "ds-test/": {
        "libname": "ds-test", "repo": "dapphub/ds-test",
        "probe": "src/test.sol", "must_contain": "",
        "remaps": ["ds-test/=lib/ds-test/src/"], "sibling": "ds-test",
    },
}


def _lib_usable(root: Path, spec: dict) -> bool:
    probe = root / "lib" / spec["libname"] / spec["probe"]
    if not probe.is_file():
        return False
    if spec.get("must_contain"):
        try:
            return spec["must_contain"] in probe.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
    return True


def _imported_prefixes(root: Path) -> set[str]:
    """Which DEP_REGISTRY prefixes the harness's .sol files import."""
    found: set[str] = set()
    for sub in ("test", "src", "pocs", "script"):
        d = root / sub
        if not d.is_dir():
            continue
        for p in d.rglob("*.sol"):
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for prefix in DEP_REGISTRY:
                if f'"{prefix}' in text or f"'{prefix}" in text:
                    found.add(prefix)
    return found


def _find_harness_roots(ws: Path) -> list[Path]:
    roots: set[Path] = set()
    for toml in ws.rglob("foundry.toml"):
        root = toml.parent
        if "/lib/" in str(root):
            continue
        roots.add(root)
    return sorted(
        roots,
        key=lambda r: (0 if any(h in str(r) for h in HARNESS_PARENT_HINTS) else 1, str(r)),
    )


def _find_donor(ws: Path, spec: dict) -> Path | None:
    name = spec["sibling"]
    for sr in (ws, ws.parent, Path.home() / "audits"):
        if not sr.is_dir():
            continue
        try:
            for cand in sr.glob(f"**/lib/{name}"):
                probe = cand / spec["probe"]
                if probe.is_file() and (
                    not spec.get("must_contain")
                    or spec["must_contain"] in probe.read_text(encoding="utf-8", errors="replace")
                ):
                    return cand
        except (OSError, PermissionError):
            continue
    return None


def _install_dep(root: Path, prefix: str, spec: dict, donor: Path | None) -> tuple[bool, str]:
    lib = root / "lib" / spec["libname"]
    lib.parent.mkdir(parents=True, exist_ok=True)
    if lib.exists():
        shutil.rmtree(lib, ignore_errors=True)
    # forge install first (network)
    try:
        proc = subprocess.run(
            ["forge", "install", spec["repo"], "--no-commit"],
            cwd=str(root), capture_output=True, text=True, timeout=180,
        )
        if proc.returncode == 0 and _lib_usable(root, spec):
            return True, "forge-install"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    if donor and donor.is_dir():
        try:
            shutil.copytree(donor, lib)
            if _lib_usable(root, spec):
                return True, f"copy:{donor}"
        except OSError as exc:
            return False, f"copy-failed:{exc.__class__.__name__}"
    return False, "no-source"


def _npm_scope_remaps(root: Path, prefix: str) -> list[str]:
    """If the import prefix is an npm SCOPE (e.g. '@openzeppelin/') and
    <root>/node_modules/<scope> exists with one or more packages, emit a
    per-package remapping into node_modules.

    This is the correct resolution for npm-style (hardhat) EVM projects where a
    single lib/<repo> submodule CANNOT provide every package of a scope. The
    anchor bug (Strata 2026-06-30): the '@openzeppelin/' DEP_REGISTRY entry
    blanket-maps '@openzeppelin/=lib/openzeppelin-contracts/', but the
    openzeppelin-contracts repo only ships the `contracts` package - the
    `contracts-upgradeable` package is a SEPARATE repo/npm-package. So
    '@openzeppelin/contracts-upgradeable/...' resolved to a non-existent
    lib/openzeppelin-contracts/contracts-upgradeable/ dir and the whole test
    tree (authored harnesses) failed to compile -> deep engines reported
    build-broken / 0 genuine coverage.

    Per-package, longest-prefix remaps (e.g. '@openzeppelin/contracts-upgradeable/'
    = 36 chars) win over any blanket '@openzeppelin/=lib/...' (14 chars) line, so
    this is additive and safe even when a broken blanket already exists.
    """
    if not (prefix.startswith("@") and prefix.endswith("/")):
        return []
    scope = prefix[:-1]  # "@openzeppelin/" -> "@openzeppelin"
    if "/" in scope[1:]:
        return []  # already a package-level prefix, not a bare scope
    nm_scope = root / "node_modules" / scope
    if not nm_scope.is_dir():
        return []
    remaps: list[str] = []
    try:
        for pkg in sorted(nm_scope.iterdir()):
            if pkg.is_dir() and not pkg.name.startswith("."):
                remaps.append(f"{scope}/{pkg.name}/=node_modules/{scope}/{pkg.name}/")
    except OSError:
        return []
    return remaps


def _ensure_remaps(root: Path, remaps: list[str], drop_prefixes: tuple[str, ...] = ()) -> None:
    rm = root / "remappings.txt"
    existing = rm.read_text(encoding="utf-8") if rm.is_file() else ""
    lines = [ln.strip() for ln in existing.splitlines() if ln.strip()]
    changed = False
    # Drop conflicting blanket remaps. forge does NOT reliably prefer the
    # longest-matching prefix when a bare-scope blanket ('@openzeppelin/=lib/...')
    # is present - it can shadow a more specific per-package remap, re-breaking
    # contracts-upgradeable. So a bare-scope blanket that we are superseding with
    # per-package node_modules remaps must be REMOVED, not just out-prefixed.
    if drop_prefixes:
        kept = [ln for ln in lines
                if not any(ln.split("=", 1)[0].strip() == dp for dp in drop_prefixes)]
        if len(kept) != len(lines):
            lines = kept
            changed = True
    for r in remaps:
        if r not in lines:
            lines.append(r)
            changed = True
    if changed:
        rm.write_text("\n".join(lines) + "\n", encoding="utf-8")


def resolve(ws: Path, check_only: bool) -> dict:
    roots = _find_harness_roots(ws)
    results = []
    fixed = 0
    needs_fix = 0
    for root in roots:
        prefixes = _imported_prefixes(root)
        if not prefixes:
            continue
        row = {"root": str(root.relative_to(ws)), "deps": {}}
        for prefix in sorted(prefixes):
            spec = DEP_REGISTRY[prefix]
            # npm-scope preference: when node_modules already provides the scope's
            # packages (hardhat/npm projects), per-package node_modules remaps are
            # the correct resolution - a single lib/<repo> submodule cannot supply
            # every package of a scope (e.g. @openzeppelin/contracts-upgradeable is
            # a separate package from @openzeppelin/contracts). Done even when the
            # shallow lib probe passes, so an already-broken blanket remap is
            # repaired (longest-prefix node_modules remaps win over the blanket).
            npm_remaps = _npm_scope_remaps(root, prefix)
            if npm_remaps:
                if check_only:
                    row["deps"][spec["libname"]] = "ok-npm-scope"
                    continue
                # supersede any bare-scope blanket (e.g. '@openzeppelin/=lib/...')
                _ensure_remaps(root, npm_remaps, drop_prefixes=(prefix.rstrip("/") + "/", prefix))
                row["deps"][spec["libname"]] = "resolved:node_modules-scope"
                fixed += 1
                continue
            if _lib_usable(root, spec):
                row["deps"][spec["libname"]] = "ok-already"
                continue
            if check_only:
                row["deps"][spec["libname"]] = "needs-install"
                needs_fix += 1
                continue
            donor = _find_donor(ws, spec)
            ok, how = _install_dep(root, prefix, spec, donor)
            if ok:
                _ensure_remaps(root, spec["remaps"])
                row["deps"][spec["libname"]] = f"installed:{how}"
                fixed += 1
            else:
                row["deps"][spec["libname"]] = f"FAILED:{how}"
                needs_fix += 1
        results.append(row)
    verdict = (
        "pass-all-deps-resolved" if needs_fix == 0
        else ("needs-resolution" if check_only else "fail-unresolved-deps")
    )
    return {
        "schema": SCHEMA, "workspace": str(ws),
        "harness_roots": len(results), "deps_fixed": fixed, "deps_needing_fix": needs_fix,
        "verdict": verdict, "roots": results,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(f"[foundry-harness-dep-resolve] workspace not found: {ws}", file=sys.stderr)
        return 2
    out = resolve(ws, args.check)
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(f"[foundry-harness-dep-resolve] {out['verdict']}: {out['harness_roots']} harness roots, "
              f"{out['deps_fixed']} deps fixed, {out['deps_needing_fix']} unresolved")
        for r in out["roots"]:
            print(f"  {r['root']}")
            for lib, act in r["deps"].items():
                print(f"      {act:28s} {lib}")
    return 0 if out["deps_needing_fix"] == 0 or args.check else 1


if __name__ == "__main__":
    raise SystemExit(main())
