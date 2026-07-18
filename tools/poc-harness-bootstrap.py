#!/usr/bin/env python3
"""poc-harness-bootstrap.py - stop agents re-deriving the forge build environment.

Observed recurrence (NUVA 2026-06-30): two separate dispatched agents (step-2c
Chimera author + a sweepRedemptions PoC verifier) each spent ~10 steps re-discovering
the SAME forge build setup - where foundry.toml lives, whether node_modules is present,
that forge-std is missing, how to point ``src`` at the real contracts, the exact
@openzeppelin remapping lines - all of which was ALREADY solved on disk (audit-deep
left forge-buildable ``poc-tests/<Contract>-engine-harness/`` dirs with lib/forge-std +
foundry.toml + remappings; the forge-deps-checker shim made src/<repo> buildable).

This tool surfaces + reuses that existing build context:
  --detect [--json]            report the buildable repo + existing reusable harness
                               dirs + forge-std lib (consumed by the dispatch brief).
  --bootstrap <Contract>       create poc-tests/<name>/ that REUSES the nearest existing
                               harness (symlink its lib/forge-std + copy foundry.toml +
                               remappings) + a stub <Contract>.t.sol importing the REAL
                               in-scope contract, and print the exact `forge test` cmd.

Stdlib-only. Idempotent. Never raises on a non-fatal probe (degrades to a clear report).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

HARNESS_GLOBS = ("poc-tests/*-engine-harness", "poc-tests/*", "chimera_harnesses/*")


def _has_forge_std(d: Path) -> bool:
    return (d / "lib" / "forge-std" / "src").is_dir() or (d / "lib" / "forge-std").is_dir()


def find_buildable_repos(ws: Path) -> list[dict]:
    """src/<repo> (or ws root) carrying a foundry.toml - the forge-buildable in-scope
    code. Reports whether node_modules is present (the @openzeppelin source)."""
    out = []
    roots = [ws]
    src = ws / "src"
    if src.is_dir():
        roots += [d for d in src.iterdir() if d.is_dir()]
    seen = set()
    for d in roots:
        d = d.resolve()
        if d in seen or not (d / "foundry.toml").is_file():
            continue
        seen.add(d)
        out.append({
            "dir": str(d),
            "has_node_modules": (d / "node_modules").is_dir(),
            "contracts_dir": next((s for s in ("contracts", "src") if (d / s).is_dir()), None),
        })
    return out


def find_reusable_harnesses(ws: Path) -> list[dict]:
    """Existing forge-buildable harness dirs (foundry.toml + lib/forge-std) an agent can
    reuse instead of re-scaffolding. Sorted so a donor with forge-std comes first."""
    out = []
    seen = set()
    for glob in HARNESS_GLOBS:
        for d in sorted(ws.glob(glob)):
            d = d.resolve()
            if d in seen or not d.is_dir() or not (d / "foundry.toml").is_file():
                continue
            seen.add(d)
            out.append({
                "dir": str(d),
                "has_forge_std": _has_forge_std(d),
                "has_remappings": (d / "remappings.txt").is_file()
                                  or "remappings" in (d / "foundry.toml").read_text(errors="ignore"),
                "name": d.name,
            })
    out.sort(key=lambda h: (not h["has_forge_std"], h["name"]))
    return out


def detect(ws: Path) -> dict:
    repos = find_buildable_repos(ws)
    harnesses = find_reusable_harnesses(ws)
    donor = next((h for h in harnesses if h["has_forge_std"]), harnesses[0] if harnesses else None)
    return {
        "schema": "auditooor.poc_harness_bootstrap.detect.v1",
        "workspace": str(ws),
        "forge_buildable_repos": repos,
        "reusable_harnesses": harnesses,
        "recommended_donor": donor,
        "build_env_ready": bool(repos and donor),
    }


def brief_block(ws: Path) -> str:
    """A verbatim block the dispatch brief injects so a PoC/harness lane does NOT
    re-derive the build setup. Empty string when nothing is reusable yet."""
    d = detect(ws)
    if not d["reusable_harnesses"] and not d["forge_buildable_repos"]:
        return ""
    lines = ["FORGE BUILD ENV - ALREADY SET UP, REUSE IT (do NOT re-derive foundry.toml/",
             "remappings/node_modules/forge-std; that is solved on disk):"]
    for r in d["forge_buildable_repos"][:3]:
        nm = "node_modules present" if r["has_node_modules"] else "node_modules MISSING (npm i)"
        lines.append(f"  - forge-buildable in-scope repo: {r['dir']} (src={r['contracts_dir']}, {nm})")
    if d["recommended_donor"]:
        donor = d["recommended_donor"]["dir"]
        lines.append(f"  - reuse the existing harness {donor} (lib/forge-std + foundry.toml +"
                     f" remappings present). For a PoC, run:")
        lines.append(f"      python3 /Users/wolf/auditooor-mcp/tools/poc-harness-bootstrap.py "
                     f"{ws} --bootstrap <ContractName> --name <poc_slug>")
        lines.append("    -> it creates poc-tests/<poc_slug>/ (symlinked forge-std + foundry.toml)"
                     " + a stub test importing the REAL contract, and prints the forge test cmd.")
    return "\n".join(lines)


_STUB_TEST = '''// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {{Test}} from "forge-std/Test.sol";
// Import the REAL in-scope contract (adjust the path if needed):
// import {{{contract}}} from "{import_path}";

contract {contract}PoC is Test {{
    function setUp() public {{}}

    function test_poc() public {{
        // TODO: deploy the real {contract} + dependencies, drive the exploit path,
        // assert the impact. Build env is ready: `forge test --match-path {test_path}`.
        assertTrue(true);
    }}
}}
'''


def bootstrap(ws: Path, contract: str, name: str | None) -> dict:
    name = name or f"{contract.lower()}_poc"
    d = detect(ws)
    donor = d["recommended_donor"]
    if not donor:
        return {"ok": False, "reason": "no reusable harness with forge-std found; run audit-deep "
                "(step-2) or forge-deps-checker --fix first to scaffold the build env"}
    donor_dir = Path(donor["dir"])
    poc_dir = ws / "poc-tests" / name
    (poc_dir / "test").mkdir(parents=True, exist_ok=True)
    # symlink lib -> donor lib (forge-std), copy foundry.toml + remappings verbatim.
    lib_link = poc_dir / "lib"
    if not lib_link.exists():
        try:
            lib_link.symlink_to(donor_dir / "lib")
        except OSError:
            shutil.copytree(donor_dir / "lib", lib_link, dirs_exist_ok=True)
    for f in ("foundry.toml", "remappings.txt"):
        if (donor_dir / f).is_file() and not (poc_dir / f).is_file():
            shutil.copy2(donor_dir / f, poc_dir / f)
    # locate the real contract source for the import hint.
    import_path = ""
    for repo in d["forge_buildable_repos"]:
        for hit in Path(repo["dir"]).rglob(f"{contract}.sol"):
            if "/node_modules/" not in str(hit) and "/lib/" not in str(hit):
                import_path = str(hit)
                break
        if import_path:
            break
    test_rel = f"test/{contract}PoC.t.sol"
    test_path = poc_dir / test_rel
    if not test_path.is_file():
        test_path.write_text(_STUB_TEST.format(contract=contract, import_path=import_path or "<real contract>",
                                               test_path=test_rel))
    return {
        "ok": True,
        "poc_dir": str(poc_dir),
        "test_file": str(test_path),
        "donor_harness": str(donor_dir),
        "real_contract_source": import_path,
        "run_cmd": f"cd {poc_dir} && forge test --match-path {test_rel} -vvv",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Detect/reuse the forge PoC build env (no re-derivation).")
    ap.add_argument("workspace")
    ap.add_argument("--detect", action="store_true")
    ap.add_argument("--brief", action="store_true", help="print the dispatch-brief block")
    ap.add_argument("--bootstrap", metavar="CONTRACT")
    ap.add_argument("--name", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(json.dumps({"ok": False, "reason": f"workspace not found: {ws}"}))
        return 2
    if args.brief:
        print(brief_block(ws))
        return 0
    if args.bootstrap:
        res = bootstrap(ws, args.bootstrap, args.name)
        print(json.dumps(res, indent=2) if args.json else
              (res.get("run_cmd") or res.get("reason", "")))
        return 0 if res.get("ok") else 1
    res = detect(ws)
    print(json.dumps(res, indent=2) if args.json else
          f"build_env_ready={res['build_env_ready']} "
          f"repos={len(res['forge_buildable_repos'])} harnesses={len(res['reusable_harnesses'])} "
          f"donor={res['recommended_donor']['dir'] if res['recommended_donor'] else None}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
