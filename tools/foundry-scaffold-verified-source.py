#!/usr/bin/env python3
"""
foundry-scaffold-verified-source.py - Scaffold a compilable Foundry project
from block-explorer-fetched verified source.

PROBLEM
-------
When an operator fetches verified contract source from a block explorer
(Etherscan / Polygonscan / Sourcify), the result is a flat multi-file
Solidity tree under `src/` (and dependency files under `lib/`) with NO
`foundry.toml` and NO `remappings.txt`. The contracts use `@`-prefixed
import aliases (`@solady/`, `@polymarket-v2/`, ...) that Foundry's
auto-remapping detection does not produce. As a result `forge build`
fails with "Unable to resolve imports", and every downstream deep engine
(halmos / medusa / echidna / foundry-invariant-runner / slither) that
needs a compilable project is skipped.

`forge-deps-checker.py` cannot help here: its very first action is
`find_forge_project()` which `sys.exit(1)`s when no `foundry.toml`
exists. It is a dependency HEALTH checker for projects that already have
a build config; it cannot create one.

WHAT THIS TOOL DOES
-------------------
Given a workspace, it DETECTS fetched verified-source contract dirs and
GENERATES a compilable Foundry setup for each:

  1. foundry.toml  (src/out/libs, solc_version from SOURCE_META compiler
     when present, else auto_detect_solc=true)
  2. remappings.txt (also embedded in foundry.toml) derived from the
     ACTUAL `@`-prefixed import prefixes used in the source, mapped to:
       - a present dependency dir under `lib/<stem>/` -> `@stem/=lib/stem/`
       - the project's own `src/` tree (self-referential alias) ->
         `@alias/src/=src/`  (the precise form that avoids the
         "Identifier already declared" double-compile bug)

DETECTION
---------
A directory is a "verified-source contract dir" when it has Solidity
sources under `src/` AND does NOT already have a `foundry.toml` /
`hardhat.config.*`. A `SOURCE_META.json` (the fetcher's per-contract
metadata sidecar) is a strong positive signal and supplies the compiler
version, but is not strictly required.

The tool walks the workspace and finds these dirs both when the
workspace IS a single contract dir and when it CONTAINS many per-contract
subdirs (the common explorer-batch-fetch layout
`<ws>/src/<batch>/<Contract>/`).

NO-OP cases (the tool writes nothing and reports them):
  - A dir already has foundry.toml -> already a Foundry project (skip).
  - A dir has hardhat.config.* -> Hardhat project (skip).
  - No `.sol` under src/ (outside lib/out/node_modules/cache) -> nothing
    to scaffold.

IDEMPOTENT
----------
Re-running is a no-op for dirs already scaffolded by this tool: it writes
a marker `<dir>/.auditooor/foundry_scaffold.json` and, on --fix, refreshes
the files only if their content differs.

ADVISORY
--------
This tool is advisory in the pipeline: a scaffold failure must not block
the slither / regex engines that do not need a compilable project. The
deep engines individually gate on a present foundry.toml.

USAGE
-----
    foundry-scaffold-verified-source.py <workspace> [--check] [--fix]
                                        [--json] [--solc-install]

  --check  (default) report which dirs would be scaffolded; write nothing.
  --fix    write foundry.toml + remappings.txt + marker for each detected dir.
  --json   machine-readable output.
  --solc-install  best-effort install the detected solc version via
                  solc-select / svm so forge build can find it.

RELATED TOOLS:
  - tools/forge-deps-checker.py : dependency HEALTH checker for projects
    that already have foundry.toml. It REQUIRES a foundry.toml; this tool
    CREATES one. forge-deps-checker invokes this scaffolder (see its
    main()) before bailing on "No foundry.toml found", so the two compose:
    scaffold -> health-check.
  - tools/auditooor-forge-wrapper.sh : forge invocation wrapper.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SCHEMA = "auditooor.foundry_scaffold_verified_source.v1"

# Directories never treated as a contract `src/` tree and never walked into
# when hunting for verified-source dirs.
SKIP_DIR_NAMES = {
    ".git", ".hg", ".svn", "node_modules", "lib", "out", "cache",
    "broadcast", "artifacts", "typechain", "typechain-types", ".auditooor",
}

IMPORT_RE = re.compile(
    r'import\s+(?:[\w*{}\s,]+\s+from\s+)?["\']([^"\']+)["\']\s*;'
)
PRAGMA_RE = re.compile(r'pragma\s+solidity\s+([^;]+);')
# v0.8.34+commit.80d5c536  ->  0.8.34
COMPILER_VER_RE = re.compile(r'v?(\d+\.\d+\.\d+)')


# --------------------------------------------------------------------------
# detection
# --------------------------------------------------------------------------

def _has_sol_under_src(d: Path) -> bool:
    src = d / "src"
    if not src.is_dir():
        return False
    for f in src.rglob("*.sol"):
        # rglob can match out/<X>.sol/ dirs in pathological trees; guard.
        if f.is_file():
            return True
    return False


def _is_foundry_or_hardhat(d: Path) -> bool:
    if (d / "foundry.toml").is_file():
        return True
    for hc in d.glob("hardhat.config.*"):
        if hc.is_file():
            return True
    return False


# Filenames that mark a directory as block-explorer-fetched verified source.
# Detection REQUIRES at least one of these so the tool never scaffolds over
# arbitrary in-repo test fixtures / harness kits that merely happen to have a
# src/*.sol tree. (SOURCE_META.json is the fetcher's per-contract sidecar;
# ABI.json is the explorer's ABI dump written alongside src/.)
VERIFIED_SOURCE_MARKERS = ("SOURCE_META.json", "ABI.json")


def _is_verified_source_dir(d: Path) -> bool:
    """A dir is fetched verified source iff it has src/*.sol AND a fetch marker."""
    if not _has_sol_under_src(d):
        return False
    if _is_foundry_or_hardhat(d):
        return False
    return any((d / m).is_file() for m in VERIFIED_SOURCE_MARKERS)


def find_verified_source_dirs(ws: Path, max_depth: int = 6) -> List[Path]:
    """Find directories that look like fetched verified source needing a scaffold.

    A candidate dir has Solidity under `src/`, NO foundry.toml /
    hardhat.config.*, AND a verified-source marker file (SOURCE_META.json or
    ABI.json) so in-repo test fixtures are never clobbered. We walk the
    workspace and collect such dirs, both when the workspace itself is one
    and when it contains many per-contract subdirs.
    """
    ws = ws.resolve()
    found: List[Path] = []

    # The workspace itself.
    if _is_verified_source_dir(ws):
        found.append(ws)

    for dirpath, dirnames, filenames in os.walk(ws):
        path = Path(dirpath)
        depth = len(path.relative_to(ws).parts)
        # prune
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIR_NAMES and not d.startswith(".")
        )
        if depth >= max_depth:
            dirnames[:] = []
        if path == ws:
            continue
        # We are interested in the CONTRACT dir (the one that owns src/),
        # not src/ itself or deeper. A contract dir has a child `src`.
        if _is_verified_source_dir(path):
            found.append(path)
            # do not descend further into a contract dir's own subtree
            dirnames[:] = []

    # de-dup, stable order
    seen = set()
    out: List[Path] = []
    for p in found:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


# --------------------------------------------------------------------------
# solc version
# --------------------------------------------------------------------------

def _load_source_meta(contract_dir: Path) -> Optional[dict]:
    meta = contract_dir / "SOURCE_META.json"
    if not meta.is_file():
        return None
    try:
        return json.loads(meta.read_text(errors="ignore"))
    except Exception:
        return None


def detect_solc_version(contract_dir: Path) -> Optional[str]:
    """Return the dominant solc version (e.g. "0.8.34") for a contract dir.

    Prefers SOURCE_META.json's `compiler` (the exact explorer-verified
    version). Falls back to scanning pragma statements and picking the
    highest pinned/lower-bound version. Returns None if undeterminable
    (caller then uses auto_detect_solc=true).
    """
    meta = _load_source_meta(contract_dir)
    if meta:
        comp = meta.get("compiler") or meta.get("solc") or ""
        m = COMPILER_VER_RE.search(str(comp))
        if m:
            return m.group(1)

    versions: List[Tuple[int, int, int]] = []
    src = contract_dir / "src"
    if src.is_dir():
        for f in src.rglob("*.sol"):
            if not f.is_file():
                continue
            text = f.read_text(errors="ignore")
            for pm in PRAGMA_RE.finditer(text):
                for vm in re.finditer(r'(\d+)\.(\d+)\.(\d+)', pm.group(1)):
                    versions.append(
                        (int(vm.group(1)), int(vm.group(2)), int(vm.group(3)))
                    )
    if versions:
        v = max(versions)
        return f"{v[0]}.{v[1]}.{v[2]}"
    return None


# --------------------------------------------------------------------------
# remappings derivation
# --------------------------------------------------------------------------

def collect_import_prefixes(contract_dir: Path) -> List[str]:
    """Collect all `@`-prefixed (or bare non-relative) import paths used.

    Returns the full import strings; remapping derivation consumes them.
    """
    imports: set[str] = set()
    src = contract_dir / "src"
    if not src.is_dir():
        return []
    for f in src.rglob("*.sol"):
        if not f.is_file():
            continue
        text = f.read_text(errors="ignore")
        for m in IMPORT_RE.finditer(text):
            imp = m.group(1)
            if imp.startswith("./") or imp.startswith("../"):
                continue
            imports.add(imp)
    return sorted(imports)


def _lib_dir_for(contract_dir: Path, stem: str) -> Optional[Path]:
    cand = contract_dir / "lib" / stem
    if cand.is_dir():
        return cand
    return None


def derive_remappings(contract_dir: Path, imports: List[str]) -> Dict[str, str]:
    """Derive Foundry remappings from the actual import prefixes + present dirs.

    For each non-relative import `@alias/rest`:
      - If a dir `lib/<alias>` exists AND `lib/<alias>/rest` resolves the
        file -> remap `@alias/=lib/alias/`.
      - Else if the file resolves under the contract's own `src/` after
        stripping a leading `<alias>/src/` (self-referential alias) ->
        remap `@alias/src/=src/`.
      - Else if the file resolves under `src/` after stripping just
        `<alias>/` -> remap `@alias/=src/`.
    Non-@ bare imports (e.g. `solmate/...`) get an analogous lib mapping if
    a lib dir matches.
    """
    remaps: Dict[str, str] = {}
    src = contract_dir / "src"

    for imp in imports:
        parts = imp.split("/")
        if not parts:
            continue
        alias_raw = parts[0]
        alias = alias_raw[1:] if alias_raw.startswith("@") else alias_raw
        rest = "/".join(parts[1:])  # path after the alias segment

        # 1) dependency in lib/<alias>/
        libd = _lib_dir_for(contract_dir, alias)
        if libd is not None and rest and (libd / rest).is_file():
            remaps[f"{alias_raw}/"] = f"lib/{alias}/"
            continue
        # some explorers nest the dep one level deeper, e.g. lib/<alias>/src/...
        # already handled because `rest` includes the `src/...` segment.

        # 2) self-referential alias: @alias/src/X  -> the file lives at src/X
        if rest.startswith("src/") and src.is_dir():
            inner = rest[len("src/"):]
            if inner and (src / inner).is_file():
                remaps[f"{alias_raw}/src/"] = "src/"
                continue
        # 3) self-referential without src segment: @alias/X -> src/X
        if rest and src.is_dir() and (src / rest).is_file():
            remaps[f"{alias_raw}/"] = "src/"
            continue

        # 4) fallback: if a lib/<alias> dir exists at all, map to it even if
        # we could not resolve the exact file (best-effort).
        if libd is not None:
            remaps.setdefault(f"{alias_raw}/", f"lib/{alias}/")

    return remaps


# --------------------------------------------------------------------------
# generation
# --------------------------------------------------------------------------

def build_foundry_toml(solc_version: Optional[str],
                       remaps: Dict[str, str]) -> str:
    lines = ["[profile.default]",
             'src = "src"',
             'out = "out"',
             'libs = ["lib"]']
    if solc_version:
        lines.append(f'solc_version = "{solc_version}"')
    else:
        lines.append("auto_detect_solc = true")
    if remaps:
        lines.append("remappings = [")
        for k in sorted(remaps):
            lines.append(f'    "{k}={remaps[k]}",')
        lines.append("]")
    return "\n".join(lines) + "\n"


def build_remappings_txt(remaps: Dict[str, str]) -> str:
    return "".join(f"{k}={remaps[k]}\n" for k in sorted(remaps))


def scaffold_one(contract_dir: Path, write: bool) -> dict:
    """Plan (and optionally write) a foundry scaffold for one contract dir."""
    imports = collect_import_prefixes(contract_dir)
    remaps = derive_remappings(contract_dir, imports)
    solc_version = detect_solc_version(contract_dir)
    toml_content = build_foundry_toml(solc_version, remaps)
    remap_content = build_remappings_txt(remaps)

    foundry_toml = contract_dir / "foundry.toml"
    remappings_txt = contract_dir / "remappings.txt"
    marker_dir = contract_dir / ".auditooor"
    marker = marker_dir / "foundry_scaffold.json"

    existing_toml = foundry_toml.read_text(errors="ignore") if foundry_toml.is_file() else None
    needs_write = (existing_toml != toml_content) or (
        not remappings_txt.is_file()
        or remappings_txt.read_text(errors="ignore") != remap_content
    )

    result = {
        "dir": str(contract_dir),
        "solc_version": solc_version or "auto_detect",
        "remappings": remaps,
        "import_prefixes": sorted({
            (i.split("/")[0]) for i in imports if not i.startswith(".")
        }),
        "wrote": False,
        "idempotent_noop": False,
    }

    if write:
        if not needs_write and marker.is_file():
            result["idempotent_noop"] = True
            return result
        try:
            foundry_toml.write_text(toml_content)
            remappings_txt.write_text(remap_content)
            marker_dir.mkdir(exist_ok=True)
            marker.write_text(json.dumps({
                "schema": SCHEMA,
                "tool": "foundry-scaffold-verified-source",
                "solc_version": solc_version or "auto_detect",
                "remappings": remaps,
            }, indent=2) + "\n")
            result["wrote"] = True
        except OSError as exc:
            result["error"] = str(exc)
    else:
        result["would_write"] = needs_write or not marker.is_file()

    return result


# --------------------------------------------------------------------------
# solc install (best effort)
# --------------------------------------------------------------------------

def ensure_solc_installed(version: str) -> dict:
    """Best-effort install of solc `version` via solc-select then svm.

    Returns a dict describing what happened. Never raises.
    """
    home_svm = Path.home() / ".svm" / version
    if (home_svm / f"solc-{version}").exists() or (home_svm / "solc").exists():
        return {"version": version, "status": "already-present-svm"}
    # solc-select
    try:
        r = subprocess.run(["solc-select", "versions"],
                           capture_output=True, text=True, timeout=15)
        if version in r.stdout:
            return {"version": version, "status": "already-present-solc-select"}
    except Exception:
        pass
    for cmd in (["solc-select", "install", version], ["svm", "install", version]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if r.returncode == 0:
                return {"version": version, "status": "installed",
                        "via": cmd[0]}
        except FileNotFoundError:
            continue
        except Exception as exc:
            return {"version": version, "status": "install-error",
                    "via": cmd[0], "error": str(exc)}
    return {"version": version, "status": "install-unavailable"}


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def run(ws: Path, write: bool, do_solc_install: bool) -> dict:
    dirs = find_verified_source_dirs(ws)
    scaffolded: List[dict] = []
    solc_installs: List[dict] = []
    seen_versions: set[str] = set()

    for d in dirs:
        res = scaffold_one(d, write=write)
        scaffolded.append(res)
        if do_solc_install:
            v = res.get("solc_version")
            if v and v != "auto_detect" and v not in seen_versions:
                seen_versions.add(v)
                solc_installs.append(ensure_solc_installed(v))

    return {
        "schema": SCHEMA,
        "workspace": str(ws),
        "mode": "fix" if write else "check",
        "detected_count": len(dirs),
        "scaffolded": scaffolded,
        "solc_installs": solc_installs,
    }


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Scaffold compilable Foundry projects from fetched verified source"
    )
    ap.add_argument("workspace", help="Workspace directory")
    ap.add_argument("--check", action="store_true",
                    help="Report only; write nothing (default)")
    ap.add_argument("--fix", action="store_true",
                    help="Write foundry.toml + remappings.txt + marker")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--solc-install", action="store_true",
                    help="Best-effort install detected solc versions")
    args = ap.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.exists():
        print(f"[scaffold] Workspace not found: {ws}", file=sys.stderr)
        sys.exit(2)

    write = bool(args.fix)
    payload = run(ws, write=write, do_solc_install=args.solc_install)

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        n = payload["detected_count"]
        if n == 0:
            print(f"[scaffold] No verified-source dirs needing a scaffold under {ws}")
        else:
            verb = "Scaffolded" if write else "Would scaffold"
            print(f"[scaffold] {verb} {n} verified-source dir(s):")
            for r in payload["scaffolded"]:
                tag = ""
                if r.get("wrote"):
                    tag = "WROTE"
                elif r.get("idempotent_noop"):
                    tag = "noop(idempotent)"
                elif r.get("would_write"):
                    tag = "would-write"
                elif r.get("error"):
                    tag = f"ERROR: {r['error']}"
                print(f"  [{tag}] {r['dir']}  solc={r['solc_version']}  "
                      f"remaps={len(r['remappings'])}")
        for si in payload["solc_installs"]:
            print(f"[scaffold] solc {si['version']}: {si['status']}")

    # Advisory tool: always exit 0 unless a real write error occurred.
    had_error = any(r.get("error") for r in payload["scaffolded"])
    sys.exit(1 if (write and had_error) else 0)


if __name__ == "__main__":
    main()
