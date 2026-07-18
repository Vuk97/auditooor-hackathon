#!/usr/bin/env python3
"""
forge-deps-checker.py - Foundry dependency health checker

Scans a workspace for missing forge dependencies (git submodules, lib/
imports, remappings) and suggests fixes.

Usage:
    forge-deps-checker.py <workspace>
    forge-deps-checker.py ~/audits/<project> --fix

Checks:
  1. Git submodules initialized
  2. lib/ directory exists and has expected subdirectories
  3. remappings.txt or foundry.toml remappings correct
  4. All imported contracts are resolvable
  5. solc version compatibility
  6. Local solc binary path (G5 fix): if foundry.toml pins solc = "./solc-X.Y.Z"
     and the file is missing, auto-create a symlink to ~/.svm/X.Y.Z/solc-X.Y.Z
     if the svm binary is present.
     Disable with env: AUDITOOOR_NO_AUTO_SOLC_SYMLINK=1

RELATED TOOLS:
  - tools/forge-test-runner.py : runs forge test against a project directory
  - tools/auditooor-forge-wrapper.sh : shell wrapper for forge invocation with env setup
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


IGNORED_FOUNDRY_SEARCH_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "lib",
    "out",
    "cache",
    "broadcast",
}


def _try_scaffold_verified_source(ws: Path, do_fix: bool) -> bool:
    """Invoke the verified-source scaffolder when no foundry.toml exists.

    Returns True if the scaffolder ran and reported it wrote (or would write,
    in --check mode) at least one foundry.toml. Advisory: never raises; on any
    error returns False so the health check degrades gracefully.

    In --check mode (do_fix=False) this is a no-op write-wise but still reports
    whether a scaffold WOULD help, so the operator sees the suggestion.
    """
    scaffolder = Path(__file__).resolve().parent / "foundry-scaffold-verified-source.py"
    if not scaffolder.is_file():
        return False
    cmd = [sys.executable, str(scaffolder), str(ws), "--json"]
    cmd.append("--fix" if do_fix else "--check")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except Exception:
        return False
    try:
        payload = json.loads(r.stdout)
    except Exception:
        return False
    detected = payload.get("detected_count", 0)
    if not detected:
        return False
    if do_fix:
        wrote_any = any(s.get("wrote") or s.get("idempotent_noop")
                        for s in payload.get("scaffolded", []))
        if wrote_any:
            print(f"[deps] Scaffolded {detected} verified-source dir(s) "
                  f"(foundry.toml + remappings.txt)")
        return wrote_any
    # check mode: just advise
    print(f"[deps] Detected {detected} verified-source dir(s) with no "
          f"foundry.toml; run with --fix to scaffold a Foundry project")
    return False


def _hardhat_npm_solidity_dirs(ws: Path) -> list[Path]:
    """Find hardhat/npm Solidity project dirs under ws: a dir with package.json
    AND a contracts/ (or src/) tree containing .sol AND no foundry.toml. Searches
    ws, ws/src/*, ws/external/* (the canonical clone layouts). These are the repos
    forge cannot build until a foundry shim (foundry.toml + remappings from
    node_modules) is scaffolded - the hardhat->forge compile-cascade."""
    out: list[Path] = []
    roots = [ws]
    for parent in ("src", "external"):
        p = ws / parent
        if p.is_dir():
            roots += [d for d in p.iterdir() if d.is_dir()]
    seen = set()
    for d in roots:
        d = d.resolve()
        if d in seen:
            continue
        seen.add(d)
        if not (d / "package.json").is_file():
            continue
        if (d / "foundry.toml").is_file():
            continue
        sol_dir = next((s for s in ("contracts", "src") if (d / s).is_dir()
                        and any((d / s).rglob("*.sol"))), None)
        if sol_dir:
            out.append(d)
    return out


def _scaffold_hardhat_foundry_shim(ws: Path, do_fix: bool) -> bool:
    """Scaffold a Foundry shim over a hardhat/npm Solidity repo so forge (and the
    audit-deep engines) can compile it. Generic fix for the hardhat->forge compile-
    cascade (NUVA nuva-evm-contracts 2026-06-29): a repo with package.json + a
    contracts/ tree but no foundry.toml fails `forge build` with
    '@openzeppelin/... not found'. The validated recipe: (1) npm install if
    node_modules is missing, (2) write remappings.txt mapping every node_modules
    package (incl. @scope/pkg) -> node_modules/<pkg>/, (3) write foundry.toml
    (src=contracts|src, libs=node_modules, via_ir=true for stack-too-deep, solc/
    optimizer from hardhat.config when detectable else sane defaults). Idempotent.
    Returns True if a shim was written (or would be, in --check). Advisory: never
    raises."""
    dirs = _hardhat_npm_solidity_dirs(ws)
    if not dirs:
        return False
    if not do_fix:
        print(f"[deps] Detected {len(dirs)} hardhat/npm Solidity repo(s) with no "
              f"foundry.toml; run with --fix to scaffold a Foundry shim "
              f"(npm install + remappings.txt + foundry.toml via_ir)")
        return False
    wrote_any = False
    for d in dirs:
        try:
            nm = d / "node_modules"
            if not nm.is_dir() and (d / "package.json").is_file():
                print(f"[deps] [hardhat-shim] npm install in {d.name} (node_modules missing)")
                try:
                    subprocess.run(["npm", "install", "--no-audit", "--no-fund"],
                                   cwd=str(d), capture_output=True, text=True, timeout=1800)
                except Exception as exc:
                    print(f"[deps] [hardhat-shim] WARN npm install failed ({type(exc).__name__}); "
                          f"remappings may be incomplete")
            # remappings from node_modules (top-level + one @scope deep)
            mappings = []
            if nm.is_dir():
                for entry in sorted(nm.iterdir()):
                    if entry.name.startswith(".") or entry.name == ".bin":
                        continue
                    if entry.name.startswith("@") and entry.is_dir():
                        for sub in sorted(entry.iterdir()):
                            if sub.is_dir():
                                mappings.append(f"{entry.name}/{sub.name}/=node_modules/{entry.name}/{sub.name}/")
                    elif entry.is_dir():
                        mappings.append(f"{entry.name}/=node_modules/{entry.name}/")
            if mappings:
                (d / "remappings.txt").write_text("\n".join(mappings) + "\n")
            sol_dir = "contracts" if (d / "contracts").is_dir() else "src"
            # detect solc version from hardhat.config (best-effort)
            solc = "0.8.28"
            for cfg in ("hardhat.config.js", "hardhat.config.ts"):
                cp = d / cfg
                if cp.is_file():
                    mm = re.search(r"version:\s*[\"'](\d+\.\d+\.\d+)[\"']",
                                   cp.read_text(errors="ignore"))
                    if mm:
                        solc = mm.group(1)
                    break
            (d / "foundry.toml").write_text(
                "[profile.default]\n"
                f'src = "{sol_dir}"\n'
                'out = "out"\n'
                'libs = ["node_modules"]\n'
                f'solc = "{solc}"\n'
                "optimizer = true\n"
                "optimizer_runs = 200\n"
                'evm_version = "paris"\n'
                "via_ir = true\n"
            )
            print(f"[deps] [hardhat-shim] scaffolded foundry.toml + remappings.txt "
                  f"({len(mappings)} remaps) for {d.name}")
            wrote_any = True
        except Exception as exc:
            print(f"[deps] [hardhat-shim] WARN failed for {d}: {type(exc).__name__}")
    return wrote_any


def _depth_from(root: Path, path: Path) -> int:
    try:
        return len(path.relative_to(root).parts)
    except ValueError:
        return 0


def find_forge_project(ws: Path, max_descendant_depth: int = 4) -> Optional[Path]:
    """Find the forge project root (has foundry.toml).

    The common audit workspace shape is either the Foundry project itself or
    a wrapper directory with the scoped repository below `external/<repo>` or
    `src/<repo>`. Search ancestors first so a caller inside a project resolves
    to that project, then search shallow descendants while skipping dependency
    and build-output directories.
    """
    ws = ws.resolve()
    current = ws
    while current != current.parent:
        if (current / "foundry.toml").exists():
            return current
        # Check common subdirectories
        for sub in ["src", "src-v2", "contracts"]:
            if (current / sub / "foundry.toml").exists():
                return current / sub
        current = current.parent

    if (ws / "foundry.toml").exists():
        return ws

    candidates: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(ws):
        path = Path(dirpath)
        depth = _depth_from(ws, path)
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in IGNORED_FOUNDRY_SEARCH_DIRS
            and not d.startswith(".")
        )
        if depth >= max_descendant_depth:
            dirnames[:] = []
        if "foundry.toml" in filenames:
            candidates.append(path)

    if candidates:
        candidates.sort(key=lambda p: (_depth_from(ws, p), str(p)))
        return candidates[0]
    return None


def check_git_submodules(project_dir: Path) -> List[str]:
    """Check if git submodules are initialized."""
    issues = []
    gitmodules = project_dir / ".gitmodules"
    if not gitmodules.exists():
        return issues

    # Parse .gitmodules for expected paths
    text = gitmodules.read_text()
    expected_paths = []
    for m in re.finditer(r'path\s*=\s*(.+)', text):
        expected_paths.append(m.group(1).strip())

    for path in expected_paths:
        full_path = project_dir / path
        if not full_path.exists() or not any(full_path.iterdir()):
            issues.append(f"Git submodule not initialized: {path}")

    return issues


def _parse_remapping_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        return None
    prefix, target = line.split("=", 1)
    prefix = prefix.strip().strip('"').strip("'")
    target = target.strip().strip('"').strip("'")
    if not prefix or not target:
        return None
    return prefix, target


def load_remappings(project_dir: Path) -> Dict[str, str]:
    """Load Foundry remappings from remappings.txt and simple TOML arrays."""
    remappings: Dict[str, str] = {}

    remappings_txt = project_dir / "remappings.txt"
    if remappings_txt.exists():
        for line in remappings_txt.read_text(errors="ignore").splitlines():
            parsed = _parse_remapping_line(line)
            if parsed:
                remappings[parsed[0]] = parsed[1]

    foundry_toml = project_dir / "foundry.toml"
    if foundry_toml.exists():
        text = foundry_toml.read_text(errors="ignore")
        # Handles the common Foundry shape:
        # remappings = ["@foo/=lib/foo/src/", "bar/=node_modules/bar/"]
        for block in re.findall(r"remappings\s*=\s*\[(.*?)\]", text, re.S):
            for item in re.findall(r'["\']([^"\']+=?[^"\']*)["\']', block):
                parsed = _parse_remapping_line(item)
                if parsed:
                    remappings[parsed[0]] = parsed[1]

    return remappings


def _source_dirs(project_dir: Path) -> List[Path]:
    src_dirs = [project_dir / "src", project_dir / "contracts"]
    return [d for d in src_dirs if d.exists()]


def _resolve_import(project_dir: Path, remappings: Dict[str, str], imp: str) -> bool:
    if imp.startswith("./") or imp.startswith("../"):
        return True

    for prefix, target in sorted(remappings.items(), key=lambda kv: len(kv[0]), reverse=True):
        if not imp.startswith(prefix):
            continue
        suffix = imp[len(prefix):]
        if (project_dir / target / suffix).exists():
            return True

    direct_candidates = [
        project_dir / imp,
        project_dir / "node_modules" / imp,
        project_dir / "lib" / imp,
    ]
    if any(path.exists() for path in direct_candidates):
        return True

    parts = imp.split("/")
    if parts:
        first_part = parts[0]
        if (project_dir / "node_modules" / first_part).exists():
            return (project_dir / "node_modules" / imp).exists()
        if (project_dir / "lib" / first_part).exists():
            return (project_dir / "lib" / imp).exists()

    return False


def _parse_semver(value: str) -> tuple[int, int, int] | None:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", value)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _cmp_semver(a: tuple[int, int, int], b: tuple[int, int, int]) -> int:
    return (a > b) - (a < b)


def _satisfies_simple_constraint(
    installed: tuple[int, int, int],
    token: str,
) -> bool:
    token = token.strip()
    if not token:
        return True

    version = _parse_semver(token)
    if not version:
        return True

    if token.startswith("^"):
        major, minor, _patch = version
        if major > 0:
            upper = (major + 1, 0, 0)
        else:
            upper = (0, minor + 1, 0)
        return _cmp_semver(installed, version) >= 0 and _cmp_semver(installed, upper) < 0

    if token.startswith("~"):
        major, minor, _patch = version
        upper = (major, minor + 1, 0)
        return _cmp_semver(installed, version) >= 0 and _cmp_semver(installed, upper) < 0

    for op in (">=", "<=", ">", "<", "=", "=="):
        if token.startswith(op):
            cmp = _cmp_semver(installed, version)
            return {
                ">=": cmp >= 0,
                "<=": cmp <= 0,
                ">": cmp > 0,
                "<": cmp < 0,
                "=": cmp == 0,
                "==": cmp == 0,
            }[op]

    return installed == version


def _satisfies_pragma(installed: tuple[int, int, int], pragma: str) -> bool:
    """Return whether an installed solc version satisfies a Solidity pragma."""
    for alternative in pragma.split("||"):
        tokens = re.findall(r"(?:\^|~|>=|<=|>|<|==|=)?\s*\d+\.\d+\.\d+", alternative)
        if tokens and all(_satisfies_simple_constraint(installed, t.replace(" ", "")) for t in tokens):
            return True
    return False


def check_lib_imports(project_dir: Path) -> List[str]:
    """Check if lib/ imports are resolvable."""
    issues = []
    remappings = load_remappings(project_dir)

    # Find all import statements in source files
    src_dirs = _source_dirs(project_dir)

    # <!-- r36-rebuttal: cap86-forge-deps-checker-isfile-2026-05-27 -->
    imported_paths: Set[str] = set()
    for src_dir in src_dirs:
        for sol_file in src_dir.rglob("*.sol"):
            # CAP-GAP-86 2026-05-27: Foundry's out/ tree puts each contract's
            # compiled artifact inside a directory named <Contract>.sol/
            # (containing <Contract>.json). rglob matches that directory; we
            # must skip directories before read_text() to avoid IsADirectoryError.
            if not sol_file.is_file():
                continue
            text = sol_file.read_text(errors="ignore")
            for m in re.finditer(r'import\s+(?:\{[^}]+\}\s+from\s+)?["\']([^"\']+)["\'];', text):
                imported_paths.add(m.group(1))

    # Check each import
    for imp in imported_paths:
        if _resolve_import(project_dir, remappings, imp):
            continue
        issues.append(f"Unresolved import: {imp}")

    return issues


def check_remappings(project_dir: Path) -> List[str]:
    """Check remappings configuration."""
    issues = []

    # Check foundry.toml for remappings
    foundry_toml = project_dir / "foundry.toml"
    remappings_txt = project_dir / "remappings.txt"

    has_remappings = False
    if foundry_toml.exists():
        text = foundry_toml.read_text()
        if "remappings" in text:
            has_remappings = True
    if remappings_txt.exists():
        has_remappings = True

    if not has_remappings:
        # Check if any imports use remapped paths
        src_dirs = [project_dir / "src", project_dir / "contracts"]
        src_dirs = [d for d in src_dirs if d.exists()]

        for src_dir in src_dirs:
            for sol_file in src_dir.rglob("*.sol"):
                # CAP-GAP-86 2026-05-27: Foundry artifact directories can be
                # named <Contract>.sol/ under out/. Only source files should
                # participate in remapping checks.
                if not sol_file.is_file():
                    continue
                text = sol_file.read_text(errors="ignore")
                if re.search(r'import\s+["\']@', text):
                    issues.append("Imports use remapped paths (@...) but no remappings configured")
                    break

    return issues


def check_solc_versions(project_dir: Path) -> List[str]:
    """Check solc version compatibility."""
    issues = []

    # Find all pragma statements
    src_dirs = [project_dir / "src", project_dir / "contracts"]
    src_dirs = [d for d in src_dirs if d.exists()]

    # <!-- r36-rebuttal: cap86-forge-deps-checker-isfile-2026-05-27 -->
    versions: Set[str] = set()
    for src_dir in src_dirs:
        for sol_file in src_dir.rglob("*.sol"):
            # CAP-GAP-86 2026-05-27: same Foundry out/ DIRECTORY-named-.sol/ guard.
            if not sol_file.is_file():
                continue
            text = sol_file.read_text(errors="ignore")
            for m in re.finditer(r'pragma\s+solidity\s+([^;]+);', text):
                versions.add(m.group(1).strip())

    if not versions:
        return issues

    # Check if solc-select has compatible versions
    try:
        result = subprocess.run(
            ["solc-select", "versions"],
            capture_output=True, text=True, timeout=10
        )
        installed: set[tuple[int, int, int]] = set()
        for line in result.stdout.splitlines():
            parsed = _parse_semver(line)
            if parsed:
                installed.add(parsed)

        for pragma in versions:
            matched = any(_satisfies_pragma(v, pragma) for v in installed)
            if not matched:
                issues.append(f"No compatible solc for pragma: {pragma}")
    except Exception:
        pass

    return issues


def _parse_solc_local_path(foundry_toml: Path) -> Optional[str]:
    """Parse the solc = "./solc-X.Y.Z" local binary path from foundry.toml.

    Returns the raw value string (e.g. "./solc-0.8.30") if found and it looks
    like a relative local path (starts with "./" or is just "solc-X.Y.Z" with
    no directory separator other than the leading dot). Returns None if solc is
    not set or is a plain version string like "0.8.30".
    """
    if not foundry_toml.exists():
        return None
    text = foundry_toml.read_text(errors="ignore")
    # Match: solc = "./solc-0.8.30"  or  solc = 'solc-0.8.30'  or unquoted
    # We only treat it as a local path if it starts with "." or does NOT look
    # like a bare semver (i.e. contains a path separator or starts with ".").
    m = re.search(
        r'^\s*solc\s*=\s*["\']?([^"\'#\n\r]+)["\']?',
        text,
        re.MULTILINE,
    )
    if not m:
        return None
    value = m.group(1).strip().strip('"').strip("'").strip()
    # Bare semver like "0.8.30" is NOT a local path - svm / forge handles those.
    if re.fullmatch(r'\d+\.\d+\.\d+', value):
        return None
    # Must start with "./" or be a bare filename that looks like "solc-X.Y.Z"
    if value.startswith("./") or value.startswith("../"):
        return value
    # bare "solc-X.Y.Z" with no directory component is also a local binary hint
    if re.fullmatch(r'solc-\d+\.\d+\.\d+', value):
        return "./" + value
    return None


def _svm_binary_path(version_str: str) -> Optional[Path]:
    """Return the path to the svm-installed solc binary for version_str.

    Checks ~/.svm/<version>/solc-<version> and ~/.svm/<version>/solc.
    Returns the Path if it exists and is executable, else None.
    """
    svm_root = Path.home() / ".svm"
    if not svm_root.is_dir():
        return None
    ver_dir = svm_root / version_str
    for candidate_name in (f"solc-{version_str}", "solc"):
        candidate = ver_dir / candidate_name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate
    return None


def check_solc_local_path(project_dir: Path) -> List[str]:
    """Check whether the local solc binary path in foundry.toml exists.

    G5 fix: foundry.toml may pin `solc = "./solc-0.8.30"` expecting a local
    binary created by bootstrap.sh. When missing, forge build fails entirely.
    This check reports the missing binary and the svm candidate path.
    """
    issues = []
    foundry_toml = project_dir / "foundry.toml"
    local_path_val = _parse_solc_local_path(foundry_toml)
    if local_path_val is None:
        return issues

    # Resolve the local binary path relative to project_dir
    local_binary = (project_dir / local_path_val).resolve()
    if local_binary.exists():
        return issues  # already in place

    # Extract version from the path value (e.g. "./solc-0.8.30" -> "0.8.30")
    version_match = re.search(r'(\d+\.\d+\.\d+)', local_path_val)
    version_str = version_match.group(1) if version_match else None

    svm_bin = _svm_binary_path(version_str) if version_str else None
    if svm_bin:
        issues.append(
            f"Local solc binary missing: {local_path_val} "
            f"(svm binary available at {svm_bin}; use --fix to symlink)"
        )
    else:
        issues.append(
            f"Local solc binary missing: {local_path_val} "
            f"(no svm binary found for version {version_str}; "
            f"run: svm install {version_str})"
        )
    return issues


def fix_solc_local_path_symlink(project_dir: Path) -> dict:
    """Auto-create a symlink from the local solc path to the svm binary.

    G5 fix: idempotent - only creates the symlink if the target is absent.
    Controlled by env AUDITOOOR_NO_AUTO_SOLC_SYMLINK=1 (skips silently).

    Returns a dict with keys:
      status: "skipped-env-guard" | "skipped-not-local-path" |
              "skipped-already-exists" | "skipped-no-svm-binary" |
              "fix-applied" | "fix-failed"
      message: human-readable explanation
      symlink_path: str (path where symlink was created, if applicable)
      svm_binary: str (svm binary path, if found)
    """
    if os.environ.get("AUDITOOOR_NO_AUTO_SOLC_SYMLINK", "").strip() == "1":
        return {"status": "skipped-env-guard",
                "message": "AUDITOOOR_NO_AUTO_SOLC_SYMLINK=1 set; skipping solc symlink creation"}

    foundry_toml = project_dir / "foundry.toml"
    local_path_val = _parse_solc_local_path(foundry_toml)
    if local_path_val is None:
        return {"status": "skipped-not-local-path",
                "message": "foundry.toml does not pin a local solc binary path"}

    local_binary = (project_dir / local_path_val).resolve()
    if local_binary.exists():
        return {"status": "skipped-already-exists",
                "message": f"Local solc binary already exists: {local_binary}",
                "symlink_path": str(local_binary)}

    version_match = re.search(r'(\d+\.\d+\.\d+)', local_path_val)
    version_str = version_match.group(1) if version_match else None
    svm_bin = _svm_binary_path(version_str) if version_str else None

    if svm_bin is None:
        return {"status": "skipped-no-svm-binary",
                "message": f"No svm binary found for version {version_str}; "
                           f"run: svm install {version_str}",
                "svm_binary": None}

    try:
        os.symlink(str(svm_bin), str(local_binary))
        return {"status": "fix-applied",
                "message": f"Created symlink {local_binary} -> {svm_bin}",
                "symlink_path": str(local_binary),
                "svm_binary": str(svm_bin)}
    except OSError as exc:
        return {"status": "fix-failed",
                "message": f"Failed to create symlink {local_binary} -> {svm_bin}: {exc}",
                "symlink_path": str(local_binary),
                "svm_binary": str(svm_bin)}


def fix_git_submodules(project_dir: Path) -> bool:
    """Try to initialize git submodules.

    On a SHALLOW superproject clone (`git clone --depth 1`, the common audit-
    workspace case), `--init --recursive` FAILS on nested pinned submodules:
    the shallow tip does not contain the exact pinned revision a nested
    submodule references (observed on ethereum-optimism/optimism: lib-keccak ->
    forge-std -> ds-test, "Unable to find current revision in submodule path").
    The top-level libs (what foundry remappings reference: forge-std, OZ,
    solady, ...) are what the build actually needs. So: try the full recursive
    init first, and if it fails, fall back to a non-recursive, shallow
    (`--depth 1`) top-level init which populates the direct deps and tolerates
    the unresolvable nested test-of-a-dep submodules.
    """
    def _run(args: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "submodule", "update", *args],
            cwd=project_dir, capture_output=True, text=True, timeout=300
        )

    print("[deps] Attempting: git submodule update --init --recursive ...")
    try:
        result = _run(["--init", "--recursive"])
        if result.returncode == 0:
            print("[deps] Submodules initialized successfully")
            return True
        print(f"[deps] Recursive init failed: {result.stderr[:200]}")
        # Fallback for shallow clones with nested pinned submodules: top-level,
        # non-recursive, shallow. Populates the direct deps the build needs.
        print("[deps] Fallback: git submodule update --init --depth 1 (top-level, non-recursive) ...")
        fb = _run(["--init", "--depth", "1"])
        if fb.returncode == 0:
            print("[deps] Top-level submodules initialized (shallow fallback)")
            return True
        print(f"[deps] Fallback init also failed: {fb.stderr[:200]}")
        return False
    except Exception as e:
        print(f"[deps] Error: {e}")
        return False


def fix_forge_install(project_dir: Path) -> bool:
    """Try to run forge install."""
    print("[deps] Attempting: forge install ...")
    try:
        result = subprocess.run(
            ["forge", "install"],
            cwd=project_dir,
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            print("[deps] Forge install completed")
            return True
        else:
            print(f"[deps] Forge install failed: {result.stderr[:200]}")
            return False
    except Exception as e:
        print(f"[deps] Error: {e}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Foundry dependency health checker")
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("--fix", action="store_true", help="Auto-fix issues where possible")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.exists():
        print(f"[deps] Workspace not found: {ws}")
        sys.exit(1)

    project_dir = find_forge_project(ws)
    if not project_dir:
        # No foundry.toml found. Before bailing, try the verified-source
        # scaffolder: when the workspace is block-explorer-fetched verified
        # source (flat src/ tree, no build config), scaffold a compilable
        # Foundry setup, then re-resolve the project root. This composes the
        # two tools: scaffold -> health-check. Advisory: a scaffolder failure
        # must not crash the health check.
        scaffolded = _try_scaffold_verified_source(ws, do_fix=args.fix)
        if scaffolded:
            project_dir = find_forge_project(ws)
        # hardhat/npm Solidity repos (package.json + contracts/, no foundry.toml)
        # need a foundry shim before forge can build them (compile-cascade fix).
        if not project_dir:
            if _scaffold_hardhat_foundry_shim(ws, do_fix=args.fix):
                scaffolded = True
                project_dir = find_forge_project(ws)
        if not project_dir:
            if args.json:
                print(json.dumps({
                    "project_dir": None,
                    "issues": [{"category": "no-foundry-toml",
                                "issue": f"No foundry.toml found in {ws}"
                                         + (" (scaffolder ran but produced no "
                                            "project root)" if scaffolded else
                                            "; run with --fix to scaffold "
                                            "verified source")}],
                    "fixable": args.fix,
                    "fix_log": [],
                }, indent=2))
            else:
                print(f"[deps] No foundry.toml found in {ws}")
                if not args.fix:
                    print("[deps] If this is block-explorer-fetched verified "
                          "source, run with --fix to scaffold a Foundry "
                          "project (foundry.toml + remappings.txt).")
            sys.exit(1)

    print(f"[deps] Checking dependencies for: {project_dir}")

    all_issues = []
    fix_log: list[dict] = []

    # G5: Check / fix local solc binary path FIRST - blocks all other checks
    # when the binary is missing.
    if args.fix:
        solc_fix_result = fix_solc_local_path_symlink(project_dir)
        fix_log.append({"check": "solc-local-path", **solc_fix_result})
        status = solc_fix_result["status"]
        if status == "fix-applied":
            print(f"[deps] [solc-local-path] fix-applied: {solc_fix_result['message']}")
        elif status in ("skipped-env-guard", "skipped-already-exists", "skipped-not-local-path"):
            pass  # silent for non-issues
        elif status == "skipped-no-svm-binary":
            print(f"[deps] [solc-local-path] WARNING: {solc_fix_result['message']}")
        elif status == "fix-failed":
            print(f"[deps] [solc-local-path] ERROR: {solc_fix_result['message']}")

    solc_path_issues = check_solc_local_path(project_dir)
    if solc_path_issues:
        all_issues.extend([("solc-local-path", i) for i in solc_path_issues])

    # Check git submodules
    submod_issues = check_git_submodules(project_dir)
    if submod_issues:
        all_issues.extend([("git-submodule", i) for i in submod_issues])
        if args.fix:
            if fix_git_submodules(project_dir):
                # Re-check
                submod_issues = check_git_submodules(project_dir)
                if not submod_issues:
                    print("[deps] [git-submodule] fixed")

    # Check lib imports
    lib_issues = check_lib_imports(project_dir)
    if lib_issues:
        all_issues.extend([("lib-import", i) for i in lib_issues])
        if args.fix:
            if fix_forge_install(project_dir):
                # Re-check
                lib_issues = check_lib_imports(project_dir)
                if not lib_issues:
                    print("[deps] [lib-import] fixed")

    # Check remappings
    remap_issues = check_remappings(project_dir)
    if remap_issues:
        all_issues.extend([("remappings", i) for i in remap_issues])

    # Check solc versions
    solc_issues = check_solc_versions(project_dir)
    if solc_issues:
        all_issues.extend([("solc", i) for i in solc_issues])

    if args.json:
        output = {
            "project_dir": str(project_dir),
            "issues": [{"category": cat, "issue": issue} for cat, issue in all_issues],
            "fixable": args.fix,
            "fix_log": fix_log,
        }
        print(json.dumps(output, indent=2))
    else:
        if not all_issues:
            print("[deps] All dependencies OK")
        else:
            print(f"\n[deps] Found {len(all_issues)} issue(s):")
            for cat, issue in all_issues:
                print(f"  [{cat}] {issue}")

            if not args.fix:
                print("\n[deps] Run with --fix to auto-resolve where possible")
                print("[deps] Manual fixes:")
                print("  - Local solc binary: symlink ./solc-X.Y.Z -> ~/.svm/X.Y.Z/solc-X.Y.Z")
                print("  - Git submodules: git submodule update --init --recursive")
                print("  - Missing libs: forge install")
                print("  - Remappings: add to foundry.toml or remappings.txt")
                print("  - Solc: solc-select install <version> OR svm install <version>")

    sys.exit(0 if not all_issues else 1)


if __name__ == "__main__":
    main()
