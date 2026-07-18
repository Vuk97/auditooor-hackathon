#!/usr/bin/env python3
"""
workspace-scan-orchestrator.py — parseable detector-log scan subset.

Runs the detector backends whose logs `engage.py` parses directly:
  * detectors/run_custom.py   — Slither-based DSL-compiled detectors (.sol)
  * tools/apply-queries.sh    — grep heuristics for Glider-style queries (.sol)
  * tools/rust-detect.py      — tree-sitter Rust detectors (.rs)
  * tools/cosmos-detector-runner.py — Cosmos-SDK Go DSL rows (.go)
  * tools/circom-detect.py    — text/shape Circom detectors (.circom)
  * tools/invariant-hunt.sh   — surfaced as an available follow-on, not run here

Auto-detects which languages are present in the workspace and runs the
relevant tools. Aggregates every per-tool log into a consolidated
<workspace>/scan_report.md with:
  - headline "N hits across M detectors"
  - per-severity breakdown (HIGH / MEDIUM / LOW)
  - top-10 noisiest detectors (for FP triage)

Graceful degradation: if a tool is missing, it's logged as SKIPPED and the
scan continues. Exits 0 even on an empty workspace so it plays nice with
CI dispatchers. (Phase 27, PR #84.)

For the broader workspace scan facade (`SCAN_REPORT.md`, `PATTERN_HITS.md`,
static analysis, Solodit plan, hypotheses), use `tools/scan.sh`.

Usage:
  python3 tools/workspace-scan-orchestrator.py --workspace <path>
  python3 tools/workspace-scan-orchestrator.py --workspace <path> --mode maintenance
  python3 tools/workspace-scan-orchestrator.py --workspace <path> --out /tmp/scan_out
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
IMPACT_MAPPING_LIB = HERE / "lib" / "program_impact_mapping.py"


# Load tools/scan_skip_remediation.py via importlib so callers don't need
# `tools/` on sys.path. The module is stdlib-only and pure-functional.
def _load_skip_remediation():
    spec = importlib.util.spec_from_file_location(
        "_scan_skip_remediation_orch",
        HERE / "scan_skip_remediation.py",
    )
    if spec is None or spec.loader is None:  # pragma: no cover (defensive)
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_scan_skip_remediation_orch"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:  # pragma: no cover (defensive)
        return None
    return mod


_SKIP_REM = _load_skip_remediation()


def _load_impact_mapping():
    spec = importlib.util.spec_from_file_location(
        "_impact_mapping_orch",
        IMPACT_MAPPING_LIB,
    )
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_impact_mapping_orch"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:  # pragma: no cover - defensive
        return None
    return mod


_IMPACT_MAPPING = _load_impact_mapping()

RUN_CUSTOM     = REPO / "detectors" / "run_custom.py"
RUN_REGEX_DETS = REPO / "detectors" / "run_regex_detectors.py"
RUST_DETECT    = REPO / "tools"     / "rust-detect.py"
COSMOS_DETECT  = REPO / "tools"     / "cosmos-detector-runner.py"
CIRCOM_DETECT  = REPO / "tools"     / "circom-detect.py"
APPLY_QUERIES  = REPO / "tools"     / "apply-queries.sh"
INVARIANT_HUNT = REPO / "tools"     / "invariant-hunt.sh"

SEV_HIGH = {"high", "critical", "HIGH", "CRITICAL", "High", "Critical"}
SEV_MED  = {"medium", "MEDIUM", "Medium"}
SEV_LOW  = {"low", "informational", "info", "LOW", "INFO", "Low", "Info"}

PROMOTION_ADVISORY_SCHEMA = "auditooor.scanner_promotion_advisories.v1"
_LOW_CONFIG_LIVENESS_DETECTOR_RE = re.compile(
    r"(fee|amp|amplification|config|constructor|factory|pool|hook|liquid|swap|init)",
    re.IGNORECASE,
)
_CREATE_FN_RE = re.compile(
    r"function\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<params>[^)]*)\)"
    r"(?P<mods>[^{;]*)\{",
    re.IGNORECASE | re.DOTALL,
)
_CONSTRUCTOR_RE = re.compile(
    r"constructor\s*\((?P<params>[^)]*)\)(?P<mods>[^{;]*)\{",
    re.IGNORECASE | re.DOTALL,
)
_CONTRACT_RE = re.compile(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)")
_CONFIG_PARAM_RE = re.compile(
    r"\b(fee|fees|swapFee|protocolFee|adminFee|amp|amplification|config|configuration|hook|hooks|poolKey)\b",
    re.IGNORECASE,
)
_FACTORY_CREATE_NAME_RE = re.compile(
    r"(create|deploy|clone|new|init|initialize|pool|market|pair|hook)",
    re.IGNORECASE,
)
_POOL_INIT_RE = re.compile(
    r"(PoolKey|PoolId|poolManager\s*\.\s*initialize|initializePool|createPool|"
    r"\.initialize\s*\(|IHooks\b)",
    re.IGNORECASE,
)
_LATER_POOL_ACTION_RE = re.compile(
    r"\b(function\s+[A-Za-z_][A-Za-z0-9_]*(?:swap|addLiquidity|removeLiquidity|"
    r"modifyLiquidity|increaseLiquidity|decreaseLiquidity|mint|burn|deposit|withdraw)"
    r"[A-Za-z0-9_]*\s*\([^)]*\)[^{;]*(?:public|external)|"
    r"\.(?:swap|addLiquidity|removeLiquidity|modifyLiquidity|mint|burn)\s*\()",
    re.IGNORECASE | re.DOTALL,
)
_PUBLIC_OR_EXTERNAL_RE = re.compile(r"\b(public|external)\b", re.IGNORECASE)


def _path_under(p: Path, root: Path) -> bool:
    """True iff ``p`` is ``root`` itself or lives beneath it (resolved)."""
    try:
        rp = p.resolve()
        rr = root.resolve()
    except OSError:
        return False
    if rp == rr:
        return True
    try:
        rp.relative_to(rr)
        return True
    except ValueError:
        return False


def _load_scope_roots(workspace: Path) -> tuple[list[Path] | None, list[Path]]:
    """Resolve ``scope.json`` in_scope/out_of_scope entries to absolute paths.

    Returns ``(include_roots, exclude_roots)``. ``include_roots`` is ``None``
    when no usable ``scope.json`` is present, so callers fall back to whole-
    workspace language detection (backward compatible). Entries are relative to
    the repo root, which for an auditooor workspace is ``<ws>/src`` (or a single
    subdir under it for a monorepo clone); we try those bases and keep the ones
    that exist on disk.

    GENERIC FIX (hyperlane step-1, 2026-06-20): without this, a polyglot monorepo
    where only one language is in scope (e.g. Hyperlane: only ``solidity/contracts``
    is in scope, but the clone ships ~948 Rust + ~1700 TS files) makes
    ``detect_languages`` flag every present language by mere file existence and
    run that language's detector over OUT-OF-SCOPE code - ~hours of wasted scan.
    """
    scope_file = None
    for cand in (workspace / "scope.json", workspace / "src" / "scope.json"):
        if cand.is_file():
            scope_file = cand
            break
    if scope_file is None:
        return None, []
    try:
        data = json.loads(scope_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, []
    if not isinstance(data, dict):
        return None, []

    bases = [workspace, workspace / "src"]
    srcdir = workspace / "src"
    if srcdir.is_dir():
        for sub in sorted(srcdir.iterdir()):
            if sub.is_dir() and not sub.name.startswith("."):
                bases.append(sub)

    def _resolve(entry: str) -> list[Path]:
        out: list[Path] = []
        for base in bases:
            p = base / entry
            if p.exists():
                try:
                    out.append(p.resolve())
                except OSError:
                    pass
        return out

    include: list[Path] = []
    exclude: list[Path] = []
    for key, val in data.items():
        if str(key).startswith("_") or not isinstance(val, list):
            continue
        k = str(key).lower()
        if "out_of_scope" in k or "exclude" in k:
            for e in val:
                exclude.extend(_resolve(str(e)))
        elif "in_scope" in k or "include" in k:
            for e in val:
                include.extend(_resolve(str(e)))

    # scope.json present but nothing resolved (paths don't match this layout) ->
    # fall back to whole-ws detection rather than silently detecting nothing.
    if not include:
        return None, exclude
    return include, exclude


_SCAN_PRUNE_DIRS = frozenset({
    ".git", "target", "node_modules", ".auditooor", "vendor", "third_party",
    "dist", "build", "out", ".cargo", ".cache", "__pycache__", ".venv",
    "artifacts", "cache",
})


def _rglob_pruned(root: Path, pattern: str):
    """Like root.rglob(pattern) but PRUNES heavy/regenerable dirs at walk-time
    (.git, target, node_modules, ...). Plain root.rglob descends the WHOLE tree
    before yielding - catastrophic on a workspace carrying multi-GB Rust target/
    build artifacts (near-intents: 3.3 GB -> the scan stage timed out at 1200s
    just walking to find a handful of .sol). Yields matching Paths."""
    import fnmatch
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SCAN_PRUNE_DIRS]
        for fn in filenames:
            if fnmatch.fnmatch(fn, pattern):
                yield Path(dirpath) / fn


def detect_languages(workspace: Path) -> set[str]:
    include_roots, exclude_roots = _load_scope_roots(workspace)
    scan_roots = include_roots if include_roots else [workspace]

    # Heavy/regenerable dirs that must be PRUNED AT WALK-TIME. The old
    # root.rglob(glob) descended the ENTIRE tree and only post-filtered paths, so
    # a workspace carrying Rust `target/` build artifacts (near-intents: 3.3 GB of
    # target/ after a cargo build) made language detection I/O-stall for minutes
    # at 0% CPU - the scan-orchestrator hung before its first log line. os.walk
    # with in-place dirnames pruning never descends these, so detection is fast
    # regardless of build artifacts.
    _HEAVY_PRUNE = frozenset({
        ".git", "target", "node_modules", ".auditooor", "vendor", "third_party",
        "dist", "build", "out", ".cargo", ".cache", "__pycache__", ".venv",
        "artifacts", "cache",
    })

    def _present(glob: str, skip_substrs: tuple[str, ...] = (),
                 skip_parts: frozenset[str] = frozenset()) -> bool:
        suffix = glob.lstrip("*")
        prune = _HEAVY_PRUNE | set(skip_parts)
        for root in scan_roots:
            # a scope entry may be a single file (e.g. Mailbox.sol), not a dir
            if root.is_file():
                if root.name.endswith(suffix) and not any(_path_under(root, e) for e in exclude_roots):
                    return True
                continue
            if not root.is_dir():
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                # prune heavy/regenerable + scope-skip dirs BEFORE descending
                dirnames[:] = [d for d in dirnames if d not in prune]
                for fn in filenames:
                    if not fn.endswith(suffix):
                        continue
                    p = Path(dirpath) / fn
                    s = str(p)
                    if any(x in s for x in skip_substrs):
                        continue
                    if any(_path_under(p, e) for e in exclude_roots):
                        continue
                    return True
        return False

    langs: set[str] = set()
    if _present("*.sol", skip_substrs=("/node_modules/", "/lib/")):
        langs.add("sol")
    if _present("*.rs", skip_substrs=("/target/",)):
        langs.add("rs")
    if _present("*.go", skip_parts=frozenset({
        ".git", ".auditooor", "node_modules", "vendor", "third_party",
        "testdata", "tests", "test", "build", "dist", "out",
    })):
        langs.add("go")
    if _present("*.circom", skip_substrs=("/node_modules/", "/lib/")):
        langs.add("circom")
    return langs


# Vendored / non-production Solidity that must never be the compilation input
# the in-scope resolver points Slither at.  @openzeppelin (and friends) are
# upstream libraries reported to the vendor, not the program; .t.sol/.s.sol are
# Foundry test/script contracts.
_VENDORED_SOL_SEGMENTS = (
    "@openzeppelin",
    "node_modules",
    "lib",
    "vendor",
    "out",
    "cache",
    "artifacts",
)
# Non-production in-tree Solidity directories that are OUT OF SCOPE by audit
# convention (and explicitly per most bounty rules: test/mock/config files are
# OOS). These commonly DUPLICATE the real contracts/ tree (e.g. a docs/ mirror)
# or are historical/non-deployed, so compiling them wastes scan time AND, worse,
# would promote OOS units into the in-scope inventory. Matched as exact path
# components, so a *file* named MockToken.sol under contracts/ is NOT excluded -
# only files that live under one of these directories.
_NON_PRODUCTION_SOL_SEGMENTS = (
    "docs",
    "mock",
    "mocks",
    "test",
    "tests",
    "previousVersions",
)
# Conventional Solidity source-tree segments.  Used only as the *no-manifest*
# fallback signal to tell a real contracts tree apart from a precompile .sol
# stub that happens to sit next to Go source (e.g. Sei `precompiles/bank`).
_SOL_SOURCE_DIR_SEGMENTS = ("contracts", "solidity")


def _is_vendored_sol(rel: Path) -> bool:
    """True for vendored / test / script Solidity that must be excluded.

    Matches the spec's 'exclude vendored @openzeppelin + .t.sol/.s.sol' as well
    as the usual build-artifact directories.
    """
    if rel.name.endswith((".t.sol", ".s.sol")):
        return True
    parts = set(rel.parts)
    if parts & set(_VENDORED_SOL_SEGMENTS):
        return True
    return bool(parts & set(_NON_PRODUCTION_SOL_SEGMENTS))


def _ensure_inscope_manifest(workspace: Path) -> bool:
    """Best-effort emit of .auditooor/inscope_units.jsonl when it is absent.

    Shells out to the idempotent, scope-filtered manifest emitter
    (workspace-coverage-heatmap.py --emit-inscope-manifest). Returns True if the
    manifest exists after the call. Never raises: any failure (tool missing,
    timeout, non-zero rc) degrades to the caller's legacy no-manifest path. This
    closes the fresh-workspace first-run ordering gap where the scan stage ran
    before any step emitted the manifest.
    """
    manifest = workspace / ".auditooor" / "inscope_units.jsonl"
    if manifest.is_file():
        return True
    emitter = HERE / "workspace-coverage-heatmap.py"
    if not emitter.is_file():
        return False
    try:
        subprocess.run(
            [
                sys.executable, str(emitter), "--emit-inscope-manifest",
                "--workspace-path", str(workspace),
            ],
            capture_output=True, text=True, timeout=600,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return manifest.is_file()


def _inscope_solidity_files(workspace: Path) -> list[Path]:
    """Resolve the in-scope Solidity files from `.auditooor/inscope_units.jsonl`.

    The funnel emits one JSONL row per in-scope unit; Solidity rows carry
    ``{"file": "<ws-relative path>.sol", "lang": "solidity"}``.  We return the
    distinct, existing, non-vendored ``.sol`` absolute paths.  Returns ``[]``
    when the manifest is absent or lists no Solidity sources, so callers can
    fall back to a path-shape heuristic without this being authoritative.
    """
    manifest = workspace / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file():
        # First-run ordering self-heal: on a fresh workspace the scan stage can
        # run before any step emits inscope_units.jsonl, so this resolver (and
        # the heuristic fallback, which does not recognise a multi-repo
        # src/<repo>/src/ layout) both return [] and Slither is skipped with
        # "no in-scope Solidity compilation input resolved" -> scan rc=1
        # (Morpho Cantina 2026-06-26: 15 foundry repos under src/, 655 .sol).
        # The manifest emitter (workspace-coverage-heatmap.py) is idempotent and
        # scope-filtered, so emit it on demand, then proceed. Any failure leaves
        # the manifest absent and we fall through to the legacy [] return.
        _ensure_inscope_manifest(workspace)
        if not manifest.is_file():
            return []
    seen: set[Path] = set()
    out: list[Path] = []
    try:
        text = manifest.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        lang = str(row.get("lang") or "").strip().lower()
        rel_raw = row.get("file") or row.get("path")
        if not rel_raw:
            continue
        rel_str = str(rel_raw)
        if not rel_str.endswith(".sol"):
            continue
        if lang and lang not in ("solidity", "sol"):
            continue
        rel = Path(rel_str)
        if _is_vendored_sol(rel):
            continue
        abs_path = rel if rel.is_absolute() else workspace / rel
        try:
            abs_path = abs_path.resolve()
        except OSError:
            continue
        if not abs_path.is_file():
            continue
        if abs_path in seen:
            continue
        seen.add(abs_path)
        out.append(abs_path)
    return sorted(out)


def _heuristic_inscope_solidity_files(workspace: Path) -> list[Path]:
    """No-manifest fallback: find real, non-vendored production Solidity sources.

    Used when no `inscope_units.jsonl` exists (e.g. a standalone scan or a
    synthetic test layout).  To avoid promoting bare precompile .sol stubs that
    merely sit next to Go source (the Sei case, which must stay a no-op), a file
    only qualifies when it lives under a conventional Solidity source segment
    (`.../contracts/...` or `.../solidity/...`).  Vendored @openzeppelin, build
    artifacts and .t.sol/.s.sol are excluded.
    """
    out: list[Path] = []
    for p in _rglob_pruned(workspace, "*.sol"):
        try:
            rel = p.relative_to(workspace)
        except ValueError:
            continue
        if _is_vendored_sol(rel):
            continue
        if not (set(rel.parts) & set(_SOL_SOURCE_DIR_SEGMENTS)):
            continue
        out.append(p.resolve())
    return sorted(out)


def _framework_cleanly_contains(root: Path, files: list[Path]) -> bool:
    """True iff every in-scope .sol file lives under the framework `root`.

    A hardhat/foundry root whose project dir does NOT contain the in-scope
    contracts (the Injective layout: hardhat.config.js under
    ``peggo/test/ethereum`` but contracts under ``peggo/solidity/contracts``)
    does not 'cleanly contain' them, so the resolver must fall back to the
    contracts directory instead of trusting the framework root.
    """
    if not files:
        return True
    try:
        root_resolved = root.resolve()
    except OSError:
        return False
    for f in files:
        try:
            f.resolve().relative_to(root_resolved)
        except (ValueError, OSError):
            return False
    return True


def _common_contracts_dir(files: list[Path]) -> "Path | None":
    """Return the shallowest directory that contains every in-scope .sol file.

    This is the 'directory holding the in-scope .sol files' the resolver points
    Slither at when no framework root cleanly contains them.
    """
    if not files:
        return None
    try:
        parents = [f.resolve().parent for f in files]
    except OSError:
        return None
    common = os.path.commonpath([str(p) for p in parents])
    common_path = Path(common)
    return common_path if common_path.is_dir() else None


def solidity_scan_target(workspace: Path) -> "Path | None":
    """Return the best Solidity target for Slither-backed run_custom.py.

    Resolution order:
      1. A usable Solidity source root from
         ``.auditooor/project_source_root_readiness.json``.
      2. A foundry.toml / hardhat.config.* framework root at the workspace
         root, ``external/`` or ``external/*`` -- BUT only when that root
         cleanly contains the in-scope contracts.  A framework whose project
         dir does not contain the in-scope .sol (Injective: hardhat config
         under ``peggo/test/ethereum`` while the contracts live under
         ``peggo/solidity/contracts``) is NOT used; we fall through.
      3. The directory that actually holds the in-scope ``.sol`` files
         (vendored ``@openzeppelin`` + ``.t.sol``/``.s.sol`` excluded), so the
         scan analyzes the real in-scope contracts even when no framework root
         is wired up around them.
      4. None -- no Solidity project at all (e.g. a Go/Rust workspace whose
         only ``.sol`` are bare precompile stubs).  Callers treat None as
         "no-solidity-project: skip Slither-backed tools gracefully" instead of
         erroring with "Expected a Solidity file when not using a compilation
         framework".
    """
    readiness = workspace / ".auditooor" / "project_source_root_readiness.json"
    try:
        payload = json.loads(readiness.read_text(encoding="utf-8"))
    except Exception:
        payload = {}
    roots = payload.get("roots") if isinstance(payload, dict) else []
    if isinstance(roots, list):
        for row in roots:
            if not isinstance(row, dict) or not row.get("usable"):
                continue
            presence = row.get("language_presence") if isinstance(row.get("language_presence"), dict) else {}
            suffix_counts = row.get("suffix_counts") if isinstance(row.get("suffix_counts"), dict) else {}
            if int(presence.get("solidity") or suffix_counts.get(".sol") or 0) <= 0:
                continue
            raw = row.get("resolved_path") or row.get("workspace_relative_path") or row.get("declared_path")
            if not raw:
                continue
            root = Path(str(raw))
            if not root.is_absolute():
                root = workspace / root
            if root.exists():
                return root

    # In-scope contracts (manifest-authoritative, path-heuristic fallback).
    inscope = _inscope_solidity_files(workspace)
    if not inscope:
        inscope = _heuristic_inscope_solidity_files(workspace)

    candidates = [workspace, workspace / "external"]
    external_dir = workspace / "external"
    if external_dir.is_dir():
        candidates.extend(sorted(external_dir.glob("*")))
    for root in candidates:
        if root.is_dir() and (
            (root / "foundry.toml").is_file()
            or (root / "hardhat.config.js").is_file()
            or (root / "hardhat.config.ts").is_file()
        ):
            # Only trust the framework root when it actually contains the
            # in-scope contracts.  Otherwise fall through to the contracts dir.
            if _framework_cleanly_contains(root, inscope):
                return root

    # No framework root cleanly contains the in-scope contracts.  Point Slither
    # at the directory that actually holds them so Peggy.sol et al. are scanned.
    contracts_dir = _common_contracts_dir(inscope)
    if contracts_dir is not None:
        return contracts_dir

    # No compilation framework AND no in-scope Solidity sources: returning None
    # tells the caller to skip Slither-backed tools rather than passing a bare
    # directory to Slither.
    return None


def solidity_scan_inputs(workspace: Path) -> "list[Path]":
    """Return the concrete file/dir targets to feed Slither for this workspace.

    Slither (and ``run_custom.py``) accept a single compilation framework
    directory OR a single ``.sol`` file, but NOT a bare directory that holds
    loose ``.sol`` files with no framework.  So:

      * When the resolved target is a framework root (foundry.toml /
        hardhat.config.* present), return ``[target]`` -- Slither drives the
        framework.
      * Otherwise the resolved target is the directory holding the in-scope
        contracts; return the individual in-scope ``.sol`` files inside it so
        Slither compiles each via solc directly (relative ``@openzeppelin``
        imports resolve because they are co-located).

    Returns ``[]`` when there is no Solidity project (caller skips gracefully).
    """
    target = solidity_scan_target(workspace)
    if target is None:
        return []
    if target.is_file():
        return [target]
    if target.is_dir() and (
        (target / "foundry.toml").is_file()
        or (target / "hardhat.config.js").is_file()
        or (target / "hardhat.config.ts").is_file()
    ):
        # Framework directory: hand the whole project to Slither.
        return [target]
    # Bare contracts directory: enumerate the in-scope .sol files within it.
    inscope = _inscope_solidity_files(workspace)
    if not inscope:
        inscope = _heuristic_inscope_solidity_files(workspace)
    try:
        target_resolved = target.resolve()
    except OSError:
        target_resolved = target
    within = []
    for f in inscope:
        try:
            f.resolve().relative_to(target_resolved)
        except (ValueError, OSError):
            continue
        within.append(f)
    if within:
        return sorted(within)
    # Fallback: any non-vendored .sol directly under the resolved dir tree.
    files: list[Path] = []
    for p in target.rglob("*.sol"):
        try:
            rel = p.relative_to(target)
        except ValueError:
            rel = Path(p.name)
        if _is_vendored_sol(rel):
            continue
        files.append(p.resolve())
    return sorted(set(files))


def _is_vendor_path(path: Path) -> bool:
    return bool({"node_modules", "lib", "vendor", "out", "cache"} & set(path.parts))


def _solidity_sources(workspace: Path) -> list[Path]:
    """Return production Solidity sources, excluding vendor paths and test/script files.

    .t.sol (Foundry test contracts) and .s.sol (Foundry script contracts) are
    excluded because they are not production code and can spuriously match the
    pool-liveness advisory shape patterns, producing false-positive advisories.
    """
    return sorted(
        p for p in _rglob_pruned(workspace, "*.sol")
        if not _is_vendor_path(p.relative_to(workspace))
        and not p.name.endswith((".t.sol", ".s.sol"))
    )


def _line_no(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _contract_name(text: str, fallback: str) -> str:
    match = _CONTRACT_RE.search(text)
    return match.group(1) if match else fallback


def _low_config_liveness_detectors(hits: list[tuple[str, str]]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for name, sev in hits:
        if bucket_severity(sev) != "LOW":
            continue
        if not _LOW_CONFIG_LIVENESS_DETECTOR_RE.search(name):
            continue
        if name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


def _function_segment(text: str, start: int) -> str:
    next_fn = re.search(r"\n\s*(?:function|constructor)\s+", text[start + 1 :])
    end = start + 1 + next_fn.start() if next_fn else min(len(text), start + 6000)
    return text[start:end]


def _factory_create_matches(text: str) -> list[re.Match[str]]:
    matches: list[re.Match[str]] = []
    for match in _CREATE_FN_RE.finditer(text):
        name = match.group("name")
        params = match.group("params") or ""
        mods = match.group("mods") or ""
        if not _PUBLIC_OR_EXTERNAL_RE.search(mods):
            continue
        if not _FACTORY_CREATE_NAME_RE.search(name):
            continue
        if not _CONFIG_PARAM_RE.search(params):
            continue
        matches.append(match)
    return matches


def _constructor_config_matches(text: str) -> list[re.Match[str]]:
    if not _factory_create_matches(text):
        return []
    matches: list[re.Match[str]] = []
    for match in _CONSTRUCTOR_RE.finditer(text):
        if _CONFIG_PARAM_RE.search(match.group("params") or ""):
            matches.append(match)
    return matches


def _make_advisory_id(rel: Path, line: int, detector_names: list[str]) -> str:
    seed = f"{rel}:{line}:{','.join(detector_names)}".encode("utf-8")
    return "scanner-promo-" + hashlib.sha1(seed).hexdigest()[:12]


def _advisory_impact_contract_summary(
    workspace: Path,
    *,
    advisory_id: str,
    contract: str,
    severity_floor: str,
) -> dict[str, Any]:
    severity_claim = severity_floor.strip().capitalize()
    if severity_claim not in {"Critical", "High", "Medium"}:
        severity_claim = ""
    if _IMPACT_MAPPING is None or not hasattr(_IMPACT_MAPPING, "impact_contract_summary"):
        required = bool(severity_claim)
        return {
            "schema_version": "auditooor.impact_contract_summary.v1",
            "required": required,
            "status": "missing_contract" if required else "not_required",
            "submission_posture": "in_scope_not_submit_ready" if required else "not_required",
            "selected_impact": "",
            "severity_tier": severity_claim or ("none" if required else ""),
            "evidence_class": "",
            "oos_traps": [],
            "stop_condition": "",
            "reasons": ["impact_contract_summary_helper_missing"] if required else [],
        }
    contracts = [contract] if contract else []
    return _IMPACT_MAPPING.impact_contract_summary(
        workspace,
        candidate_id=advisory_id,
        angle_id=advisory_id,
        contracts=contracts,
        severity_claim=severity_claim,
        direct_submit=False,
    )


def _advisory_next_commands(workspace: Path, summary: dict[str, Any], recommended: str) -> list[str]:
    commands: list[str] = []
    if bool(summary.get("required")) and str(summary.get("status") or "") != "mapped":
        commands.append(f"make impact-contract-check WS={workspace} STRICT=1")
    commands.append(recommended)
    return commands


def find_low_config_liveness_advisories(
    workspace: Path,
    hits: list[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Surface Revert-like LOW scanner hits as conservative PoC work items.

    This does not upgrade detector severity. It emits an advisory only when a
    relevant LOW detector name co-occurs with a source shape that can plausibly
    turn constructor/factory config into pool or hook liveness impact:
    public factory create/deploy/init, fee/amp/config params, PoolKey/hook/pool
    initialization, and a later swap/liquidity action in the same file.
    """
    detector_names = _low_config_liveness_detectors(hits)
    if not detector_names:
        return []

    advisories: list[dict[str, Any]] = []
    for path in _solidity_sources(workspace):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not _POOL_INIT_RE.search(text):
            continue
        if not _LATER_POOL_ACTION_RE.search(text):
            continue

        matches = [("factory_create", m) for m in _factory_create_matches(text)]
        matches += [("constructor_config", m) for m in _constructor_config_matches(text)]
        if not matches:
            continue

        rel = path.relative_to(workspace)
        contract = _contract_name(text, path.stem)
        for shape_context, match in matches:
            segment = _function_segment(text, match.start())
            if not _POOL_INIT_RE.search(segment):
                continue
            later_action = _LATER_POOL_ACTION_RE.search(text, match.end())
            if not later_action:
                continue

            line = _line_no(text, match.start())
            signals = [
                "low_detector_name_matches_config_liveness",
                shape_context,
                "fee_amp_or_config_parameter",
                "poolkey_or_hook_pool_initialization",
                "later_swap_or_liquidity_action",
            ]
            recommended_next_step = (
                "Build a Foundry PoC that deploys/creates the pool with the "
                "suspect fee/amp/config, initializes PoolKey/hook wiring, then "
                "executes swap/liquidity actions to prove liveness impact."
            )
            advisory_id = _make_advisory_id(rel, line, detector_names)
            impact_contract_summary = _advisory_impact_contract_summary(
                workspace,
                advisory_id=advisory_id,
                contract=contract,
                severity_floor="LOW",
            )
            advisories.append(
                {
                    "id": advisory_id,
                    "schema_version": PROMOTION_ADVISORY_SCHEMA,
                    "source": "workspace-scan-orchestrator",
                    "kind": "capability_gap",
                    "promotion_status": "needs_poc",
                    "decision": "needs_poc",
                    "severity_floor": "LOW",
                    "severity_promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "submit_ready": False,
                    "impact_contract_required": True,
                    "impact_contract_summary": impact_contract_summary,
                    "shape": "factory_constructor_pool_liveness_config",
                    "contract": contract,
                    "file": str(rel),
                    "line": line,
                    "matched_low_detectors": detector_names,
                    "signals": signals,
                    "reason": (
                        "LOW scanner hit overlaps a Revert-like factory/constructor "
                        "config shape controlling pool or hook initialization; requires "
                        "a concrete swap/liquidity PoC before any severity claim."
                    ),
                    "recommended_next_step": recommended_next_step,
                    "next_commands": _advisory_next_commands(
                        workspace,
                        impact_contract_summary,
                        recommended_next_step,
                    ),
                }
            )
    return advisories


def write_scanner_promotion_advisories(
    out_dir: Path,
    workspace: Path,
    advisories: list[dict[str, Any]],
) -> Path:
    payload = {
        "schema_version": PROMOTION_ADVISORY_SCHEMA,
        "workspace": str(workspace),
        "advisory_count": len(advisories),
        "advisories": advisories,
    }
    path = out_dir / "scanner_promotion_advisories.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def run_tool(cmd: list[str], log_path: Path, tag: str) -> tuple[str, str]:
    """Run a tool, capture combined output to log_path. Returns (status, log)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        log_path.write_text(output)
        status = "OK" if proc.returncode == 0 else f"RC={proc.returncode}"
        return status, output
    except FileNotFoundError:
        log_path.write_text(f"[SKIPPED] {tag}: executable missing\n")
        return "SKIPPED", ""
    except subprocess.TimeoutExpired:
        log_path.write_text(f"[TIMEOUT] {tag}: exceeded 30m\n")
        return "TIMEOUT", ""
    except Exception as e:
        log_path.write_text(f"[ERROR] {tag}: {e}\n")
        return "ERROR", ""


def slither_python_candidates() -> list[str]:
    candidates = [
        os.environ.get("AUDITOOOR_PYTHON_SLITHER", "").strip(),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "python3",
    ]
    out: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in out:
            out.append(candidate)
    return out


def select_slither_python() -> str:
    """Find a Python interpreter that can import slither-analyzer."""
    for candidate in slither_python_candidates():
        try:
            proc = subprocess.run(
                [candidate, "-c", "import slither"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except Exception:
            continue
        if proc.returncode == 0:
            return candidate
    return sys.executable


_PRAGMA_RE = re.compile(
    r"pragma\s+solidity\s+[\^>=<~ ]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)


def detect_solc_pragma(sol_files: list[Path]) -> "str | None":
    """Return the highest pragma minor version seen across `sol_files`.

    Reads each file's ``pragma solidity`` line and returns the highest
    ``major.minor.patch`` floor (e.g. ``0.8.0`` for ``pragma solidity ^0.8.0``).
    Used to pin solc-select before Slither compiles a bare .sol file that has no
    framework to drive solc version selection.  Returns None when no pragma is
    found so the caller leaves the active solc unchanged.
    """
    best: tuple[int, int, int] | None = None
    best_str: str | None = None
    for f in sol_files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = _PRAGMA_RE.search(text)
        if not m:
            continue
        parts = m.group(1).split(".")
        nums = tuple(int(x) for x in parts) + (0,) * (3 - len(parts))
        triple = (nums[0], nums[1], nums[2])
        if best is None or triple > best:
            best = triple
            best_str = ".".join(str(n) for n in triple)
    return best_str


def _solc_select_use(version: str) -> bool:
    """Best-effort: select `version` via solc-select (installing if needed).

    Returns True on success.  Never raises; a failure just leaves the active
    solc as-is (Slither will then surface its own version error in the log).
    """
    if shutil.which("solc-select") is None:
        return False
    try:
        proc = subprocess.run(
            ["solc-select", "use", version],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode == 0:
            return True
        # Not installed yet: install then retry.
        subprocess.run(
            ["solc-select", "install", version],
            capture_output=True, text=True, timeout=300,
        )
        proc = subprocess.run(
            ["solc-select", "use", version],
            capture_output=True, text=True, timeout=120,
        )
        return proc.returncode == 0
    except Exception:
        return False


def pin_solc_for_pragma(sol_files: list[Path]) -> "str | None":
    """Detect the pragma floor across `sol_files` and pin solc-select to it.

    Returns the version actually pinned (or already active) on success, else
    None.  A ``^0.8.0`` floor is bumped to a known-good patch (``0.8.20``) when
    available because the bare ``.0`` patch is often missing from solc-select.
    """
    version = detect_solc_pragma(sol_files)
    if version is None:
        return None
    if _solc_select_use(version):
        return version
    # ^0.x.0 floors frequently lack the .0 patch build; try a safe bump.
    try:
        major, minor, _patch = (int(x) for x in version.split("."))
    except ValueError:
        return None
    for bump in (f"{major}.{minor}.20", f"{major}.{minor}.19",
                 f"{major}.{minor}.10", f"{major}.{minor}.1"):
        if _solc_select_use(bump):
            return bump
    return None


# ---- parsers ---------------------------------------------------------------

# run_custom.py emits lines like:
#   === Running <detector-name> ===
#   [HIGH] <description>
_SLITHER_DET = re.compile(r"^=== Running (?P<name>[\w\-]+) ===")
_SLITHER_HIT = re.compile(r"^\s*\[(?P<sev>HIGH|MEDIUM|LOW|INFO|INFORMATIONAL|CRITICAL)\]")

# rust-detect.log lines:
#   === <name>  (N hits) ===
#   [sev] path:line:col  message
_RUST_DET = re.compile(r"^=== (?P<name>[\w\-]+)\s+\((?P<n>\d+) hits\) ===")
_RUST_HIT = re.compile(r"^\s*\[(?P<sev>\w+)\]\s+\S+:\d+:\d+")

# circom-detect.log uses the same block/hit shape as rust-detect.log.
_CIRCOM_DET = _RUST_DET
_CIRCOM_HIT = _RUST_HIT

# apply-queries lines like: QUERY_NAME | 3 | file:12 | HITS
_AQ_LINE = re.compile(r"^(?P<name>[A-Z0-9_\-]+)\s*\|\s*(?P<count>\d+)\s*\|.*\|\s*(?P<verdict>HITS|CLEAN|SKIP)")
_COMPILE_FAIL_RE = re.compile(
    r"(Slither compile failed|crytic[- ]compile failed|compile failed|compilation failed|FAILED exit=|SKIPPED \(rc=)",
    re.IGNORECASE,
)
_MODULES_FAILED_RE = re.compile(r"^Modules failed\s*:\s*(?P<count>\d+)\s*$", re.MULTILINE)


def parse_slither_output(text: str) -> list[tuple[str, str]]:
    """Return list of (detector_name, severity) tuples."""
    out, current = [], None
    for ln in text.splitlines():
        m = _SLITHER_DET.match(ln)
        if m:
            current = m.group("name"); continue
        m = _SLITHER_HIT.match(ln)
        if m and current:
            out.append((current, m.group("sev").upper()))
    return out


def parse_rust_log(path: Path) -> list[tuple[str, str]]:
    if not path.exists():
        return []
    out, current = [], None
    for ln in path.read_text(errors="replace").splitlines():
        m = _RUST_DET.match(ln)
        if m:
            current = m.group("name"); continue
        m = _RUST_HIT.match(ln)
        if m and current:
            out.append((current, m.group("sev").upper()))
    return out


def parse_circom_log(path: Path) -> list[tuple[str, str]]:
    if not path.exists():
        return []
    out, current = [], None
    for ln in path.read_text(errors="replace").splitlines():
        m = _CIRCOM_DET.match(ln)
        if m:
            current = m.group("name"); continue
        m = _CIRCOM_HIT.match(ln)
        if m and current:
            out.append((current, m.group("sev").upper()))
    return out


def parse_cosmos_findings(path: Path) -> list[tuple[str, str]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    findings = data.get("findings")
    if not isinstance(findings, list):
        return []
    out: list[tuple[str, str]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        pattern = str(finding.get("pattern") or "<unknown>")
        severity = str(finding.get("severity") or "MEDIUM").upper()
        out.append((pattern, severity))
    return out


def parse_apply_queries(text: str) -> list[tuple[str, str]]:
    out = []
    for ln in text.splitlines():
        m = _AQ_LINE.match(ln)
        if m and m.group("verdict") == "HITS":
            # Treat grep heuristics as LOW by default.
            for _ in range(int(m.group("count"))):
                out.append((m.group("name"), "LOW"))
    return out


def bucket_severity(sev: str) -> str:
    if sev in SEV_HIGH: return "HIGH"
    if sev in SEV_MED:  return "MEDIUM"
    return "LOW"


def command_version(argv: list[str]) -> str:
    exe = shutil.which(argv[0])
    if exe is None:
        return "missing"
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception as exc:
        return f"error: {type(exc).__name__}"
    text = (proc.stdout or proc.stderr or "").strip().splitlines()
    return text[0] if text else f"rc={proc.returncode}"


def skipped_compilation_counts(tool_status: dict[str, str], tool_logs: dict[str, str]) -> dict[str, int]:
    skipped_tools = sum(
        1
        for status in tool_status.values()
        if status.startswith("SKIPPED") and "(no ." not in status
    )
    compile_failures = 0
    modules_failed = 0
    for text in tool_logs.values():
        compile_failures += len(_COMPILE_FAIL_RE.findall(text or ""))
        match = _MODULES_FAILED_RE.search(text or "")
        if match:
            modules_failed += int(match.group("count"))
    return {
        "skipped_tools": skipped_tools,
        "compile_failure_markers": compile_failures,
        "modules_failed": modules_failed,
        "total": skipped_tools + compile_failures + modules_failed,
    }


def collect_skip_remediation(
    tool_logs: dict[str, str],
    tool_log_paths: dict[str, str] | None = None,
) -> dict:
    """Parse each per-tool log for skip/error rows and aggregate.

    Returns the JSON-safe summary documented in
    ``scan_skip_remediation.aggregate``: a top-N rows list plus
    by-tool/by-class counts. Returns an empty-rows summary if the helper
    module is unavailable so the orchestrator never hard-fails on a
    missing helper.
    """
    if _SKIP_REM is None:
        return {
            "schema_version": "auditooor.scan_skip_remediation.v1",
            "row_count": 0,
            "top_n": 0,
            "by_error_class": {},
            "by_tool": {},
            "rows": [],
        }
    tool_log_paths = tool_log_paths or {}
    all_rows: list = []
    for tool, text in tool_logs.items():
        log_path = tool_log_paths.get(tool, "")
        rows = _SKIP_REM.parse_log_text(
            text or "",
            tool=tool,
            log_path=str(log_path) if log_path else "",
            default_module=tool,
        )
        all_rows.extend(rows)
    return _SKIP_REM.aggregate(all_rows, top_n=_SKIP_REM.DEFAULT_TOP_N)


def write_environment_manifest(out_dir: Path, workspace: Path, langs: set[str],
                               tool_status: dict[str, str],
                               tool_logs: dict[str, str],
                               skipped_counts: dict[str, int] | None = None,
                               skip_remediation: dict | None = None,
                               tool_log_paths: dict[str, str] | None = None,
                               scanner_promotion_advisories: list[dict[str, Any]] | None = None) -> Path:
    """Emit the detector-runner environment contract for scan reproducibility.

    Contract: JSON object with schema_version, workspace, languages_detected,
    versions, tool_status, skipped_compilation_counts, and ``skipped_modules``.
    The counts are conservative log-derived signals; ``skipped_modules`` adds
    the top-N exact (tool, module, error class, hint) rows pulled from the
    per-tool logs by ``scan_skip_remediation.parse_log_text``. The full
    diagnostics still live in the per-tool logs referenced by
    ``scan_report.md``.
    """
    skipped_counts = skipped_counts or skipped_compilation_counts(tool_status, tool_logs)
    skip_remediation = skip_remediation or collect_skip_remediation(
        tool_logs, tool_log_paths=tool_log_paths
    )
    manifest = {
        "schema_version": "auditooor.detector_environment.v1",
        "workspace": str(workspace),
        "platform": platform.platform(),
        "languages_detected": sorted(langs),
        "versions": {
            "python": sys.version.split()[0],
            "slither": command_version(["slither", "--version"]),
            "solc": command_version(["solc", "--version"]),
            "solc-select": command_version(["solc-select", "versions"]),
        },
        "tool_status": dict(tool_status),
        "skipped_compilation_counts": skipped_counts,
        # P2-3 / handover #17: top-N exact skipped-module examples + hints.
        "skipped_modules": skip_remediation,
        "scanner_promotion_advisories": {
            "schema_version": PROMOTION_ADVISORY_SCHEMA,
            "artifact": "scanner_promotion_advisories.json",
            "artifact_path": str(out_dir / "scanner_promotion_advisories.json"),
            "artifact_relative_to_manifest": "scanner_promotion_advisories.json",
            "advisory_count": len(scanner_promotion_advisories or []),
        },
    }
    path = out_dir / "detector_environment_manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return path


def write_report(out_dir: Path, workspace: Path, hits: list[tuple[str, str]],
                 tool_status: dict[str, str],
                 skipped_counts: dict[str, int] | None = None,
                 skip_remediation: dict | None = None,
                 scanner_promotion_advisories: list[dict[str, Any]] | None = None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    report = out_dir / "scan_report.md"

    per_det = Counter(n for n, _ in hits)
    per_sev = Counter(bucket_severity(s) for _, s in hits)
    total = len(hits)
    n_dets = len(per_det)

    lines = [
        f"# Workspace Scan Report",
        "",
        f"**Workspace**: `{workspace}`",
        "",
        f"## {total} hits across {n_dets} detectors",
        "",
        "## Severity breakdown",
        "",
        f"- HIGH:   {per_sev.get('HIGH', 0)}",
        f"- MEDIUM: {per_sev.get('MEDIUM', 0)}",
        f"- LOW:    {per_sev.get('LOW', 0)}",
        "",
        "## Tool status",
        "",
    ]
    for tool, st in tool_status.items():
        lines.append(f"- `{tool}`: {st}")
    lines += [
        "",
        "## Detector environment manifest",
        "",
        "- `detector_environment_manifest.json` records Python/slither/solc versions, tool statuses, and skipped-compilation counters.",
    ]
    if skipped_counts:
        lines.append(
            "- Skipped/failed compilation coverage: "
            f"total={skipped_counts.get('total', 0)} "
            f"(skipped_tools={skipped_counts.get('skipped_tools', 0)}, "
            f"compile_failure_markers={skipped_counts.get('compile_failure_markers', 0)}, "
            f"modules_failed={skipped_counts.get('modules_failed', 0)})."
        )

    # P2-3 / handover #17: top-N exact skipped-module examples + hints.
    if skip_remediation and skip_remediation.get("row_count", 0) > 0:
        lines += ["", "## Skipped modules — remediation hints", ""]
        lines.append(
            f"- {skip_remediation.get('row_count', 0)} skip/error row(s) parsed "
            f"from per-tool logs; showing top {len(skip_remediation.get('rows') or [])}."
        )
        by_class = skip_remediation.get("by_error_class") or {}
        if by_class:
            lines.append(
                "- Error-class breakdown: "
                + ", ".join(f"{k}={v}" for k, v in sorted(by_class.items()))
                + "."
            )
        lines.append("")
        # Render the table via the helper so the format stays single-sourced.
        if _SKIP_REM is not None:
            row_objs = []
            for r in skip_remediation.get("rows") or []:
                row_objs.append(
                    _SKIP_REM.SkipRow(
                        tool=str(r.get("tool", "")),
                        module=str(r.get("module", "")),
                        error_class=str(r.get("error_class", "")),
                        error_excerpt=str(r.get("error_excerpt", "")),
                        hint=str(r.get("hint", "")),
                        log_path=str(r.get("log_path", "")),
                    )
                )
            md = _SKIP_REM.render_markdown_table(row_objs)
            if md:
                lines.append(md)
                lines.append("")
        lines.append(
            "_See per-tool logs (`run_custom.log`, `apply_queries.log`, "
            "`rust-detect.log`, `circom-detect.log`) for the full error text._"
        )
    advisories = scanner_promotion_advisories or []
    if advisories:
        lines += ["", "## Low-hit promotion advisories", ""]
        lines.append(
            f"- {len(advisories)} LOW scanner hit(s) matched the conservative "
            "factory/constructor pool-liveness shape; written to "
            "`scanner_promotion_advisories.json`."
        )
        lines.append("- These are `needs_poc` / `capability_gap` work items, not severity upgrades.")
        reportable_blocked = 0
        for row in advisories:
            contract = row.get("impact_contract_summary")
            if isinstance(contract, dict) and contract.get("required") and contract.get("status") != "mapped":
                reportable_blocked += 1
        if reportable_blocked:
            lines.append(
                f"- {reportable_blocked} advisory row(s) are reportable-severity candidates "
                "still blocked on an exact impact contract."
            )
        lines.append("")
        for row in advisories[:10]:
            lines.append(
                f"- `{row.get('id')}` — `{row.get('file')}:{row.get('line')}` "
                f"({row.get('contract')}) — {row.get('reason')}"
            )
    lines += ["", "## Top-10 noisiest detectors (FP triage candidates)", ""]
    if per_det:
        for name, n in per_det.most_common(10):
            lines.append(f"- `{name}` — {n} hits")
    else:
        lines.append("_(no hits)_")
    lines.append("")
    report.write_text("\n".join(lines))
    return report


# ---- main ------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="One-command workspace scan.")
    ap.add_argument("--workspace", type=Path, required=True,
                    help="Workspace root to scan")
    ap.add_argument("--mode", choices=["discovery", "maintenance"],
                    default="discovery",
                    help="Detector tier mode (feeds run_custom.py, see SKILL_ISSUES #104)")
    ap.add_argument("--out", type=Path, default=None,
                    help="Output directory for logs + scan_report.md "
                         "(default: <workspace>/)")
    args = ap.parse_args()

    ws = args.workspace.resolve()
    if not ws.exists():
        print(f"[err] workspace not found: {ws}", file=sys.stderr)
        return 0  # graceful exit
    out_dir = (args.out or ws).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    langs = detect_languages(ws)
    print(f"[orch] workspace={ws}")
    print(f"[orch] languages detected: {sorted(langs) or '(none)'}")
    print(f"[orch] mode={args.mode}  out={out_dir}")

    hits: list[tuple[str, str]] = []
    status: dict[str, str] = {}
    tool_logs: dict[str, str] = {}
    tool_log_paths: dict[str, str] = {}

    # -- Solidity path -------------------------------------------------------
    if "sol" in langs:
        # Resolve the Slither-compatible compilation target.  Returns None when
        # no foundry.toml / hardhat.config.* is present (e.g. a Go/Rust chain
        # workspace with only precompile .sol stubs).  In that case all
        # Slither-backed tools are skipped gracefully so the scan stage does
        # not fail with "Expected a Solidity file when not using a compilation
        # framework".  Non-Slither tools (apply-queries grep, regex detectors)
        # still run against the workspace because they do not invoke solc.
        sol_target = solidity_scan_target(ws)
        # The concrete file/dir targets Slither can actually compile.  Either a
        # single framework directory OR the individual in-scope .sol files in a
        # bare contracts directory (Slither errors on a bare dir with no
        # framework, so we never hand it one).
        sol_inputs = solidity_scan_inputs(ws)
        _no_framework = sol_target is None
        _bare_file_inputs = (
            sol_target is not None
            and sol_target.is_dir()
            and not (
                (sol_target / "foundry.toml").is_file()
                or (sol_target / "hardhat.config.js").is_file()
                or (sol_target / "hardhat.config.ts").is_file()
            )
        )
        if _no_framework:
            print(
                "[orch] WARN: .sol files detected but no in-scope Solidity "
                "sources resolved (no foundry.toml / hardhat.config.* and no "
                "in-scope contracts dir) — Slither-backed tools will be skipped "
                "(no-solidity-project)"
            )
        elif _bare_file_inputs:
            print(
                f"[orch] no framework root cleanly contains the in-scope "
                f"contracts; pointing Slither at {len(sol_inputs)} in-scope "
                f".sol file(s) under {sol_target}"
            )

        if RUN_CUSTOM.exists():
            if _no_framework or not sol_inputs:
                status["detectors/run_custom.py"] = "SKIPPED (no-solidity-project)"
                # Write an informative log so run_custom.log exists and is parseable
                log = out_dir / "run_custom.log"
                log.write_text(
                    "[ok] loaded 0 custom detector(s): no in-scope Solidity "
                    "compilation input resolved — Slither scan skipped\n"
                    "[done] total hits: 0\n",
                    encoding="utf-8",
                )
            else:
                log = out_dir / "run_custom.log"
                slither_py = select_slither_python()
                # For bare-file inputs (no framework) pin solc-select to the
                # detected pragma so solc can compile the loose .sol files.
                if _bare_file_inputs:
                    pinned = pin_solc_for_pragma(sol_inputs)
                    if pinned:
                        print(f"[orch] pinned solc {pinned} from .sol pragma")
                # Run run_custom.py once per resolved input (a framework dir is a
                # single input; bare files are one input each) and concatenate.
                combined_out: list[str] = []
                statuses: list[str] = []
                for inp in sol_inputs:
                    st, out = run_tool(
                        [slither_py, str(RUN_CUSTOM), str(inp),
                         f"--mode={args.mode}"],
                        out_dir / f".run_custom_{inp.name}.partial",
                        "run_custom.py")
                    statuses.append(st)
                    header = f"\n=== run_custom target: {inp} ===\n"
                    combined_out.append(header + (out or ""))
                    hits += parse_slither_output(out or "")
                out = "".join(combined_out)
                log.write_text(out, encoding="utf-8")
                # Aggregate status: OK only if every per-target run was OK.
                st = "OK" if all(s == "OK" for s in statuses) else (
                    ",".join(sorted(set(statuses))))
                status["detectors/run_custom.py"] = st
                tool_logs["detectors/run_custom.py"] = out
                tool_log_paths["detectors/run_custom.py"] = str(log)
        else:
            status["detectors/run_custom.py"] = "SKIPPED (missing)"

        if APPLY_QUERIES.exists():
            log = out_dir / "apply_queries.log"
            st, out = run_tool(["bash", str(APPLY_QUERIES), str(ws)], log,
                               "apply-queries.sh")
            status["tools/apply-queries.sh"] = st
            tool_logs["tools/apply-queries.sh"] = out
            tool_log_paths["tools/apply-queries.sh"] = str(log)
            hits += parse_apply_queries(out)
        else:
            status["tools/apply-queries.sh"] = "SKIPPED (missing)"

        # L28-B fix — regex-API wave* detectors (e.g. wave17 v4-hook scans).
        # These are NOT Slither AbstractDetector subclasses, so run_custom.py
        # does NOT discover them. Without this branch, `make audit` skips
        # every new regex-shape pattern, exactly the L28-B failure mode.
        # Regex detectors do not call solc so they run even when _no_framework.
        if RUN_REGEX_DETS.exists():
            log = out_dir / "run_regex_detectors.log"
            manifest = out_dir / "regex_detectors_manifest.json"
            # Regex detectors operate on source text (no solc), so they walk
            # every non-vendored .sol under the target.  Use the framework root
            # when one was resolved; otherwise scan the whole workspace so a
            # bare contracts-dir layout still gets full text coverage.
            if sol_target is not None and not _bare_file_inputs:
                regex_target = sol_target
            else:
                regex_target = ws
            st, out = run_tool(
                ["python3", str(RUN_REGEX_DETS), str(regex_target),
                 "--workspace", str(ws), "--output", str(manifest)],
                log, "run_regex_detectors.py")
            status["detectors/run_regex_detectors.py"] = st
            tool_logs["detectors/run_regex_detectors.py"] = out
            tool_log_paths["detectors/run_regex_detectors.py"] = str(log)
            # Stream regex-detector findings into the same hits aggregator
            # so per-detector counts and total roll-ups include them.
            try:
                if manifest.is_file():
                    payload = json.loads(manifest.read_text(encoding="utf-8"))
                    for f in payload.get("findings", []) or []:
                        sev = f.get("severity") or "Unknown"
                        det = f.get("detector") or "<unknown>"
                        msg = f.get("message") or ""
                        loc = f"{f.get('file','')}:{f.get('line',0)}"
                        hits.append((sev, f"{det}: {msg[:200]} ({loc})"))
            except Exception:
                pass
        else:
            status["detectors/run_regex_detectors.py"] = "SKIPPED (missing)"
    else:
        status["detectors/run_custom.py"] = "SKIPPED (no .sol)"
        status["tools/apply-queries.sh"] = "SKIPPED (no .sol)"
        status["detectors/run_regex_detectors.py"] = "SKIPPED (no .sol)"

    # -- Rust path -----------------------------------------------------------
    if "rs" in langs:
        if RUST_DETECT.exists():
            log = out_dir / "rust_detect.stdout"
            st, _out = run_tool(
                ["python3", str(RUST_DETECT), str(ws),
                 "--log", str(out_dir / "rust-detect.log")],
                log, "rust-detect.py")
            status["tools/rust-detect.py"] = st
            tool_logs["tools/rust-detect.py"] = _out
            tool_log_paths["tools/rust-detect.py"] = str(log)
            hits += parse_rust_log(out_dir / "rust-detect.log")
        else:
            status["tools/rust-detect.py"] = "SKIPPED (missing)"
    else:
        status["tools/rust-detect.py"] = "SKIPPED (no .rs)"

    # -- Go/Cosmos path ------------------------------------------------------
    if "go" in langs:
        if COSMOS_DETECT.exists():
            log = out_dir / "cosmos_detect.stdout"
            findings_json = out_dir / "cosmos_findings.json"
            st, _out = run_tool(
                [
                    "python3",
                    str(COSMOS_DETECT),
                    str(ws),
                    "--out",
                    str(findings_json),
                ],
                log,
                "cosmos-detector-runner.py",
            )
            status["tools/cosmos-detector-runner.py"] = st
            tool_logs["tools/cosmos-detector-runner.py"] = _out
            tool_log_paths["tools/cosmos-detector-runner.py"] = str(log)
            hits += parse_cosmos_findings(findings_json)
        else:
            status["tools/cosmos-detector-runner.py"] = "SKIPPED (missing)"
    else:
        status["tools/cosmos-detector-runner.py"] = "SKIPPED (no .go)"

    # -- Circom path ---------------------------------------------------------
    if "circom" in langs:
        if CIRCOM_DETECT.exists():
            log = out_dir / "circom_detect.stdout"
            st, _out = run_tool(
                ["python3", str(CIRCOM_DETECT), str(ws),
                 "--log", str(out_dir / "circom-detect.log")],
                log, "circom-detect.py")
            status["tools/circom-detect.py"] = st
            tool_logs["tools/circom-detect.py"] = _out
            tool_log_paths["tools/circom-detect.py"] = str(log)
            hits += parse_circom_log(out_dir / "circom-detect.log")
        else:
            status["tools/circom-detect.py"] = "SKIPPED (missing)"
    else:
        status["tools/circom-detect.py"] = "SKIPPED (no .circom)"

    # invariant-hunt is opt-in (needs a contract class), so just mark it.
    status["tools/invariant-hunt.sh"] = (
        "AVAILABLE" if INVARIANT_HUNT.exists() else "SKIPPED (missing)")

    skipped_counts = skipped_compilation_counts(status, tool_logs)
    skip_remediation = collect_skip_remediation(tool_logs, tool_log_paths=tool_log_paths)
    promotion_advisories = find_low_config_liveness_advisories(ws, hits)
    advisory_path = write_scanner_promotion_advisories(out_dir, ws, promotion_advisories)
    report = write_report(
        out_dir, ws, hits, status, skipped_counts,
        skip_remediation=skip_remediation,
        scanner_promotion_advisories=promotion_advisories,
    )
    manifest = write_environment_manifest(
        out_dir, ws, langs, status, tool_logs, skipped_counts,
        skip_remediation=skip_remediation,
        tool_log_paths=tool_log_paths,
        scanner_promotion_advisories=promotion_advisories,
    )
    print(f"[orch] wrote {report}")
    print(f"[orch] wrote {manifest}")
    print(f"[orch] wrote {advisory_path}")
    print(f"[orch] total hits: {len(hits)}")
    print(f"[orch] skip-remediation rows: {skip_remediation.get('row_count', 0)}")
    print(f"[orch] scanner-promotion advisories: {len(promotion_advisories)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
