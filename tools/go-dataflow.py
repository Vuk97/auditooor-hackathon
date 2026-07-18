#!/usr/bin/env python3
"""go-dataflow.py - Python wrapper for the native offline Go data-flow backend.

Phase-1 Go arm of the cross-language def-use slicer. It invokes the standalone Go
program in tools/go-dataflow/ (go/ssa + callgraph/cha + VTA), which prints DefUsePath
v1 records as a JSON array on stdout, then validates them against the SHARED schema
(tools/dataflow_schema.py) and MERGES them into <ws>/.auditooor/dataflow_paths.jsonl
alongside records from other language arms (Solidity, Rust, ...).

It does NOT edit tools/dataflow-slice.py or readme_runbook_steps.json - the router and
step-1c wiring live separately.

Pipeline (in the Go binary):
  go/packages.LoadAllSyntax -> go/ssa (InstantiateGenerics) ->
  callgraph/cha (+ VTA refine) -> backward def-use slices across packages.

R80 honesty/degrade contract:
  - If the Go toolchain is missing, the binary can't be built, or the target does not
    compile, this wrapper writes a single DEGRADE record (degraded=True,
    engine="unsupported-or-compile-fail-degrade", confidence="heuristic") and exits 0.
  - It NEVER silently produces nothing: a degrade is always recorded and reported.
  - semantic-ssa records are IR-backed; heuristic/degraded records are advisory only.

Usage:
  python3 tools/go-dataflow.py --workspace <ws> [--target <pkg-or-dir>] [--json]
                               [--max-depth N] [--forward] [--out PATH]
                               [--no-merge]   # truncate instead of merge

Target resolution:
  --target may be a Go package pattern (e.g. ./x/bank/keeper/...), an absolute dir, or
  omitted. When omitted, the wrapper looks for a go.mod under <ws> (and common nested
  src/ layouts) and runs ./... in that module root.
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
from typing import Any, Dict, List, Optional, Tuple

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import dataflow_schema as dfs  # shared frozen schema  # noqa: E402
try:  # single-source the pinned-toolchain logic across all go-invoking engines
    import go_toolchain_env as _gte  # noqa: E402
except Exception:  # pragma: no cover
    _gte = None

GO_SRC_DIR = _HERE / "go-dataflow"


def _default_max_depth(default: int = 24) -> int:
    """B-hops: HIGH env-overridable safety ceiling (was a small 8 cap)."""
    raw = os.environ.get("AUDITOOOR_DATAFLOW_MAX_DEPTH")
    if raw:
        try:
            v = int(raw)
            if v > 0:
                return v
        except ValueError:
            pass
    return default


# ---------------------------------------------------------------- toolchain --

def _find_go() -> Optional[str]:
    return shutil.which("go")


def _build_binary(go_bin: str) -> Tuple[Optional[str], str]:
    """Build the standalone Go program offline. Returns (binary_path, err)."""
    if not (GO_SRC_DIR / "main.go").exists():
        return None, f"go-dataflow source missing at {GO_SRC_DIR}"
    out_bin = GO_SRC_DIR / ".bin" / "go-dataflow"
    out_bin.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    # offline: never reach the network; vendor/GOPATH must satisfy x/tools
    env.setdefault("GOPROXY", "off")
    env["GOFLAGS"] = "-mod=mod"
    try:
        p = subprocess.run(
            [go_bin, "build", "-o", str(out_bin), "."],
            cwd=str(GO_SRC_DIR), env=env,
            capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        return None, "go build timed out (600s)"
    except Exception as e:  # pragma: no cover
        return None, f"go build exec error: {type(e).__name__}: {e}"
    if p.returncode != 0:
        return None, f"go build failed: {p.stderr.strip()[:400]}"
    return str(out_bin), ""


# ---------------------------------------------------------------- targets ----

def _resolve_module_root(ws: Path, target: Optional[str]) -> Tuple[Optional[Path], List[str], str]:
    """Return (cwd_for_go, patterns, err). cwd is the module root."""
    if target:
        tp = Path(target)
        if tp.is_absolute() and tp.exists():
            # absolute dir/file -> find nearest go.mod upward, pattern = ./...
            d = tp if tp.is_dir() else tp.parent
            root = _nearest_gomod(d)
            if root is None:
                return None, [], f"no go.mod found at or above {d}"
            # build a relative ./... pattern from root to d
            rel = os.path.relpath(d, root)
            pat = "./..." if rel in (".", "") else f"./{rel}/..."
            return root, [pat], ""
        # treat as a package pattern relative to a module root under ws
        root = _nearest_gomod(ws) or _scan_for_gomod(ws)
        if root is None:
            return None, [], f"no go.mod under {ws} to resolve pattern {target!r}"
        return root, [target], ""
    # no target: find a module root under ws
    root = _nearest_gomod(ws) or _scan_for_gomod(ws)
    if root is None:
        return None, [], f"no go.mod found under {ws}"
    return root, ["./..."], ""


def _nearest_gomod(start: Path) -> Optional[Path]:
    cur = start.resolve()
    for _ in range(40):
        if (cur / "go.mod").exists():
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


def _scan_for_gomod(ws: Path) -> Optional[Path]:
    """Find the first go.mod under ws, preferring common src/ layouts."""
    prefer = [ws / "src", ws]
    for base in prefer:
        gm = base / "go.mod"
        if gm.exists():
            return base
    # shallow walk (depth<=4)
    ws = ws.resolve()
    best: Optional[Path] = None
    for dirpath, dirnames, filenames in os.walk(ws):
        depth = Path(dirpath).relative_to(ws).parts
        if len(depth) > 4:
            dirnames[:] = []
            continue
        # skip vendored/dependency caches
        dirnames[:] = [d for d in dirnames if d not in ("vendor", "node_modules", ".git")]
        if "go.mod" in filenames:
            best = Path(dirpath)
            break
    return best


# ----------------------------------------------------- multi-module ----------
# Path segments that mark an OUT-OF-SCOPE go.mod (vendored deps, generated test
# data, example trees, third-party copies, git internals). A module whose path
# contains any of these segments is excluded from the per-module enumeration.
_OOS_MODULE_SEGMENTS = frozenset(
    {"node_modules", "vendor", "testdata", ".git", "third_party", "examples",
     # Cosmos-SDK simulation / test scaffold modules are OOS test harnesses, never
     # production value-moving code (the Solidity `test/` analog). `simapp` is the
     # canonical sim application; `testutil` is the shared test helper module. Both
     # are separate go.mod modules that (a) add nothing to the in-scope coupled-state
     # surface and (b) trip go/ssa on sim-only constructs - the nuva
     # src/vault/simapp `ForEachElement called on type contain` panic that STARVED
     # the whole Go dataflow arm. Excluding them mirrors the testdata/examples
     # exclusion and removes them from the enumeration + the timeout surface.
     "simapp", "testutil"}
)


def _default_module_cap(default: int = 64) -> int:
    """HIGH env-overridable ceiling on the number of modules processed per ws.

    Multi-module repos (e.g. cosmos-sdk ships ~20 sub-modules) are legitimately
    large, so the default is generous. A run that hits the cap LOGS it (no silent
    truncation - see main()). Override via AUDITOOOR_GO_MODULE_CAP.
    """
    raw = os.environ.get("AUDITOOOR_GO_MODULE_CAP")
    if raw:
        try:
            v = int(raw)
            if v > 0:
                return v
        except ValueError:
            pass
    return default


def _enumerate_module_roots(ws: Path) -> List[Path]:
    """Return ALL in-scope go.mod module roots under ws (sorted, deterministic).

    A module root is a directory containing a go.mod whose path - relative to ws -
    has NO segment in _OOS_MODULE_SEGMENTS. Sub-modules of one repo (e.g.
    cosmos-sdk/store, cosmos-sdk/x/feegrant) ARE separate in-scope modules and are
    each returned: they are independent Go modules with their own dependency graph,
    and go ./... in the parent does NOT descend into a nested module.

    Pruning: os.walk prunes any OOS segment from the descent so we never pay for
    walking node_modules / vendor / .git. The result is sorted by path string for a
    stable, deterministic processing order (so the module cap truncates the SAME
    tail every run and the report is reproducible).
    """
    ws = ws.resolve()
    roots: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(ws):
        # prune OOS subtrees from the descent (do not walk into them at all)
        dirnames[:] = [d for d in dirnames if d not in _OOS_MODULE_SEGMENTS]
        if "go.mod" in filenames:
            roots.append(Path(dirpath))
            # NOTE: do NOT prune here - a nested module (cosmos-sdk/store) lives
            # under a parent module dir (cosmos-sdk) and is a SEPARATE in-scope
            # module that go ./... in the parent will not reach. Keep descending.
    roots.sort(key=lambda p: str(p))
    return roots


# ---------------------------------------------------------------- run --------

def _has_go_work(cwd: Path) -> bool:
    """True when a go.work file governs cwd (workspace mode is active)."""
    gw = os.environ.get("GOWORK", "")
    if gw == "off":
        return False
    if gw and os.path.exists(gw):
        return True
    d = Path(cwd)
    for _ in range(8):
        if (d / "go.work").exists():
            return True
        if d.parent == d:
            break
        d = d.parent
    return False


_TOOLCHAIN_RE = re.compile(r"^\s*toolchain\s+(go\d+\.\d+(?:\.\d+)?)", re.M)
# ONLY a 3-part `go X.Y.Z` yields a valid GOTOOLCHAIN name (goX.Y.Z); a 2-part `go X.Y`
# is a language MINIMUM, not a toolchain pin, and `goX.Y` is a malformed GOTOOLCHAIN that
# errors the binary - so require the patch component.
_GO_DIRECTIVE_RE = re.compile(r"^\s*go\s+(\d+\.\d+\.\d+)", re.M)


def _workspace_toolchain(cwd: Path) -> str:
    """Return the exact Go toolchain a workspace PINS (`go.work`/`go.mod` `toolchain
    goX.Y.Z`, else `go.mod` `go X.Y.Z` -> `goX.Y.Z`), or '' if none.

    WHY (root-caused NUVA 2026-07-08): the Go slice DEGRADES SILENTLY when the pinned
    toolchain is unavailable and the ambient one cannot compile a dep. NUVA's src/vault
    go.work pins `toolchain go1.25.8`; with GOPROXY=off the arm cannot fetch it and falls
    back to the ambient go1.26.2, which FAILS to compile `bytedance/sonic` (undefined
    GoMapIterator - a runtime internal changed in 1.26). go/packages.LoadAllSyntax then
    loads only the sonic-free packages -> 35 state-write sinks vs 686 under the pin (a ~20x
    coupled-state under-count, 0 sink.cell). Pinning GOTOOLCHAIN to the ws value makes go
    use the cached/installed pinned toolchain (offline once cached). Generic to every large
    cosmos-sdk Go ws whose deps need an exact toolchain."""
    if _gte is not None:  # single-source via the shared helper
        return _gte.workspace_go_toolchain(cwd)
    for name in ("go.work", "go.mod"):
        d = Path(cwd)
        for _ in range(8):
            f = d / name
            if f.exists():
                txt = f.read_text(encoding="utf-8", errors="replace")
                m = _TOOLCHAIN_RE.search(txt)
                if m:
                    return m.group(1)
                if name == "go.mod":
                    g = _GO_DIRECTIVE_RE.search(txt)
                    if g:
                        return "go" + g.group(1)
                break
            if d.parent == d:
                break
            d = d.parent
    return ""


def _toolchain_available(tc: str) -> bool:
    """True when the pinned toolchain `tc` (e.g. go1.25.8) is usable OFFLINE - it matches
    the ambient `go` or is already in the module toolchain cache. Used to emit a LOUD WARN
    (not a silent under-emit) when GOPROXY=off cannot supply an unavailable pinned toolchain."""
    if _gte is not None:  # single-source via the shared helper
        return _gte.toolchain_available(tc)
    if not tc:
        return True
    home = Path(os.path.expanduser("~"))
    if list((home / "go" / "pkg" / "mod" / "golang.org").glob(f"toolchain@*{tc[2:]}*")):
        return True
    if (home / "sdk" / tc).exists():
        return True
    try:
        out = subprocess.run(["go", "version"], capture_output=True, text=True, timeout=20)
        return tc in out.stdout
    except Exception:
        return False


def _sanitize_goflags_for_workspace(goflags: str, cwd: Path) -> str:
    """Strip any -mod=<x> token from GOFLAGS when a go.work governs cwd.

    go.work (workspace mode) is INCOMPATIBLE with -mod: go/packages.Load then
    fails ("-mod may not be set in workspace mode"), and the Go dataflow arm
    degrades to a single 725-byte degrade record instead of loading the module.
    Verified NUVA 2026-07-06: the audit-deep launch env carries GOFLAGS=-mod=mod,
    which the arm inherits -> the whole provlabs/vault (the Go value-movers) got
    NO dataflow slice; with -mod stripped the arm produced 15MB of real in-scope
    Go records (bounded by the emit caps). Non-workspace single-module trees are
    left untouched (they may legitimately want -mod=mod)."""
    if not _has_go_work(cwd):
        return goflags
    toks = [t for t in goflags.split() if t != "-mod" and not t.startswith("-mod=")]
    return " ".join(toks)


def _run_binary(binary: str, cwd: Path, patterns: List[str], max_depth: int,
                forward: bool, run_timeout: Optional[int] = None) -> Tuple[Optional[List[Dict[str, Any]]], str]:
    cmd = [binary, "-max-depth", str(max_depth)]
    if forward:
        cmd.append("-forward")
    # PANIC-CAPABLE sink arm (env-gated pass-through, default OFF): when
    # AUDITOOOR_DATAFLOW_PANIC_SINKS is truthy the binary ALSO emits kind=="panic"
    # records for param-tainted panic-capable SSA nodes (type-assert w/o comma-ok,
    # index/slice OOB, pointer nil-deref) - the substrate the Go must-succeed-panic-
    # reachability reasoner (tools/go-mustsucceed-panic-reachability.py) consumes.
    # Kept behind an env toggle so the default value/state/authority slice is
    # byte-identical for every existing consumer.
    if str(os.environ.get("AUDITOOOR_DATAFLOW_PANIC_SINKS", "")).strip().lower() \
            not in ("", "0", "false", "no"):
        cmd.append("-panic-sinks")
    cmd.extend(patterns)
    env = dict(os.environ)
    env.setdefault("GOPROXY", "off")
    # go.work workspace mode rejects -mod; strip it so packages.Load actually loads.
    env["GOFLAGS"] = _sanitize_goflags_for_workspace(env.get("GOFLAGS", ""), cwd)
    # PIN the workspace-required Go toolchain (root-caused NUVA 2026-07-08). Without this the
    # arm inherits the ambient toolchain; when the ws pins a newer/older one whose deps only
    # compile under it (NUVA: sonic needs go1.25.8, ambient go1.26.2 fails), packages.Load
    # SILENTLY degrades to a fraction of the slice (35 vs 686 state-write sinks). Setting
    # GOTOOLCHAIN makes go use the cached/installed pinned toolchain (offline once cached).
    tc = _workspace_toolchain(cwd)
    if tc:
        env["GOTOOLCHAIN"] = tc
        if env.get("GOPROXY") == "off" and not _toolchain_available(tc):
            # GOPROXY=off cannot fetch the pinned toolchain and it is not cached -> the emit
            # WILL degrade. Do NOT do so silently: loosen the proxy for the toolchain fetch
            # so the slice is COMPLETE, with a loud WARN (correctness over strict-offline).
            print(f"[go-dataflow] WARN pinned toolchain {tc} not available offline; "
                  f"loosening GOPROXY to fetch it (was off) so the Go slice is not silently "
                  f"degraded - install {tc} locally to stay fully offline", file=sys.stderr)
            env["GOPROXY"] = "https://proxy.golang.org,direct"
    # Per-module run timeout, env-configurable. The hardcoded 900s SILENTLY truncated large
    # cosmos-sdk modules once the toolchain fix let them load FULLY: NUVA's vault takes ~19min
    # (1140s) for the real 686-path slice, so 900s degraded it to ~1 record (a coverage
    # regression masquerading as an emit). Raise via AUDITOOOR_GO_DATAFLOW_RUN_TIMEOUT for
    # heavy Go/Cosmos workspaces.
    # 2026-07-11 RE-MEASURED: NUVA src/vault now takes 2550s (~42.5min) for a 1436-path slice
    # (path count doubled 686->1436 as the semantic-ssa / coupled-state emission grew), so the
    # prior 1800s default SILENTLY TRUNCATED it to 0 real paths -> audit-complete
    # fail-dataflow-substrate-starved (a full-closure LoadAllSyntax+InstantiateGenerics+Build
    # over cosmos-sdk is genuinely ~40min, NOT a hang: RC=0, status=ok, 0 invalid_dropped).
    # Default lifted to 3600s (headroom over the measured 2550s for the larger fleet Go-L1
    # modules polygon/optimism); the timeout is a CEILING so small modules are unaffected.
    if run_timeout is not None and run_timeout > 0:
        # explicit per-invocation ceiling (used by the in-scope batched runner so one
        # slow generics-heavy package cannot starve the whole arm - see
        # _run_inscope_batched). Overrides the env default for THIS call only.
        run_to = run_timeout
    else:
        try:
            run_to = int(os.environ.get("AUDITOOOR_GO_DATAFLOW_RUN_TIMEOUT", "3600"))
        except ValueError:
            run_to = 3600
    try:
        p = subprocess.run(cmd, cwd=str(cwd), env=env,
                           capture_output=True, text=True, timeout=run_to)
    except subprocess.TimeoutExpired:
        return None, f"go-dataflow run timed out ({run_to}s)"
    except Exception as e:  # pragma: no cover
        return None, f"go-dataflow exec error: {type(e).__name__}: {e}"
    out = p.stdout.strip()
    if not out:
        return None, f"empty output (rc={p.returncode}); stderr={p.stderr.strip()[:300]}"
    try:
        recs = json.loads(out)
    except json.JSONDecodeError as e:
        return None, f"bad JSON from go-dataflow: {e}; head={out[:200]}"
    if not isinstance(recs, list):
        return None, "go-dataflow output is not a JSON array"
    return recs, ""


def _run_one_module(
    binary: str,
    cwd: Path,
    patterns: List[str],
    max_depth: int,
    forward: bool,
    ws: Path,
    run_timeout: Optional[int] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Run the go-dataflow binary for ONE module root and return (records, report).

    Returns:
      records: the SCHEMA-VALID records for this module. On any failure
        (run error, go-side degrade, all-invalid) this is a single MODULE-TAGGED
        degrade record (degraded=True) so the caller can merge it like any other
        row and the module is never silently dropped (R80).
      report: a per-module summary {module, module_rel, records, degraded, error,
        invalid_dropped, semantic_ssa, ...}.

    A failing module here does NOT raise and does NOT abort sibling modules; the
    caller iterates every module and only the union is written.
    """
    try:
        module_rel = os.path.relpath(cwd, ws)
    except ValueError:  # pragma: no cover - different drive on Windows
        module_rel = str(cwd)
    rep: Dict[str, Any] = {
        "module": str(cwd),
        "module_rel": module_rel,
        "records": 0,
        "degraded": False,
        "error": None,
        "invalid_dropped": 0,
        "semantic_ssa": 0,
    }

    def _module_degrade(reason: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        rec = dfs.degrade_record("go", reason)
        # tag the degrade with the module path so the union is attributable
        rec["module"] = str(cwd)
        rec["module_rel"] = module_rel
        rep["degraded"] = True
        rep["error"] = reason
        rep["records"] = 1
        return [rec], rep

    recs, rerr = _run_binary(binary, cwd, patterns, max_depth, forward, run_timeout)
    if recs is None:
        return _module_degrade(f"run failure: {rerr}")

    # the binary may itself return a single degrade record on load/compile fail
    if len(recs) == 1 and recs[0].get("degraded"):
        return _module_degrade(recs[0].get("degrade_reason", "go-side degrade"))

    valid: List[Dict[str, Any]] = []
    invalid = 0
    sample_errs: List[str] = []
    for r in recs:
        ok, verrs = dfs.validate(r)
        if ok:
            # stamp module attribution onto every real record too (additive;
            # extra keys are allowed by the schema validator)
            r.setdefault("module", str(cwd))
            r.setdefault("module_rel", module_rel)
            valid.append(r)
        else:
            invalid += 1
            if len(sample_errs) < 3:
                sample_errs.append("; ".join(verrs[:4]))
    rep["invalid_dropped"] = invalid

    if not valid:
        return _module_degrade(
            f"no schema-valid records (invalid={invalid}; sample={sample_errs})")

    rep["records"] = len(valid)
    rep["semantic_ssa"] = sum(
        1 for r in valid if r.get("confidence") == "semantic-ssa" and not r.get("degraded"))
    return valid, rep


# ---------------------------------------------------------------- merge ------

def _merge_write(out_path: Path, new_records: List[Dict[str, Any]], merge: bool) -> int:
    """Write the go-arm records to the shared sidecar.

    B-merge: the language-scoped merge logic now lives canonically in
    dataflow_schema.merge_write (extracted from this function - it was the only arm
    that was merge-correct). This thin wrapper delegates to it so the four arms share
    one merge implementation. merge=False keeps the legacy truncating write (--no-merge).
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if merge:
        return dfs.merge_write(str(out_path), new_records, "go")
    return dfs.write_jsonl(str(out_path), new_records)


def _degrade_and_exit(out_path: Path, reason: str, as_json: bool, merge: bool) -> int:
    rec = dfs.degrade_record("go", reason)
    _merge_write(out_path, [rec], merge)
    result = {
        "status": "degraded",
        "language": "go",
        "out": str(out_path),
        "records": 1,
        "semantic_ssa_paths": 0,
        "reason": reason,
    }
    print(json.dumps(result, indent=2) if as_json
          else f"DEGRADED (go arm): {out_path}\n  reason: {reason}")
    return 0  # R80: advisory, exit 0, never silent


def _summarize(valid: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute the per-arm stat block from the (non-degrade) valid records.

    Shared by the single-module and multi-module report paths so both surface the
    identical metric shape (semantic_ssa_paths / unguarded / multi_hop / sink_kinds
    / representative sample). Degrade rows (degraded=True) contribute 0 to every
    metric naturally.
    """
    real = [r for r in valid if not r.get("degraded")]
    sem = sum(1 for r in real if r.get("confidence") == "semantic-ssa")
    unguarded = sum(1 for r in real if r.get("unguarded"))
    multi_hop = sum(1 for r in real if r.get("call_depth", 0) >= 2)
    max_depth = max((r.get("call_depth", 0) for r in real), default=0)
    by_kind: Dict[str, int] = {}
    for r in real:
        k = (r.get("sink") or {}).get("kind", "?")
        by_kind[k] = by_kind.get(k, 0) + 1
    sample = None
    mh = sorted((r for r in real if r.get("call_depth", 0) >= 2),
                key=lambda r: -r.get("call_depth", 0))
    if mh:
        r = mh[0]
        sample = {
            "path_id": r["path_id"],
            "call_depth": r["call_depth"],
            "unguarded": r["unguarded"],
            "source": {"kind": r["source"]["kind"], "var": r["source"].get("var"),
                       "fn": r["source"].get("fn")},
            "sink": {"kind": r["sink"]["kind"], "callee": r["sink"].get("callee"),
                     "file": r["sink"].get("file"), "line": r["sink"].get("line")},
            "hop_count": len(r.get("hops", [])),
        }
    return {
        "semantic_ssa_paths": sem,
        "unguarded_paths": unguarded,
        "multi_hop_paths": multi_hop,
        "max_call_depth": max_depth,
        "sink_kinds": by_kind,
        "sample_multi_hop": sample,
    }


# ------------------------------------------------- in-scope batched run ------
# WHY (root-caused axelar-dlt 2026-07-13): on a huge cosmos-sdk monorepo
# (axelar-core: ~200 in-scope go packages, single go.mod) a blanket `./...` run
# builds go/ssa + slices over the FULL import closure (all of cosmos-sdk +
# tendermint + ethermint). That genuinely exceeds the 3600s ceiling, so the arm
# emits ONE degrade record ("go-dataflow run timed out") -> 0 real Go paths ->
# `fail-dataflow-substrate-starved` RED on every heavy Go-L1 ws. But per-package
# runs are cheap: `./config` = 9s/5 paths, `./utils` = 32s/64 paths (measured),
# because a single package's closure is a small cosmos-sdk subset, not the union.
# The batched runner derives the IN-SCOPE package set from
# `<ws>/.auditooor/inscope_units.jsonl`, runs the binary per bounded batch with a
# PER-BATCH timeout under a TOTAL budget, and merges whatever completed. Fast
# packages produce real paths; a slow batch degrades ALONE (module-tagged, R80)
# without starving the arm. Falls back to blanket `./...` when no manifest exists.


def _inscope_go_dirs(ws: Path, module_root: Path) -> List[str]:
    """Return sorted, distinct `./rel/pkg` patterns for every IN-SCOPE .go package
    dir under `module_root`, derived from `<ws>/.auditooor/inscope_units.jsonl`.

    Each manifest row's `file` is ws-relative (e.g. src/axelar-core/x/nexus/keeper/
    foo.go). We map it to the package DIRECTORY relative to the go.mod root and emit
    a NON-RECURSIVE pattern (`./x/nexus/keeper`, no `/...`) so each invocation loads
    only that one package's import closure. Rows whose file is not a .go under
    module_root (Rust/Solidity, OOS trees) are ignored. Returns [] when the manifest
    is absent/empty (caller then falls back to the blanket `./...` single run)."""
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file():
        return []
    root = module_root.resolve()
    dirs: set[str] = set()
    try:
        for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            f = rec.get("file") or ""
            if not f.endswith(".go"):
                continue
            lang = (rec.get("lang") or "").lower()
            if lang and lang != "go":
                continue
            abs_f = (ws / f).resolve()
            try:
                rel = os.path.relpath(abs_f.parent, root)
            except ValueError:
                continue
            # only dirs genuinely under the module root (no `..` escapes)
            if rel == os.pardir or rel.startswith(os.pardir + os.sep):
                continue
            # exclude vendored/generated/test-scaffold segments (mirror enum pruning)
            parts = set(Path(rel).parts)
            if parts & _OOS_MODULE_SEGMENTS:
                continue
            pat = "./..." if rel in (".", "") else "./" + rel.replace(os.sep, "/")
            # the module-root package itself is `.`; use "." not "./..." to stay
            # non-recursive/self-only
            if rel in (".", ""):
                pat = "."
            dirs.add(pat)
    except OSError:
        return []
    return sorted(dirs)


def _batch(items: List[str], size: int) -> List[List[str]]:
    if size < 1:
        size = 1
    return [items[i:i + size] for i in range(0, len(items), size)]


def _batched_env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw:
        try:
            v = int(raw)
            if v > 0:
                return v
        except ValueError:
            pass
    return default


def _run_inscope_batched(
    binary: str, ws: Path, out_path: Path, module_root: Path, dirs: List[str],
    max_depth: int, forward: bool, merge: bool, as_json: bool,
    cache_fp: str = "",
) -> int:
    """Run the go-dataflow binary over the IN-SCOPE package set in bounded batches,
    each with a per-batch timeout under a total wall-clock budget, then merge the
    union. A slow/timeout batch degrades ALONE (batch-tagged, R80) and does not
    starve the arm; the arm is 'ok' iff >=1 batch produced real (non-degrade)
    records. Batches not reached before the budget are LOGGED as skipped (no silent
    truncation)."""
    import time
    batch_size = _batched_env_int("AUDITOOOR_GO_DATAFLOW_BATCH_SIZE", 8)
    batch_to = _batched_env_int("AUDITOOOR_GO_DATAFLOW_BATCH_TIMEOUT", 300)
    total_budget = _batched_env_int("AUDITOOOR_GO_DATAFLOW_TOTAL_BUDGET", 1800)

    # SCOPED-BUILD default-ON for the batched runner (root-caused axelar-dlt
    # 2026-07-14). EMPIRICAL: on axelar-core the type-check
    # (packages.Load(LoadAllSyntax)) for the smallest in-scope package `./config`
    # is 0.5s, but the go/ssa prog.Build() over its 265-package cosmos-sdk import
    # closure exceeds 240s - so EVERY per-package batch timed out (RC=124, 0 real
    # records) and the arm degraded to fail-dataflow-substrate-starved. Because the
    # batched runner ALREADY scopes each invocation to ONE in-scope package, we
    # instruct the Go binary (via env, read in analyze()) to build SSA bodies for
    # the INITIAL (in-scope, pattern-matched) packages ONLY - every in-scope body
    # is still built (intra-package + in-package inter-proc fully sliced); hops that
    # LEAVE the in-scope package into an unbuilt cosmos-sdk dependency terminate,
    # which is the intended per-package boundary (the union over all batches still
    # covers every in-scope package's own bodies). MEASURED after this: `./config`
    # 240s+->1.0s, `./x/reward/keeper` 240s+->3.5s emitting 7320 kind==panic +
    # 54 state-write + 5 mint + 3 value-move records, 0 degraded (119 panic sinks
    # citing in-scope x/reward/keeper.Keeper methods). Operator-overridable OFF by
    # exporting AUDITOOOR_GO_DATAFLOW_SCOPED_BUILD=0 before the run.
    os.environ.setdefault("AUDITOOOR_GO_DATAFLOW_SCOPED_BUILD", "1")

    batches = _batch(dirs, batch_size)
    union: List[Dict[str, Any]] = []
    batch_reports: List[Dict[str, Any]] = []
    skipped_batches: List[List[str]] = []
    start = time.monotonic()

    for idx, batch in enumerate(batches):
        elapsed = time.monotonic() - start
        remaining = total_budget - elapsed
        if remaining <= 5:
            # budget exhausted: record the untried tail as skipped (non-silent)
            skipped_batches.extend(batches[idx:])
            break
        this_to = int(min(batch_to, remaining))
        recs, rep = _run_one_module(
            binary, module_root, batch, max_depth, forward, ws, run_timeout=this_to)
        # tag the report with the batch patterns so a degrade is attributable
        rep["batch"] = batch
        rep["batch_index"] = idx
        # stamp batch patterns onto each record for downstream attribution
        for r in recs:
            r.setdefault("batch_index", idx)
        union.extend(recs)
        batch_reports.append(rep)

    n = _merge_write(out_path, union, merge)

    real_batches = sum(1 for r in batch_reports if not r["degraded"] and r["records"] > 0)
    degraded_batches = sum(1 for r in batch_reports if r["degraded"])
    real_records = sum(r["records"] for r in batch_reports if not r["degraded"])
    arm_ok = real_batches >= 1
    stats = _summarize(union)

    result = {
        "status": "ok" if arm_ok else "degraded",
        "language": "go",
        "out": str(out_path),
        "inscope_batched": True,
        "module_root": str(module_root),
        "inscope_packages": len(dirs),
        "batches_total": len(batches),
        "batches_processed": len(batch_reports),
        "batches_with_records": real_batches,
        "batches_degraded": degraded_batches,
        "batches_skipped_by_budget": len(skipped_batches),
        "batch_size": batch_size,
        "batch_timeout": batch_to,
        "total_budget": total_budget,
        "records": n,
        "real_records": real_records,
        **stats,
    }
    # persist the source-fingerprint sidecar: a run is CACHEABLE only when every
    # in-scope package produced real records and none degraded or was budget-skipped
    # (a thin/degraded slice must never be reused - the next call retries it).
    _complete = (arm_ok and degraded_batches == 0
                 and len(skipped_batches) == 0 and real_records > 0)
    _write_cache_meta(out_path, cache_fp, result, _complete)
    if as_json:
        print(json.dumps(result, indent=2))
    else:
        verdict = "OK" if arm_ok else "DEGRADED"
        print(f"{verdict} (go arm, in-scope batched): {n} records "
              f"({real_records} real) -> {out_path}")
        print(f"  in-scope packages={len(dirs)} batches={len(batches)} "
              f"processed={len(batch_reports)} with_records={real_batches} "
              f"degraded={degraded_batches} skipped_by_budget={len(skipped_batches)}")
        if skipped_batches:
            print(f"  BUDGET HIT (total_budget={total_budget}s); skipped "
                  f"{len(skipped_batches)} batch(es) (raise "
                  f"AUDITOOOR_GO_DATAFLOW_TOTAL_BUDGET to include them)")
        print(f"  semantic-ssa={stats['semantic_ssa_paths']} "
              f"unguarded={stats['unguarded_paths']} "
              f"multi_hop={stats['multi_hop_paths']} "
              f"max_call_depth={stats['max_call_depth']}")
    return 0  # R80: advisory arm, exit 0 always


def _run_multi_module(
    binary: str, ws: Path, out_path: Path, modules: List[Path],
    max_depth: int, forward: bool, merge: bool, as_json: bool,
) -> int:
    """Per-module run + single union merge_write for a multi-module workspace.

    - runs the go-dataflow binary once per in-scope module root (cwd=module root,
      ./...), accumulating every module's records;
    - each module's failure produces a MODULE-TAGGED degrade (does not abort the
      siblings - R80 per-module degrade);
    - merge_write(language="go") the UNION exactly once so module B never wipes
      module A's go rows (the accumulate-then-single-write contract);
    - the arm is 'ok' iff >=1 module produced real (non-degrade) records;
    - the module count is capped (env-overridable); a capped run LOGS the skipped
      tail (no silent truncation).
    """
    module_cap = _default_module_cap()
    discovered = len(modules)
    capped = discovered > module_cap
    skipped_modules: List[str] = []
    if capped:
        skipped_modules = [os.path.relpath(m, ws) for m in modules[module_cap:]]
        modules = modules[:module_cap]

    union: List[Dict[str, Any]] = []
    module_reports: List[Dict[str, Any]] = []
    for cwd in modules:
        recs, rep = _run_one_module(binary, cwd, ["./..."], max_depth, forward, ws)
        union.extend(recs)
        module_reports.append(rep)

    # single union write (accumulate-then-write: module B never wipes module A)
    n = _merge_write(out_path, union, merge)

    real_modules = sum(1 for r in module_reports if not r["degraded"] and r["records"] > 0)
    degraded_modules = sum(1 for r in module_reports if r["degraded"])
    real_records = sum(r["records"] for r in module_reports if not r["degraded"])
    arm_ok = real_modules >= 1
    stats = _summarize(union)

    result = {
        "status": "ok" if arm_ok else "degraded",
        "language": "go",
        "out": str(out_path),
        "multi_module": True,
        "modules_discovered": discovered,
        "modules_processed": len(modules),
        "modules_with_records": real_modules,
        "modules_degraded": degraded_modules,
        "module_cap": module_cap,
        "module_cap_hit": capped,
        "modules_skipped_by_cap": skipped_modules,
        "records": n,
        "real_records": real_records,
        "module_reports": module_reports,
        **stats,
    }
    if as_json:
        print(json.dumps(result, indent=2))
    else:
        verdict = "OK" if arm_ok else "DEGRADED"
        print(f"{verdict} (go arm, multi-module): {n} records "
              f"({real_records} real) -> {out_path}")
        print(f"  modules: discovered={discovered} processed={len(modules)} "
              f"with_records={real_modules} degraded={degraded_modules}")
        if capped:
            print(f"  MODULE CAP HIT (cap={module_cap}); skipped {len(skipped_modules)} "
                  f"module(s): {skipped_modules[:5]}{'...' if len(skipped_modules) > 5 else ''} "
                  f"(raise AUDITOOOR_GO_MODULE_CAP to include them)")
        print(f"  semantic-ssa={stats['semantic_ssa_paths']} "
              f"unguarded={stats['unguarded_paths']} "
              f"multi_hop={stats['multi_hop_paths']} "
              f"max_call_depth={stats['max_call_depth']}")
        for r in module_reports:
            flag = "DEGRADE" if r["degraded"] else "ok"
            print(f"    [{flag}] {r['module_rel']}: records={r['records']}"
                  + (f" error={r['error']}" if r["error"] else ""))
    return 0  # R80: advisory arm, exit 0 always


# ------------------------------------------------ source-fingerprint cache ---
# WHY (root-caused NUVA 2026-07-14): the full go/ssa closure over a heavy
# cosmos-sdk module (NUVA vault keeper ~2550s / ~42min for its 1436-path slice)
# is recomputed on EVERY pipeline invocation - state-coupling-graph, audit-deep
# and audit-complete each shell out to this tool independently. Under the batched
# per-package ceiling the heavy package degrades, so the pipeline NEVER persists a
# COMPLETE slice to reuse: it re-pays ~40min AND re-degrades on every run, and the
# staleness cascade (dataflow_paths.jsonl regenerates -> depth_certificate stales)
# forces yet another rebuild. Fix: fingerprint the in-scope Go source; when a
# COMPLETE (0-degraded / 0-skipped) slice already exists for the same source+args,
# REUSE it instead of recomputing. A degraded/partial slice is NEVER cached, so a
# genuine gap always retries. Invalidation is size+mtime (build-cache convention;
# the pipeline does not rewrite source between runs). Force recompute with
# AUDITOOOR_GO_DATAFLOW_NO_CACHE=1.
_CACHE_SCHEMA = "go-dataflow-source-cache.v1"


def _panic_sinks_on() -> int:
    return 0 if str(os.environ.get("AUDITOOOR_DATAFLOW_PANIC_SINKS", "")).strip().lower() \
        in ("", "0", "false", "no") else 1


def _go_source_fingerprint(ws: Path, module_roots: List[Path],
                           max_depth: int, forward: bool) -> str:
    """SHA over (size,mtime) of every in-scope-module .go file + go.mod/go.sum,
    keyed also by the args that change the slice (depth/forward/panic-sinks). An
    empty module set yields '' (caller then skips caching)."""
    import hashlib
    h = hashlib.sha256()
    h.update(f"{_CACHE_SCHEMA}|md={max_depth}|fw={int(forward)}|ps={_panic_sinks_on()}\n".encode())
    entries: List[str] = []
    for mr in sorted({Path(m).resolve() for m in module_roots}, key=str):
        if not mr.exists():
            continue
        for p in mr.rglob("*.go"):
            try:
                st = p.stat()
            except OSError:
                continue
            entries.append(f"{p}|{st.st_size}|{int(st.st_mtime)}")
        for extra in ("go.mod", "go.sum"):
            fpath = mr / extra
            try:
                st = fpath.stat()
            except OSError:
                continue
            entries.append(f"{fpath}|{st.st_size}|{int(st.st_mtime)}")
    for e in sorted(entries):
        h.update((e + "\n").encode())
    h.update(f"count={len(entries)}\n".encode())
    return h.hexdigest()


def _cache_meta_path(out_path: Path) -> Path:
    return Path(str(out_path) + ".meta.json")


def _cache_disabled() -> bool:
    return str(os.environ.get("AUDITOOOR_GO_DATAFLOW_NO_CACHE", "")).strip().lower() \
        not in ("", "0", "false", "no")


def _try_cache_reuse(out_path: Path, fp: str, as_json: bool) -> Optional[int]:
    """Return 0 (reuse, do NOT recompute) when a COMPLETE slice for this exact
    fingerprint already exists on disk; None to fall through to a real run."""
    if _cache_disabled() or not fp:
        return None
    mp = _cache_meta_path(out_path)
    try:
        if not (out_path.exists() and out_path.stat().st_size > 0 and mp.exists()):
            return None
        meta = json.loads(mp.read_text())
    except Exception:
        return None
    if meta.get("schema") != _CACHE_SCHEMA or meta.get("fingerprint") != fp \
            or meta.get("status") != "complete-cacheable":
        return None
    print(f"[go-dataflow] CACHE HIT: reusing COMPLETE slice "
          f"({meta.get('real_records')} real records) - in-scope Go source unchanged "
          f"since it was built. Set AUDITOOOR_GO_DATAFLOW_NO_CACHE=1 to force recompute.",
          file=sys.stderr)
    res = dict(meta.get("result") or {})
    res["cache"] = "hit"
    if as_json:
        print(json.dumps(res, indent=2))
    return 0


def _write_cache_meta(out_path: Path, fp: str, result: Dict[str, Any],
                      complete: bool) -> None:
    """Persist the fingerprint sidecar next to the slice. Only a COMPLETE run is
    marked reusable; a degraded/partial run writes a non-cacheable marker so the
    next invocation retries rather than serving a thin slice."""
    if _cache_disabled() or not fp:
        return
    try:
        _cache_meta_path(out_path).write_text(json.dumps({
            "schema": _CACHE_SCHEMA,
            "fingerprint": fp,
            "status": "complete-cacheable" if complete else "partial-not-cacheable",
            "real_records": result.get("real_records"),
            "records": result.get("records"),
            "result": result,
        }, indent=2))
    except Exception:
        pass


# ---------------------------------------------------------------- main -------

def main() -> int:
    ap = argparse.ArgumentParser(description="Phase-1 Go data-flow slice (offline go/ssa backend)")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--target", help="Go package pattern, abs dir/file, or omit to scan for go.mod")
    ap.add_argument("--max-depth", type=int, default=_default_max_depth(),
                    help="max inter-procedural boundary depth (HIGH safety ceiling; "
                         "depth is effectively unbounded - the Go binary's visited-set is "
                         "the real terminator. Override via AUDITOOOR_DATAFLOW_MAX_DEPTH)")
    ap.add_argument("--forward", action="store_true", help="also emit forward-direction records")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="override output jsonl path")
    ap.add_argument("--no-merge", action="store_true",
                    help="truncate the sidecar instead of merging with other-language records")
    ap.add_argument("--panic-sinks", dest="panic_sinks", action="store_true",
                    default=None,
                    help="ALSO emit kind==panic records (param-tainted panic-capable "
                         "SSA nodes: type-assert w/o comma-ok, index/slice OOB, nil-deref) "
                         "- the substrate the go-mustsucceed-panic-reachability reasoner "
                         "consumes. Equivalent to AUDITOOOR_DATAFLOW_PANIC_SINKS=1; the "
                         "explicit flag lets the step-1c router turn the arm on deterministically "
                         "so the panic substrate is written BEFORE the reasoner reads it.")
    args = ap.parse_args()

    # An explicit --panic-sinks flag pins the env the binary dispatch + the cache
    # fingerprint (`_panic_sinks_on`) both read, so the flag and the env toggle are
    # a single source of truth. Setting it BEFORE the fingerprint is computed keeps
    # the cache key consistent (a panic-sinks slice never aliases a non-panic one).
    if args.panic_sinks:
        os.environ["AUDITOOOR_DATAFLOW_PANIC_SINKS"] = "1"

    ws = Path(args.workspace).resolve()
    out_dir = ws / ".auditooor"
    out_path = Path(args.out) if args.out else (out_dir / "dataflow_paths.jsonl")
    merge = not args.no_merge

    # ---- source-fingerprint cache: reuse a COMPLETE slice for unchanged source.
    # Checked BEFORE the go build + ~40min run so a cache hit costs milliseconds.
    # Only the target-less (whole-workspace) dispatch is cached - a --target run is
    # an ad-hoc probe and left uncached. cache_fp is threaded to the dispatchers so
    # they persist the sidecar on a COMPLETE run.
    cache_fp = ""
    if not args.target:
        try:
            _fp_modules = _enumerate_module_roots(ws)
        except Exception:
            _fp_modules = []
        cache_fp = _go_source_fingerprint(ws, _fp_modules, args.max_depth, args.forward) \
            if _fp_modules else ""
        if cache_fp:
            _hit = _try_cache_reuse(out_path, cache_fp, args.json)
            if _hit is not None:
                return _hit

    go_bin = _find_go()
    if not go_bin:
        return _degrade_and_exit(out_path, "go toolchain not found on PATH", args.json, merge)

    binary, berr = _build_binary(go_bin)
    if binary is None:
        return _degrade_and_exit(out_path, f"build failure: {berr}", args.json, merge)

    # ----- multi-module dispatch (only when --target is omitted) -----
    # When the workspace contains MORE THAN ONE in-scope go.mod (e.g. polygon:
    # bor + cometbft + cosmos-sdk + ~20 cosmos sub-modules), run the binary PER
    # module and merge the UNION. Exactly-one-module (or an explicit --target)
    # falls through to the byte-identical single-module path below.
    if not args.target:
        modules = _enumerate_module_roots(ws)
        if len(modules) > 1:
            return _run_multi_module(
                binary, ws, out_path, modules,
                args.max_depth, args.forward, merge, args.json)
        # ----- single-module IN-SCOPE BATCHED dispatch -----
        # A single huge cosmos-sdk module (axelar-core) times out under a blanket
        # `./...` full-closure run (root-caused axelar-dlt 2026-07-13). When an
        # in-scope manifest yields a package set, run it in bounded batches so fast
        # packages produce real paths and one slow package cannot starve the arm.
        # Env-gateable OFF (AUDITOOOR_GO_DATAFLOW_INSCOPE_BATCH=0) to force the legacy
        # blanket run; falls back to `./...` automatically when no manifest exists.
        if len(modules) == 1 and os.environ.get(
                "AUDITOOOR_GO_DATAFLOW_INSCOPE_BATCH", "1") != "0":
            module_root = modules[0]
            dirs = _inscope_go_dirs(ws, module_root)
            # only batch when it actually narrows the run (a non-trivial package set
            # that is not just the recursive-everything pattern)
            if dirs and dirs != ["./..."]:
                return _run_inscope_batched(
                    binary, ws, out_path, module_root, dirs,
                    args.max_depth, args.forward, merge, args.json, cache_fp=cache_fp)

    cwd, patterns, terr = _resolve_module_root(ws, args.target)
    if cwd is None:
        return _degrade_and_exit(out_path, f"target resolution: {terr}", args.json, merge)

    recs, rerr = _run_binary(binary, cwd, patterns, args.max_depth, args.forward)
    if recs is None:
        return _degrade_and_exit(out_path, f"run failure: {rerr}", args.json, merge)

    # the binary may itself return a single degrade record on load/compile fail
    if len(recs) == 1 and recs[0].get("degraded"):
        return _degrade_and_exit(out_path, recs[0].get("degrade_reason", "go-side degrade"),
                                 args.json, merge)

    # validate every record against the shared schema (keep producers honest)
    valid: List[Dict[str, Any]] = []
    invalid = 0
    sample_errs: List[str] = []
    for r in recs:
        ok, verrs = dfs.validate(r)
        if ok:
            valid.append(r)
        else:
            invalid += 1
            if len(sample_errs) < 3:
                sample_errs.append("; ".join(verrs[:4]))

    if not valid:
        return _degrade_and_exit(
            out_path,
            f"no schema-valid records (invalid={invalid}; sample={sample_errs})",
            args.json, merge)

    n = _merge_write(out_path, valid, merge)

    sem = sum(1 for r in valid if r.get("confidence") == "semantic-ssa" and not r.get("degraded"))
    unguarded = sum(1 for r in valid if r.get("unguarded"))
    multi_hop = sum(1 for r in valid if r.get("call_depth", 0) >= 2)
    max_depth = max((r.get("call_depth", 0) for r in valid), default=0)
    by_kind: Dict[str, int] = {}
    for r in valid:
        k = (r.get("sink") or {}).get("kind", "?")
        by_kind[k] = by_kind.get(k, 0) + 1

    # a representative multi-hop sample for the report
    sample = None
    mh = sorted((r for r in valid if r.get("call_depth", 0) >= 2),
                key=lambda r: -r.get("call_depth", 0))
    if mh:
        r = mh[0]
        sample = {
            "path_id": r["path_id"],
            "call_depth": r["call_depth"],
            "unguarded": r["unguarded"],
            "source": {"kind": r["source"]["kind"], "var": r["source"].get("var"),
                       "fn": r["source"].get("fn")},
            "sink": {"kind": r["sink"]["kind"], "callee": r["sink"].get("callee"),
                     "file": r["sink"].get("file"), "line": r["sink"].get("line")},
            "hop_count": len(r.get("hops", [])),
        }

    result = {
        "status": "ok",
        "language": "go",
        "out": str(out_path),
        "module_root": str(cwd),
        "patterns": patterns,
        "records": n,
        "invalid_dropped": invalid,
        "semantic_ssa_paths": sem,
        "unguarded_paths": unguarded,
        "multi_hop_paths": multi_hop,
        "max_call_depth": max_depth,
        "sink_kinds": by_kind,
        "sample_multi_hop": sample,
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"OK (go arm): {n} records -> {out_path}")
        print(f"  semantic-ssa={sem} unguarded={unguarded} multi_hop={multi_hop} "
              f"max_call_depth={max_depth}")
        print(f"  sink_kinds={by_kind}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
