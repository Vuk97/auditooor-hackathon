#!/usr/bin/env python3
"""
rust-detect.py — orchestrator for auditooor Rust/Soroban detectors.

As of R74-C this is a THIN WRAPPER around `tools/ast-engine.py` that:
  1. Instantiates AstEngine("rust", source) for each .rs file
  2. Passes the underlying (tree, source, filepath) to each legacy
     detector unchanged (back-compat with the 16 existing rust_wave1
     detectors that expect raw tree-sitter nodes).
  3. Additionally passes `engine` as a kw-only argument for new-style
     detectors that want the language-neutral surface.

Detector contract (legacy — unchanged):
    def run(tree, source_bytes, filepath) -> list[dict]

Detector contract (new — opt-in):
    def run(tree, source_bytes, filepath, *, engine=None) -> list[dict]

Usage:
    python3 tools/rust-detect.py <workspace_root>
    python3 tools/rust-detect.py <workspace_root> --only <detector_name>
    python3 tools/rust-detect.py <workspace_root> --file <single_rs_path>

Exit code: 0 always (this is a linter, not a gate).
"""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import os
import signal
import sys
import traceback
from pathlib import Path

# ---- per-detector-call wall-clock cap --------------------------------------
# A single detector.run() can spin in a CPU-bound runaway on a pathological
# file (observed on near-intents: one detector at ~93% CPU for 18+ min on a
# large Rust source). Without a per-call cap the only backstop is the
# orchestrator's per-tool 1800s timeout, which kills rust-detect WHOLESALE -
# losing every other detector's results (the log is written only at the end).
# A SIGALRM cap lets us skip just the offending (detector, file) pair and keep
# going. CAVEAT: SIGALRM only interrupts Python-level execution between
# bytecodes; a runaway INSIDE a C extension (re backtracking / tree-sitter
# query) won't be interrupted until that C call returns. The 1800s per-tool
# cap remains the backstop for that case.
_PER_CALL_TIMEOUT_S = int(
    os.environ.get("AUDITOOOR_RUST_DETECT_CALL_TIMEOUT_S", "90") or "0"
)


class _DetectorTimeout(Exception):
    """Raised by the SIGALRM handler when one detector.run() exceeds the cap."""


def _alarm_handler(signum, frame):  # pragma: no cover - trivial
    raise _DetectorTimeout()


def _run_detector_call(run_fn, timeout_s):
    """Invoke run_fn() under an optional SIGALRM wall-clock cap.

    Returns the hits list (run_fn() or []). Raises _DetectorTimeout if the cap
    fires; any other exception from run_fn propagates unchanged so the caller's
    existing crash handler logs it. Restores the prior SIGALRM handler and
    clears the alarm in all cases.
    """
    use_alarm = bool(timeout_s and timeout_s > 0 and hasattr(signal, "SIGALRM"))
    old = None
    if use_alarm:
        old = signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(int(timeout_s))
    try:
        return run_fn() or []
    finally:
        if use_alarm:
            signal.alarm(0)
            if old is not None:
                signal.signal(signal.SIGALRM, old)


# ---- catastrophic-regex hardening for template detectors -------------------
# The auto-generated "_INDICATOR_PATTERNS" detectors (r94 phaseN pipeline)
# compile patterns with re.MULTILINE|re.IGNORECASE|re.DOTALL. Patterns with
# multiple greedy wildcards over very common short literals (e.g.
# 'for.*in.*ids_and_amounts.*extend_from_slice') catastrophically backtrack on a
# large source (8008-line mpc lib.rs => 99% CPU, never returns). The stdlib `re`
# engine holds the GIL during matching, so the SIGALRM cap above CANNOT
# interrupt it. The third-party `regex` module supports a per-call `timeout=`
# that DOES interrupt at the C level (raises TimeoutError). We recompile each
# template detector's `_COMPILED` patterns with `regex` and inject a default
# timeout so a pathological pattern raises (-> skipped for that file) instead of
# hanging the whole scan, while fast patterns on small files are unaffected.
_REGEX_TIMEOUT_S = float(
    os.environ.get("AUDITOOOR_RUST_DETECT_REGEX_TIMEOUT_S", "2") or "0"
)


class _TimeoutPattern:
    """Wrap a `regex`-compiled pattern so search/match/etc. carry a default
    timeout. On catastrophic backtracking the call raises TimeoutError, which
    the per-detector handler treats as a skip. Unknown attrs pass through."""

    __slots__ = ("_p", "_timeout")

    def __init__(self, compiled, timeout_s):
        self._p = compiled
        self._timeout = timeout_s

    def _kw(self, kwargs):
        if self._timeout and "timeout" not in kwargs:
            kwargs["timeout"] = self._timeout
        return kwargs

    def search(self, *a, **k):
        return self._p.search(*a, **self._kw(k))

    def match(self, *a, **k):
        return self._p.match(*a, **self._kw(k))

    def fullmatch(self, *a, **k):
        return self._p.fullmatch(*a, **self._kw(k))

    def findall(self, *a, **k):
        return self._p.findall(*a, **self._kw(k))

    def finditer(self, *a, **k):
        return self._p.finditer(*a, **self._kw(k))

    def sub(self, *a, **k):
        return self._p.sub(*a, **self._kw(k))

    def subn(self, *a, **k):
        return self._p.subn(*a, **self._kw(k))

    def split(self, *a, **k):
        return self._p.split(*a, **self._kw(k))

    def __getattr__(self, name):
        return getattr(self._p, name)


def _harden_template_detector(mod, timeout_s=_REGEX_TIMEOUT_S):
    """If `mod` is a regex-template detector (exposes `_INDICATOR_PATTERNS` and
    `_COMPILED`), recompile its patterns with the `regex` module under a per-call
    timeout. No-op when the module is not a template detector or `regex` is
    unavailable (we then rely on the SIGALRM cap + the orchestrator tool cap).
    Returns the number of patterns hardened."""
    patterns = getattr(mod, "_INDICATOR_PATTERNS", None)
    if not patterns or not hasattr(mod, "_COMPILED"):
        return 0
    if not (timeout_s and timeout_s > 0):
        return 0
    try:
        import regex as _rx
    except ImportError:
        return 0
    # Mirror the auto-gen template's compile flags.
    flags = _rx.MULTILINE | _rx.IGNORECASE | _rx.DOTALL
    hardened = []
    count = 0
    for pat in patterns:
        try:
            hardened.append(_TimeoutPattern(_rx.compile(pat, flags), timeout_s))
            count += 1
        except Exception:
            # Keep whatever the module already compiled for this slot.
            hardened.append(None)
    # Only replace slots we could recompile; leave others as the module had them.
    existing = list(getattr(mod, "_COMPILED", []))
    merged = []
    for idx, hp in enumerate(hardened):
        if hp is not None:
            merged.append(hp)
        elif idx < len(existing):
            merged.append(existing[idx])
    if merged:
        mod._COMPILED = merged
    return count

# Make the ast-engine module importable as `ast_engine` (the file is
# `ast-engine.py` which isn't a valid module name, so we import by path).
_HERE = Path(__file__).resolve().parent
_AST_ENGINE_PATH = _HERE / "ast-engine.py"


def _import_ast_engine():
    spec = importlib.util.spec_from_file_location(
        "ast_engine", _AST_ENGINE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---- detector loading ------------------------------------------------------

_SKIP_DETECTOR_DIRS = {"__pycache__", "test_fixtures"}
_NESTED_DETECTOR_PREFIX = "nested_"


def _iter_detector_paths(detectors_dir: Path):
    for py in sorted(
        detectors_dir.rglob("*.py"),
        key=lambda path: path.relative_to(detectors_dir).as_posix(),
    ):
        rel = py.relative_to(detectors_dir)
        if py.name.startswith("_") or py.name == "__init__.py":
            continue
        if any(part in _SKIP_DETECTOR_DIRS for part in rel.parts[:-1]):
            continue
        if len(rel.parts) > 1 and not rel.parts[0].startswith(
            _NESTED_DETECTOR_PREFIX
        ):
            continue
        yield py


def _iter_all_detector_paths(detectors_dir: Path):
    for py in sorted(
        detectors_dir.rglob("*.py"),
        key=lambda path: path.relative_to(detectors_dir).as_posix(),
    ):
        rel = py.relative_to(detectors_dir)
        if py.name.startswith("_") or py.name == "__init__.py":
            continue
        if any(part in _SKIP_DETECTOR_DIRS for part in rel.parts[:-1]):
            continue
        yield py


def _module_name_for(detectors_dir: Path, py: Path) -> str:
    rel = py.relative_to(detectors_dir).with_suffix("")
    safe = "_".join(rel.parts)
    safe = "".join(char if char.isalnum() or char == "_" else "_" for char in safe)
    return f"_auditooor_rust_detector_{safe}"


def _display_name_for(detectors_dir: Path, py: Path, used: set[str]) -> str:
    name = py.stem
    if name not in used:
        used.add(name)
        return name

    rel = py.relative_to(detectors_dir).with_suffix("")
    name = "__".join(rel.parts)
    name = "".join(char if char.isalnum() or char in {"_", "-"} else "_" for char in name)
    used.add(name)
    return name


def _load_detectors(detectors_dir: Path, only: str | None):
    # Put the detector dir on sys.path so detectors can `from _util import ...`
    dpath = str(detectors_dir)
    if dpath not in sys.path:
        sys.path.insert(0, dpath)

    detectors = []
    used_names: set[str] = set()
    selected_paths = list(_iter_detector_paths(detectors_dir))
    if only:
        matched = [
            py for py in selected_paths
            if only in {
                py.stem,
                "__".join(py.relative_to(detectors_dir).with_suffix("").parts),
            }
        ]
        if not matched:
            selected_paths = [
                py
                for py in _iter_all_detector_paths(detectors_dir)
                if only in {
                    py.stem,
                    "__".join(py.relative_to(detectors_dir).with_suffix("").parts),
                }
            ]
        else:
            selected_paths = matched

    for py in selected_paths:
        rel = py.relative_to(detectors_dir)
        rel_name = "__".join(rel.with_suffix("").parts)
        if only and only not in {py.stem, rel_name}:
            continue
        parent = str(py.parent)
        if parent not in sys.path:
            sys.path.append(parent)
        name = _display_name_for(detectors_dir, py, used_names)
        spec = importlib.util.spec_from_file_location(
            _module_name_for(detectors_dir, py), py)
        if spec is None or spec.loader is None:
            print(f"[warn] skipping detector {rel.as_posix()}: no loader",
                  file=sys.stderr)
            continue
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            print(f"[warn] skipping detector {rel.as_posix()}: {e}",
                  file=sys.stderr)
            continue
        if not hasattr(mod, "run"):
            continue
        # Harden auto-generated regex-template detectors against catastrophic
        # backtracking (regex-module per-call timeout). No-op for non-template
        # detectors or when `regex` is unavailable.
        _harden_template_detector(mod)
        # Probe signature to see if the detector accepts the `engine` kwarg.
        try:
            sig = inspect.signature(mod.run)
            accepts_engine = "engine" in sig.parameters
        except (TypeError, ValueError):
            accepts_engine = False
        detectors.append((name, mod, accepts_engine))
    return detectors


# ---- file discovery --------------------------------------------------------

def _discover_files(root: Path, single: Path | None) -> list[Path]:
    if single:
        return [single.resolve()]
    # Target shape: <root>/contracts/**/src/**/*.rs
    patterns = [
        "contracts/*/src/**/*.rs",
        "*/contracts/*/src/**/*.rs",  # if root is one level up
    ]
    seen = set()
    out = []
    for pat in patterns:
        for p in root.glob(pat):
            rp = p.resolve()
            if rp in seen:
                continue
            seen.add(rp)
            # Skip fuzz/bench/tests directories and generated files
            parts = set(rp.parts)
            if parts & {"fuzz", "benches", "tests", "target"}:
                continue
            if rp.name.endswith("test.rs") or rp.name == "tests.rs":
                continue
            out.append(rp)
    # Generic fallback: the patterns above only match the Anchor/Solana
    # `contracts/*/src/` layout. Standard cargo workspaces (cosmos-sdk, Substrate,
    # zebra/Zcash, plain crates) use `src/<crate>/src/**/*.rs` or `**/*.rs` and would
    # otherwise yield ZERO files - silently dropping the entire Rust detector surface.
    # When the Anchor patterns find nothing, fall back to a full recursive walk so
    # rust-detect works on ANY Rust layout, not just Anchor.
    if not out:
        _exclude_dirs = {
            "fuzz", "benches", "tests", "target", ".git", "vendor",
            "node_modules", ".cargo", "proptest-regressions",
            ".auditooor", "dist", "build", "out", "__pycache__", ".cache",
        }
        # os.walk with IN-PLACE dirnames pruning so we NEVER descend target/ etc.
        # root.rglob("*.rs") previously walked the ENTIRE tree first and only
        # post-filtered by parts - catastrophic on a workspace carrying multi-GB
        # Rust target/ build artifacts (near-intents: 3.3 GB -> the scan stage hit
        # its 1200s timeout). Pruning keeps the walk bounded to real source.
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _exclude_dirs]
            for fn in filenames:
                if not fn.endswith(".rs"):
                    continue
                if fn.endswith("test.rs") or fn == "tests.rs":
                    continue
                rp = (Path(dirpath) / fn).resolve()
                if rp in seen:
                    continue
                seen.add(rp)
                out.append(rp)
    return sorted(out)


# ---- main ------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("workspace", type=Path,
                    help="Workspace root (e.g. /path/to/k2/src)")
    ap.add_argument("--only", help="Run only this detector (module stem)")
    ap.add_argument("--file", dest="single_file", type=Path,
                    help="Run detectors on a single .rs file (used by tests)")
    ap.add_argument("--log", type=Path, default=None,
                    help="Log path (default: <workspace>/audit/rust-detect.log)")
    args = ap.parse_args()

    workspace = args.workspace.resolve()

    # Bring up ast-engine and instantiate the Rust parser once.
    try:
        ast_engine = _import_ast_engine()
    except Exception as e:
        print(f"[fatal] could not load ast-engine: {e}", file=sys.stderr)
        sys.exit(2)

    here = Path(__file__).resolve().parent.parent
    detectors_dir = here / "detectors" / "rust_wave1"
    detectors = _load_detectors(detectors_dir, args.only)
    if not detectors:
        print(f"[err] no detectors found under {detectors_dir}"
              f"{' matching --only=' + args.only if args.only else ''}",
              file=sys.stderr)
        sys.exit(1)

    files = _discover_files(workspace, args.single_file)
    if not files:
        print(f"[err] no Rust files found under {workspace}", file=sys.stderr)
        sys.exit(1)

    # Log path
    log_path = args.log
    if log_path is None:
        log_path = workspace / "audit" / "rust-detect.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[ok] loaded {len(detectors)} detector(s):")
    for name, _, accepts in detectors:
        tag = "  [engine-aware]" if accepts else ""
        print(f"  - {name}{tag}")
    print(f"[ok] scanning {len(files)} Rust file(s) under {workspace}")

    hits_by_detector: dict[str, list[tuple[Path, dict]]] = {
        name: [] for name, _, _ in detectors
    }
    total_hits = 0
    parse_errors = 0
    timed_out = 0

    for rs_path in files:
        try:
            source = rs_path.read_bytes()
        except Exception as e:
            print(f"[warn] could not read {rs_path}: {e}", file=sys.stderr)
            continue
        try:
            engine = ast_engine.AstEngine("rust", source)
            tree = engine.parse()
        except Exception as e:
            parse_errors += 1
            print(f"[warn] parse error {rs_path}: {e}", file=sys.stderr)
            continue

        for name, mod, accepts_engine in detectors:
            if accepts_engine:
                run_fn = (lambda m=mod, e=engine:
                          m.run(tree, source, str(rs_path), engine=e))
            else:
                run_fn = lambda m=mod: m.run(tree, source, str(rs_path))
            try:
                hits = _run_detector_call(run_fn, _PER_CALL_TIMEOUT_S)
            except _DetectorTimeout:
                print(f"[warn] detector {name} TIMED OUT "
                      f"(>{_PER_CALL_TIMEOUT_S}s) on {rs_path}; skipping",
                      file=sys.stderr)
                timed_out += 1
                continue
            except TimeoutError:
                # regex-module per-call timeout fired on a catastrophic pattern.
                print(f"[warn] detector {name} REGEX TIMEOUT "
                      f"(>{_REGEX_TIMEOUT_S}s) on {rs_path}; skipping",
                      file=sys.stderr)
                timed_out += 1
                continue
            except Exception as e:
                print(f"[warn] detector {name} crashed on {rs_path}: {e}",
                      file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                continue
            for h in hits:
                hits_by_detector[name].append((rs_path, h))
                total_hits += 1

    # ---- write log ----------------------------------------------------------
    with log_path.open("w") as f:
        f.write("# rust-detect.log\n")
        f.write(f"# workspace: {workspace}\n")
        f.write(f"# detectors: {len(detectors)}\n")
        f.write(f"# files scanned: {len(files)}\n")
        f.write(f"# parse errors: {parse_errors}\n")
        f.write(f"# detector timeouts (>{_PER_CALL_TIMEOUT_S}s): {timed_out}\n")
        f.write(f"# total hits: {total_hits}\n\n")

        for name, _, _ in detectors:
            bucket = hits_by_detector[name]
            f.write(f"=== {name}  ({len(bucket)} hits) ===\n")
            for path, h in bucket:
                sev = h.get("severity", "info")
                line = h.get("line", 0)
                col = h.get("col", 0)
                snip = h.get("snippet", "").replace("\n", " ")
                msg = h.get("message", "")
                if len(snip) > 200:
                    snip = snip[:200] + "..."
                f.write(f"  [{sev}] {path}:{line}:{col}  {msg}\n")
                f.write(f"      > {snip}\n")
            f.write("\n")

    # ---- stdout summary -----------------------------------------------------
    print("")
    print("=== per-detector hit counts ===")
    for name, _, _ in detectors:
        n = len(hits_by_detector[name])
        flag = "  NOISY" if n > 20 else ""
        print(f"  {n:4d}  {name}{flag}")
    print(f"\n[done] total hits: {total_hits}   log: {log_path}")


if __name__ == "__main__":
    main()
