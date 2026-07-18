#!/usr/bin/env python3
"""dataflow.py - the cross-language DefUsePath ROUTER + stitcher (B-router).

ONE entrypoint for the polyglot def-use slice. It:

  1. AUTO-DETECTS which language arms are present in a workspace, reusing the SAME
     language-detection predicates `make audit` uses (tools/audit-honesty-check.py::
     _detect_lang) - it does NOT invent its own detector. The detector there returns a
     single "primary" (or "mixed"); this router extends the SAME glob predicates into
     the SET of present languages so a mixed (e.g. Solidity + Go) workspace dispatches
     every present arm, not just one.
  2. DISPATCHES each present arm via subprocess:
       - solidity  -> tools/dataflow-slice.py
       - rust      -> tools/rust-dataflow.py
       - go        -> tools/go-dataflow.py
       - zk/circom -> tools/zk-dataflow.py   (only when .circom files exist)
       - javascript-> tools/js-dataflow.py   (ocore .js via acorn + Obyte .oscript AAs)
     Each arm writes LANGUAGE-SCOPED into the SHARED sidecar
     <ws>/.auditooor/dataflow_paths.jsonl via dataflow_schema.merge_write, so they
     accumulate instead of truncating one another (the polyglot truncation fix).
  3. UNIFIES + VALIDATES the result: re-reads the merged sidecar, drops any
     schema-invalid row, and reports the per-language record counts. Every surviving
     row carries its own `language` field (set by its producing arm) so a downstream
     consumer can tell a Solidity flow from a Go flow within the one file.

Default mode preserves the legacy advisory behavior. `--strict` is the canonical
fail-closed mode: it uses only `.auditooor/inscope_units.jsonl` to determine
applicable languages, rebuilds the merged sidecar for this attempt, and exits nonzero
for manifest errors, arm failures, degraded or truncated output, invalid rows, stale or
absent output, and missing semantic coverage for any applicable inventory language.
It writes backend receipts and applies the canonical dataflow capability query.

Usage:
  python3 tools/dataflow.py --workspace <ws> [--json] [--strict]
                            [--only solidity,go,rust,zk,javascript]  # restrict to a subset
                            [--mode both|value-flow|storage]  # solidity arm mode
                            [--max-hops N]                 # pass-through hop ceiling
                            [--no-merge]                   # arms truncate (legacy)
                            [--target <path>]              # single explicit target

Exit codes: default mode retains advisory exit behavior. `--strict` returns nonzero
            when the canonical dataflow substrate is incomplete or invalid.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import dataflow_schema as dfs  # shared frozen schema + reader  # noqa: E402


# Strict mode consumes only this vocabulary from the authoritative scope manifest.
# Aliases share an implementation arm but retain separate coverage accounting.
_STRICT_LANGUAGE_TO_ARM = {
    "solidity": "solidity", "evm": "solidity",
    "rust": "rust", "go": "go",
    "javascript": "javascript", "js": "javascript",
    "typescript": "javascript", "ts": "javascript",
    "oscript": "oscript",
    "zk": "zk", "circom": "zk",
}

_STRICT_CANONICAL_LANGUAGE = {
    "solidity": "solidity", "evm": "solidity",
    "rust": "rust", "go": "go",
    "javascript": "javascript", "js": "javascript",
    "typescript": "typescript", "ts": "typescript",
    "oscript": "oscript",
    "zk": "circom", "circom": "circom",
}

_STRICT_OUTPUT_LANGUAGES = {
    "solidity": {"solidity", "evm"},
    "evm": {"solidity", "evm"},
    "rust": {"rust"},
    "go": {"go"},
    "javascript": {"javascript", "js"},
    "js": {"javascript", "js"},
    "typescript": {"typescript", "ts"},
    "ts": {"typescript", "ts"},
    "oscript": {"oscript"},
    "zk": {"zk", "circom"},
    "circom": {"zk", "circom"},
}

_RECEIPT_SCHEMA = "auditooor.language_backend_receipt.v1"
_CAPABILITY_CONTRACT_TOOL = _HERE / "language-capability-contract.py"
_SEMANTIC_BACKENDS = {
    "solidity": ("slither", "semantic-ssa"),
    "go": ("go-ssa", "semantic-ssa"),
    "rust": ("mir", "semantic-ssa"),
}


# --------------------------------------------------------------------------- #
# Language detection: REUSE make audit's detector predicates (do not invent).
# --------------------------------------------------------------------------- #
def _load_canonical_detector():
    """Import tools/audit-honesty-check.py (hyphenated) to reuse _detect_lang."""
    spec = importlib.util.spec_from_file_location(
        "audit_honesty_check_for_router", _HERE / "audit-honesty-check.py")
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception:
        return None
    return mod


# Path parts that mark a .sol file as OUT-OF-SCOPE for the Solidity arm: vendored
# libs, build output, and audit-generated harness/fuzz scaffolding (economic_fuzz,
# chimera_harnesses, poc-tests, .auditooor/*). Mirrors dataflow-slice.py's
# _resolve_targets._EXCLUDE_PARTS so the router's has_sol predicate agrees with the
# slice arm's own in-scope target resolution. WHY (axelar-dlt 2026-07-12): a Go+Rust
# workspace carried a single generated harness fixture
# `economic_fuzz/EconomicInvariantFuzz.t.sol`; the old `any(ws.glob('**/*.sol'))`
# predicate flipped has_sol=True, dispatched the Solidity arm, and the arm - finding
# no in-scope foundry/hardhat root - degraded with a bogus
# "<workspace> is a directory" compile-error row. A workspace with ZERO in-scope .sol
# must emit NOTHING for the Solidity arm (clean not-applicable), not a compile-error
# degrade.
_EXCLUDE_SOL_PARTS = frozenset({
    "node_modules", "out", "cache", "crytic-export", "lib",
    ".auditooor", "chimera_harnesses", "poc-tests", "poc_execution",
    "prior_audits", "medusa", "medusa-corpus", "fuzz_run", "economic_fuzz",
    "test", "tests",
})


def _has_inscope_sol(ws: Path) -> bool:
    """True iff the workspace contains at least one .sol file that is NOT under a
    vendored/build/harness directory. Used so the router SKIPS the Solidity arm on a
    workspace whose only .sol files are audit-generated fuzz harnesses (or vendored
    libs) - dispatching the arm there yields a bogus 'is a directory' compile-error
    degrade instead of a clean no-op."""
    for p in ws.glob("**/*.sol"):
        # p is absolute; only inspect the parts BELOW the workspace root so an
        # excluded component in the ws's own absolute path never false-excludes.
        try:
            rel_parts = p.relative_to(ws).parts
        except ValueError:  # pragma: no cover - glob under ws is always relative-able
            rel_parts = p.parts
        if not (set(rel_parts) & _EXCLUDE_SOL_PARTS):
            return True
    return False


def _has_inscope_units(ws: Path, languages: set[str], patterns: tuple[str, ...]) -> bool:
    """True iff the authoritative inventory (or fallback glob) contains a source unit.

    Authoritative gate = the enumerator's <ws>/.auditooor/inscope_units.jsonl: when it
    exists, this is True ONLY if it carries a row in ``languages``. This is
    what keeps the arm from false-firing on the whole Solidity fleet - a Solidity-only
    workspace still ships stray toolchain scripts (hardhat.config.js, .mocharc.js,
    OZ-lib test helpers) OUTSIDE node_modules, so a pure file-presence glob would flip
    has_js=True everywhere and then the router's silent-0 guard would spuriously warn.
    The enumerator, by contrast, only tags program files that are genuinely in scope.
    Gating on it makes the
    router predicate agree byte-for-byte with the arm's own in-scope target resolution.

    Fallback (only when inscope_units.jsonl is ABSENT, e.g. a bare workspace the
    enumerator has not run over): a glob for the requested source suffixes outside vendored/build
    trees, mirroring js-dataflow.py::_EXCLUDE_PARTS."""
    units = ws / ".auditooor" / "inscope_units.jsonl"
    if units.is_file():
        try:
            with open(units, encoding="utf-8", errors="replace") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        rec = json.loads(ln)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if rec.get("lang") in languages:
                        return True
            return False
        except OSError:
            return False
    _excl = frozenset({
        "node_modules", "vendor", "bower_components", ".git",
        "dist", "build", "out", "coverage", ".auditooor",
    })
    for pat in patterns:
        for p in ws.glob(pat):
            try:
                rel_parts = set(p.relative_to(ws).parts)
            except ValueError:  # pragma: no cover
                rel_parts = set(p.parts)
            if not (rel_parts & _excl):
                return True
    return False


def _has_inscope_js(ws: Path) -> bool:
    return _has_inscope_units(ws, {"js", "javascript"}, ("**/*.js",))


def _has_inscope_oscript(ws: Path) -> bool:
    return _has_inscope_units(ws, {"oscript"}, ("**/*.oscript", "**/*.aa"))


def _present_languages(ws: Path) -> Dict[str, bool]:
    """Return {solidity,rust,go,zk,javascript: present?} using the SAME glob
    predicates as make audit's tools/audit-honesty-check.py::_detect_lang, extended
    to a set.

    audit-honesty-check._detect_lang collapses to a single primary (or "mixed"); for
    the router we need EVERY present arm, so we evaluate the identical has_* predicates
    here (and additionally detect circom + js/oscript, which the honesty detector does
    not cover). The canonical detector's verdict is still consulted as a cross-check.
    """
    # identical predicates to audit-honesty-check._detect_lang
    has_rust = (
        any(ws.glob("src/**/*.rs"))
        or (ws / "src" / "Cargo.toml").exists()
        or any((ws / "src").glob("*/Cargo.toml"))
        # also accept a top-level crate (router is broader than the honesty gate,
        # which only scans src/; a Cargo.toml at the ws root is a real Rust ws)
        or (ws / "Cargo.toml").exists()
    )
    # in-scope .sol only: a lone vendored/harness .sol (e.g. a generated
    # economic_fuzz/*.t.sol on a Go+Rust ws) must NOT dispatch the Solidity arm.
    has_sol = _has_inscope_sol(ws)
    has_go = (
        any(ws.glob("src/**/*.go"))
        or (ws / "go.mod").exists()
        or any(ws.glob("**/go.mod"))
    )
    has_zk = any(ws.glob("**/*.circom"))
    # JS and Oscript receive distinct arms. Oscript's arm invokes the ocore parser;
    # it remains syntactic evidence and cannot satisfy semantic capability gates.
    has_js = _has_inscope_js(ws)
    has_oscript = _has_inscope_oscript(ws)
    return {"solidity": has_sol, "rust": has_rust, "go": has_go, "zk": has_zk,
            "javascript": has_js, "oscript": has_oscript}


# --------------------------------------------------------------------------- #
# Arm dispatch
# --------------------------------------------------------------------------- #
def _arm_cmd(lang: str, ws: Path, args: argparse.Namespace) -> Optional[List[str]]:
    """Build the subprocess argv for one arm, or None if no tool exists."""
    py = sys.executable or "python3"
    common = ["--workspace", str(ws)]
    if args.no_merge:
        common.append("--no-merge")
    if lang == "solidity":
        tool = _HERE / "dataflow-slice.py"
        if getattr(args, "strict", False) and not tool.is_file():
            return None
        cmd = [py, str(tool), *common, "--mode", args.mode, "--json"]
        if args.max_hops is not None:
            cmd += ["--max-hops", str(args.max_hops)]
        # Keystone capabilities ON by default (R80-degrade keeps them safe):
        # closure-corrected unguarded folds up-graph/modifier guards; economic
        # storage-write value-movers surface accounting sinks. Opt out via flags.
        if not args.no_closure:
            cmd += ["--closure-unguarded"]
        if not args.no_storage_value and args.mode in ("storage", "both"):
            cmd += ["--emit-storage-value"]
        if args.target:
            cmd += ["--target", args.target]
        return cmd
    if lang == "rust":
        tool = _HERE / "rust-dataflow.py"
        if getattr(args, "strict", False) and not tool.is_file():
            return None
        cmd = [py, str(tool), *common, "--json"]
        if args.max_hops is not None:
            cmd += ["--max-hops", str(args.max_hops)]
        if args.target:
            cmd += ["--target", args.target]
        return cmd
    if lang == "go":
        tool = _HERE / "go-dataflow.py"
        if getattr(args, "strict", False) and not tool.is_file():
            return None
        cmd = [py, str(tool), *common, "--json"]
        if args.max_hops is not None:
            cmd += ["--max-depth", str(args.max_hops)]
        if args.target:
            cmd += ["--target", args.target]
        # PANIC SUBSTRATE (feeds step-2d-go-mustsucceed): emit kind==panic records
        # BY DEFAULT so the consensus-halt reasoner (go-mustsucceed-panic-
        # reachability.py) has its substrate written into dataflow_paths.jsonl at
        # step-1c, BEFORE it consumes it at step-2d. Without this the panic arm is
        # env-gated OFF, dataflow_paths.jsonl carries 0 kind==panic rows, and the
        # reasoner runs vacuously (0 attacker-tainted panic nodes -> 0 obligations).
        # Additive to the value/state/authority slice existing consumers filter on.
        # Opt out with AUDITOOOR_DATAFLOW_PANIC_SINKS in {0,false,no} (a caller that
        # explicitly disables it wins).
        if str(os.environ.get("AUDITOOOR_DATAFLOW_PANIC_SINKS", "")).strip().lower() \
                not in ("0", "false", "no"):
            cmd += ["--panic-sinks"]
        return cmd
    if lang == "zk":
        tool = _HERE / "zk-dataflow.py"
        if getattr(args, "strict", False) and not tool.is_file():
            return None
        # zk arm uses --workspace; it defaults to the shared sidecar (merge) now.
        # It has no --no-merge / --mode; it is a no-op on non-circom workspaces.
        return [py, str(tool), "--workspace", str(ws), "--json"]
    if lang == "javascript":
        # The legacy JS tool can enumerate Oscript too, but routing reserves Oscript
        # rows for the parser-backed arm below. This prevents an enumerator from
        # satisfying a parser-backed substrate receipt by execution order.
        tool = _HERE / "js-dataflow.py"
        if getattr(args, "strict", False) and not tool.is_file():
            return None
        cmd = [py, str(tool), *common, "--skip-oscript", "--json"]
        if args.max_hops is not None:
            cmd += ["--max-hops", str(args.max_hops)]
        if args.target:
            cmd += ["--target", args.target]
        return cmd
    if lang == "oscript":
        tool = _HERE / "oscript-ast-dataflow.py"
        if getattr(args, "strict", False) and not tool.is_file():
            return None
        return [py, str(tool), *common, "--json"]
    return None


def _kill_process_group(proc: "subprocess.Popen") -> None:
    """Best-effort SIGKILL the arm's ENTIRE process group. Because the arm is
    launched with start_new_session=True it is a group leader (pgid == pid), so
    this also reaps any multiprocessing GRANDCHILDREN - the ones that otherwise
    hold the captured stdout/stderr pipe open and wedge communicate() in poll()."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def _run_arm(lang: str, cmd: List[str], timeout: int) -> Dict[str, Any]:
    """Run one arm subprocess in its OWN process group; return a per-arm report
    dict (never raises).

    The go/rust arm backends spawn multiprocessing GRANDCHILDREN that inherit the
    captured stdout/stderr pipe. Plain subprocess.run(capture_output=True,
    timeout=...) then DEADLOCKS on timeout: it SIGKILLs only the DIRECT child, and
    its internal communicate() blocks forever in poll() waiting for a pipe-EOF the
    still-alive grandchildren never send (observed NUVA 2026-07-06 - the arm parent
    and a multiprocessing worker both wedged in poll(), 0% CPU, long past the
    per-arm timeout; the legacy step-1c path is advisory, while strict mode converts
    this status into a hard failure. Isolate the arm in a new session and, on
    timeout, kill the WHOLE group so the pipe write-ends close and the drain cannot
    hang."""
    rep: Dict[str, Any] = {"language": lang, "argv": cmd}
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,
        )
    except Exception as e:  # pragma: no cover - defensive
        rep.update(status="exec-error", error=f"{type(e).__name__}: {e}")
        return rep
    try:
        out_s, err_s = proc.communicate(timeout=timeout)
        returncode = proc.returncode
    except subprocess.TimeoutExpired:
        _kill_process_group(proc)
        # group is dead => pipe write-ends closed => this drain returns promptly.
        try:
            proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:  # pragma: no cover - group refused to die
            pass
        rep.update(status="timeout", returncode=None)
        return rep
    except Exception as e:  # pragma: no cover - defensive
        _kill_process_group(proc)
        rep.update(status="exec-error", error=f"{type(e).__name__}: {e}")
        return rep
    rep["returncode"] = returncode
    rep["command_sha256"] = hashlib.sha256(
        json.dumps(cmd, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    rep["stdout_sha256"] = hashlib.sha256((out_s or "").encode("utf-8")).hexdigest()
    rep["stderr_sha256"] = hashlib.sha256((err_s or "").encode("utf-8")).hexdigest()
    # arms print a --json summary on stdout; capture it when parseable
    out = (out_s or "").strip()
    summary: Optional[Dict[str, Any]] = None
    if out:
        # the summary is the LAST json object on stdout (arms may print other lines)
        for chunk in (out, out.splitlines()[-1] if out.splitlines() else ""):
            try:
                summary = json.loads(chunk)
                break
            except (json.JSONDecodeError, ValueError):
                continue
    rep["status"] = "ok" if returncode == 0 else "arm-nonzero"
    rep["summary"] = summary
    if returncode != 0:
        rep["stderr_tail"] = (err_s or "")[-300:]
    return rep


# --------------------------------------------------------------------------- #
# Vendored-dependency path filter (generic, language-agnostic)
# --------------------------------------------------------------------------- #
# A def-use path whose BOTH endpoints (source AND sink) live in third-party
# vendored code is library-internal noise: it can never be an in-scope protocol
# finding, only an artifact of the analyzer compiling the project's deps. We drop
# only the both-ends-vendored paths; a protocol->library or library->protocol
# path is KEPT (the protocol may feed attacker-controlled data into a library
# sink, which is in-scope). This mirrors how every audit program treats unmodified
# upstream deps as out-of-scope, and keeps the EVM/Rust/Go detector surface focused
# on the real source instead of node_modules / .cargo / vendor / forge-std.
_VENDORED_MARKERS: tuple[str, ...] = (
    "/node_modules/",        # npm / Solidity (Hardhat, Foundry remappings)
    "/.cargo/registry/",     # Rust crates.io vendored crates
    "/.cargo/git/",          # Rust git-dependency checkouts
    "/vendor/",              # Go (and some Solidity) vendored deps
    "/lib/forge-std/",       # Foundry std lib
    "/lib/openzeppelin",     # forge OZ (contracts + -upgradeable)
    "/lib/solmate/",
    "/lib/solady/",
    "/lib/ds-test/",
    "/@openzeppelin/",       # remapped / build-copied OZ (e.g. build/@openzeppelin/)
    "/site-packages/",       # python deps (defensive)
)


def _is_vendored(file_path: str) -> bool:
    if not file_path:
        return False
    return any(marker in file_path for marker in _VENDORED_MARKERS)


def _filter_vendored_paths(out_path: Path) -> int:
    """Drop records whose source AND sink files are both vendored. Rewrites the
    sidecar in place. Returns the count of dropped records (0 if file absent or
    nothing dropped). Never raises - a filter error leaves the sidecar untouched."""
    if not out_path.is_file():
        return 0
    kept: List[str] = []
    dropped = 0
    try:
        with open(out_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    rec = json.loads(stripped)
                except (json.JSONDecodeError, ValueError):
                    kept.append(stripped)  # preserve unparseable rows verbatim
                    continue
                src_file = (rec.get("source") or {}).get("file", "")
                sink_file = (rec.get("sink") or {}).get("file", "")
                if _is_vendored(src_file) and _is_vendored(sink_file):
                    dropped += 1
                    continue
                kept.append(stripped)
    except OSError:
        return 0
    if dropped:
        try:
            out_path.write_text("\n".join(kept) + ("\n" if kept else ""),
                                encoding="utf-8")
        except OSError:
            return 0
    return dropped


def _strict_inventory(ws: Path) -> tuple[Optional[Dict[str, List[str]]], List[str]]:
    """Load and validate the strict authoritative in-scope inventory.

    Each nonblank row must name a supported language and an existing workspace-relative
    source file. Returning all errors at once prevents a partially trusted manifest
    from silently narrowing the mandatory arm set.
    """
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    errors: List[str] = []
    if not manifest.is_file():
        return None, [f"strict inventory missing: {manifest}"]
    inventory: Dict[str, List[str]] = {}
    try:
        lines = manifest.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError) as exc:
        return None, [f"strict inventory unreadable: {type(exc).__name__}: {exc}"]
    nonblank = 0
    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            continue
        nonblank += 1
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, ValueError) as exc:
            errors.append(f"strict inventory malformed JSON line {line_no}: {exc}")
            continue
        if not isinstance(rec, dict):
            errors.append(f"strict inventory row {line_no} is not an object")
            continue
        raw_lang = rec.get("lang")
        raw_file = rec.get("file")
        if not isinstance(raw_lang, str) or not raw_lang.strip():
            errors.append(f"strict inventory row {line_no} missing language")
            continue
        lang = raw_lang.strip().lower()
        if lang not in _STRICT_LANGUAGE_TO_ARM:
            errors.append(f"strict inventory row {line_no} has unsupported language: {lang}")
            continue
        if not isinstance(raw_file, str) or not raw_file.strip():
            errors.append(f"strict inventory row {line_no} missing source file")
            continue
        rel = Path(raw_file.strip())
        if rel.is_absolute():
            errors.append(f"strict inventory row {line_no} source path is absolute: {raw_file}")
            continue
        source = (ws / rel).resolve()
        try:
            source.relative_to(ws)
        except ValueError:
            errors.append(f"strict inventory row {line_no} source path escapes workspace: {raw_file}")
            continue
        if not source.is_file():
            errors.append(f"strict inventory row {line_no} source missing: {raw_file}")
            continue
        inventory.setdefault(lang, []).append(str(rel))
    if not nonblank:
        errors.append("strict inventory is empty")
    if not inventory and not errors:
        errors.append("strict inventory has no applicable language")
    return (None if errors else inventory), errors


def _strict_present(inventory: Dict[str, List[str]]) -> Dict[str, bool]:
    """Map validated inventory languages to the router's implementation arms."""
    present = {arm: False for arm in ("solidity", "rust", "go", "zk", "javascript", "oscript")}
    for lang in inventory:
        present[_STRICT_LANGUAGE_TO_ARM[lang]] = True
    return present


def _rebuild_strict_output(out_path: Path, receipt_path: Optional[Path] = None) -> Optional[str]:
    """Discard the previous merge before a strict attempt.

    Strict validation must never count rows from a prior successful run after an arm
    fails today. The sidecar is recreated only by the current attempt's arms.
    """
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        for path in (out_path, receipt_path):
            if path is not None and path.exists():
                path.unlink()
    except OSError as exc:
        return f"strict output reset failed: {type(exc).__name__}: {exc}"
    return None


def _strict_arm_issues(reports: List[Dict[str, Any]]) -> List[str]:
    """Return hard failures reported by arm execution or arm JSON summaries."""
    errors: List[str] = []
    for report in reports:
        lang = str(report.get("language", "?"))
        status = report.get("status")
        if status != "ok":
            errors.append(f"arm {lang} failed: {status}")
            continue
        summary = report.get("summary")
        if not isinstance(summary, dict):
            continue
        summary_status = str(summary.get("status", "")).lower()
        if summary_status in {"degrade", "degraded", "error", "failed", "timeout"}:
            errors.append(f"arm {lang} reported {summary_status}")
        if summary.get("degraded") or summary.get("truncated") or summary.get("dataflow_truncated"):
            errors.append(f"arm {lang} reported degraded or truncated output")
    return errors


def _record_has_semantic_backend(language: str, rec: Dict[str, Any]) -> bool:
    """Accept only the compiler or IR backend promised by the capability contract."""
    if rec.get("degraded") or rec.get("dataflow_truncated"):
        return False
    if str(rec.get("confidence", "")).lower() != "semantic-ssa":
        return False
    engine = str(rec.get("engine", "")).lower()
    if language == "solidity":
        return engine.startswith("slither")
    if language == "go":
        return "go-ssa" in engine or "go/ssa" in engine
    if language == "rust":
        return engine.startswith("rustc-mir")
    return False


def _summary_backend_tokens(summary: Dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for key in ("backend", "semantic_backend", "engine"):
        value = summary.get(key)
        if value:
            tokens.add(str(value).lower())
    crates = summary.get("crates")
    if isinstance(crates, dict):
        for crate in crates.values():
            if isinstance(crate, dict) and crate.get("backend"):
                tokens.add(str(crate["backend"]).lower())
    return tokens


def _summary_proves_examined_empty(
    language: str, summary: Dict[str, Any], inventory_unit_count: int,
) -> bool:
    """Recognize only an explicit all-units compiler/IR examined-empty proof."""
    if summary.get("examined_empty") is not True:
        return False
    examined = summary.get("examined_unit_count")
    if not isinstance(examined, int) or examined != inventory_unit_count or examined < 1:
        return False
    tokens = _summary_backend_tokens(summary)
    if language == "solidity":
        return any("slither" in token for token in tokens)
    if language == "go":
        return any("go-ssa" in token or "go/ssa" in token for token in tokens)
    if language == "rust":
        return bool(tokens) and all(token in {"mir", "rustc-mir"} or token.startswith("rustc-mir")
                                    for token in tokens)
    return False


def _strict_backend_receipts(
    ws: Path,
    inventory: Dict[str, List[str]],
    arm_reports: List[Dict[str, Any]],
    valid_records: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Build current-attempt capability receipts from reports and validated rows."""
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    inventory_sha256 = hashlib.sha256(manifest.read_bytes()).hexdigest()
    grouped: Dict[str, Dict[str, Any]] = {}
    for token, files in inventory.items():
        canonical = _STRICT_CANONICAL_LANGUAGE[token]
        group = grouped.setdefault(canonical, {"tokens": [], "files": []})
        group["tokens"].append(token)
        group["files"].extend(files)
    reports = {str(report.get("language", "")): report for report in arm_reports}
    row_languages = {
        "solidity": {"solidity", "evm"}, "go": {"go"}, "rust": {"rust"},
        "javascript": {"javascript", "js"}, "typescript": {"typescript", "ts"},
        "oscript": {"oscript"}, "circom": {"circom", "zk"},
    }
    receipts: List[Dict[str, Any]] = []
    for canonical in sorted(grouped):
        group = grouped[canonical]
        files = list(group["files"])
        unique_files = sorted(set(files))
        source_hashes = [
            {"file": rel, "sha256": hashlib.sha256((ws / rel).read_bytes()).hexdigest()}
            for rel in unique_files
        ]
        source_set_sha256 = hashlib.sha256(
            json.dumps(source_hashes, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        records = [
            rec for rec in valid_records
            if str(rec.get("language", "")).lower() in row_languages[canonical]
        ]
        engines = sorted({str(rec.get("engine", "")) for rec in records if rec.get("engine")})
        arm = _STRICT_LANGUAGE_TO_ARM[str(group["tokens"][0])]
        report = reports.get(arm, {"language": arm, "status": "missing"})
        summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
        arm_ok = report.get("status") == "ok" and str(summary.get("status", "ok")).lower() \
            not in {"degrade", "degraded", "error", "failed", "timeout"}
        semantic_records = [rec for rec in records if _record_has_semantic_backend(canonical, rec)]
        summary_backends = _summary_backend_tokens(summary)
        examined_empty = False
        backend = engines[0] if len(engines) == 1 else ("mixed" if engines else "unavailable")
        if not engines and len(summary_backends) == 1:
            backend = next(iter(summary_backends))
        confidence = "unavailable"
        status = "blocked" if arm_ok else "failed"
        if canonical in _SEMANTIC_BACKENDS:
            expected_backend, expected_confidence = _SEMANTIC_BACKENDS[canonical]
            examined_empty = arm_ok and not records and _summary_proves_examined_empty(
                canonical, summary, len(files))
            semantic_records_are_sufficient = bool(semantic_records)
            if canonical in {"go", "rust"} and len(semantic_records) != len(records):
                semantic_records_are_sufficient = False
            if canonical == "rust" and any(
                token not in {"mir", "rustc-mir"} and not token.startswith("rustc-mir")
                for token in summary_backends
            ):
                semantic_records_are_sufficient = False
            if arm_ok and (semantic_records_are_sufficient or examined_empty):
                backend = expected_backend
                confidence = expected_confidence
                status = "pass"
            elif records:
                confidences = sorted({str(rec.get("confidence", "")) for rec in records})
                confidence = confidences[0] if len(confidences) == 1 else "mixed"
        execution = None
        if canonical in _SEMANTIC_BACKENDS and arm_ok:
            argv = report.get("argv")
            if isinstance(argv, list) and argv and all(isinstance(part, str) and part for part in argv):
                artifact_rows = semantic_records
                artifact_sha256 = hashlib.sha256(
                    json.dumps(artifact_rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
                ).hexdigest()
                execution = {
                    "argv": argv,
                    "executable": argv[0],
                    "command_sha256": report.get("command_sha256"),
                    "returncode": report.get("returncode"),
                    "stdout_sha256": report.get("stdout_sha256"),
                    "stderr_sha256": report.get("stderr_sha256"),
                    "artifact_kind": f"{expected_backend}-semantic-rows",
                    "artifact_sha256": artifact_sha256,
                }
            else:
                status = "blocked"
        elif records:
            confidences = sorted({str(rec.get("confidence", "")) for rec in records})
            confidence = confidences[0] if len(confidences) == 1 else "mixed"
        receipt = {
            "receipt_schema": _RECEIPT_SCHEMA,
            "phase": "dataflow",
            "language": canonical,
            "inventory_languages": sorted(group["tokens"]),
            "backend": backend,
            "confidence": confidence,
            "status": status,
            "degraded": (not arm_ok) or any(bool(rec.get("degraded")) for rec in records),
            "arm": arm,
            "arm_status": report.get("status", "missing"),
            "record_count": len(records),
            "semantic_record_count": len(semantic_records),
            "examined_empty": examined_empty,
            "examined_unit_count": len(files) if examined_empty else None,
            "inventory_unit_count": len(files),
            "inventory_sha256": inventory_sha256,
            "source_set_sha256": source_set_sha256,
            "source_hashes": source_hashes,
            "engines_observed": engines,
            "arm_summary_backends": sorted(summary_backends),
            "execution": execution,
        }
        receipts.append(receipt)
    return receipts


def _write_backend_receipts(path: Path, receipts: List[Dict[str, Any]]) -> Optional[str]:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in receipts),
                       encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        return f"language backend receipt write failed: {type(exc).__name__}: {exc}"
    return None


def _query_dataflow_capability(
    inventory_languages: set[str], receipt_path: Path,
) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Reuse the canonical contract query for the strict dataflow phase."""
    spec = importlib.util.spec_from_file_location(
        "language_capability_contract_for_dataflow", _CAPABILITY_CONTRACT_TOOL)
    if spec is None or spec.loader is None:
        return None, f"cannot load language capability contract: {_CAPABILITY_CONTRACT_TOOL}"
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        contract = module.load_contract()
        validation_errors = module.validate_contract(contract)
        if validation_errors:
            return None, "language capability contract invalid: " + "; ".join(validation_errors)
        receipts = module.load_evidence([receipt_path])
        return module.query_contract(
            contract, inventory_languages, ("dataflow",), receipts
        ), None
    except Exception as exc:
        return None, f"language capability query failed: {type(exc).__name__}: {exc}"


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def _zero_record_present_arms(
    present: Dict[str, bool],
    records_by_language: Dict[str, int],
    arms_to_run: List[str],
) -> List[str]:
    """Arms whose language IS present but produced 0 records (likely a compile/deps
    failure masquerading as an empty slice). Pure helper for the silent-0 guard."""
    return [
        lang for lang in arms_to_run
        if present.get(lang) and int(records_by_language.get(lang, 0) or 0) == 0
    ]


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Cross-language DefUsePath router + stitcher (one unified jsonl).")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--only",
                    help="comma list to restrict arms (solidity,rust,go,zk,javascript,oscript)")
    ap.add_argument("--mode", choices=["value-flow", "storage", "both"], default="both",
                    help="solidity arm slice mode (pass-through)")
    ap.add_argument("--max-hops", type=int, default=None,
                    help="hop ceiling pass-through (default: each arm's HIGH unbounded ceiling)")
    ap.add_argument("--no-merge", action="store_true",
                    help="arms truncate the sidecar (legacy; only sane for a single arm)")
    ap.add_argument("--target", help="single explicit target path (passed to each arm)")
    ap.add_argument("--timeout", type=int, default=1800, help="per-arm subprocess timeout (s)")
    ap.add_argument("--no-closure", action="store_true",
                    help="disable closure-corrected unguarded on the solidity arm "
                         "(default ON: folds up-graph/modifier guards so unguarded is "
                         "honest on role-gated codebases; R80-degrades if Slither absent)")
    ap.add_argument("--no-storage-value", action="store_true",
                    help="disable economic storage-write value-mover sinks on the "
                         "solidity arm (default ON when mode includes storage)")
    ap.add_argument("--keep-vendored-paths", action="store_true",
                    help="do NOT drop both-ends-vendored def-use paths "
                         "(node_modules/.cargo/vendor/forge-std/OZ). Default: drop "
                         "them so the detector surface stays on in-scope protocol "
                         "source. Only drops paths whose source AND sink are both "
                         "vendored; protocol<->library paths are always kept.")
    ap.add_argument("--strict", action="store_true",
                    help="fail closed using only .auditooor/inscope_units.jsonl; "
                         "require fresh, valid, non-degraded semantic records for "
                         "every applicable inventory language")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[dataflow] ERR workspace not found: {ws}", file=sys.stderr)
        return 2

    out_path = ws / ".auditooor" / "dataflow_paths.jsonl"
    receipt_path = ws / ".auditooor" / "language_backend_receipts" / "dataflow.jsonl"

    only = None
    if args.only:
        only = {
            s.strip().lower() if args.strict else s.strip()
            for s in args.only.split(",") if s.strip()
        }

    strict_inventory: Optional[Dict[str, List[str]]] = None
    canon_primary = None
    if args.strict:
        reset_error = _rebuild_strict_output(out_path, receipt_path)
        if reset_error:
            result = {
                "status": "error", "verdict": "strict-output-reset-failed",
                "workspace": str(ws), "out": str(out_path), "strict_errors": [reset_error],
            }
            print(json.dumps(result, indent=2) if args.json else f"[dataflow] FAIL {reset_error}")
            return 3
        strict_inventory, inventory_errors = _strict_inventory(ws)
        if inventory_errors:
            result = {
                "status": "error", "verdict": "strict-inventory-invalid",
                "workspace": str(ws), "out": str(out_path),
                "strict_errors": inventory_errors,
            }
            print(json.dumps(result, indent=2) if args.json
                  else "[dataflow] FAIL " + "; ".join(inventory_errors))
            return 3
        assert strict_inventory is not None
        present = _strict_present(strict_inventory)
        required_arms = {arm for arm, is_present in present.items() if is_present}
        if only is not None and only != required_arms:
            error = ("strict mode requires every applicable arm; inventory requires "
                     f"{sorted(required_arms)}, --only requested {sorted(only)}")
            result = {
                "status": "error", "verdict": "strict-arm-selection-invalid",
                "workspace": str(ws), "out": str(out_path), "strict_errors": [error],
            }
            print(json.dumps(result, indent=2) if args.json else f"[dataflow] FAIL {error}")
            return 3
    else:
        present = _present_languages(ws)
        # Legacy-only cross-check against the canonical primary detector.
        canon = _load_canonical_detector()
        if canon is not None and hasattr(canon, "_detect_lang"):
            try:
                canon_primary = canon._detect_lang(ws)
            except Exception:
                canon_primary = None

    arms_to_run = [lang for lang, on in present.items()
                   if on and (only is None or lang in only)]

    # ----- graceful no-op: no language arm applies -----
    if not arms_to_run:
        result = {
            "status": "no-op",
            "verdict": "no-language-arm",
            "workspace": str(ws),
            "out": str(out_path),
            "detected_present": present,
            "canonical_primary": canon_primary,
            "arms_run": [],
            "records_by_language": {},
            "total_records": 0,
        }
        print(json.dumps(result, indent=2) if args.json
              else f"[dataflow] no-op (no .sol/.rs/.go/.circom under {ws})")
        return 0

    # ----- dispatch each present arm (sequential; merge is per-language-scoped) -----
    arm_reports: List[Dict[str, Any]] = []
    for lang in arms_to_run:
        cmd = _arm_cmd(lang, ws, args)
        if cmd is None:
            arm_reports.append({"language": lang, "status": "no-tool"})
            continue
        arm_reports.append(_run_arm(lang, cmd, args.timeout))

    # ----- drop library-internal (both-ends-vendored) noise paths -----
    vendored_dropped = 0
    if not args.keep_vendored_paths:
        vendored_dropped = _filter_vendored_paths(out_path)

    # ----- unify + validate: re-read the merged sidecar -----
    records_by_language: Dict[str, int] = {}
    degraded_by_language: Dict[str, int] = {}
    truncated_by_language: Dict[str, int] = {}
    invalid_rows = 0
    total = 0
    valid_records: List[Dict[str, Any]] = []
    strict_coverage_by_inventory_language: Dict[str, int] = {}
    if strict_inventory is not None:
        strict_coverage_by_inventory_language = {
            language: 0 for language in strict_inventory
        }
    if out_path.is_file():
        try:
            with open(out_path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        invalid_rows += 1
                        continue
                    ok, _errs = dfs.validate(rec)
                    if not ok:
                        invalid_rows += 1
                        continue
                    valid_records.append(rec)
                    lang = rec.get("language", "?")
                    records_by_language[lang] = records_by_language.get(lang, 0) + 1
                    if rec.get("degraded"):
                        degraded_by_language[lang] = degraded_by_language.get(lang, 0) + 1
                    if rec.get("dataflow_truncated"):
                        truncated_by_language[lang] = truncated_by_language.get(lang, 0) + 1
                    if strict_inventory is not None and not rec.get("degraded") \
                            and not rec.get("dataflow_truncated"):
                        row_language = str(lang).lower()
                        for inventory_language in strict_coverage_by_inventory_language:
                            canonical = _STRICT_CANONICAL_LANGUAGE[inventory_language]
                            if row_language in _STRICT_OUTPUT_LANGUAGES[inventory_language] \
                                    and _record_has_semantic_backend(canonical, rec):
                                strict_coverage_by_inventory_language[inventory_language] += 1
                    total += 1
        except OSError:
            pass

    result = {
        "status": "ok",
        "verdict": "stitched",
        "workspace": str(ws),
        "out": str(out_path),
        "detected_present": present,
        "canonical_primary": canon_primary,
        "arms_run": arms_to_run,
        "arm_reports": arm_reports,
        "records_by_language": records_by_language,
        "degraded_by_language": degraded_by_language,
        "truncated_by_language": truncated_by_language,
        "invalid_rows_dropped_on_reread": invalid_rows,
        "vendored_paths_dropped": vendored_dropped,
        "total_records": total,
    }
    if strict_inventory is not None:
        strict_errors = _strict_arm_issues(arm_reports)
        if invalid_rows:
            strict_errors.append(f"strict output contains {invalid_rows} invalid row(s)")
        if degraded_by_language:
            strict_errors.append("strict output contains degraded record(s)")
        if truncated_by_language:
            strict_errors.append("strict output contains truncated record(s)")
        receipts: List[Dict[str, Any]] = []
        capability_report: Optional[Dict[str, Any]] = None
        try:
            receipts = _strict_backend_receipts(
                ws, strict_inventory, arm_reports, valid_records)
            receipt_error = _write_backend_receipts(receipt_path, receipts)
        except OSError as exc:
            receipt_error = f"language backend receipt build failed: {type(exc).__name__}: {exc}"
        if receipt_error:
            strict_errors.append(receipt_error)
        else:
            capability_report, capability_error = _query_dataflow_capability(
                set(strict_inventory), receipt_path)
            if capability_error:
                strict_errors.append(capability_error)
            elif capability_report is not None and not capability_report.get("ok"):
                blocked = capability_report.get("blocked_languages", [])
                unknown = capability_report.get("unknown_inventory_languages", [])
                strict_errors.append(
                    "language capability contract blocked dataflow: "
                    f"blocked={blocked}, unknown={unknown}")
        if not out_path.is_file():
            all_examined_empty = bool(receipts) and all(
                receipt.get("status") == "pass" and receipt.get("examined_empty") is True
                for receipt in receipts
            )
            if capability_report is not None and capability_report.get("ok") and all_examined_empty:
                try:
                    out_path.touch()
                except OSError as exc:
                    strict_errors.append(
                        f"strict examined-empty output materialization failed: {type(exc).__name__}: {exc}")
            else:
                strict_errors.append("strict output absent after arm dispatch")
        result["strict_inventory_languages"] = sorted(strict_inventory)
        result["strict_coverage_by_inventory_language"] = strict_coverage_by_inventory_language
        result["language_backend_receipt_path"] = str(receipt_path)
        result["language_backend_receipts"] = receipts
        result["language_capability_query"] = capability_report
        result["strict_errors"] = strict_errors
        if strict_errors:
            result["status"] = "error"
            result["verdict"] = "strict-failed"
    # Silent-0 guard: an arm whose language IS present but produced 0 records is
    # almost always a COMPILE/DEPS failure (e.g. Solidity foundry roots whose deps
    # are not yet resolved -> slither-compile fails -> 0 paths), NOT a genuine
    # "no dataflow exists" result. Surface it LOUDLY so the operator/loop does not
    # mistake a compile-starved 0 for a clean slice (Morpho Cantina 2026-06-26:
    # step-1c produced 0 because deps were unresolved until step-2; same command
    # produced 475 once `forge-deps-checker --fix` had run).
    zero_record_present_arms = _zero_record_present_arms(
        present, records_by_language, arms_to_run
    )
    result["zero_record_present_arms"] = zero_record_present_arms
    if zero_record_present_arms:
        result["zero_record_hint"] = (
            "Arm(s) with source present produced 0 records - likely a compile/deps "
            "failure, not an empty slice. For Solidity run "
            "`python3 tools/forge-deps-checker.py <ws> --fix` (resolve foundry "
            "remappings/submodules) then re-run; verify the per-arm log for "
            "slither compile-error."
        )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[dataflow] stitched {total} records -> {out_path}")
        print(f"  arms_run={arms_to_run} by_language={records_by_language}")
        if degraded_by_language:
            print(f"  degraded={degraded_by_language}")
        if truncated_by_language:
            print(f"  truncated(ceiling-hit)={truncated_by_language}")
        if zero_record_present_arms:
            print(f"  WARN zero-record arms (source present, likely compile/deps "
                  f"failure): {zero_record_present_arms}")
            print(f"       -> {result['zero_record_hint']}")
    return 3 if strict_inventory is not None and result.get("strict_errors") else 0


if __name__ == "__main__":
    sys.exit(main())
