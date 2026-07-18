#!/usr/bin/env python3
"""Per-harness MUTATION-KILL VERIFIER (Rule R80 / R81 oracle half).

PRINCIPLE
---------
Coverage is only real if it is MUTATION-VERIFIED. Inject ONE bug into a
function's body; the harness/PoC that claims to "cover" that function MUST now
FAIL. If the harness passes both WITH and WITHOUT the bug, the coverage is
VACUOUS (hollow) - it checks nothing real - no matter whether the proof is a
Halmos property, an Echidna invariant, a Foundry test, or an agent attack.

The canonical anchor: the 32 morpho-midnight per-function Halmos harnesses whose
only assertion is `assert(true)` (e.g. `Halmos_IMidnight_multicall`). They
"passed" symbolically and were counted as COVERED, yet they never reference the
function-under-test, so every mutant of that function SURVIVES. This tool proves
them vacuous mechanically.

WHAT THIS TOOL IS (the ORACLE half)
-----------------------------------
tools/mutation-engine.py is the GENERATOR half: given a source file + target
function it emits mutants (one bug each). This tool is the ORACLE half: for a
function + its harness/PoC it

  (1) runs the harness on CLEAN code -> must PASS  (baseline);
  (2) for each generated mutant: apply -> re-run harness -> record PASS/FAIL ->
      RESTORE the original source (always, even on error / interrupt);
  (3) verdict:
        non-vacuous - the harness FAILS on >=1 mutant (it genuinely kills
                      mutants, so it really checks the function);
        vacuous     - the harness PASSES on ALL mutants (it checks nothing
                      real about the function);
        no-baseline - the harness does NOT pass on clean code (cannot be a
                      coverage oracle until the baseline is green);
        no-mutants  - the generator produced 0 mutants for the function
                      (e.g. the body has no mutable operators) - inconclusive.

The JSON output is shaped to seed the very `*mutation*.json` artifact that R80's
`finding-evidence-honesty-check.py::_has_mutation_record()` looks for, so a real
reproducible record replaces an asserted one.

RELATED TOOLS (tool-dedup rule, codified 2026-05-28)
----------------------------------------------------
`find tools/ -iname '*mutation*'` + a grep of the honesty gates was run first.
Every pre-existing reference CONSUMES a mutation-verification *record* or
GENERATES mutants; none of them RUN a harness against mutants to decide vacuity:

  - tools/mutation-engine.py: GENERATOR only. It emits mutants and explicitly
    delegates the oracle decision: "an external runner (the harness re-run) is
    the ORACLE half that decides vacuity." THIS tool is that runner. We import
    its `generate_mutants()` directly rather than re-implementing operators.
  - tools/finding-evidence-honesty-check.py (R80): `_has_mutation_record()` only
    DETECTS whether a `*mutation*.json` artifact / in-draft marker EXISTS; it
    cannot tell a real record from a fabricated one. This tool produces the real
    record it should be detecting.
  - tools/audit-honesty-check.py (R80 whole-workspace): references the
    "mutation-verified non-vacuous harness" principle in prose; runs no harness
    against mutants.
  - tools/halmos-runner.sh / forge-resolve.sh: invoke an engine ONCE on the
    current tree; no mutate -> re-run -> restore loop, no vacuity verdict. This
    tool reuses forge-resolve.sh to locate `forge` and shells halmos/forge for
    the per-mutant re-runs.

GAP THIS TOOL FILLS: there was NO tool that closes the loop
(generate mutant -> apply -> re-run the cited harness -> restore -> decide
vacuous/non-vacuous). The honesty gates could only ask "does a record exist?";
they could not ask "is this harness actually non-vacuous?". This tool answers
that, generically, for any workspace.

GENERICITY
----------
- ANY workspace via --workspace (zero workspace hardcoding; morpho appears only
  in tests / the smoke anchor).
- Language-aware harness runners: Solidity is first-class (halmos / forge);
  Rust (`cargo test`), Go (`go test`), Move/Cairo and anything else via an
  explicit `--harness '<shell command>'`. The per-language default runner table
  is extensible via env hooks AUDITOOOR_MVC_RUNNER_<LANG> without code changes.
- The harness may be given as (a) a path to a test/harness file (we derive a
  runner from its language/extension) or (b) a literal shell command. A literal
  command is always authoritative.

SAFETY
------
The function-under-test source file is mutated IN PLACE for each re-run, then
ALWAYS restored from an in-memory copy captured before the first mutation. A
SIGINT/SIGTERM handler and a try/finally guarantee restoration even on crash or
interrupt. Nothing is committed; the tree is byte-identical after the run.

VERDICTS (exact vocab)
----------------------
  non-vacuous | vacuous | no-baseline | no-mutants
  | no-property-discovered | error

SILENT-SKIP vs ENGINE-ERROR (the no-execution disambiguation)
-------------------------------------------------------------
A baseline run that exits 0 but prints no recognised pass/fail token is a
"silent skip" (status `no-execution`).  Two very different things look like
this and MUST be told apart, or every silent harness collapses to `error`,
mutation_verified_genuine drops to 0, and a genuinely-covered workspace is
falsely flagged DEEP_AUDIT_HOLLOW (the beanstalk / mezo / morpho-midnight
symptom):

  (A) A REAL Halmos / property harness that ran and found NO counterexample.
      Halmos emits no per-test PASS/FAIL line in this case - exit 0, silent.
      This is NOT an error: the engine executed.  Whether it is *genuine*
      coverage is decided by the mutation loop - if some mutant flips the
      harness to a counterexample/failure, the clean silent-exit-0 was a real
      no-counterexample PASS and coverage is `non-vacuous`.  If NO mutant
      flips it (it stays silent/passing on every mutant), the harness never
      discovered a property over this function -> typed skip
      `no-property-discovered` (NOT credited, NOT an error).

  (B) A genuine ENGINE / BUILD failure: a non-zero exit, OR a compile-error
      token in the output (crytic-compile / `out/build-info` missing, solc
      error, "compilation failed", etc.).  A harness that never compiled can
      NEVER be credited - this stays `error` / `no-baseline` and the mutation
      loop is NOT entered (we will not credit code that did not build).

The discriminator is therefore: non-zero exit OR a compile-error token ==
hard `error`/`no-baseline`; a clean silent exit-0 with no compile-error token
== ENTER the mutation loop and let a kill (or its absence) decide.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import fcntl as _fcntl  # POSIX file locking for source-mutation serialization
except ImportError:  # pragma: no cover - non-POSIX
    _fcntl = None


def _acquire_source_mutation_lock(source_file: Path):
    """Serialize concurrent source-mutation on the SAME file across processes.

    THE 2026-06-23 SSV POISON: several per-function mutation-verify runs mutated
    contracts/modules/{SSVClusters,SSVOperators}.sol CONCURRENTLY. Each captured
    its `original` from the working tree AT ENTRY - but a sibling was mid-mutation,
    so the captured "original" was the sibling's mutant. Restores then wrote a
    sibling's mutant back, and a SIGKILL during any window left a mutant on disk;
    every later baseline ran against MUTATED code. An exclusive per-file lock held
    across the entire mutate->run->restore window makes the operation atomic w.r.t.
    other processes, so each run always sees - and restores to - the pristine file.
    Degrades to a no-op lock when fcntl is unavailable (the cut-pristine guard is
    the backstop). Returns a file object to hold (close == release) or None."""
    if _fcntl is None:
        return None
    try:
        key = hashlib.sha1(str(source_file.resolve()).encode()).hexdigest()[:16]
        lock_path = Path(tempfile.gettempdir()) / f"auditooor-mvc-src-{key}.lock"
        fh = open(lock_path, "w")
        _fcntl.flock(fh.fileno(), _fcntl.LOCK_EX)
        return fh
    except OSError:
        return None

# medusa is the canonical Solidity invariant fuzzer, but it ALWAYS exits 0 (even
# when a property/assertion test fails) and its failure summary "N test(s) failed"
# matches NONE of the generic _FAIL_TOKENS. Without this, every genuine medusa
# mutant-kill is misread as a vacuous pass and NO medusa-based invariant can ever
# be credited as mutation-verified (the optimism OptimismPortal2 no-double-spend
# invariant showed 0/40 for exactly this reason). Match medusa's summary directly.
_MEDUSA_FAIL_RE = re.compile(r"([1-9]\d*)\s+test\(s\)\s+failed")
_MEDUSA_PASS_RE = re.compile(r"(\d+)\s+test\(s\)\s+passed,\s*0\s+test\(s\)\s+failed")

# echidna prints a per-property verdict line ("<name>: passing 🎉" /
# "<name>: failed!💥"; older builds say "falsified"/"failing"). Like medusa it is
# inconsistent about its exit code across versions, so the TEXT is authoritative.
# This is load-bearing because echidna (hevm) is the ONLY invariant engine that
# can fuzz selfdestruct / SafeSend-path OP-Stack contracts - medusa's fork-VM
# stack-underflows on selfdestruct (LiquidityController showed exactly this), so
# without an echidna oracle every such contract's mutation-verified invariant is
# misread and can NEVER be credited toward core-coverage / engine-harness-proof.
_ECHIDNA_FAIL_RE = re.compile(r":\s*(failed!|falsified|failing)", re.I)
_ECHIDNA_PASS_RE = re.compile(r":\s*passing", re.I)

# `go test` prints a per-package summary line on SUCCESS: "ok   <import/path>
# 0.312s" (or "(cached)"). Unlike forge/rustc it emits NO "test result: ok" token,
# so without this recognizer a passing Go baseline is misclassified `no-execution`
# (silent) - which (a) makes the emitted mvc_sidecar baseline.status diverge from a
# genuine PASS (the axelar-dlt reference records baseline pass) so the flat-schema
# reader branch of audit-honesty-check._mutation_verified_cut_harnesses rejects it,
# and (b) makes a VACUOUS Go harness's surviving mutants classify `no-execution`
# instead of `pass`, so `survived` stays 0 and the explicit `vacuous` verdict is
# never reached (it falls through to the ambiguous silent-skip path). Anchored to
# line-start "ok<ws><pkg>" so a stray "ok" inside a log line cannot false-pass; a
# FAILED package prints "FAIL\t<pkg>" (caught by _FAIL_TOKENS `--- fail:` / the
# non-zero exit) and never an "ok<ws><pkg>" summary, so fail wins correctly.
_GO_PASS_RE = re.compile(r"(?m)^ok\s+\S+\s+(?:[\d.]+s|\(cached\))")

# Mocha / Hardhat (`npx hardhat test` / `mocha`) is a FIRST-CLASS Solidity harness
# runner for Hardhat repos (axelar-sc ships 3 Hardhat projects and NO foundry.toml,
# so its ITS invariant harnesses can ONLY be re-run under Hardhat/Mocha). Mocha does
# NOT emit any forge/medusa/echidna/go token: it prints a plain summary block
#   "  4 passing (1s)"                (all green; NO "failing" line at all)
#   "  3 passing (1s)\n  1 failing"   (>=1 red; a separate "M failing" line follows)
# Without a native recognizer a passing Hardhat harness classifies `no-execution`
# (silent skip) and a genuine mutant-kill (Mocha "1 failing") is misread as a
# vacuous pass - so a Hardhat-only SC lane (2026-07-12 axelar-sc) had to hand-write
# a run-invariant.sh shim to re-emit forge tokens. Match Mocha's summary directly,
# mirroring the medusa/echidna verdict-is-authoritative pattern. FAIL wins over PASS
# (a mixed run prints both a "passing" and a "failing" line). A compile-broken mutant
# prints NEITHER line (Hardhat aborts at "Compilation failed" -> _COMPILE_ERROR_TOKENS
# -> `error`), so a build break can never be a false kill.
_MOCHA_PASS_RE = re.compile(r"(?m)^\s*(\d+)\s+passing\b")
_MOCHA_FAIL_RE = re.compile(r"(?m)^\s*([1-9]\d*)\s+failing\b")

SCHEMA = "auditooor.mutation_verify_coverage.v1"

_HERE = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Import the generator half (tools/mutation-engine.py) by file path. The file
# name contains a hyphen, so a plain `import` is impossible; load by spec.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Fail-closed VACUITY pre-filter: a harness whose ONLY assertion is a sentinel
# tautology (assert(true)/assert!(true)/assert True/...) can NEVER be a coverage
# oracle. We short-circuit BEFORE the (expensive) mutation loop and return a
# typed `no-property-discovered` verdict so a sentinel scaffold can never reach
# `non-vacuous`/`genuine_coverage`. Shared predicate with the generator
# (tools/lib/harness_vacuity.py) so emit-time and credit-time agree.
# ---------------------------------------------------------------------------
def _load_sentinel_predicate():
    import importlib.util as _ilu

    tool = _HERE / "lib" / "harness_vacuity.py"
    if not tool.is_file():
        return None
    try:
        spec = _ilu.spec_from_file_location("harness_vacuity", str(tool))
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:  # noqa: BLE001
        return None


_SENTINEL_MOD = _load_sentinel_predicate()


# ---------------------------------------------------------------------------
# P0-d / P1-a: the shared kill-genuineness + kill-kind predicates live in
# tools/lib/mutation_kill.py (single source of truth). The PRODUCER applies them
# so a setUp()-crash false-kill (mode 12) is reclassified harness-broken-by-mutant
# and a panic-only equivalent-mutant (mode 9) is not credited as behaviour-changing.
# ---------------------------------------------------------------------------
def _load_mutation_kill():
    import importlib.util as _ilu

    tool = _HERE / "lib" / "mutation_kill.py"
    if not tool.is_file():
        return None
    try:
        spec = _ilu.spec_from_file_location("mutation_kill", str(tool))
        mod = _ilu.module_from_spec(spec)
        sys.modules["mutation_kill"] = mod  # py3.14: register BEFORE exec_module
        spec.loader.exec_module(mod)
        return mod
    except Exception:  # noqa: BLE001
        return None


_MUTATION_KILL_MOD = _load_mutation_kill()


def _classify_kill_kind(tail: str) -> str:
    """kill_kind for a mutant's output_tail (delegates to the shared lib).

    Returns: harness-broken-by-mutant | equivalent-mutant | behavior-changing |
    not-a-kill. Fail-open fallback (lib unavailable) does a coarse classification
    so the producer never crashes."""
    if _MUTATION_KILL_MOD is not None:
        try:
            return str(_MUTATION_KILL_MOD.classify_kill_kind(tail))
        except Exception:  # noqa: BLE001
            pass
    t = tail or ""
    low = t.lower()
    # Mirror the shared lib: a real Halmos counterexample / echidna `: falsified`
    # is a FAIL in _classify but carries no "fail"/"panic" substring, so the old
    # narrow guard returned not-a-kill for a genuine silent-baseline kill. Use the
    # producer's fail set. Fail-closed: no failure signal at all -> not-a-kill.
    #
    # PASS-OVERRIDE (mirrors lib._is_pass_override + _classify's pass-first order):
    # a co-occurring fail substring inside a NEGATED/PASSING tail ("no
    # counterexample", "no failing sequence", "0 failing", "5 passed; 0 failed",
    # "test result: ok", ": passing") must NOT be read as a kill - UNLESS a genuine
    # engine FAIL summary is present (medusa "M>0 failed", forge "N failed" N>=1,
    # echidna ": failed!/: falsified", explicit counterexample frame).
    _has_fail_summary = re.search(
        r"[1-9]\d*\s+test\(s\)\s+failed|[1-9]\d*\s+failed\b|"
        r":\s*failed!|:\s*falsified|(?:^|\n)\s*counterexample:",
        t, re.I | re.M)
    _is_pass = re.search(
        r"\d+\s+test\(s\)\s+passed,\s*0\s+test\(s\)\s+failed|test\s+result:\s*ok\b|"
        r"\b\d+\s+passed;\s*0\s+failed\b|\b\d+\s+passed,\s*0\s+failed\b|:\s*passing\b|"
        r"no\s+counterexample|counterexample\s+search\s+exhausted|property\s+holds|"
        r"no\s+failing\s+sequence|\b0\s+failing\b|\bno\s+failing\s+tests?\b",
        t, re.I)
    if _is_pass and not _has_fail_summary:
        return "not-a-kill"
    if not re.search(
            r"\bfail\b|\bfailed\b|\bfailing\b|\bpanic\b|counterexample|falsified|"
            r"assertion\s+(?:failed|violated)|failing\s+assertion|\[fail\]|"
            r":\s*failed!|--- fail:|test\s+result:\s+failed|test\(s\)\s+failed",
            t, re.I):
        return "not-a-kill"
    if "setup()" in low and not any(
            tok in t for tok in ("invariant_", "property_", "echidna_", "check_")):
        return "harness-broken-by-mutant"
    if re.search(r"panic\(uint256\)|\b0x11\b|\b0x01\b", t, re.I) and not any(
            tok in t for tok in ("invariant_", "property_", "echidna_", "check_")):
        return "equivalent-mutant"
    return "behavior-changing"


def _harness_is_sentinel_only(harness_path: Path | None) -> bool:
    """True iff the harness FILE is a sentinel-only scaffold (no real property).

    Only fires for an on-disk harness file we can read; a literal shell command
    or unreadable harness returns False (the mutation loop then decides). Never
    raises - a missing predicate or read error is fail-open here because the
    mutation loop remains a stronger downstream oracle.
    """
    if harness_path is None or _SENTINEL_MOD is None:
        return False
    try:
        if not harness_path.is_file():
            return False
        text = harness_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    try:
        return bool(_SENTINEL_MOD.is_sentinel_only_harness(text))
    except Exception:  # noqa: BLE001
        return False


def _load_generator():
    import importlib.util

    tool = _HERE / "mutation-engine.py"
    if not tool.is_file():
        raise FileNotFoundError(f"mutation-engine.py not found at {tool}")
    spec = importlib.util.spec_from_file_location("mutation_engine", str(tool))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Language detection for harness/source (mirrors the generator's table).
# ---------------------------------------------------------------------------
_EXT_LANG = {
    ".sol": "solidity",
    ".rs": "rust",
    ".go": "go",
    ".move": "move",
    ".cairo": "cairo",
}


def _lang_of(path: Path, override: str = "auto") -> str:
    if override and override != "auto":
        return override
    return _EXT_LANG.get(path.suffix.lower(), "solidity")


# ---------------------------------------------------------------------------
# Rust delegation loader: import tools/rust-mutation-verify.py by file path.
# Returns the module when available, or None when the file is absent (the
# caller falls through to the coarse generic cargo runner).
# ---------------------------------------------------------------------------
def _load_rust_mutation_verify():
    import importlib.util as _ilu
    tool = _HERE / "rust-mutation-verify.py"
    if not tool.is_file():
        return None
    try:
        spec = _ilu.spec_from_file_location("rust_mutation_verify", str(tool))
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# Harness runner resolution. A runner takes (workspace, harness_path|None) and
# returns a shell command (list[str]) plus a cwd. Returns None when the language
# has no built-in runner and no explicit --harness command was given.
# ---------------------------------------------------------------------------
def _forge_bin() -> str:
    """Resolve forge via tools/lib/forge-resolve.sh if present, else PATH."""
    resolver = _HERE / "lib" / "forge-resolve.sh"
    if resolver.is_file():
        try:
            out = subprocess.run(
                ["bash", str(resolver)], capture_output=True, text=True, timeout=30
            )
            cand = (out.stdout or "").strip().splitlines()
            for line in cand:
                line = line.strip()
                if line and Path(line).name == "forge" and Path(line).exists():
                    return line
        except Exception:  # noqa: BLE001
            pass
    return "forge"


def _harness_contract_name(harness_path: Path) -> str | None:
    """Best-effort: first `contract X` declared in a Solidity harness file."""
    try:
        for line in harness_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = line.strip()
            if s.startswith("contract ") or s.startswith("abstract contract "):
                tok = s.split()
                # contract NAME ... -> NAME (strip 'is', '{')
                idx = tok.index("contract")
                if idx + 1 < len(tok):
                    return tok[idx + 1].rstrip("{").split("(")[0]
    except Exception:  # noqa: BLE001
        return None
    return None


def _harness_real_output_bound(harness_path: Path | None) -> bool | None:
    """Look up the `real_output_bound` honesty flag for a harness file from its
    sibling authored-harness manifest (wave-4 engine-real-output-property-class).

    Walks up from the harness file looking for a `harness_manifest.json` (rust,
    authored[] keyed by harness_file) or an `attempt_manifest.json` (evm,
    top-level flag). Returns:
      True  -> the harness asserts a RELATION over the REAL fn output (genuine).
      False -> the harness asserts over a hand-authored MODEL (needs-binding).
      None  -> no authored manifest found (unknown; do not downgrade).
    Generic stdlib, no workspace literals.
    """
    if harness_path is None:
        return None
    here = harness_path.resolve()
    name = here.name
    for parent in [here.parent, *here.parents][:6]:
        # Rust: authored[] entries each carry harness_file + real_output_bound.
        rm = parent / "auditooor_harnesses" / "harness_manifest.json"
        for cand in (parent / "harness_manifest.json", rm):
            if cand.is_file():
                try:
                    d = json.loads(cand.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                for entry in (d.get("authored") or []):
                    if not isinstance(entry, dict):
                        continue
                    hf = str(entry.get("harness_file") or "")
                    if hf and Path(hf).name == name:
                        return bool(entry.get("real_output_bound"))
        # EVM: a single attempt_manifest.json with a top-level flag.
        am = parent / "attempt_manifest.json"
        if am.is_file():
            try:
                d = json.loads(am.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                d = None
            if isinstance(d, dict) and "real_output_bound" in d:
                return bool(d.get("real_output_bound"))
    return None


def _project_root(start: Path | None, ws: Path, marker: str) -> Path:
    """Nearest ancestor of ``start`` (bounded by ``ws``) that contains ``marker``
    (foundry.toml / Cargo.toml / go.mod). Returns the project dir, or ``ws`` if none.

    WHY: multi-project audit workspaces nest the real build project in a SUBDIR
    (e.g. src/pol-token/foundry.toml, src/bor/go.mod) with its OWN remappings/deps.
    Running the engine from the audit-tree ROOT makes every import unresolvable
    ("Source 'forge-std/Test.sol' not found") - which surfaced as the auto-harness
    'no-execution' / engine-error that blocked function/core/engine coverage on
    polygon. Resolving to the nested project dir (cwd + --root) fixes it. Generic
    across Solidity/Rust/Go nested projects."""
    try:
        ws_res = ws.resolve()
    except OSError:
        ws_res = ws
    cur = start or ws
    try:
        cur = cur.resolve()
    except OSError:
        pass
    if cur.is_file():
        cur = cur.parent
    chain: list[Path] = []
    c = cur
    for _ in range(40):
        chain.append(c)
        if c == ws_res or c.parent == c:
            break
        c = c.parent
        try:
            c.relative_to(ws_res)  # stay within (or at) the workspace subtree
        except ValueError:
            break
    for cand in chain:            # deepest-first => nearest enclosing project
        if (cand / marker).is_file():
            return cand
    return ws


def _is_mixed_compiler_ws(ws: Path) -> bool:
    """True when ``ws`` is a Hardhat / mixed-solc monorepo with NO single foundry
    project at its root - the shape where ``halmos --root <ws>`` build-fails.

    WHY: axelar-sc bundles 3 Hardhat repos on different solc versions with no
    root foundry.toml. ``halmos --root <ws>`` then hands the WHOLE monorepo to
    crytic-compile, which cannot pick one compiler and build-fails -> the auto
    coverage lane fell back to --register-manual-mvc twice on 2026-07-12. When
    this shape is detected the runner scopes the build+run to the single harness
    /contract dir instead of the monorepo root.

    Detected by: no foundry.toml at the audit-tree root AND a hardhat.config.*
    present within a bounded top-of-tree scan (root + immediate/2nd-level subdirs).
    A normal single-foundry workspace (root foundry.toml) is never mixed, so the
    existing invocation stays byte-identical for it."""
    try:
        if (ws / "foundry.toml").is_file():
            return False
    except OSError:
        return False
    names = ("hardhat.config.js", "hardhat.config.ts", "hardhat.config.cjs", "hardhat.config.mjs")
    # Bounded scan: ws root, then up to two directory levels deep. Avoids an
    # unbounded rglob over a large monorepo while still catching packages/*/ and
    # <repo>/ layouts where each Hardhat project sits one or two dirs down.
    for name in names:
        if (ws / name).is_file():
            return True
    try:
        lvl1 = [d for d in ws.iterdir() if d.is_dir()]
    except OSError:
        return False
    for d1 in lvl1:
        for name in names:
            if (d1 / name).is_file():
                return True
        try:
            lvl2 = [d for d in d1.iterdir() if d.is_dir()]
        except OSError:
            continue
        for d2 in lvl2:
            for name in names:
                if (d2 / name).is_file():
                    return True
    return False


def _default_runner(language: str, ws: Path, harness_path: Path | None) -> tuple[list[str], Path] | None:
    """Built-in per-language runner. Extensible via AUDITOOOR_MVC_RUNNER_<LANG>.

    The env hook is a shell-command template; tokens {workspace}, {harness},
    {contract} are substituted when present. For built-in runners the cwd (+ the
    Solidity halmos --root) is the NESTED project dir, not the audit-tree root, so
    a subdirectory foundry.toml/Cargo.toml/go.mod resolves its own deps.
    """
    env_key = f"AUDITOOOR_MVC_RUNNER_{language.upper()}"
    tmpl = os.environ.get(env_key)
    if tmpl:
        contract = _harness_contract_name(harness_path) if (harness_path and language == "solidity") else ""
        cmd = tmpl.format(
            workspace=str(ws),
            harness=str(harness_path) if harness_path else "",
            contract=contract or "",
        )
        return shlex.split(cmd), ws

    if language == "solidity":
        # Hardhat / Mocha native dispatch (mirrors the forge/halmos + medusa engine
        # dispatch): a Hardhat repo has NO foundry.toml, so halmos --root would
        # crytic-compile a non-foundry tree and build-fail. When the harness is a
        # JS/TS Mocha test (or its project root is a Hardhat project with no nested
        # foundry.toml), re-run it under `npx hardhat test <harness>` so its Mocha
        # summary (_MOCHA_*_RE) classifies natively - no hand-written shim needed.
        # forge/halmos/medusa/go dispatch below is byte-identical (this branch only
        # fires for a .js/.ts harness or a hardhat.config-rooted project).
        hh_harness = bool(harness_path and Path(harness_path).suffix.lower() in (".js", ".ts", ".cjs", ".mjs"))
        # A .sol harness that lives inside its OWN nested foundry project is a
        # foundry/halmos harness - NEVER hijack it to Hardhat (the mixed-compiler
        # monorepo can carry BOTH a root hardhat.config AND nested foundry projects).
        _foundry_root = _project_root(harness_path, ws, "foundry.toml")
        _has_own_foundry = (_foundry_root / "foundry.toml").is_file()
        hh_root = _project_root(harness_path, ws, "hardhat.config.js")
        if not any((hh_root / c).is_file() for c in (
                "hardhat.config.js", "hardhat.config.ts", "hardhat.config.cjs")):
            hh_root = _project_root(harness_path, ws, "hardhat.config.ts")
        has_hh_cfg = any((hh_root / c).is_file() for c in (
            "hardhat.config.js", "hardhat.config.ts", "hardhat.config.cjs"))
        # Dispatch Hardhat only for a JS/TS Mocha harness, or a Hardhat-rooted
        # harness with NO owning foundry project (the pure-Hardhat-repo case).
        if hh_harness or (has_hh_cfg and not _has_own_foundry):
            cmd = ["npx", "hardhat", "test"]
            if harness_path and Path(harness_path).is_file():
                cmd.append(str(harness_path))
            return cmd, hh_root
        # Prefer halmos for symbolic property harnesses (the morpho case),
        # fall back to forge test. We match by the harness contract when known.
        contract = _harness_contract_name(harness_path) if harness_path else None
        halmos = os.environ.get("AUDITOOOR_MVC_HALMOS_BIN", "halmos")
        root = _project_root(harness_path, ws, "foundry.toml")
        # Mixed-compiler / Hardhat monorepo with NO nested foundry project for the
        # harness (root fell back to ws, which has no foundry.toml): halmos --root
        # <ws> would crytic-compile the whole monorepo across incompatible solc
        # versions and build-fail. Scope the build+run to the harness's own dir
        # (e.g. its poc-tests/<cluster> project) so only that contract/test builds.
        # A nested foundry project is already resolved above, so THAT path (and the
        # normal single-foundry-root ws) is untouched - byte-identical.
        if harness_path and not (root / "foundry.toml").is_file() and _is_mixed_compiler_ws(ws):
            scoped = Path(harness_path).resolve().parent
            root = scoped
        if contract:
            return [halmos, "--root", str(root), "--contract", contract], root
        return [halmos, "--root", str(root)], root

    if language == "rust":
        root = _project_root(harness_path, ws, "Cargo.toml")
        return ["cargo", "test", "--quiet"], root

    if language == "go":
        root = _project_root(harness_path, ws, "go.mod")
        return ["go", "test", "./..."], root

    # Move / Cairo / unknown: no safe built-in default; require --harness.
    return None


# ---------------------------------------------------------------------------
# Run a harness command; classify PASS/FAIL. PASS == exit 0 AND no failure
# markers in output. Symbolic/forge tools sometimes exit 0 while reporting a
# counterexample, so we also scan stdout/stderr for failure tokens.
# ---------------------------------------------------------------------------
_FAIL_TOKENS = (
    "[fail]",         # "[FAIL]" / "[fail]" / "[FAILED]" (substring match)
    ": failed",       # "test_foo: failed", "result: failed"
    "failed ",        # "FAILED tests/..." (pytest), "failed to ..."
    "test failed",
    "counterexample",
    "failing assertion",
    "assertion failed",
    "panicked",
    "test result: failed",
    "symbolic test result: 0 passed",
    " 1 failed",
    " 2 failed",
    " 3 failed",
    " 4 failed",
    " 5 failed",
    "--- fail:",      # Go "--- FAIL: TestFoo" style
)
# Tokens that, when present in output, indicate a genuine pass.  Checked AFTER
# fail tokens so a counterexample-with-[pass]-prefix is still caught as fail.
_PASS_TOKENS = (
    "[pass]",
    "symbolic test result:",
    "test result: ok",
    "passed;",
    "suite result: ok",
)
# Tokens that indicate a genuine COMPILE / BUILD failure - the harness never
# built, so it can NEVER be credited as coverage even if the engine exited 0.
# A build failure is a hard `error`, NOT a silent skip: we must not enter the
# mutation loop for code that did not compile (the prompt's explicit guard).
_COMPILE_ERROR_TOKENS = (
    "compilation failed",
    "compiler error",
    "compile error",
    "error: cannot find",      # solc / cargo "cannot find symbol/type"
    "crytic-compile",          # crytic-compile failure surfaced by halmos
    "build-info",              # missing out/build-info (foundry not built)
    "could not compile",       # cargo "could not compile <crate>"
    "errors found",            # solc summary line on a failed compile
    "error[",                  # rustc "error[E0277]" style
    "parsererror",             # solc ParserError
    "declarationerror",        # solc DeclarationError
    "typeerror:",              # solc TypeError
    "no such file or directory",
    "thread 'main' panicked",  # harness driver itself crashed before tests
)


def _compile_error_culprits(out: str) -> list[str]:
    """Source files named in a compile/parser error in the engine output.
    forge/solc cite the offending file as `path/File.sol:line[:col]` (often under
    a `--> ` arrow or right after `Error (NNNN):`). Returns the cited .sol paths."""
    culprits: list[str] = []
    for m in re.finditer(r"([A-Za-z0-9_./\\-]+\.sol):\d+", out or ""):
        f = m.group(1).strip()
        if f and f not in culprits:
            culprits.append(f)
    return culprits


def _baseline_blocked_by_sibling(out: str, *, harness: str | None,
                                 harness_path, source_file) -> str | None:
    """When the baseline fails with a COMPILE error, decide if the break is in a
    file OTHER than the harness-under-test or its CUT (a sibling poisoning the
    SHARED forge build - the classic parallel-authoring collision). Returns the
    culprit file if so, else None.

    GENERIC + load-bearing: forge/solc compile the WHOLE project, so one broken
    sibling test file fails EVERY harness's baseline -> they all falsely record
    no-baseline and agents chase phantom failures. Distinguishing 'a sibling broke
    the tree' from 'MY harness is broken' lets the gate/orchestrator fix the real
    culprit instead of penalizing good harnesses. Conservative: only fires when a
    compile-error token is present AND none of the cited error files belong to the
    harness-under-test / its CUT."""
    low = (out or "").lower()
    if not any(t in low for t in _COMPILE_ERROR_TOKENS):
        return None
    culprits = _compile_error_culprits(out)
    if not culprits:
        return None
    own_tokens: set[str] = set()
    # the CUT source basename
    try:
        own_tokens.add(Path(source_file).name.lower())
    except Exception:  # noqa: BLE001
        pass
    # the harness file (explicit path, or derived from --match-contract Halmos_<C>_<fn>)
    if harness_path is not None:
        try:
            own_tokens.add(Path(harness_path).name.lower())
        except Exception:  # noqa: BLE001
            pass
    mc = re.search(r"--match-(?:contract|path)\s+(\S+)", harness or "")
    if mc:
        own_tokens.add(mc.group(1).strip().strip("'\"").lower())
    def _is_own(c: str) -> bool:
        cl = c.lower()
        base = Path(c).name.lower()
        return any(tok and (tok in cl or tok in base or base.rstrip(".tsol") in tok)
                   for tok in own_tokens)
    sibling = [c for c in culprits if not _is_own(c)]
    # blocked-by-sibling only if EVERY culprit is a sibling (none is our own file)
    if sibling and not any(_is_own(c) for c in culprits):
        return sibling[0]
    return None


def _classify(rc: int, out: str) -> tuple[str, bool]:
    """Return (status, passed). status in {pass, fail, no-execution, error}.

    no-execution: rc==0, NO compile-error token, and the output contains
    neither a recognised pass token nor a recognised fail token.  This is the
    "silent skip" shape - and CRUCIALLY it is NOT automatically an error: a
    real Halmos / property harness that found no counterexample exits 0 and
    prints no per-test summary, which is exactly this shape.  The caller
    (verify) disambiguates a silent skip from a genuine error by running the
    mutation loop: if a mutant flips the harness to a failure the clean
    silent-exit-0 was a real PASS (non-vacuous coverage); if nothing flips it
    the harness discovered no property (typed skip), not an oracle.

    error: a genuine ENGINE / BUILD failure - either a non-zero exit, OR a
    compile-error token in the output even on exit 0 (crytic-compile /
    build-info missing / solc/rustc error).  Code that never compiled can
    never be credited, so this stays a hard error / no-baseline regardless of
    exit code and the mutation loop is NOT entered.
    """
    # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
    low = out.lower()
    # MEDUSA SUMMARY IS AUTHORITATIVE - checked FIRST, before the generic token
    # scan and the compile-error scan. A medusa run prints a definitive summary
    # ("N test(s) passed, M test(s) failed"); that verdict must win over (a) stray
    # benign "failed " substrings in verbose worker/RPC logs (which would otherwise
    # false-FAIL a 10/10-pass run via _FAIL_TOKENS) and (b) the "crytic-compile"
    # token medusa emits on EVERY successful build (which would false-ERROR it). A
    # run that printed a summary definitionally compiled AND executed.
    if _MEDUSA_FAIL_RE.search(low):          # M>0 test(s) failed -> real medusa failure
        return "fail", False
    if _MEDUSA_PASS_RE.search(low):          # N passed, 0 failed -> genuine pass
        return "pass", True
    # ECHIDNA per-property verdicts (see note above _ECHIDNA_*_RE). Fail wins over
    # pass when both appear (a mixed run with >=1 failing property is a fail).
    if _ECHIDNA_FAIL_RE.search(low):
        return "fail", False
    if _ECHIDNA_PASS_RE.search(low):
        return "pass", True
    # MOCHA / HARDHAT summary is authoritative (see note above _MOCHA_*_RE), checked
    # BEFORE the generic token scan and the compile-error scan so Mocha's own idiom
    # wins over stray "failed "/"error" substrings in verbose Hardhat/plugin logs. A
    # "M failing" (M>=1) line is a genuine kill; a "N passing" line with NO "failing"
    # line is a genuine pass. Fail wins when both are present (mixed run).
    if _MOCHA_FAIL_RE.search(low):
        return "fail", False
    if _MOCHA_PASS_RE.search(low):
        return "pass", True
    failed = any(t in low for t in _FAIL_TOKENS)
    if failed:
        # A failure token wins even on rc==0 (counterexample-with-exit-0 case).
        return "fail", False
    # A compile/build-failure token is a hard error even on exit 0: the harness
    # never built, so it can never be a coverage oracle. This must be checked
    # BEFORE the silent-exit-0 path so a build failure is never mistaken for a
    # "real engine ran but found no counterexample" silent skip.
    if any(t in low for t in _COMPILE_ERROR_TOKENS):
        return "error", False
    if rc == 0:
        # rc==0 with a recognised pass token is a genuine pass. medusa's
        # "N test(s) passed, 0 test(s) failed" is a genuine pass too.
        passed_token = (any(t in low for t in _PASS_TOKENS)
                        or bool(_MEDUSA_PASS_RE.search(low))
                        or bool(_GO_PASS_RE.search(low)))
        if passed_token:
            return "pass", True
        # rc==0, no compile error, no pass/fail token: a SILENT SKIP. Do NOT
        # collapse this to "error" here - it is ambiguous between a real
        # no-counterexample halmos run and a stub. verify() resolves it via
        # the mutation loop (kill => real PASS; no kill => no-property-discovered).
        return "no-execution", False
    # Non-zero exit with no recognizable failure token: treat as error (could be
    # a build error, tool-missing, etc.). Distinguish "no test ran" from "fail".
    return "error", False


# ---------------------------------------------------------------------------
# P0-b6 (dynamic half / mode 6): reachability-witness execution check. Before
# crediting any kill for a VALUE-MOVING function, the function's reachability
# witness counter must have reached >0 in the baseline run (the value-moving fn
# actually executed). A kill with witness==0 is reclassified
# value-path-never-executed (a mock-callpath-vacuity: the mock delivered value
# differently than prod so the value-moving handler never landed) and NOT credited.
# ---------------------------------------------------------------------------
# A witness is an `assertGt(wX + ..., 0)` / `witness_*`/`w<Name>` ghost counter
# the harness asserts >0. We look for a satisfied witness assertion in the
# baseline output, OR (when the engine does not echo it) for a witness assertion
# in the harness file paired with a non-zero counter in the baseline tail.
_WITNESS_ASSERT_RE = re.compile(
    r"(?:assertGt|assert)\s*\(\s*(?:w[A-Z]\w*|witness_\w*)[^,]*,\s*0\s*\)", re.I)
_WITNESS_NAME_RE = re.compile(r"\b(w[A-Z]\w*|witness_\w+)\b")
# A value-moving function signature hint: the function name or its known
# value-moving verbs. The caller passes the function name; we treat deposit/
# borrow/repay/withdraw/mint/burn/transfer/redeem/claim/release/send as value-moving.
_VALUE_MOVING_VERBS = (
    "deposit", "borrow", "repay", "withdraw", "mint", "burn", "transfer",
    "redeem", "claim", "release", "send", "payout", "wrap", "unwrap",
    "allocate", "deallocate", "stake", "unstake",
)


def _is_value_moving_fn(fn_name: str) -> bool:
    low = (fn_name or "").lower()
    return any(v in low for v in _VALUE_MOVING_VERBS)


def _witness_reached(harness_path: Path | None, baseline_tail: str) -> bool | None:
    """Did the value-moving fn's reachability witness reach >0 in the baseline?

    Returns:
      True  - a witness assertion is present AND the baseline shows it satisfied
              (the witness-assert line did not fail / the run passed with it).
      False - the harness declares a witness assertion but the baseline shows it
              UNSATISFIED (the value-moving handler never landed, mode 6).
      None  - no witness assertion found in the harness (cannot judge; do NOT
              downgrade - hand-written PoCs without witnesses are not penalised).
    """
    if harness_path is None:
        return None
    try:
        if not harness_path.is_file():
            return None
        htext = harness_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if not _WITNESS_ASSERT_RE.search(htext):
        return None  # no reachability witness declared -> cannot judge
    tail = baseline_tail or ""
    low = tail.lower()
    # A failed witness assertion in the baseline = the value-moving fn never landed.
    if re.search(r"(?:reachability|witness)[^\n]*(?:fail|FAIL|0\s*>\s*0|assertion)",
                 tail, re.I):
        return False
    # If the baseline names a witness with a value > 0, it landed.
    for m in re.finditer(r"\b(?:w[A-Z]\w*|witness_\w+)\s*[:=]\s*(\d+)", tail):
        if int(m.group(1)) > 0:
            return True
    # The witness is declared and the baseline passed with no failed-witness frame:
    # the assertGt(..,0) held -> the value-moving fn executed. Treat as reached.
    if "fail" not in low:
        return True
    return None


def _run(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
    try:
        p = subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout
        )
        return p.returncode, (p.stdout or "") + "\n" + (p.stderr or "")
    except subprocess.TimeoutExpired as e:
        return 124, f"TIMEOUT after {timeout}s\n{(e.stdout or '')}\n{(e.stderr or '')}"
    except FileNotFoundError as e:
        return 127, f"runner-not-found: {e}"
    except Exception as e:  # noqa: BLE001
        return 1, f"runner-error: {e}"


# ---------------------------------------------------------------------------
# Core verify routine.
# ---------------------------------------------------------------------------
def verify(
    *,
    workspace: Path,
    source_file: Path,
    function: str,
    harness: str | None,
    language: str = "auto",
    classes: list[str] | None = None,
    max_mutants: int | None = None,
    timeout: int = 600,
    runner_cmd: list[str] | None = None,
    runner_cwd: Path | None = None,
) -> dict:
    """Run the mutate -> re-run -> restore loop and decide vacuity.

    Exactly one of (harness path, runner_cmd literal) drives the re-run. The
    source file is restored from an in-memory copy in a finally block.
    """
    gen = _load_generator()

    lang = _lang_of(source_file, language)

    # ---------------------------------------------------------------------------
    # Rust delegation: for language=rust, delegate to rust-mutation-verify.py's
    # run_for_mvc() when no explicit runner_cmd is given and no AUDITOOOR_MVC_RUNNER_RUST
    # env hook overrides it. This provides per-function targeted cargo test rather
    # than the coarse whole-workspace "cargo test --quiet" default, which cannot
    # attribute a kill to a specific function's harness and leaves per_function_verified
    # at 0 for Rust workspaces (the monero-oxide diagnosis).
    #
    # The harness argument is used as the cargo test filter:
    #   - If it is a path to a .rs file, extract #[test] function names as filters.
    #   - If it is a bare string (test name / substring), pass directly to cargo test.
    #   - If it is None, run all tests (coarser, but still more honest than silence).
    #
    # An explicit runner_cmd or AUDITOOOR_MVC_RUNNER_RUST always takes precedence
    # (the env hook is checked inside _default_runner before this block fires).
    # ---------------------------------------------------------------------------
    if lang == "rust" and runner_cmd is None and not os.environ.get("AUDITOOOR_MVC_RUNNER_RUST"):
        _rmu = _load_rust_mutation_verify()
        if _rmu is not None:
            return _rmu.run_for_mvc(
                workspace=workspace,
                source_file=source_file,
                function=function,
                test_filter=harness,
                classes=classes,
                max_mutants=max_mutants,
                timeout=timeout,
            )
        # If rust-mutation-verify.py is not available, fall through to the generic
        # coarse runner so the caller is not silently blocked.

    # Resolve the runner.
    harness_path: Path | None = None
    if runner_cmd is None:
        if harness:
            hp = Path(harness)
            if hp.exists() and hp.is_file() and hp.suffix.lower() in _EXT_LANG:
                harness_path = hp
                resolved = _default_runner(lang, workspace, harness_path)
            else:
                # Treat `harness` as a literal command. If it contains SHELL
                # OPERATORS (cd .. && .., ;, |, redirects, subshells) it MUST run
                # through a shell - shlex.split would tokenize "cd X && forge .."
                # into ["cd","X","&&","forge",..] and subprocess (no shell) execs
                # only "cd" (exit 0, empty output) so forge NEVER runs -> every
                # harness records no-execution -> 0/N genuine on every workspace
                # whose orchestrator passes a "cd <root> && forge test .." command
                # (the canonical genuine-coverage form, Makefile
                # _audit-deep-solidity-genuine-coverage). Run via bash -c so the
                # exact command executes as a manual shell would. Simple commands
                # (no operators) keep the arg-list path.
                if re.search(r"(\s&&\s|\s\|\s|;|\$\(|`|>\s|<\s|\bcd\s)", harness):
                    resolved = (["bash", "-c", harness], workspace)
                else:
                    resolved = (shlex.split(harness), workspace)
        else:
            resolved = _default_runner(lang, workspace, None)
        if resolved is None:
            return {
                "schema": SCHEMA,
                "verdict": "error",
                "reason": (
                    f"no built-in harness runner for language '{lang}' and no "
                    f"explicit --harness command/file given. Pass --harness "
                    f"'<shell command>' or set AUDITOOOR_MVC_RUNNER_{lang.upper()}."
                ),
            }
        runner_cmd, runner_cwd = resolved
    else:
        runner_cwd = runner_cwd or workspace

    # Resolve a forge token if the runner uses bare 'forge'.
    if runner_cmd and runner_cmd[0] == "forge":
        runner_cmd = [_forge_bin(), *runner_cmd[1:]]

    if not source_file.is_file():
        return {"schema": SCHEMA, "verdict": "error",
                "reason": f"source not found: {source_file}"}

    # Fail-closed VACUITY GATE: reject a sentinel-only harness BEFORE the
    # mutation loop. A scaffold whose only assertion is assert(true) /
    # assert!(true) / assert True can never kill a mutant, so running the loop is
    # wasted work AND - critically - it must never be allowed to reach
    # `non-vacuous`. We return a typed `no-property-discovered` verdict (the same
    # not-credited, not-an-error class the mutation loop assigns to a silent
    # stub), with genuine_coverage explicitly False.
    if _harness_is_sentinel_only(harness_path):
        try:
            reason = _SENTINEL_MOD.sentinel_reason(
                harness_path.read_text(encoding="utf-8", errors="replace")
            )
        except Exception:  # noqa: BLE001
            reason = "sentinel-only harness body"
        fn_name, _ = _parse_fn_arg(function)
        return {
            "schema": SCHEMA,
            "workspace": str(workspace),
            "source_file": str(source_file),
            "function": fn_name,
            "language": lang,
            "harness": harness,
            "harness_path": str(harness_path),
            "verdict": "no-property-discovered",
            "vacuity_gate": "sentinel-only-harness",
            "genuine_coverage": False,
            "mutation_verified": False,
            "reason": (
                "harness is a SENTINEL-ONLY scaffold and cannot be credited as "
                f"coverage: {reason}. Replace the sentinel with a real "
                "source-grounded property over the function before this harness "
                "can be mutation-verified (vacuity gate, fail-closed)."
            ),
        }

    # Acquire the per-file source-mutation lock BEFORE capturing `original`, so a
    # concurrent run cannot have a mutant on disk when we read it (the SSV poison).
    _src_lock = _acquire_source_mutation_lock(source_file)
    original = source_file.read_text(encoding="utf-8")
    # HEAD-anchor: if the working file is byte-identical to its committed pin, keep
    # `original` (same bytes); the lock already guarantees we hold the pristine
    # text. (We do NOT force-restore to HEAD on a legitimately-dirty WIP file - the
    # cut-pristine guard fails the baseline closed in that case instead.)

    # Generate mutants up front (before touching disk).
    name, line_hint = _parse_fn_arg(function)
    try:
        mutants, fn_name, span = gen.generate_mutants(
            original, lang,
            name=name, line_hint=line_hint,
            classes=classes or gen.ALL_CLASSES,
            max_mutants=max_mutants,
        )
    except LookupError:
        return {"schema": SCHEMA, "verdict": "error",
                "reason": f"function not found: {function}"}

    result: dict = {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "source_file": str(source_file),
        "function": fn_name,
        "function_span": {"start_line": span[0], "end_line": span[1]},
        "language": lang,
        "harness": harness,
        "runner_command": " ".join(runner_cmd),
        "runner_cwd": str(runner_cwd),
        "timeout_s": timeout,
        "mutant_count": len(mutants),
        # wave-4 engine-real-output-property-class: does the cited harness assert
        # a relation over the REAL fn output (True) or over a hand-authored model
        # (False)? None when no authored manifest is found. Only real_output_bound
        # is True is counted toward GENUINE coverage; a model+seam harness that
        # kills is honest scaffolding (needs-binding), not genuine.
        "real_output_bound": _harness_real_output_bound(harness_path),
    }

    # Install restoration guards.
    _restored = {"done": False}

    def _restore():
        if not _restored["done"]:
            try:
                source_file.write_text(original, encoding="utf-8")
            finally:
                _restored["done"] = True

    def _sig(_signum, _frame):
        _restore()
        # Re-raise default behaviour.
        raise KeyboardInterrupt

    old_int = signal.getsignal(signal.SIGINT)
    old_term = signal.getsignal(signal.SIGTERM)
    try:
        signal.signal(signal.SIGINT, _sig)
        signal.signal(signal.SIGTERM, _sig)

        # ---- Step 1: baseline on CLEAN code ----
        rc0, out0 = _run(runner_cmd, runner_cwd, timeout)
        b_status, b_pass = _classify(rc0, out0)
        result["baseline"] = {
            "status": b_status,
            "exit_code": rc0,
            "output_tail": _tail(out0),
        }
        # A "silent" baseline (no-execution: exit 0, no compile error, no
        # pass/fail token) is AMBIGUOUS: it is the exact shape of a real Halmos
        # / property harness that found no counterexample, but ALSO of a stub
        # that never ran anything. We do NOT decide it here. Instead we carry
        # `silent_baseline=True` into the mutation loop: a kill proves the clean
        # exit-0 was a genuine no-counterexample PASS (non-vacuous); no kill ->
        # the harness discovered no property (typed skip), not an oracle.
        silent_baseline = (b_status == "no-execution")
        result["silent_baseline"] = silent_baseline
        if not b_pass and not silent_baseline:
            # SHARED-BUILD COLLISION RESILIENCE: if the baseline compile failed in
            # a file OTHER than this harness / its CUT, a SIBLING broke the shared
            # forge build (the parallel-authoring foot-gun). Do NOT penalize this
            # harness with no-baseline (which falsely reads as "harness broken");
            # emit a typed blocked-by-sibling-compile naming the real culprit so
            # the orchestrator fixes the sibling and re-verifies. Generic across
            # all forge/solc workspaces.
            culprit = _baseline_blocked_by_sibling(
                out0, harness=harness, harness_path=harness_path,
                source_file=source_file)
            if culprit is not None:
                result["verdict"] = "blocked-by-sibling-compile"
                result["blocking_file"] = culprit
                result["reason"] = (
                    f"baseline build failed in a SIBLING file ({culprit}), not this "
                    f"harness / its CUT - the shared forge build is poisoned. Fix "
                    f"{culprit} and re-verify; this harness is NOT credited NOR "
                    f"penalized (status={b_status})."
                )
                return result
            # A genuine ENGINE / BUILD failure (non-zero exit, compile-error
            # token, or a hard FAIL on clean code). This can never be a coverage
            # oracle and the mutation loop is NOT entered: we will not credit a
            # harness that did not build / did not pass on clean code.
            # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
            result["verdict"] = "no-baseline"
            result["reason"] = (
                "harness does not PASS on clean code; cannot be a coverage "
                f"oracle (baseline status={b_status}, exit={rc0})."
            )
            return result

        if not mutants:
            if silent_baseline:
                # Silent baseline with nothing to mutate: we cannot tell a real
                # no-counterexample run from a stub (no kill is observable).
                # Typed skip, NOT an error and NOT credited.
                result["verdict"] = "no-property-discovered"
                result["reason"] = (
                    "harness exited 0 with no recognizable pass/fail output "
                    "(silent skip) and the generator produced 0 mutants, so no "
                    "kill can be observed; cannot confirm a real property ran. "
                    "Typed skip, not credited as coverage (not an engine error)."
                )
                result["mutant_results"] = []
                return result
            result["verdict"] = "no-mutants"
            result["reason"] = (
                "generator produced 0 mutants for the function (no mutable "
                "operators in the body); vacuity is inconclusive."
            )
            result["mutant_results"] = []
            return result

        # ---- Step 2: per-mutant re-run ----
        # P0-b6 (mode 6): if this is a VALUE-MOVING fn and the harness declares a
        # reachability witness, the baseline must show the witness reached >0. A
        # witness==0 means the value-moving handler never executed (mock-callpath-
        # vacuity), so NO kill on it can be credited - reclassify
        # value-path-never-executed.
        baseline_tail = (result.get("baseline") or {}).get("output_tail", "")
        witness = _witness_reached(harness_path, baseline_tail)
        result["witness_reached"] = witness
        value_path_dead = bool(
            _is_value_moving_fn(fn_name) and witness is False)
        result["value_path_dead"] = value_path_dead

        mutant_results = []
        killed = 0                 # genuine behaviour-changing kills (credited)
        survived = 0
        behavior_changing_kills = 0
        panic_only_kills = 0       # equivalent-mutant (mode 9), NOT credited
        broken_by_mutant = 0       # setUp-crash false-kill (mode 12), NOT credited
        # per-invariant mutant attribution: invariant_frame -> [mutant_id, ...]
        invariant_attribution: dict[str, list[str]] = {}
        for mut in mutants:
            source_file.write_text(mut["_mutated_source"], encoding="utf-8")
            try:
                rc, out = _run(runner_cmd, runner_cwd, timeout)
            finally:
                source_file.write_text(original, encoding="utf-8")
            status, passed = _classify(rc, out)
            tail = _tail(out)
            # P0-d / P1-a: classify the kill. A kill is only CREDITED when it is
            # behaviour-changing (a real invariant/property assertion fired) AND
            # (P0-b6) the value-moving fn's witness actually executed.
            kill_kind = "not-a-kill"
            mutant_killed = False
            if status == "fail":
                kill_kind = _classify_kill_kind(tail)
                if kill_kind == "behavior-changing" and not value_path_dead:
                    mutant_killed = True
                    killed += 1
                    behavior_changing_kills += 1
                    # attribute the kill to the named invariant/property frame(s).
                    for fr in re.findall(
                            r"((?:invariant_|property_|echidna_|check_)\w+)", tail):
                        invariant_attribution.setdefault(fr, [])
                        if mut["mutant_id"] not in invariant_attribution[fr]:
                            invariant_attribution[fr].append(mut["mutant_id"])
                elif kill_kind == "equivalent-mutant":
                    panic_only_kills += 1
                elif kill_kind == "harness-broken-by-mutant":
                    broken_by_mutant += 1
                elif value_path_dead:
                    kill_kind = "value-path-never-executed"
            elif status == "pass":
                survived += 1
            mutant_results.append({
                "mutant_id": mut["mutant_id"],
                "operator": mut["operator"],
                "operator_class": mut["operator_class"],
                "line": mut["line"],
                "label": mut["label"],
                "original_line": mut["original_line"],
                "mutated_line": mut["mutated_line"],
                "harness_status": status,
                "killed": mutant_killed,
                "kill_kind": kill_kind,
                "exit_code": rc,
                "output_tail": tail,
            })

        result["mutant_results"] = mutant_results
        result["killed_count"] = killed
        result["survived_count"] = survived
        result["error_count"] = len(mutants) - killed - survived - panic_only_kills - broken_by_mutant
        result["behavior_changing_kill_count"] = behavior_changing_kills
        result["panic_only_kill_count"] = panic_only_kills
        result["harness_broken_kill_count"] = broken_by_mutant
        result["invariant_mutant_attribution"] = {
            k: sorted(v) for k, v in invariant_attribution.items()}

        # ---- Step 3: verdict ----
        # P1-a (modes 9, 16): require >=1 NON-PANIC behaviour-changing kill before
        # non-vacuous. A run whose only kills are panic-0x11/0x01 equivalent-mutants
        # is `equivalent-mutant-only` (NOT credited). A run whose only "kills" broke
        # the harness setUp (mode 12) was already excluded from `killed`. A
        # value-moving fn whose witness never executed (P0-b6/mode 6) is
        # value-path-never-executed (NOT credited).
        if value_path_dead and killed == 0:
            result["verdict"] = "value-path-never-executed"
            result["reason"] = (
                f"the value-moving fn {fn_name}'s reachability witness never "
                "reached >0 in the baseline run (mock-callpath-vacuity, mode 6): "
                "the value-moving handler never executed, so no kill on it can be "
                "credited. Add receive()/fallback() to the mock CUT subclass (or "
                "bind the real value path) so the fn actually executes."
            )
        elif killed == 0 and (panic_only_kills >= 1 or broken_by_mutant >= 1) and survived == 0:
            # All observed "kills" were panic-only equivalent-mutants and/or
            # setUp-crash false-kills, no genuine behaviour-changing kill and no
            # surviving mutant to call it vacuous. Equivalent-mutant-only.
            result["verdict"] = "equivalent-mutant-only"
            result["reason"] = (
                f"harness produced {panic_only_kills} panic-only (EVM-enforced) "
                f"and {broken_by_mutant} setUp-crash 'kills' but ZERO non-panic "
                f"behaviour-changing kills of {fn_name}; an equivalent mutant any "
                "assertion would 'kill' proves nothing. Pick a guard/auth/cap/state "
                "mutant (NOT a +=->-= that only panics) - NOT credited."
            )
        elif killed >= 1:
            # A kill is decisive regardless of baseline shape: the harness
            # output FLIPS to a failure on a mutant, so the clean run (whether
            # it printed [PASS] or was a silent halmos no-counterexample) was a
            # genuine, function-sensitive oracle.
            result["verdict"] = "non-vacuous"
            result["reason"] = (
                f"harness FAILED on {killed}/{len(mutants)} mutants with a "
                f"behaviour-changing kill; it genuinely checks {fn_name}"
                + (" (clean-code baseline was a silent no-counterexample run, "
                   "now proven real by the mutant kill)." if silent_baseline
                   else ".")
            )
        elif silent_baseline:
            # No kill AND the baseline was silent: we never saw the harness emit
            # a pass token NOR flip on any mutant. We cannot distinguish a real
            # harness whose property simply does not constrain this function
            # from a stub that never ran. This is a TYPED SKIP, NOT an engine
            # error and NOT credited as coverage - it must not look like a
            # genuine vacuous-but-executed result (which a real [PASS] baseline
            # surviving all mutants would be).
            result["verdict"] = "no-property-discovered"
            result["reason"] = (
                f"harness exited 0 with no recognizable output on clean code "
                f"(silent skip) and killed 0/{len(mutants)} mutants of {fn_name}; "
                f"no property over the function was ever observed. Typed skip, "
                f"not credited as coverage (not an engine error)."
            )
        elif survived == len(mutants):
            result["verdict"] = "vacuous"
            result["reason"] = (
                f"harness PASSED on ALL {len(mutants)} mutants of {fn_name}; it "
                f"checks nothing real about the function (hollow coverage)."
            )
        else:
            # No kills but some mutant re-runs errored (build/tool failures).
            result["verdict"] = "vacuous"
            result["reason"] = (
                f"harness killed 0/{len(mutants)} mutants "
                f"({survived} survived, {result['error_count']} errored); "
                f"no mutant was killed, so coverage of {fn_name} is not "
                f"demonstrated. Treat as vacuous until a kill is shown."
            )

        # wave-4: GENUINE coverage requires BOTH a non-vacuous (kill-proven)
        # oracle AND a real-output-bound harness. A model+seam harness
        # (real_output_bound is False) that kills is honest scaffolding that
        # still needs binding to the real CUT before it counts as genuine; we
        # downgrade it to needs-binding rather than crediting it as genuine.
        # real_output_bound is None (no manifest) leaves the verdict unchanged so
        # hand-written PoCs and pre-wave harnesses are not penalised.
        rob = result.get("real_output_bound")
        result["genuine_coverage"] = bool(result["verdict"] == "non-vacuous" and rob is True)
        if result["verdict"] == "non-vacuous" and rob is False:
            result["coverage_status"] = "needs-binding"
            result["reason"] += (
                " NOTE: harness asserts over a hand-authored MODEL "
                "(real_output_bound=false); bind it to the real CUT output before "
                "counting it as genuine coverage (wave-4)."
            )
        elif result["verdict"] == "non-vacuous" and rob is True:
            result["coverage_status"] = "genuine"
        return result
    finally:
        _restore()
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)
        if _src_lock is not None:
            try:
                _src_lock.close()  # releases the flock
            except OSError:
                pass


def _tail(s: str, n: int = 1200) -> str:
    s = s.strip()
    return s[-n:] if len(s) > n else s


def _parse_fn_arg(arg: str) -> tuple[str | None, int | None]:
    if ":" in arg:
        _, _, tail = arg.rpartition(":")
        if tail.isdigit():
            return None, int(tail)
    if arg.isdigit():
        return None, int(arg)
    return arg, None


# ---------------------------------------------------------------------------
# PATH-RELEVANT MUTANT MODE (additive; default OFF).
#
# Given a DefUsePath (from <ws>/.auditooor/dataflow_paths.jsonl), target the
# DOMINATING GUARD that sits ON the path for the mutant - proving the path's
# guard is LOAD-BEARING for the whole multi-hop slice - instead of (or in
# addition to) the function-local mutant the per-function mode uses by default.
#
# Resolution rules (all default-off when no path is given):
#   - If the path has guard_nodes: mutate the guard's enclosing function with the
#     `guard_removal` (+ `relational`/`boundary`) classes at the guard line. A
#     harness that asserts the flow's conservation/bounds MUST FAIL when the
#     path's guard is removed -> the guard is proven load-bearing.
#   - If the path is UNGUARDED (the canonical finding shape): there is no guard
#     to remove, so we mutate the SINK function with the `value_mutation` (+
#     `arithmetic`) classes - a value-conservation harness over the flow MUST
#     FAIL when the sink creates/changes value. This proves the seeded
#     conservation harness is non-vacuous over the real value-mover.
#
# The existing per-function mutant path is UNCHANGED and remains the default; this
# only fires when --dataflow-path / --dataflow-paths is supplied.
# ---------------------------------------------------------------------------
def _load_dataflow_paths(paths_file: Path) -> list[dict]:
    out: list[dict] = []
    try:
        for line in paths_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    return out


def _resolve_path_relevant_target(rec: dict, workspace: Path) -> dict | None:
    """Return the mutant target for a DefUsePath, or None when unresolvable.

    The returned dict carries: source_file (Path), function (str -> file:line or
    name), classes (list[str]), mode ('guard-on-path' | 'sink-value'). The source
    file path is resolved relative to the workspace when not absolute.
    """
    if not isinstance(rec, dict) or rec.get("degraded"):
        return None

    def _abs(p: str | None) -> Path | None:
        if not p:
            return None
        pp = Path(p)
        if pp.is_absolute():
            return pp
        cand = workspace / pp
        return cand if cand.exists() else pp

    guards = rec.get("guard_nodes") or []
    if guards:
        g = guards[0]
        gf = _abs(g.get("file"))
        gl = g.get("line")
        if gf is not None and gf.is_file() and gl:
            return {
                "source_file": gf,
                "function": f"{gf}:{int(gl)}",
                "classes": ["guard_removal", "relational", "boundary"],
                "mode": "guard-on-path",
                "guard_expr": g.get("expr"),
            }
    # Unguarded path: mutate the value-moving SINK function instead.
    sink = rec.get("sink") or {}
    sf = _abs(sink.get("file"))
    sl = sink.get("line")
    sfn = sink.get("fn")
    if sf is not None and sf.is_file():
        if sl:
            fn_arg = f"{sf}:{int(sl)}"
        elif sfn:
            fn_arg = sfn
        else:
            return None
        return {
            "source_file": sf,
            "function": fn_arg,
            "classes": ["value_mutation", "arithmetic", "relational"],
            "mode": "sink-value",
        }
    return None


def verify_dataflow_path(
    *,
    workspace: Path,
    rec: dict,
    harness: str | None,
    timeout: int = 600,
    max_mutants: int | None = None,
    runner_cmd: list[str] | None = None,
    runner_cwd: Path | None = None,
) -> dict:
    """Path-relevant mutation-verify for a single DefUsePath record.

    Targets the path's dominating guard (load-bearing proof) when present, else
    the value sink (conservation non-vacuity). Delegates to the existing verify()
    so the mutate->run->restore loop, classification, and durable sidecar credit
    are all reused unchanged. The result is TAGGED with the path id + mode so the
    credit readers recognise a flow-relevant verdict."""
    target = _resolve_path_relevant_target(rec, workspace)
    path_id = str(rec.get("path_id") or "path")
    if target is None:
        return {
            "schema": SCHEMA,
            "verdict": "error",
            "dataflow_path_id": path_id,
            "reason": (
                "could not resolve a path-relevant mutant target (no readable "
                "guard file/line and no readable sink file) for this DefUsePath."
            ),
        }
    rec_out = verify(
        workspace=workspace,
        source_file=target["source_file"],
        function=target["function"],
        harness=harness,
        language="auto",
        classes=target["classes"],
        max_mutants=max_mutants,
        timeout=timeout,
        runner_cmd=runner_cmd,
        runner_cwd=runner_cwd,
    )
    # Additive credit tags (never change the verdict vocabulary).
    rec_out["dataflow_path_id"] = path_id
    rec_out["path_relevant_mode"] = target["mode"]
    rec_out["flow_seeded"] = True
    rec_out["dataflow_seeded"] = True
    if target.get("guard_expr"):
        rec_out["targeted_guard_expr"] = target["guard_expr"]
    return rec_out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def verify_premade_mutant(
    *,
    workspace: Path,
    source_file: Path,
    function: str,
    baseline_harness: str,
    mutant_harness: str,
    timeout: int = 600,
    harness_path: str | None = None,
) -> dict:
    """Harness-level mutation verification WITHOUT mutating the audit-tree source.

    Some engines (medusa especially) express a mutant as a separate PRE-MADE
    MUTANT HARNESS (e.g. ``MutantPortalNoDoubleSpendHarness`` = the CUT with one
    guard dropped) rather than an in-place source edit. This mode runs the
    BASELINE harness (over the real CUT) and the MUTANT harness, classifies both
    via the shared (now medusa-aware) oracle, and decides non-vacuity - never
    touching the real source file (no transient audit-tree mutation, the risk of
    the source-mutate verify() path). non-vacuous iff baseline PASSES and the
    mutant FAILS. Both args are literal shell commands (cd into the harness dir +
    invoke the engine).

    Nested-project-root (loop-fix 2026-06-22, companion to _default_runner's fix):
    multi-project workspaces nest the real build project in a SUBDIR
    (src/pol-token/foundry.toml) with its OWN remappings. When ``harness_path`` is
    known, run BOTH the baseline and mutant commands from the nearest enclosing
    project dir so ``forge``/``halmos`` resolve imports + remappings - otherwise a
    bare ``forge test`` from the audit-tree root errors to ``no-baseline`` even
    though the harness is sound. Falls back to ``workspace`` when no marker / no
    harness_path. The explicit shell commands may still ``cd`` themselves; running
    from the project root is the correct default when they do not."""
    runner_cwd = workspace
    if harness_path:
        hp = Path(harness_path)
        marker = {".sol": "foundry.toml", ".rs": "Cargo.toml", ".go": "go.mod"}.get(
            hp.suffix.lower(), "foundry.toml"
        )
        runner_cwd = _project_root(hp, workspace, marker)
    b_rc, b_out = _run(shlex.split(baseline_harness), runner_cwd, timeout)
    b_status, _ = _classify(b_rc, b_out)
    m_rc, m_out = _run(shlex.split(mutant_harness), runner_cwd, timeout)
    m_status, _ = _classify(m_rc, m_out)

    if b_status != "pass":
        verdict = "no-baseline"      # baseline must be green to be an oracle
    elif m_status == "fail":
        verdict = "non-vacuous"      # genuine kill: baseline holds, mutant breaks
    elif m_status in ("pass", "no-execution"):
        verdict = "vacuous"          # the invariant did not catch the dropped guard
    else:
        verdict = "error"            # build/engine failure on the mutant
    fn_name, _ = _parse_fn_arg(function)
    # Infer language from the CUT source / harness extension (was hardcoded solidity).
    _pm_lang = (_EXT_LANG.get(Path(source_file).suffix) if source_file else None) \
        or (_EXT_LANG.get(Path(harness_path).suffix) if harness_path else None) or "solidity"
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "source_file": str(source_file),
        "function": fn_name,
        "language": _pm_lang,
        "mode": "premade-mutant-harness",
        "verdict": verdict,
        "mutation_verified": verdict == "non-vacuous",
        "harness_path": harness_path or "",
        "runner_cwd": str(runner_cwd),
        "baseline_harness": baseline_harness,
        "mutant_harness": mutant_harness,
        "baseline": {"status": b_status, "rc": b_rc, "tail": b_out[-600:]},
        "mutant": {"status": m_status, "rc": m_rc, "tail": m_out[-600:]},
    }


def register_manual_mvc(
    *,
    workspace: Path,
    harness_path: Path,
    source_file: Path | None = None,
    function: str | None = None,
    invariants: list[str] | None = None,
    mutants_killed: int = 1,
) -> dict:
    """P1-c (mode 11 residual): emit a CONFORMING mvc_sidecar entry for a
    HAND-AUTHORED whole-contract mutant harness (`*_MutantVacuity.t.sol`, chimera
    proof) that has no sidecar writer of its own. Without this, a genuine manual
    proof is invisible to the ledger / cross-function-coverage producer (near-intents
    OmniBridge_MutantVacuity.t.sol, beanstalk SiloCoreInvariants).

    The record is shaped EXACTLY like a non-vacuous mutation_verify_coverage.v1
    sidecar so the three existing readers AND the ledger producer ingest it. It is
    marked manual_registration=True for provenance, carries a
    harness_source_sha256 (stale-sidecar guard, P1-b), and (un-fakeable) requires
    the harness file to exist on disk."""
    harness_path = Path(harness_path)
    if not harness_path.is_file():
        return {"schema": SCHEMA, "verdict": "error",
                "reason": f"manual harness not found on disk: {harness_path}"}
    # Discover invariant/property frames declared in the harness if not given.
    try:
        htext = harness_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        htext = ""
    if not invariants:
        invariants = sorted(set(re.findall(
            r"function\s+((?:invariant_|property_|echidna_|check_)\w+)", htext)))
    fn = function or (Path(source_file).stem if source_file else harness_path.stem)
    # Infer language from the source/harness file EXTENSION (was hardcoded
    # "solidity" -> a Go/Rust manual mutant harness was mis-tagged language=solidity,
    # which mis-set `contract`/`function` and could mislead any downstream reader that
    # keys on language; NUVA 2026-06-30 cross-fn .go test mis-tagged solidity). Prefer
    # the CUT source ext, then the harness ext; default solidity only if unknown.
    _man_lang = (_EXT_LANG.get(Path(source_file).suffix) if source_file else None) \
        or _EXT_LANG.get(harness_path.suffix) or "solidity"
    rec: dict = {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "source_file": str(source_file) if source_file else "",
        "function": fn,
        "language": _man_lang,
        "mode": "manual-mutant-harness",
        "manual_registration": True,
        "verdict": "non-vacuous",
        "mutation_verified": True,
        "mutants_killed": int(mutants_killed),
        "harness_path": str(harness_path),
        "invariants": invariants,
        # baseline marker so readers that demand a passing+executed baseline credit it.
        "baseline": {"status": "pass",
                     "output_tail": f"manual registration of {harness_path.name}"},
        # one synthetic behaviour-changing kill row so _record_is_nonvacuous and the
        # killed-row consumers credit it; a real manual harness IS a kept proof.
        "mutant_results": [{
            "killed": True,
            "kill_kind": "behavior-changing",
            "harness_status": "fail",
            "output_tail": (invariants[0] + "() FAIL (manual mutant-vacuity proof)")
            if invariants else "property FAIL (manual mutant-vacuity proof)",
        }],
    }
    return rec


# Recognized in-tree build-layout LEAF directory names. A monorepo wraps each
# sub-project in its OWN dir whose contracts live under one of these (e.g.
# src/vault-v2/src/*.sol, src/pos-contracts/contracts/*.sol). The dir segment
# IMMEDIATELY ENCLOSING the innermost build-leaf is the sub-project discriminant.
_BUILD_LEAF_DIRS = {"src", "contracts", "sources", "source", "lib", "test", "tests"}


def _subproject_discriminant(source_file: str | None) -> str:
    """Sub-project dir segment for a CUT path, or "" when there is no wrapping
    sub-project (a plain single-project layout).

    THE MONOREPO SLUG-COLLISION (LANE L1, found by the morpho MV-floor workflow):
    a sidecar slug keyed on basename+fn alone makes
    ``src/vault-v2/src/VaultV2.sol::deposit`` and
    ``src/vault-v2-marketadapter/src/VaultV2.sol::deposit`` produce the SAME slug
    (``vaultv2-deposit``), so the second non-vacuous proof CLOBBERS the first on
    disk and a genuine per-fn credit is silently dropped (a serving-join /
    collision). The fix adds a discriminant = the dir segment immediately
    enclosing the INNERMOST recognized build-leaf dir (``vault-v2`` vs
    ``vault-v2-marketadapter``), so the two CUTs get DISTINCT slugs.

    CONSERVATIVE + ADDITIVE: a plain single-project layout (``src/Foo.sol``,
    ``src/contracts/Foo.sol``) has no enclosing sub-project segment, so this
    returns "" and the existing ``<srcbase>-<fn>`` slug is unchanged - no churn
    of unrelated sidecars. The discriminant is also suppressed when it would
    duplicate the source basename (it adds nothing to disambiguate).
    """
    s = str(source_file or "")
    s = s.split(":")[0]  # drop ::line / :line suffix
    if not s:
        return ""
    parts = Path(s.replace("\\", "/")).parts
    if len(parts) < 2:
        return ""
    dirs = list(parts[:-1])  # drop the filename
    base_stem = Path(parts[-1]).stem.lower()
    leaf_idx = [i for i, d in enumerate(dirs) if d.lower() in _BUILD_LEAF_DIRS]
    if not leaf_idx:
        return ""
    innermost_leaf = leaf_idx[-1]
    if innermost_leaf == 0:
        return ""
    # CONSERVATIVE: only the DOUBLE-build-dir monorepo shape carries a
    # discriminant - the enclosing sub-project dir must itself sit UNDER another
    # build-leaf (the audit-clone wrapper), i.e. there are >=2 build-leaf dirs in
    # the path (src/<subproject>/src/File.sol, src/<sub>/contracts/File.sol). A
    # plain single project (<root>/src/File.sol - one build-leaf) keeps its bare
    # <srcbase>-<fn> slug, so absolute and relative single-project paths alike are
    # never churned.
    if len(leaf_idx) < 2:
        return ""
    disc = dirs[innermost_leaf - 1]
    norm = re.sub(r"[^a-z0-9]+", "-", disc.lower()).strip("-")
    # suppress a discriminant that is a build-leaf itself or equals the basename.
    if not norm or norm in _BUILD_LEAF_DIRS or norm == base_stem:
        return ""
    return norm


def _persist_durable_sidecar(workspace: Path, rec: dict) -> str | None:
    """Persist a genuine-KILL (non-vacuous) verdict into the DURABLE sidecar dir
    that the coverage gates read, so a hand-authored / premade-mutant harness proof
    is actually CREDITED - not lost to stdout.

    WHY (wiring-not-supply): core-coverage-completeness + function-coverage read
    mutation KILLs from ``.auditooor/mvc_sidecar/*.json`` (and cross-function-coverage),
    NOT from a --out path the caller happens to choose. A manual step-4b harness proven
    via this tool was therefore invisible to the gate unless the operator KNEW to write
    --out into that exact dir (the polygon PolygonMigration/DefaultEmissionManager/
    StakeManager proofs evaporated this way - core-coverage stayed 0/40 despite 3
    mutation-verified harnesses). Auto-persisting the proof closes the loop.

    Only non-vacuous kills are persisted (the only records that earn coverage credit;
    _record_is_kill gates the gate side too). Deterministic filename (no Date/random,
    so a re-run overwrites its own record idempotently). Opt out with
    AUDITOOOR_MVC_NO_AUTO_SIDECAR=1. Returns the written path or None.
    """
    import os as _os
    import re as _re
    if _os.environ.get("AUDITOOOR_MVC_NO_AUTO_SIDECAR"):
        return None
    if rec.get("verdict") != "non-vacuous":
        return None
    # P1-b (mode 13, source-hash half): record the harness file's content hash so a
    # consumer can detect a STALE sidecar - a genuine harness that was later
    # clobbered by an `assert(true)` regeneration must not ride its banked kills.
    rec = dict(rec)  # do not mutate the caller's record in place
    hsh = _harness_source_sha256(rec.get("harness_path"))
    if hsh is not None:
        rec["harness_source_sha256"] = hsh
    fn = str(rec.get("function") or "fn")
    srcbase = Path(str(rec.get("source_file") or "src")).stem
    # LANE L1: prepend the monorepo sub-project discriminant so two same-basename
    # CUTs in different sub-projects (vault-v2/src/VaultV2.sol vs
    # vault-v2-marketadapter/src/VaultV2.sol) get DISTINCT slugs instead of one
    # clobbering the other. "" for a plain single-project layout (slug unchanged).
    disc = _subproject_discriminant(rec.get("source_file"))
    parts = [disc, srcbase, fn] if disc else [srcbase, fn]
    slug = _re.sub(r"[^A-Za-z0-9]+", "-", "-".join(parts)).strip("-").lower() or "mvc"
    # Durabilize referenced evidence (the /tmp-evaporation fix): copy any
    # evidence_logs that live outside the workspace (e.g. /tmp/*.log, /tmp/corpus/)
    # into <ws>/.auditooor/mvc_evidence/<slug>/ and rewrite the paths, so a credited
    # kill stays RE-VERIFIABLE after a restart instead of dangling at a wiped /tmp
    # path. Stamps `evidence_durable` so a coverage-theater reader can tell whether
    # the kill is backed by on-disk evidence (durable file OR in-sidecar tail/counts).
    rec = _durabilize_evidence(workspace, rec, slug)
    sidecar_dir = workspace / ".auditooor" / "mvc_sidecar"
    try:
        sidecar_dir.mkdir(parents=True, exist_ok=True)
        out = sidecar_dir / f"mvc-{slug}.json"
        out.write_text(json.dumps(rec, indent=2), encoding="utf-8")
        return str(out)
    except OSError:
        return None


def _durabilize_evidence(workspace: Path, rec: dict, slug: str) -> dict:
    """Copy out-of-workspace evidence_logs into a durable workspace dir + rewrite.

    Generic + best-effort: a sidecar that points its evidence at an ephemeral path
    (/tmp/...) loses re-verifiability on restart. We copy each existing referenced
    file/dir into ``<ws>/.auditooor/mvc_evidence/<slug>/`` (gitignored), rewrite
    evidence_logs to the durable copies, and set ``evidence_durable`` True when the
    kill is backed by durable on-disk evidence (a copied file) OR by in-sidecar
    proof (a mutant_results output_tail, or per-mutant call counts). Never raises;
    returns the (possibly updated) record. Opt out with AUDITOOOR_MVC_NO_EVIDENCE_COPY=1.
    """
    import os as _os
    import shutil as _shutil
    if _os.environ.get("AUDITOOOR_MVC_NO_EVIDENCE_COPY"):
        return rec
    rec = dict(rec)
    logs = rec.get("evidence_logs")
    in_sidecar_proof = bool(
        any(str(m.get("output_tail") or "").strip()
            for m in (rec.get("mutant_results") or []) if isinstance(m, dict))
        or rec.get("mutants_killed")
        or rec.get("total_calls_mutant_a")
        or rec.get("mutation_detail")
    )
    if not isinstance(logs, list) or not logs:
        rec["evidence_durable"] = in_sidecar_proof
        return rec
    dest_dir = workspace / ".auditooor" / "mvc_evidence" / slug
    new_logs: list[str] = []
    copied_any = False
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        rec["evidence_durable"] = in_sidecar_proof
        return rec
    for ref in logs:
        src = Path(str(ref))
        try:
            inside = (workspace.resolve() in src.resolve().parents
                      or src.resolve() == workspace.resolve())
        except (OSError, ValueError):
            inside = False
        if inside and src.exists():
            new_logs.append(str(src))
            copied_any = True
            continue
        if not src.exists():
            # Dangling (already-wiped /tmp): cannot copy; drop from the durable set.
            continue
        try:
            target = dest_dir / src.name
            if src.is_dir():
                if target.exists():
                    _shutil.rmtree(target, ignore_errors=True)
                _shutil.copytree(src, target)
            else:
                _shutil.copy2(src, target)
            new_logs.append(str(target))
            copied_any = True
        except (OSError, _shutil.Error):
            continue
    # Rewrite to the durable set (empty when every referenced log was dangling) -
    # an honest evidence_logs that no longer points at wiped paths.
    rec["evidence_logs"] = new_logs
    rec["evidence_durable"] = bool(copied_any or in_sidecar_proof)
    return rec


def _harness_source_sha256(harness_path) -> str | None:
    """sha256 of the harness FILE content, or None when no readable harness path.

    P1-b: stored in the sidecar at persist time; a consumer re-hashes the named
    harness_path and rejects the sidecar when the hash drifted (stale-sidecar
    guard, mode 13). Generic stdlib."""
    if not harness_path:
        return None
    p = Path(str(harness_path))
    try:
        if not p.is_file():
            return None
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return None


def sidecar_harness_drifted(rec: dict, ws: Path) -> bool:
    """True iff the sidecar record carries a harness_source_sha256 that NO LONGER
    matches the on-disk harness_path content (the harness was clobbered/edited
    after the sidecar was banked - mode 13). A consumer rejects such a sidecar.

    Conservative: returns False (no drift) when the record has no recorded hash
    (pre-P1-b sidecars are not retroactively rejected) or when the harness file is
    missing (a separate on-disk check already handles a vanished harness)."""
    if not isinstance(rec, dict):
        return False
    recorded = rec.get("harness_source_sha256")
    if not isinstance(recorded, str) or not recorded:
        return False
    hp = rec.get("harness_path")
    if not hp:
        return False
    p = Path(str(hp))
    if not p.is_absolute():
        p = ws / p
    try:
        if not p.is_file():
            return False
        current = hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return False
    return current != recorded


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Per-harness mutation-KILL verifier (R80/R81 oracle half)."
    )
    ap.add_argument("--workspace", required=True, help="workspace root (generic; any ws)")
    ap.add_argument(
        "--function", required=False, default=None,
        help="target function: file:line, name, or bare line. The source file is "
             "taken from --source (or the file part of a file:line --function). "
             "Not required when --dataflow-path / --dataflow-paths is given (the "
             "target is resolved from the DefUsePath record).",
    )
    ap.add_argument(
        "--source", default=None,
        help="source FILE containing the function-under-test. If omitted and "
             "--function is `path:line`, the path is used.",
    )
    ap.add_argument(
        "--harness", default=None,
        help="harness/PoC: a path to a test file OR a literal shell command "
             "('forge test --match-contract X', 'cargo test foo', ...). If a path "
             "in a known language is given, a runner is derived from it.",
    )
    ap.add_argument("--language", default="auto",
                    choices=["auto", "solidity", "rust", "go", "move", "cairo"])
    ap.add_argument("--classes", default=None,
                    help="comma-separated mutation operator classes (default: all)")
    ap.add_argument("--mutant-harness", default=None,
                    help="PRE-MADE mutant harness shell command. When set, --harness is the "
                         "BASELINE command; this is the mutant. Harness-level (medusa-idiom) "
                         "verification with NO audit-tree source mutation.")
    ap.add_argument("--harness-path", default=None,
                    help="(premade-mutant) the harness .sol/.rs FILE path, recorded as "
                         "harness_path so the engine-harness-proof gate can credit it as "
                         "mutation-verified (overrides its static tautology heuristic).")
    ap.add_argument("--max", type=int, default=None, help="cap number of mutants")
    ap.add_argument("--timeout", type=int, default=600, help="per-run timeout seconds")
    ap.add_argument("--out", default=None,
                    help="write the full JSON record to this path (seeds a "
                         "*mutation*.json artifact for R80).")
    # PATH-RELEVANT MUTANT MODE (additive; default OFF). Targets the DefUsePath's
    # dominating guard (load-bearing proof) when present, else the value sink
    # (conservation non-vacuity). Reuses the same verify() loop + sidecar credit.
    ap.add_argument("--dataflow-path", default=None,
                    help="path_id of a DefUsePath to mutation-verify in PATH-RELEVANT "
                         "mode. Looked up in --dataflow-paths (default "
                         "<ws>/.auditooor/dataflow_paths.jsonl). Mutually exclusive "
                         "with the per-function --function/--source mode.")
    ap.add_argument("--dataflow-paths", default=None,
                    help="override DefUsePath jsonl (default "
                         "<ws>/.auditooor/dataflow_paths.jsonl).")
    ap.add_argument("--register-manual-mvc", default=None,
                    help="P1-c: register a HAND-AUTHORED mutant harness "
                         "(*_MutantVacuity.t.sol / chimera proof) by writing a "
                         "conforming .auditooor/mvc_sidecar/*.json so the ledger / "
                         "cross-function-coverage producer credits it. Pass the "
                         "harness FILE path; --source/--function optional.")
    ap.add_argument("--json", action="store_true", help="emit full JSON to stdout")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).resolve()

    # ---- P1-c: manual mvc registration (additive; default OFF) ----
    if args.register_manual_mvc:
        hp = Path(args.register_manual_mvc)
        if not hp.is_absolute():
            cand = Path.cwd() / hp
            hp = cand if cand.exists() else (ws / hp)
        srcf = None
        if args.source:
            srcf = Path(args.source)
            if not srcf.is_absolute():
                srcf = ws / srcf
        rec = register_manual_mvc(
            workspace=ws, harness_path=hp, source_file=srcf, function=args.function)
        if rec.get("verdict") == "error":
            print(json.dumps(rec, indent=2))
            return 2
        if args.out:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(json.dumps(rec, indent=2), encoding="utf-8")
        durable = _persist_durable_sidecar(ws, rec)
        if durable:
            rec["durable_sidecar"] = durable
        print(json.dumps(rec, indent=2))
        return 0

    # ---- PATH-RELEVANT MUTANT MODE (additive; default OFF) ----
    if args.dataflow_path:
        paths_file = (
            Path(args.dataflow_paths).expanduser().resolve() if args.dataflow_paths
            else ws / ".auditooor" / "dataflow_paths.jsonl"
        )
        if not paths_file.is_file():
            print(json.dumps({"schema": SCHEMA, "verdict": "error",
                              "reason": f"dataflow paths file not found: {paths_file}"}))
            return 2
        recs = _load_dataflow_paths(paths_file)
        match = next((r for r in recs if str(r.get("path_id")) == str(args.dataflow_path)), None)
        if match is None:
            print(json.dumps({"schema": SCHEMA, "verdict": "error",
                              "reason": f"no DefUsePath with path_id={args.dataflow_path!r} in {paths_file}"}))
            return 2
        classes = [c.strip() for c in args.classes.split(",")] if args.classes else None
        rec = verify_dataflow_path(
            workspace=ws,
            rec=match,
            harness=args.harness,
            timeout=args.timeout,
            max_mutants=args.max,
        )
        if args.out:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(json.dumps(rec, indent=2), encoding="utf-8")
        _durable = _persist_durable_sidecar(ws, rec)
        if _durable:
            rec["durable_sidecar"] = _durable
        if args.json:
            print(json.dumps(rec, indent=2))
        else:
            slim = dict(rec)
            slim.pop("mutant_results", None)
            print(json.dumps(slim, indent=2))
        verdict = rec.get("verdict")
        if verdict == "non-vacuous":
            return 0
        if verdict == "vacuous":
            return 1
        return 2

    if not args.function:
        print(json.dumps({"schema": SCHEMA, "verdict": "error",
                          "reason": "one of --function or --dataflow-path is required."}))
        return 2

    # Resolve the source file.
    src = None
    if args.source:
        src = Path(args.source)
    else:
        name, _line = _parse_fn_arg(args.function)
        if ":" in args.function:
            head = args.function.rsplit(":", 1)[0]
            if head and Path(head).suffix:
                src = Path(head)
    if src is None:
        print(json.dumps({"schema": SCHEMA, "verdict": "error",
                          "reason": "no --source given and --function is not a file:line path."}))
        return 2
    if not src.is_absolute():
        # Resolve relative to CWD then workspace.
        cand = Path.cwd() / src
        src = cand if cand.exists() else (ws / src)

    classes = [c.strip() for c in args.classes.split(",")] if args.classes else None

    if args.mutant_harness:
        if not args.harness:
            print(json.dumps({"schema": SCHEMA, "verdict": "error",
                              "reason": "--mutant-harness requires --harness (the baseline command)"}))
            return 2
        rec = verify_premade_mutant(
            workspace=ws,
            source_file=src,
            function=args.function,
            baseline_harness=args.harness,
            mutant_harness=args.mutant_harness,
            timeout=args.timeout,
            harness_path=args.harness_path,
        )
        if args.out:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(json.dumps(rec, indent=2), encoding="utf-8")
        _durable = _persist_durable_sidecar(ws, rec)
        if _durable:
            rec["durable_sidecar"] = _durable
        print(json.dumps(rec, indent=2))
        return 0

    rec = verify(
        workspace=ws,
        source_file=src,
        function=args.function,
        harness=args.harness,
        language=args.language,
        classes=classes,
        max_mutants=args.max,
        timeout=args.timeout,
    )

    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(rec, indent=2), encoding="utf-8")

    _durable = _persist_durable_sidecar(ws, rec)
    if _durable:
        rec["durable_sidecar"] = _durable

    # Always emit something to stdout: full JSON with --json, else a slim summary
    # (heavy per-mutant output tails dropped). This holds even when --out is set,
    # so a CLI run is never silent.
    if args.json:
        print(json.dumps(rec, indent=2))
    else:
        slim = dict(rec)
        slim.pop("mutant_results", None)
        print(json.dumps(slim, indent=2))

    verdict = rec.get("verdict")
    # Exit code: 0 non-vacuous, 1 vacuous, 2 everything else
    # (no-baseline / no-mutants / no-property-discovered / error). A typed
    # silent-skip (no-property-discovered) is NOT a credit and NOT exit 0.
    if verdict == "non-vacuous":
        return 0
    if verdict == "vacuous":
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
