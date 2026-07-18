#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-INVARIANT-FUZZ-GATE registered via agent-pathspec-register.py -->
"""Invariant-fuzz completeness gate - "you cannot build a harness and skip fuzzing it".

The recurring failure on morpho-midnight: a chimera/Recon invariant harness was
BUILT (real CUT, property_ invariants) but the coverage-guided engines were never
actually run, and the economic-invariant surface (fee / credit / bundle) was never
even authored - so "invariant coverage" was claimed on a harness that only ever
ran under the light forge default, with one invariant and no fee surface.

This gate enforces, per workspace, for EVERY invariant harness it finds:
  1. BREADTH  - >= MIN_INVARIANTS distinct invariant properties (property_* /
     echidna_* / invariant_*). One lone solvency invariant is not "covered".
  2. NON-VACUITY - >= 1 mutation-verify test (test_mutation_breaks_* / a
     test that injects a bug and asserts an invariant flips). A harness that only
     ever passes proves nothing.
  3. ACTUALLY FUZZED - real evidence a coverage-guided engine RAN the harness: a
     medusa/echidna corpus dir, or a deep-engine fuzz artifact, or a recorded
     engine log. A harness that was authored but never executed FAILS
     (fail-invariant-harness-not-fuzzed) - the exact skip we are closing.

A harness missing (1)/(2)/(3) FAILS. A workspace with NO invariant harness gets a
pass-no-invariant-harness (advisory - the gate cannot force a harness onto a
language/target where one is not applicable, but L37 records it).

CLI: python3 tools/invariant-fuzz-completeness.py --workspace <ws> [--json] [--min-invariants N]
Exit: 0 = pass; 1 = fail; 2 = usage error.
"""
from __future__ import annotations

import argparse
import importlib.util as _ilu
import hashlib
import json
import os
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Canonical source-extension registry: classify a file's language so the gate can
# tell an LLM-hunt-only language (no static/fuzz engine can exist for it, e.g.
# Obyte Oscript) apart from an engine language (solidity/go/rust). Used only by
# the LLM-hunt coverage arm below; engine-language paths are untouched.
# ---------------------------------------------------------------------------
try:
    from lib.source_extensions import (  # type: ignore
        lang_of as _reg_lang_of,
        is_llm_hunt_only as _reg_is_llm_hunt_only,
    )
except Exception:  # pragma: no cover - fallback when run as a bare script
    _T = Path(__file__).resolve().parent
    if str(_T) not in sys.path:
        sys.path.insert(0, str(_T))
    try:
        from lib.source_extensions import (  # type: ignore
            lang_of as _reg_lang_of,
            is_llm_hunt_only as _reg_is_llm_hunt_only,
        )
    except Exception:  # pragma: no cover

        def _reg_lang_of(_p: str):  # type: ignore[misc]
            return None

        def _reg_is_llm_hunt_only(_p: str) -> bool:  # type: ignore[misc]
            return False


# ---------------------------------------------------------------------------
# P0-d: the kill-genuineness predicate is promoted to tools/lib/mutation_kill.py
# (single source of truth) and imported back here. The producer
# (mutation-verify-coverage.py) and the two other consumers
# (engine-harness-proof-check.py / audit-honesty-check.py) import the SAME module
# so producer and every consumer agree on what counts as a genuine kill.
# ---------------------------------------------------------------------------
def _load_mutation_kill():
    tool = Path(__file__).resolve().parent / "lib" / "mutation_kill.py"
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


# ---------------------------------------------------------------------------
# Per-unit non-economic-surface disposition (single source of truth in
# tools/lib/non_economic_disposition.py). A harness dir whose ONLY .sol files
# are AUTO-GENERATED scaffolds (the per-function-invariant-gen `assert(true)` /
# check_ Halmos stubs) over a contract that has a DOCUMENTED non-economic /
# OOS disposition is credited as non-economic-surface-dispositioned instead of
# fail-invariant-fuzz-incomplete - NOT a vacuous pass (the disposition is
# never-false-pass-guarded: bounded class, real rationale, on-disk CUT, and it
# is REJECTED for any transfer-mover). See the lib docstring.
# ---------------------------------------------------------------------------
def _load_non_economic_disposition():
    tool = Path(__file__).resolve().parent / "lib" / "non_economic_disposition.py"
    if not tool.is_file():
        return None
    try:
        spec = _ilu.spec_from_file_location("non_economic_disposition", str(tool))
        mod = _ilu.module_from_spec(spec)
        sys.modules["non_economic_disposition"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:  # noqa: BLE001
        return None


_NED_MOD = _load_non_economic_disposition()

# A harness .sol is an AUTO-GENERATED scaffold (no genuine economic invariant)
# when it carries the per-function-invariant-gen header. Only such scaffold-only
# harness dirs are eligible for a non-economic disposition credit; a hand-authored
# invariant harness must still pass the real bar.
_AUTOGEN_SCAFFOLD_MARKER = "Auto-generated by tools/per-function-invariant-gen.py"

# r36-rebuttal: lane FIX-INVARIANT-FUZZ-DEPTH registered in .auditooor/agent_pathspec.json
SCHEMA = "auditooor.invariant_fuzz_completeness.v1"
GATE = "invariant-fuzz-completeness"
MIN_INVARIANTS = 2
MIN_SEQLEN = 50   # multi-step depth: sequence-fatal bugs need deep call sequences
MIN_ACTIONS = 5   # action diversity: a single-action harness cannot compose an exploit
# P1-d (mode 15): a credited step-2c campaign must execute >= 1,000,000 calls. A
# 500K run (ssv) or a status=skipped dry-run (polygon) does NOT count. Absent
# until now (grep confirmed no 1_000_000 constant), so a smoke campaign passed.
MIN_CALLS = 1_000_000

# Asset-centric coverage floor (2026-07-02): a harness-centric gate (iterate the
# harnesses that HAPPEN to exist) can only ever see the value-moving files that an
# agent chose to author a harness FOR. It structurally cannot see a value-moving
# in-scope file for which ZERO economic invariant was authored - so a workspace
# where 12 of 19 value-moving files have no harness at all still 'passes'. The
# asset-coverage check enumerates the value-moving in-scope FILE set (from
# .auditooor/value_moving_functions.json intersected with inscope_units.jsonl) and
# subtracts the harness CUT set actually fuzzed (fuzz_campaign_receipt campaigns[].cut
# with a >=1M / mutation-verified run, plus mvc_sidecar source_file). Any residual
# value-moving in-scope file with no real harness and no typed per-asset disposition
# is an asset-gap. ADVISORY by default (warn-invariant-fuzz-asset-gap); it hard-fails
# (fail-invariant-fuzz-asset-gap) ONLY when AUDITOOOR_INVARIANT_FUZZ_ASSET_STRICT is
# set - so it can never retroactively brick a prior audit that predates this check.
# Echidna needs >=500K calls (hevm is slower); medusa needs the full >=1M floor.
MIN_CALLS_ECHIDNA = 500_000
_ASSET_STRICT_ENV = "AUDITOOOR_INVARIANT_FUZZ_ASSET_STRICT"

# E1 (2026-07-03): fuzz-receipt <-> runner-log RECONCILIATION.
# fuzz_campaign_receipt.json records a per-campaign result.calls / config.testLimit
# that the asset-coverage credit (`_fuzzed_cut_files`) and the audit-complete
# attestations read BLINDLY - no runner log is ever cross-checked. CONFIRMED SSV
# fabrication: the SSVClusterSolvency campaign records result.calls=1,000,127 while
# the ONLY real echidna run log (fuzz_logs/solvency.log, _campaign_index.log) shows
# `Total calls: 500172` at limit=500000 - the number 1,000,127 exists in NO run log.
# Systemic: EBAccounting records 200,225 but its log shows Total calls: 500,244.
# This check reconciles each campaign's claimed call count against the max
# `Total calls: N` parsed from that campaign's runner log(s); a claim that appears
# in NO log for the harness (beyond a small tolerance) OR exceeds the max logged
# count is flagged `fuzz-receipt-unreconciled`.
# ADVISORY-FIRST + NEVER-RETRO-RED: emitted as a WARN (warn-fuzz-receipt-unreconciled)
# unless the named default-OFF env below is set; env unset behaves byte-identically
# to before (the reconcile result is computed and surfaced but never blocks).
_RECEIPT_RECONCILE_STRICT_ENV = "AUDITOOOR_FUZZ_RECEIPT_RECONCILE_STRICT"
# tolerance: an engine overshoots its testLimit slightly (echidna 500172 vs a 500000
# limit). A claimed count is "matched" to a log count if it is within this many
# calls OR within this fraction - so a genuine 500172-vs-500000 render reconciles but
# a 1,000,127-claim-vs-500,172-log (2x) does not.
_RECONCILE_ABS_TOL = 2_000
_RECONCILE_FRAC_TOL = 0.02


def _receipt_reconcile_strict() -> bool:
    """Uniform gate-strict semantics (2026-07-03 graduate-to-default-ON, operator
    decision overriding the prior default-OFF posture): hard-fail on a
    fuzz-receipt-unreconciled campaign when the gate is enforced.
      - explicit opt-out  AUDITOOOR_FUZZ_RECEIPT_RECONCILE_STRICT in {0,false,no,off}
        -> DISABLED (advisory reconcile field still attached, escape hatch);
      - explicit opt-in   any other truthy value -> ENFORCED;
      - unset (new default): ENFORCED iff AUDITOOOR_L37_STRICT is truthy (the strict
        audit umbrella `make audit-complete STRICT=1` always sets it), else advisory
        so a bare non-strict / library caller keeps the byte-identical advisory verdict.
    NEVER-FALSE-PASS is unchanged: the reconcile predicate that decides which campaign
    is unreconciled is untouched - only WHEN that flag flips the verdict changes."""
    v = os.environ.get(_RECEIPT_RECONCILE_STRICT_ENV, "").strip().lower()
    if v in ("0", "false", "no", "off"):
        return False                      # explicit opt-out (escape hatch)
    if v:                                  # any other explicit value
        return True                        # explicit opt-in
    # unset -> default-ON only under the L37 strict umbrella
    return os.environ.get("AUDITOOOR_L37_STRICT", "").strip().lower() not in (
        "", "0", "false", "no")

# P1-d (mode 8 residual): also recognise `function check_` Halmos-convention
# properties (per-function-invariant-gen uses the check_ prefix), else an authored
# check_ property is invisible to the breadth count.
_PROP_RE = re.compile(r"function\s+(property_|echidna_|invariant_|check_)\w+", re.M)
_MUT_RE = re.compile(r"function\s+test_\w*mutation\w*|function\s+test_mutation_breaks_\w+", re.I)
# harness anchor files (Recon/chimera + generic invariant suites)
_HARNESS_ANCHORS = ("CryticTester.sol", "Properties.sol", "CryticToFoundry.sol")
_SKIP_DIRS = {".git", "node_modules", "out", "cache", "lib", "broadcast", "artifacts"}


def _iter_sol(root: Path):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in _SKIP_DIRS and not d.startswith(".")]
        for fn in fns:
            if fn.endswith(".sol"):
                yield Path(dp) / fn


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _find_harness_dirs(ws: Path) -> list[Path]:
    """A harness dir = a directory containing a .sol with >=1 invariant property
    function. Detection is by CONTENT (any .sol whose body has a
    property_/echidna_/invariant_ function), not just the 3 Recon anchor
    FILENAMES - a hand-authored harness (e.g. chimera_harnesses/<name>/
    VaultV2EconomicInvariant.t.sol with invariant_conservation) was previously
    invisible because its filename was not CryticTester/Properties/CryticToFoundry,
    so the gate falsely reported pass-no-invariant-harness. The anchor names are
    kept as a fast-accept but no longer the only way in."""
    dirs: dict[str, Path] = {}
    for p in _iter_sol(ws):
        if p.name in _HARNESS_ANCHORS or _PROP_RE.search(_read(p)):
            if _is_autogen_engine_harness(p.parent):
                continue
            if _is_audited_project_test_dir(p.parent):
                continue
            dirs[str(p.parent)] = p.parent
    return sorted(dirs.values(), key=str)


# G11 (2026-06-27): this gate is the ECONOMIC-INVARIANT (Chimera/Recon, step-2c)
# bar - hand-authored protocol invariants over the real CUT. Auto-generated per-
# function engine-harness scaffolds under poc-tests/<Name>-engine-harness/ are a
# DIFFERENT artifact (step-4b engine-harness-author): they carry templated, often
# tautological invariants (e.g. `a>=b || b>=a` control + harness-internal totalIn/
# totalOut accounting) and their per-function coverage is already established by the
# step-3 per-fn hunt (function-coverage-completeness) and verified for non-vacuity
# by engine-harness-proof-check.py. Counting them in the economic-invariant
# denominator is over-counting ("enumerate over symbols not adversary goals") and
# would demand a full economic-invariant rewrite of each scaffold. Scope them OUT
# here. NOT a fail-open: they remain covered by step-3 + engine-harness-proof.
_AUTOGEN_ENGINE_HARNESS_RE = re.compile(r"(^|/)poc-tests/[^/]*-engine-harness(/|$)")


def _is_autogen_engine_harness(d: Path) -> bool:
    return bool(_AUTOGEN_ENGINE_HARNESS_RE.search(str(d).replace("\\", "/")))


# The AUDITED PROJECT's OWN test suite (a ``test/`` or ``tests/`` dir nested INSIDE
# an in-scope source repo under ``src/``, e.g. src/nuva-evm-contracts/test) is the
# upstream project's Hardhat/Foundry test directory - OOS test infra, NOT one of OUR
# mutation-verified audit harnesses. OUR hand-authored economic-invariant harnesses
# live in dedicated roots OUTSIDE src/ (chimera_harnesses/<name>/test, poc-tests/...,
# .auditooor/...). Requiring the project's own tests to carry an audit mutation-verify
# kill is a scope error that BLOCKS the gate (NUVA 2026-06-30: src/nuva-evm-contracts/
# test surfaced a phantom "no mutation-verify test" deficiency). Excluded from the
# harness-obligation set (analogous to _is_autogen_engine_harness). NOT a fail-open:
# OUR chimera/poc harnesses still carry the full obligation.
_AUDITED_PROJECT_TEST_RE = re.compile(r"(^|/)src/.+/(test|tests)(/|$)")


def _is_audited_project_test_dir(d: Path) -> bool:
    return bool(_AUDITED_PROJECT_TEST_RE.search(str(d).replace("\\", "/")))


# An UNFILLED gen-invariants.sh scaffold (header present, body is only
# assert(true)/invariant_placeholder, target instantiation still commented out)
# is NOT a harness - it is a stub the agent never filled. Counting it as a
# deficient harness BLOCKS the gate ("only 1 invariant"); crediting it would be
# coverage-theater. Both are wrong: it must be EXCLUDED from enumeration. The
# all-placeholder case is guarded after the loop (genuine_harness_count==0 -> the
# same no-genuine-harness fail as zero harnesses), so this can never false-green.
_SCAFFOLD_HEADER_RE = re.compile(
    r"Auto-scaffolded by tools/gen-invariants\.sh|TODO:\s*agent\s+(?:fills|replaces)",
    re.I,
)


def _is_gen_invariants_scaffold_staging_dir(hd: Path) -> bool:
    """A directory whose EVERY .sol carries the gen-invariants.sh scaffold header is the
    scaffold STAGING area (e.g. <ws>/test/Invariant_*.t.sol), not one of OUR canonical
    hand-authored economic-invariant harnesses (which live in chimera_harnesses/ /
    poc-tests/ and never carry the header). A mixed filled+unfilled staging dir slips past
    _is_unfilled_scaffold_harness (which only excludes ALL-unfilled dirs) and then
    enumerates as one harness with mut=False, wrongly failing the gate. Exclude it. NOT a
    fail-open: if excluding scaffold dirs leaves zero harnesses the no-genuine-harness fail
    still fires; the real harnesses (header-free) are unaffected."""
    sols = list(hd.glob("*.sol"))
    if not sols:
        return False
    return all(_SCAFFOLD_HEADER_RE.search(_read(p)) for p in sols)


def _is_unfilled_scaffold_harness(hd: Path) -> bool:
    sols = list(hd.glob("*.sol"))
    if not sols:
        return False
    for p in sols:
        txt = _read(p)
        if not _SCAFFOLD_HEADER_RE.search(txt):
            return False  # a real (non-scaffold) .sol in the dir -> not a pure stub
        # any non-placeholder property name => the agent filled it => real harness
        real_props = [
            txt[m.start():m.end()].split()[-1]
            for m in _PROP_RE.finditer(txt)
            if "placeholder" not in txt[m.start():m.end()].lower()
        ]
        if real_props:
            return False
        # an ACTIVE (uncommented) targetContract(...) => the CUT is wired => real
        if re.search(r"^\s*targetContract\s*\(", txt, re.M):
            return False
    return True


def _has_in_scope_solidity_source(ws: Path) -> bool:
    """True if the workspace has in-scope production Solidity source (so 'no
    harness' is a GAP, not a non-applicable no-op). Prefers the authoritative
    inscope manifest; falls back to a non-vendored .sol walk."""
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if manifest.is_file():
        for ln in _read(manifest).splitlines():
            ln = ln.strip()
            if ln.endswith('.sol"') or '.sol"' in ln or '.sol' in ln:
                if '"lang": "solidity"' in ln or ".sol" in ln:
                    return True
    for p in _iter_sol(ws):
        rel = str(p).lower()
        if any(seg in rel for seg in ("/test/", "/tests/", "/mock", ".t.sol", "/script/")):
            continue
        return True
    return False


def _invariant_fuzz_rebuttal(ws: Path) -> str | None:
    for name in ("invariant_fuzz_rebuttal.md", "l37_rebuttal.md", "r81_rebuttal.md"):
        p = ws / ".auditooor" / name
        if p.is_file():
            m = re.search(r"(?:invariant-fuzz|l37|r81)-rebuttal:\s*(.+?)\s*-->", _read(p))
            if m:
                return m.group(1).strip()
    return None


# r36-rebuttal: lane FIX-FORK-DIVERGENCE-CONTENT registered in .auditooor/agent_pathspec.json
# A fuzz artifact/log is only EVIDENCE if the engine ACTUALLY EXECUTED call
# sequences. A run that died in setUp (RPC 429 / pruned fork / compile error) is
# saved with runs:0 / calls:0 - keyword+size alone would FALSELY credit it
# (observed on a bean fork harness: forge-invariant 429'd, runs:0, yet the .md
# matched 'invariant' + >200 bytes). These regexes extract the engine's own
# execution counters; >=1 positive run/call (or an explicit [PASS] invariant
# line, or a medusa "fuzzing complete"/"call_sequences_tested" summary) is the
# minimum bar. A 0-call / setup-failure artifact is NOT execution evidence.
_RUNS_RE = re.compile(r"\bruns:\s*(\d+)", re.I)
_CALLS_RE = re.compile(r"\bcalls:\s*(\d+)", re.I)
_SEQ_TESTED_RE = re.compile(r"call[_ ]sequences[_ ]tested[:=]?\s*(\d+)", re.I)
_PASS_INVARIANT_RE = re.compile(r"\[PASS\][^\n]*invariant", re.I)
_FUZZ_DONE_RE = re.compile(r"fuzzing\s+complete|test\s+summary|elapsed\s*time", re.I)


def _artifact_shows_execution(text: str) -> bool:
    """True only if the engine output proves call sequences actually executed.
    Rejects setup-failure / 0-call runs (RPC 429, pruned fork, compile error)."""
    if not text:
        return False
    # forge-invariant: any invariant line with runs>0 or calls>0
    if any(int(m) > 0 for m in _RUNS_RE.findall(text)):
        return True
    if any(int(m) > 0 for m in _CALLS_RE.findall(text)):
        return True
    # medusa/echidna: sequences tested counter, or an explicit completion summary
    if any(int(m) > 0 for m in _SEQ_TESTED_RE.findall(text)):
        return True
    if _PASS_INVARIANT_RE.search(text):
        return True
    if _FUZZ_DONE_RE.search(text):
        return True
    return False


# ---------------------------------------------------------------------------
# P1-d (modes 15, 10 residual): 1M-floor + no-dry-run + selfdestruct-engine.
# ---------------------------------------------------------------------------
# The engine's executed call count. forge prints "calls: N" per invariant line;
# medusa prints "call_sequences_tested: N" / "calls tested: N"; echidna prints
# "tests: N" / total executed. Sum the largest observed counter family so a
# 500K smoke campaign (ssv) and a status=skipped dry-run (polygon) cannot be
# credited as a >=1M campaign.
_CALLS_TESTED_RE = re.compile(r"calls?[_ ]tested[:=]?\s*([\d,]+)", re.I)
_TOTAL_CALLS_RE = re.compile(r"total\s+calls[:=]?\s*([\d,]+)", re.I)
# forge-invariant per-line `calls: N` (comma-aware so a 1,024,000 render counts).
_CALLS_NUM_RE = re.compile(r"\bcalls:\s*([\d,]+)", re.I)
# medusa >=1.5 progress line: "calls:    1217043 ( 13565/sec)" - a CUMULATIVE
# running total printed every few seconds, so the MAX (final) line is the executed
# count, NOT the sum. Distinguished from forge's per-invariant `calls: N` (which IS
# summed) by the trailing "( N/sec)". Without this, a genuine medusa 1.5.1 campaign
# is uncreditable: its total never matches the older "Total calls:" / "calls tested:"
# strings, and summing its progress snapshots over-counts to a fabrication-flag
# mismatch (verified NUVA 2026-07-06: real 1,217,043-call DedicatedVaultRouter run).
# a medusa progress line is identified by the trailing "( N/sec)" rate marker.
_MEDUSA_PROGRESS_LINE_RE = re.compile(r"\(\s*[\d,]+\s*/\s*sec\)", re.I)
# A dry-run / skipped manifest is NOT a campaign: the engine was never invoked.
_DRYRUN_RE = re.compile(
    r"\bstatus\s*[:=]\s*(?:skipped|dry-run|dryrun)\b|"
    r"dry[- ]?run\s*:?\s*engine\s+(?:was\s+)?not\s+invoked|"
    r"engine\s+(?:was\s+)?not\s+invoked", re.I)
# selfdestruct / SafeSend value-delivery: medusa stack-underflows on these, so a
# medusa-only campaign over such a CUT cannot be credited - require echidna.
_SELFDESTRUCT_RE = re.compile(r"\bselfdestruct\b|\bSafeSend\b", re.I)


def _int(s: str) -> int:
    try:
        return int(str(s).replace(",", "").strip())
    except (TypeError, ValueError):
        return 0


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(text: str) -> str:
    """Remove SGR/CSI ANSI escape sequences. medusa (and echidna) emit COLORED
    progress lines when stdout is a TTY or color is not disabled, interleaving
    `\\x1b[1m` codes BETWEEN `calls:` and the number (`calls: \\x1b[1m 487280 (...)`),
    which breaks the `calls: N` counter regexes and makes a real >=1M campaign log
    read as 0 executed calls (serving-join false-red on the invariant-fuzz gate).
    Strip the codes before any counter scan so a colored log parses identically to
    a NO_COLOR one."""
    return _ANSI_ESCAPE_RE.sub("", text) if text else text


def _executed_call_count(text: str) -> int:
    """Extract the engine's TOTAL executed call count from a campaign artifact.

    Sums the per-invariant `calls: N` counters (forge) and takes the max of the
    medusa/echidna aggregate counters. Returns 0 when no counter is present."""
    if not text:
        return 0
    text = _strip_ansi(text)
    # Line-aware so the two `calls: N` aggregations never mix: a medusa >=1.5 progress
    # line ("calls: N ( M/sec)") is a CUMULATIVE running total -> take the MAX; a forge
    # per-invariant line ("calls: N") is per-invariant -> SUM. (A negative-lookahead
    # split backtracks and truncates the number, so classify per line instead.)
    forge_calls = 0
    medusa_progress = 0
    for line in text.splitlines():
        cm = _CALLS_NUM_RE.search(line)
        if not cm:
            continue
        n = _int(cm.group(1))
        if _MEDUSA_PROGRESS_LINE_RE.search(line):
            medusa_progress = max(medusa_progress, n)
        else:
            forge_calls += n
    seq = max([_int(m) for m in _SEQ_TESTED_RE.findall(text)] or [0])
    tested = max([_int(m) for m in _CALLS_TESTED_RE.findall(text)] or [0])
    total = max([_int(m) for m in _TOTAL_CALLS_RE.findall(text)] or [0])
    return max(forge_calls, medusa_progress, seq, tested, total)


def _artifact_is_dry_run(text: str) -> bool:
    """True iff the manifest declares a skipped / dry-run / engine-not-invoked
    status (polygon `status=skipped`). Such a manifest is NOT a campaign."""
    return bool(text) and bool(_DRYRUN_RE.search(text))


# ---------------------------------------------------------------------------
# Real-engine-evidence predicate (2026-07-02): tighten "actually fuzzed".
# ---------------------------------------------------------------------------
# The old _artifact_shows_execution accepted ANY positive counter / [PASS] line /
# 'fuzzing complete' summary - so a bare `forge test` baseline over a Sanity.t.sol
# (genuine_coverage=False, no corpus, one call) and an echidna run that reached an
# assertion-never-reached vacuous witness were credited IDENTICALLY to a real 1.2M
# medusa campaign. A harness counts as COVERAGE-GUIDED-FUZZED only when a raw fuzz
# log shows a real engine executing at scale:
#   - medusa: `Total calls` (or call_sequences_tested / calls tested) >= MIN_CALLS
#   - echidna: executed calls >= MIN_CALLS_ECHIDNA (hevm is slower; 500K floor)
# A forge-test baseline / genuine_coverage:false / a never-reached vacuous witness
# may satisfy NON-VACUITY (a distinct axis) but must NOT alone satisfy actually-
# fuzzed - it is marked baseline-only. This is purely a stricter classifier; it is
# consulted only under the new asset-strict env, so existing PASS behaviour is
# unchanged when the env is unset (advisory).
_MEDUSA_TOTAL_CALLS_RE = re.compile(r"total\s+calls[:=]?\s*([\d,]+)", re.I)
_MEDUSA_ENGINE_RE = re.compile(r"\bmedusa\b", re.I)
_ECHIDNA_ENGINE_RE = re.compile(r"\bechidna\b", re.I)
# a genuine_coverage:false marker (fuzz_run manifest) => baseline-only, not fuzzed.
_GENUINE_COVERAGE_FALSE_RE = re.compile(
    r'"?genuine_coverage"?\s*[:=]\s*(?:false|"false"|0)\b', re.I)
# bare forge-test baseline: a `forge test` invocation with no invariant/medusa/
# echidna engine and no scaled call counter.
_FORGE_TEST_BASELINE_RE = re.compile(r"\bforge\s+test\b", re.I)


def _log_shows_coverage_guided_fuzz(text: str) -> bool:
    """True ONLY when a RAW fuzz log proves a coverage-guided engine executed at
    scale: medusa `Total calls` >= MIN_CALLS, OR echidna executed >= MIN_CALLS_ECHIDNA.
    A bare forge-test baseline, a genuine_coverage:false manifest, or a vacuous
    never-reached witness is baseline-only and returns False (it does NOT alone
    satisfy actually-fuzzed)."""
    if not text:
        return False
    if _GENUINE_COVERAGE_FALSE_RE.search(text):
        return False
    if _artifact_is_dry_run(text):
        return False
    calls = _executed_call_count(text)
    is_medusa = bool(_MEDUSA_ENGINE_RE.search(text)) or bool(_MEDUSA_TOTAL_CALLS_RE.search(text))
    is_echidna = bool(_ECHIDNA_ENGINE_RE.search(text))
    if is_medusa and calls >= MIN_CALLS:
        return True
    if is_echidna and calls >= MIN_CALLS_ECHIDNA:
        return True
    # engine string absent but a raw counter clears the strict medusa floor: still
    # a real coverage-guided run (forge-invariant deep run). A bare `forge test`
    # baseline with no scaled counter never reaches here.
    if calls >= MIN_CALLS and not _FORGE_TEST_BASELINE_RE.search(text):
        return True
    return False


def _harness_is_actually_fuzzed(ws: Path, harness_dir: Path) -> bool:
    """Strict 'actually fuzzed' classifier over the raw logs reachable from this
    harness. Baseline-only evidence (forge test / genuine_coverage:false / vacuous
    witness) returns False. Consulted only under the asset-strict env so existing
    advisory PASS behaviour is unchanged when the env is unset."""
    texts: list[str] = []
    for base in (harness_dir, harness_dir.parent, harness_dir.parent.parent,
                 ws / ".auditooor", ws / ".auditooor" / "fuzz-logs",
                 ws / ".auditooor" / "fuzz_logs", ws / ".auditooor" / "fuzz_runs"):
        if not base or not base.is_dir():
            continue
        for p in (list(base.glob("*medusa*.log")) + list(base.glob("*echidna*.log"))
                  + list(base.glob("*.log")) + list(base.glob("status.txt"))):
            if not p.is_file():
                continue
            try:
                texts.append(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
    return any(_log_shows_coverage_guided_fuzz(t) for t in texts)


def _strip_sol_comments(text: str) -> str:
    """Remove // line comments and /* */ block comments so a CUT-needs-echidna
    decision is made on CODE, not prose. forge-std's StdCheats.sol mentions
    'selfdestruct' only in a descriptive comment - matching that word in a
    comment falsely flagged the whole workspace as needing echidna (morpho
    2026-06-27). Conservative: a lexer would be exact, but for the narrow
    selfdestruct/SafeSend force-send signal, stripping comments is sufficient
    and never under-detects a real force-send call (which lives in code)."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    return text


def _cut_needs_echidna(harness_dir: Path, ws: Path | None = None) -> bool:
    """True iff a CUT reachable from the harness dir force-sends ETH via
    selfdestruct / SafeSend (mode 10). medusa stack-underflows on these, so a
    medusa-only campaign cannot be credited - echidna(hevm) is required.

    G8 fix (2026-06-27): scan only REAL CUT source. The previous unfiltered
    rglob("*.sol") had THREE false-positive sources that flagged genuinely
    mutation-verified morpho harnesses as needing echidna:
      1. When harness_dir.parent.parent resolves to the workspace root (e.g.
         chimera_harnesses/<name>/), the rglob walked the ENTIRE tree and
         matched 187 vendored lib/forge-std test-framework files. Those are NOT
         the CUT. Reuse the _SKIP_DIRS + dotdir exclusion that _iter_sol applies
         (skips lib/, out/, cache/, node_modules/, .git, dot-dirs).
      2. The match fired on the word 'selfdestruct' inside a COMMENT in
         forge-std StdCheats.sol. Strip comments before matching so only an
         actual force-send call counts.
      3. WORKSPACE-BOUNDARY LEAK: for a harness at the workspace ROOT (e.g.
         <ws>/test/), harness_dir.parent.parent escaped ABOVE <ws> into the
         sibling-workspace parent (/Users/wolf/audits) and matched OTHER
         audits' selfdestruct code. Clamp every scanned base to stay within
         <ws> when ws is provided.
    All fixes are false-green-safe: a real selfdestruct/SafeSend force-send in
    in-scope CUT code is still detected (it is code, not a comment, lives
    outside vendored lib/ trees, and is inside the workspace)."""
    ws_resolved = ws.resolve() if ws else None
    seen: set[str] = set()
    for base in (harness_dir, harness_dir.parent, harness_dir.parent.parent):
        if not base or not base.is_dir():
            continue
        # Never scan above the workspace root (sibling-workspace leak guard).
        if ws_resolved is not None:
            try:
                base.resolve().relative_to(ws_resolved)
            except ValueError:
                continue
        for dp, dns, fns in os.walk(base):
            dns[:] = [d for d in dns if d not in _SKIP_DIRS and not d.startswith(".")]
            for fn in fns:
                if not fn.endswith(".sol"):
                    continue
                p = Path(dp) / fn
                key = str(p)
                if key in seen:
                    continue
                seen.add(key)
                try:
                    body = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _SELFDESTRUCT_RE.search(_strip_sol_comments(body)):
                    return True
    return False


def _engine_is_echidna(harness_dir: Path, ev: list[str]) -> bool:
    """Best-effort: did the campaign use echidna? An echidna corpus/log/config
    (echidna.yaml / echidna-corpus / *echidna*.log) is the signal."""
    if any("echidna" in e.lower() for e in ev):
        return True
    for base in (harness_dir, harness_dir.parent, harness_dir.parent.parent):
        if not base or not base.is_dir():
            continue
        if any(base.glob("echidna.yaml")) or (base / "echidna-corpus").is_dir():
            return True
        if list(base.glob("*echidna*.log")):
            return True
    return False


def _run_forge_build_contract(root: Path, rel_sol: str) -> "bool | None":
    """Compile ONE harness .sol under a foundry `root`. True=compiles, False=fails,
    None=cannot determine (no forge / no foundry root / exec error). Split out so the
    freshness gate is unit-testable by monkeypatching this function."""
    import shutil
    import subprocess
    forge = shutil.which("forge")
    if not forge or not (root / "foundry.toml").is_file():
        return None
    try:
        p = subprocess.run([forge, "build", "--contracts", rel_sol],
                           cwd=str(root), capture_output=True, text=True, timeout=240)
    except (OSError, subprocess.SubprocessError):
        return None
    out = (p.stdout or "") + (p.stderr or "")
    if re.search(r"Error \(\d+\)|should be marked as abstract|not found or not visible|Compilation failed", out):
        return False
    return p.returncode == 0 or None


def _harness_source_fresh(ws: Path, harness_dir: Path, harness_rel: str) -> "bool | None":
    """Does this harness still COMPILE against the CURRENT in-scope source? A
    fuzz_campaign_receipt records a past >=1M run, but if the CUT was re-pinned since
    (e.g. Strata 2be97f9 removed Accounting.jrtBaseNav / grew IStrataCDO), the harness
    no longer builds and its recorded call count is STALE evidence that must NOT credit
    the >=1M floor. Best-effort: True=compiles (fresh), False=drifted (withhold credit),
    None=unknown (forge absent / not a foundry harness -> credit as before, no regression).
    Result cached per (harness, source-fingerprint, harness-mtime)."""
    root = harness_dir.parent  # chimera_harnesses/ (foundry root with remappings)
    sol = ws / harness_rel if harness_rel else None
    if not sol or not sol.is_file():
        # fall back to the harness dir's own primary .sol
        cand = [p for p in harness_dir.glob("*.sol") if not p.name.endswith(".t.sol")]
        if not cand:
            return None
        sol = cand[0]
    rel_from_root = str(sol.relative_to(root)) if str(root) in str(sol) else sol.name
    # cache key: harness path + its mtime + a coarse source fingerprint (src HEAD file)
    try:
        hmtime = int(sol.stat().st_mtime)
    except OSError:
        hmtime = 0
    src_fp = ""
    for cand in (ws / "src" / "contracts" / ".git" / "HEAD", ws / ".git" / "HEAD"):
        if cand.is_file():
            try:
                src_fp = cand.read_text(encoding="utf-8", errors="replace").strip()[:80]
            except OSError:
                pass
            break
    key = f"{rel_from_root}|{hmtime}|{src_fp}"
    cache_p = ws / ".auditooor" / ".harness_compile_cache.json"
    cache = {}
    if cache_p.is_file():
        try:
            cache = json.loads(cache_p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            cache = {}
    if key in cache:
        return cache[key]
    res = _run_forge_build_contract(root, rel_from_root)
    if res is not None:  # only cache determinate verdicts (None may be transient)
        cache[key] = res
        try:
            cache_p.parent.mkdir(parents=True, exist_ok=True)
            cache_p.write_text(json.dumps(cache, indent=0))
        except OSError:
            pass
    return res


def _receipt_calls_for_harness(ws: Path, harness_dir: Path) -> int:
    """Machine-readable call count for THIS harness from fuzz_campaign_receipt.json.
    The receipt is exactly the artifact the gate's FAIL message names ("a
    *_campaign_receipt.json with a numeric total_calls"), but the per-harness metric
    only greps free-text logs - so a receipt-backed >=1M campaign whose medusa log
    lacks a greppable 'calls: N' line reads as exec_calls=0 (serving-join false-red).
    Join a campaign to this harness_dir by (a) its `harness` path living under the dir,
    or (b) its `name` matching the dir basename. Returns the max credited call count.
    COMPILE-FRESHNESS GUARD: a receipt campaign only credits the >=1M floor when its
    harness STILL COMPILES against the current source - a drifted harness (CUT re-pinned
    since the run) is stale evidence and is NOT credited (best-effort; unknown => credit,
    so no regression where forge is unavailable)."""
    rec = ws / ".auditooor" / "fuzz_campaign_receipt.json"
    hd_name = harness_dir.name.lower()
    hd_rel = _norm_rel(ws, str(harness_dir))
    check_fresh = os.environ.get("AUDITOOOR_INVARIANT_FUZZ_CALLS_STRICT", "").strip().lower() in ("1", "true", "yes", "on")
    best = 0
    # The aggregate .auditooor/fuzz_campaign_receipt.json is OPTIONAL - a lane sandboxed
    # to chimera_harnesses/** writes only the per-harness campaign_result.json (read
    # below). Do NOT early-return when the aggregate is absent, or the per-harness join
    # is unreachable (nuva 2026-07-13 false-red).
    d = None
    if rec.is_file():
        try:
            d = json.loads(rec.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            d = None
    for c in ((d.get("campaigns") if isinstance(d, dict) else None) or []):
        if not isinstance(c, dict):
            continue
        h_path = _norm_rel(ws, str(c.get("harness") or ""))
        name = str(c.get("name") or "").lower()
        # match: campaign harness path is inside this dir, OR names align
        matched = (h_path and hd_rel and (h_path == hd_rel or h_path.startswith(hd_rel.rstrip("/") + "/"))) \
            or (name and name == hd_name)
        if not matched:
            continue
        res = c.get("result") if isinstance(c.get("result"), dict) else {}
        # prefer result.calls; fall back to config.testLimit only if calls absent
        calls = _int(res.get("calls"))
        if not calls:
            cfg = c.get("config") if isinstance(c.get("config"), dict) else {}
            calls = _int(cfg.get("testLimit"))
        if not calls:
            continue
        if check_fresh:
            fresh = _harness_source_fresh(ws, harness_dir, h_path)
            if fresh is False:
                # drifted harness -> stale receipt evidence, do NOT credit the floor
                continue
            # SHA-freshness: a recorded harness_source_sha256 that no longer matches the
            # on-disk harness means the run PREDATES the current harness (e.g. it was
            # edited/re-authored since) - the call count is stale even though the harness
            # now compiles. Withhold; a genuinely fresh re-run re-stamps the sha.
            rec_sha = str(c.get("harness_source_sha256") or "")
            if rec_sha:
                sol = ws / h_path if h_path else None
                if not (sol and sol.is_file()):
                    cand = [p for p in harness_dir.glob("*.sol") if not p.name.endswith(".t.sol")]
                    sol = cand[0] if cand else None
                if sol and sol.is_file():
                    try:
                        cur_sha = hashlib.sha256(sol.read_bytes()).hexdigest()
                    except OSError:
                        cur_sha = ""
                    if cur_sha and cur_sha != rec_sha:
                        continue
        best = max(best, calls)
    # SERVING-JOIN (nuva 2026-07-13): a coverage lane sandboxed to chimera_harnesses/**
    # (cannot write .auditooor/) emits the natural per-harness receipt
    # <harness_dir>/campaign_result.json (schema auditooor.medusa_campaign_result.v1,
    # field `campaign_calls`) instead of the aggregate .auditooor/fuzz_campaign_receipt.json
    # this fn historically read. Without joining it, a genuine >=1.2M medusa campaign
    # reads as 0 calls and the asset false-reds. Credit its campaign_calls (best-effort
    # freshness guard, same as the aggregate path; only when the campaign passed clean).
    per = harness_dir / "campaign_result.json"
    if per.is_file():
        try:
            pd = json.loads(per.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            pd = None
        if isinstance(pd, dict):
            pc = _int(pd.get("campaign_calls") or pd.get("total_calls"))
            status_ok = str(pd.get("campaign_status") or "").strip().lower() not in ("fail", "failed", "error", "counterexample")
            no_cex = not pd.get("counterexample")
            if pc and status_ok and no_cex:
                if check_fresh:
                    if _harness_source_fresh(ws, harness_dir, str(pd.get("harness") or "")) is not False:
                        best = max(best, pc)
                else:
                    best = max(best, pc)
    return best


def _mvc_sidecar_calls(ws: Path, harness_dir: Path) -> int:
    """Max machine-readable executed-call count recorded in an mvc_sidecar mapping
    to THIS harness dir.

    Serving-join (Strata 2026-07-07): a step-4b lane recorded its real 1.2M medusa
    campaign under the mvc_sidecar `medusa_campaign.calls_executed` field (with a
    corpus_dir + FNDA evidence proving the run happened), but _campaign_call_metrics
    only read the fuzz_campaign_receipt.json + *.log files - so the count was
    invisible and the >=1M floor read UNVERIFIABLE (corpus-only-no-counter),
    false-red-ing a genuine campaign. NEVER-FALSE: credits a count ONLY from a
    sidecar that (a) maps to this harness dir and (b) carries EXECUTION EVIDENCE (a
    corpus_dir / fnda_evidence / properties_passed>0) - never a bare integer with no
    proof the engine ran."""
    sc_dir = ws / ".auditooor" / "mvc_sidecar"
    if not sc_dir.is_dir():
        return 0
    hd_sols = {p.name for p in harness_dir.glob("*.sol")}
    hd_stems = {p.stem for p in harness_dir.glob("*.sol")}
    best = 0
    for sc in sorted(sc_dir.glob("*.json")):
        try:
            d = json.loads(sc.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(d, dict):
            continue
        mc = d.get("medusa_campaign") if isinstance(d.get("medusa_campaign"), dict) else {}
        hp = Path(str(d.get("harness_path") or "")).name
        cmd = str(d.get("harness") or "") + " " + str(d.get("runner_command") or "")
        cfg = str(mc.get("config") or "") + " " + str(mc.get("corpus_dir") or "")
        mapped = (hp in hd_sols) or any(st in cmd for st in hd_stems) \
            or any(st in cfg for st in hd_stems) or (harness_dir.name in cfg)
        if not mapped:
            continue
        # execution-evidence guard: a count is only credited when a real run backs it.
        has_exec = bool(mc.get("corpus_dir")) or bool(mc.get("fnda_evidence")) \
            or int(mc.get("properties_passed") or 0) > 0
        if not has_exec:
            continue
        # include `call_count` (a real medusa sidecar sometimes records under it) -
        # consistency with _sidecar_cleared_call_floor; still execution-evidence gated above.
        for c in (mc.get("calls_executed"), mc.get("campaign_calls"), mc.get("call_count"),
                  d.get("campaign_calls"), d.get("executed_calls"), d.get("calls_executed"),
                  d.get("call_count")):
            try:
                n = int(c)
            except (TypeError, ValueError):
                continue
            if n > best:
                best = n
    return best


def _campaign_call_metrics(ws: Path, harness_dir: Path) -> tuple[int, bool]:
    """(max_executed_call_count, any_dry_run_manifest) across the campaign
    artifacts/logs reachable from this harness. The dry-run flag hard-fails the
    gate even if some other artifact shows execution (a skipped manifest sitting
    next to a real one is still an honesty smell we surface). The machine-readable
    fuzz_campaign_receipt.json AND a harness-mapped mvc_sidecar's recorded
    medusa_campaign.calls_executed are consulted too (structured call counters are
    the canonical evidence the gate asks for, not just a greppable log line)."""
    max_calls = max(_receipt_calls_for_harness(ws, harness_dir),
                    _mvc_sidecar_calls(ws, harness_dir))
    dry_run = False
    texts: list[str] = []
    deng = ws / ".auditooor" / "deep-engine-findings"
    if deng.is_dir():
        for p in list(deng.glob("*.md")) + list(deng.glob("*.txt")):
            try:
                texts.append(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
    for base in (harness_dir, harness_dir.parent, harness_dir.parent.parent,
                 ws / ".auditooor",
                 ws / ".auditooor" / "fuzz_logs",   # canonical (persist-fuzz-campaign target)
                 ws / ".auditooor" / "fuzz-logs",   # legacy hyphen spelling
                 ws / ".auditooor" / "fuzz_runs"):
        if not base or not base.is_dir():
            continue
        for p in (list(base.glob("*medusa*.log")) + list(base.glob("*echidna*.log"))
                  + list(base.glob("status.txt")) + list(base.rglob("status.txt"))):
            if not p.is_file():
                continue
            try:
                texts.append(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
    for t in texts:
        max_calls = max(max_calls, _executed_call_count(t))
        if _artifact_is_dry_run(t):
            dry_run = True
    return max_calls, dry_run


def _engine_evidence(ws: Path, harness_dir: Path) -> list[str]:
    """Real evidence a coverage-guided engine RAN: corpus dirs (medusa/echidna),
    a deep-engine fuzz artifact, or a recorded engine log. An artifact/log only
    counts when its content proves the engine EXECUTED call sequences (not a
    setup-failure / 0-call run) - see _artifact_shows_execution."""
    ev = []
    # medusa/echidna corpus dirs near the harness. A corpus dir is only written
    # by an engine that actually generated call sequences, so a NON-EMPTY corpus
    # (>=1 file with content) is genuine execution evidence on its own.
    for base in (harness_dir, harness_dir.parent, harness_dir.parent.parent):
        if not base or not base.is_dir():
            continue
        for name in ("corpus", "medusa-corpus", "echidna-corpus", "crytic-export"):
            d = base / name
            if d.is_dir() and any(p.is_file() and p.stat().st_size > 0 for p in d.rglob("*")):
                ev.append(f"corpus:{d.relative_to(ws) if str(ws) in str(d) else d}")
    # deep-engine fuzz artifact in the workspace - content must prove execution.
    deng = ws / ".auditooor" / "deep-engine-findings"
    if deng.is_dir():
        for p in deng.glob("*.md"):
            low = p.name.lower()
            if ("fuzz" in low or "solvency" in low or "invariant" in low) and p.stat().st_size > 200:
                try:
                    txt = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _artifact_shows_execution(txt):
                    ev.append(f"artifact:{p.name}")
                    break
    # r36-rebuttal: lane FIX-INVARIANT-FUZZ-GATE registered in .auditooor/agent_pathspec.json
    # recorded engine logs (medusa/echidna) IN THE WORKSPACE (never a hardcoded
    # /tmp path - evidence must live with the workspace to be reproducible). The
    # log content must prove the engine executed (not a 429/setup-failure log).
    for logdir in (ws / ".auditooor", ws / ".auditooor" / "fuzz-logs", harness_dir):
        if logdir.is_dir():
            for p in list(logdir.glob("*medusa*.log")) + list(logdir.glob("*echidna*.log")):
                if p.stat().st_size > 50:
                    try:
                        txt = p.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    if _artifact_shows_execution(txt):
                        ev.append(f"log:{p.name}")
                        break
    return sorted(set(ev))


# r36-rebuttal: lane FIX-INVARIANT-FUZZ-DEPTH registered in .auditooor/agent_pathspec.json
_SEQLEN_RE = re.compile(r'"?(?:callSequenceLength|seqLen)"?\s*[:=]\s*"?(\d+)', re.I)
# a fuzz ACTION = a public, non-view, non-property/test function in the harness
_ACTION_RE = re.compile(
    r"function\s+(\w+)\s*\([^)]*\)\s*(?:external|public)(?![^{;]*\bview\b)(?![^{;]*\bpure\b)", re.M)
_NON_ACTION_PREFIX = ("property_", "echidna_", "invariant_", "test_", "setUp", "_")


def _multistep_depth(harness_dir: Path) -> tuple[int, int]:
    """Return (max_seqlen_from_engine_config, distinct_fuzz_action_count)."""
    seqlen = 0
    for base in (harness_dir, harness_dir.parent, harness_dir.parent.parent):
        if not base or not base.is_dir():
            continue
        for cfg in list(base.glob("medusa.json")) + list(base.glob("echidna.yaml")) + list(base.glob("*.yaml")):
            for mm in _SEQLEN_RE.finditer(_read(cfg)):
                seqlen = max(seqlen, int(mm.group(1)))
    actions: set[str] = set()
    for p in harness_dir.glob("*.sol"):
        for mm in _ACTION_RE.finditer(_read(p)):
            name = mm.group(1)
            if not name.startswith(_NON_ACTION_PREFIX):
                actions.add(name)
    return seqlen, len(actions)


# G8 (2026-06-27): credit the durable mvc_sidecar (schema
# auditooor.mutation_verify_coverage.v1) + the sidecar's real baseline run, so a
# harness mutation-verified by tools/mutation-verify-coverage.py is credited even
# when the non-vacuity proof is NOT an in-tree `test_mutation_breaks_*` fn. This is
# the same serving-join class as check_live_engines' _standalone_coverage_campaign.
# NEVER-FALSE-PASS: mut credit requires >=1 mutant killed via a GENUINE
# invariant/property ASSERTION failure - a kill that is only a setUp()/compile/
# CastOverflow revert does NOT prove the invariant catches a behaviour change
# (R80 / coverage-theater guard).
_MVC_SCHEMA = "auditooor.mutation_verify_coverage.v1"


def _is_genuine_invariant_kill(tail: str) -> bool:
    """True iff the failing mutant output shows an actual invariant/property
    assertion failing - NOT merely a setUp()/compile/cast revert that broke the
    harness scaffold (which proves nothing about the invariant's catching power).

    P0-d: delegates to the promoted shared predicate in tools/lib/mutation_kill.py
    (single source of truth). The inline body is kept ONLY as a fail-open fallback
    for when the shared module cannot be loaded - it is byte-equivalent to the
    promoted copy."""
    if _MUTATION_KILL_MOD is not None:
        try:
            return bool(_MUTATION_KILL_MOD._is_genuine_invariant_kill(tail))
        except Exception:  # noqa: BLE001
            pass
    t = tail or ""
    low = t.lower()
    if "fail" not in low:
        return False
    has_assertion = any(tok in t for tok in ("invariant_", "property_", "echidna_"))
    if not has_assertion:
        return False
    if "setUp()" in t and not re.search(
            r"(?:invariant_|property_|echidna_)\w*\s*\(\)[^\n]*(?:fail|FAIL)", t):
        if re.search(r"\bsetUp\(\)\b[^\n]*(?:fail|FAIL)", t):
            return False
    return True


def _sidecar_is_genuine(d: dict) -> bool:
    """Canonical mvc_sidecar credit predicate (caveat A schema normalization),
    delegated to the shared tools/lib/mutation_kill.py so producer + all readers
    agree. Fail-closed False fallback when the shared lib is unavailable (the
    schema-specific loop above is the backstop credit path)."""
    if _MUTATION_KILL_MOD is not None:
        try:
            return bool(_MUTATION_KILL_MOD.sidecar_is_genuine(d))
        except Exception:  # noqa: BLE001
            pass
    return False


def _mvc_sidecar_credit(ws: Path, hd: Path) -> tuple[bool, list[str]]:
    """(mut_credit, engine_evidence) from durable mvc_sidecar records mapping to
    this harness dir. Sound per the block comment above."""
    sc_dir = ws / ".auditooor" / "mvc_sidecar"
    if not sc_dir.is_dir():
        return False, []
    hd_sols = {p.name for p in hd.glob("*.sol")}
    hd_stems = {p.stem for p in hd.glob("*.sol")}
    mut_credit = False
    ev: list[str] = []
    for sc in sorted(sc_dir.glob("*.json")):
        try:
            d = json.loads(sc.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(d, dict):
            continue
        # Dual-schema credit (corecov_cluster_sidecar_credit_fix class): the
        # canonical auto-producer schema (_MVC_SCHEMA) is fast-pathed; a durable
        # sidecar in ANOTHER schema (e.g. mvc_sidecar_v1 cluster/manual records)
        # is admitted ONLY when the SHARED canonical predicate _sidecar_is_genuine
        # adjudicates it genuine - the SAME bar the other readers (core-coverage /
        # engine-harness-proof / audit-honesty) already apply. Without this, a
        # genuine cluster harness mutation-verified by the manual/cluster producer
        # was skipped here purely on schema string, leaving invariant-fuzz red while
        # core-coverage credited the very same sidecar (the 4th-gate blind spot).
        # NEVER-FALSE-PASS: a non-genuine record (0-kill / vacuous) still returns
        # False from _sidecar_is_genuine and is skipped exactly as before.
        if d.get("schema") != _MVC_SCHEMA and not _sidecar_is_genuine(d):
            continue
        # map this sidecar to THIS harness dir: the verified harness file/command
        # must reference a .sol that lives in hd.
        hp = Path(str(d.get("harness_path") or "")).name
        cmd = str(d.get("harness") or "") + " " + str(d.get("runner_command") or "")
        mapped = (hp in hd_sols) or any(st in cmd for st in hd_stems)
        if not mapped:
            continue
        # engine evidence: a baseline run that PASSED + executed (proves the harness
        # actually ran the invariants, not a 0-call/setup-fail).
        base = d.get("baseline") or {}
        if str(base.get("status")) == "pass" and _artifact_shows_execution(
                str(base.get("output_tail") or "")):
            ev.append(f"mvc-baseline:{sc.name}")
        # mut credit: >=1 mutant killed via a GENUINE invariant-assertion failure.
        for m in (d.get("mutant_results") or []):
            if m.get("killed") and _is_genuine_invariant_kill(str(m.get("output_tail") or "")):
                mut_credit = True
                ev.append(f"mvc-kill:{sc.name}")
                break
        # caveat A (schema normalization): ALSO credit via the CANONICAL predicate so a
        # genuine sidecar in the OTHER schema (auto-producer verdict=='non-vacuous' +
        # killed_count, or cluster mutation_verified + mutation_detail) is not missed
        # by the assertion-tail-only loop above (serving-join). Additive + fail-closed:
        # sidecar_is_genuine requires verdict=='non-vacuous'/mutation_verified AND a
        # real kill, so a vacuous / 0-kill record still credits nothing.
        if not mut_credit and _sidecar_is_genuine(d):
            mut_credit = True
            ev.append(f"mvc-kill:{sc.name}")
    return mut_credit, sorted(set(ev))


def _harness_dir_non_economic_disposition(ws: Path, hd: Path, dispositions: list) -> dict | None:
    """Return the disposition crediting this harness dir as non-economic, or None.

    Eligible ONLY when EVERY .sol in the harness dir is an AUTO-GENERATED scaffold
    (per-function-invariant-gen header) AND every such scaffold's contract-under-
    test maps to an accepted non-economic disposition. A hand-authored harness, or
    a scaffold over a non-dispositioned (value-moving) contract, is NOT credited -
    it still has to pass the real economic-invariant bar.

    Mapping: a scaffold's CUT file is read from its `Function under test: ... at
    <path>` header line; if absent we fall back to the harness dir's own repo
    segment. Either path is then matched against the accepted dispositions."""
    if _NED_MOD is None or not dispositions:
        return None
    # Only the .sol files that CONTRIBUTE invariant-property functions are what made
    # this a harness dir; hand-authored forge unit tests (test_ only) in the same
    # dir are irrelevant to the economic-invariant bar and are ignored. A dir is
    # eligible iff EVERY property-contributing file is an AUTO-GENERATED scaffold
    # whose contract-under-test maps to an accepted disposition. A genuine
    # hand-authored property_/invariant_/echidna_ harness blocks the credit (it
    # must pass the real bar), and a scaffold over a non-dispositioned (value-
    # moving) contract blocks it too.
    prop_files = [p for p in hd.glob("*.sol") if _PROP_RE.search(_read(p))]
    if not prop_files:
        return None
    matched: dict | None = None
    for p in prop_files:
        txt = _read(p)
        if _AUTOGEN_SCAFFOLD_MARKER not in txt:
            return None  # a genuine (non-scaffold) invariant harness -> not eligible
        cut_rel = ""
        m = re.search(r"Function under test:[^\n]*\bat\s+([^\s:]+\.sol)", txt)
        if m:
            cut_rel = m.group(1)
            try:
                cut_rel = str(Path(cut_rel).resolve().relative_to(ws.resolve()))
            except (ValueError, OSError):
                pass
        match_target = cut_rel or str(hd.relative_to(ws) if str(ws) in str(hd) else hd)
        disp = _NED_MOD.file_is_dispositioned(match_target, dispositions)
        if disp is None:
            return None  # a scaffold whose CUT is not dispositioned -> not eligible
        matched = disp
    return matched


# ---------------------------------------------------------------------------
# Asset-centric coverage (2026-07-02): enumerate value-moving in-scope FILES and
# subtract the harness CUT set actually fuzzed. All-language safe: gated on the
# value_moving_functions.json / inscope manifests that the funnel produces for
# every workspace regardless of language; when either manifest is absent the check
# is a no-op (returns no gaps + not-applicable), never a false-fail.
# ---------------------------------------------------------------------------
def _norm_rel(ws: Path, path: str) -> str:
    """Best-effort workspace-relative normalization of a file path so paths from
    different manifests (absolute vs relative) compare equal."""
    if not path:
        return ""
    p = str(path).replace("\\", "/").strip()
    try:
        rp = Path(p)
        if rp.is_absolute():
            return str(rp.resolve().relative_to(ws.resolve())).replace("\\", "/")
    except (ValueError, OSError):
        pass
    return p.lstrip("./")


# Value-moving SOURCE signals the value_moving_functions.json producer's
# transfer_hit/ledger_write_hit heuristic under-detects (Strata 2026-07-07: the
# whole re-scope successor DiscreteAccounting - which computes the NAV split - plus
# StrataCDO / SharesCooldown / the strategies were NOT in the value-moving set, so
# their total absence of an economic-invariant harness never lowered the coverage
# fraction and invariant-fuzz/core-coverage FALSELY reported "5/6 covered, complete").
# An external/public non-view function that (a) is a recognized ERC4626/vault/cooldown
# value-mover by name, OR (b) sends value / writes the accounting ledger in its body,
# marks the FILE value-moving. Superset detector: it can only ADD files to the
# must-be-covered denominator -> never-false-pass (strictly harder, never greener).
_VM_FN_NAMES = (
    "deposit", "mint", "withdraw", "redeem", "finalize", "finalizewithfee",
    "finalizewithtokenoverride", "finalizelatesettlement", "cancel", "request",
    "reducereserve", "accruefee", "updatebalanceflow", "updateaccounting",
    "transfer", "transferfrom", "swap", "exactinputsingle", "rebalance",
    "claim", "unstake", "settle",
)
_VM_FN_RE = re.compile(
    r"function\s+(\w+)\s*\([^)]*\)\s*(?:external|public)(?![^{;]*\bview\b)(?![^{;]*\bpure\b)",
    re.I)
_VM_BODY_RE = re.compile(
    r"\bsafeTransfer\w*\s*\(|\.transfer\s*\(|\.call\s*\{\s*value|"
    r"calculateNAVSplit|splitValuatedNavOut|\bnav\s*=|jrtNav\w*\s*=|srtNav\w*\s*=|"
    r"reserveNav\w*\s*=|_mint\s*\(|_burn\s*\(", re.I)


def _source_value_moving_files(ws: Path, inscope: set[str]) -> set[str]:
    """In-scope .sol files that move/account value by SOURCE scan (superset of the
    JSON producer). Never-false: only files with a real external value-mover
    signal are added; a pure view/config file matches nothing."""
    out: set[str] = set()
    for rel in inscope:
        p = ws / rel
        if not (p.is_file() and rel.endswith(".sol")):
            continue
        try:
            txt = _strip_sol_comments(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        ext_fns = [m.group(1).lower() for m in _VM_FN_RE.finditer(txt)]
        name_hit = any(fn in _VM_FN_NAMES for fn in ext_fns)
        # body signal only counts inside an external/public non-view fn context
        body_hit = bool(ext_fns) and bool(_VM_BODY_RE.search(txt))
        if name_hit or body_hit:
            out.add(rel)
    return out


def _value_moving_inscope_files(ws: Path) -> set[str]:
    """Set of value-moving in-scope FILES: value_moving_functions.json entries with
    transfer_hit or ledger_write_hit, UNIONED with a source-scan superset (the JSON
    producer under-detects accounting-writers / delegating orchestrators / external-
    call value-movers), intersected with the inscope_units manifest."""
    vm: set[str] = set()
    vmf = ws / ".auditooor" / "value_moving_functions.json"
    if vmf.is_file():
        try:
            d = json.loads(vmf.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            d = {}
        for fn in (d.get("functions") or []):
            if isinstance(fn, dict) and (fn.get("transfer_hit") or fn.get("ledger_write_hit")):
                f = _norm_rel(ws, str(fn.get("file") or ""))
                if f:
                    vm.add(f)
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    inscope: set[str] = set()
    if manifest.is_file():
        for ln in _read(manifest).splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                u = json.loads(ln)
            except ValueError:
                continue
            f = _norm_rel(ws, str(u.get("file") or ""))
            if f:
                inscope.add(f)
    # source-scan superset (only over the in-scope set so we never widen scope)
    vm |= _source_value_moving_files(ws, inscope or vm)
    if inscope:
        vm &= inscope
    return vm


def _sidecar_cleared_call_floor(ws: Path, d: dict) -> bool:
    """True iff this mvc_sidecar carries REAL fuzz-DEPTH evidence that meets the engine
    call floor (medusa / go-native >=MIN_CALLS, echidna >=MIN_CALLS_ECHIDNA).

    DECOUPLES fuzz-depth asset-coverage from mutation-QUALITY. A sidecar can be
    genuinely mutation_verified (it catches a behaviour change) yet SHALLOW - e.g. a
    forge invariant `runs:256` = 128k calls emitted as mode='manual-mutant-harness'
    with NO campaign_calls. Mutation-verification alone must NEVER close a >=1M
    fuzz-DEPTH asset gap (nuva 2026-07: DepositorFactory/WithdrawalFactory were
    falsely credited by 128k forge sidecars). This is the DEPTH check; the sidecar
    still legitimately credits the MUTATION gates elsewhere - those are untouched.

    Returns False when there is NO campaign call evidence at all (NEVER a vacuous
    default-True). PRESERVED legit case: a count proven via a separately credited
    fuzz_campaign_receipt CUT for the same harness still clears the floor (transitive
    credit rides the SAME floor the direct-credit path enforces)."""
    if not isinstance(d, dict):
        return False
    mc = d.get("medusa_campaign") if isinstance(d.get("medusa_campaign"), dict) else {}
    engine = str(d.get("engine") or mc.get("engine") or "").strip().lower()
    is_echidna = "echidna" in engine
    floor = MIN_CALLS_ECHIDNA if is_echidna else MIN_CALLS
    # structured executed-call counters (same fields _mvc_sidecar_calls reads).
    # A forge-invariant `runs:256` (=128k) or a no-campaign manual-mutant-harness
    # yields best=0 or <floor -> does NOT clear the medusa depth floor.
    best = 0
    # `call_count` is the field a real medusa/echidna sidecar sometimes records the
    # executed count under (nuva mvc-src-crosschainvaulthandler: engine=medusa,
    # call_count=1,225,621) - reading only campaign_calls/calls_executed left a genuine
    # >=1M campaign invisible (serving-join false-red). The floor+engine gate below
    # still rejects any shallow call_count (a forge 128k never clears the medusa floor).
    for c in (mc.get("calls_executed"), mc.get("calls"), mc.get("campaign_calls"),
              mc.get("call_count"),
              d.get("campaign_calls"), d.get("executed_calls"), d.get("calls_executed"),
              d.get("calls"), d.get("call_count")):
        try:
            n = int(c)
        except (TypeError, ValueError):
            continue
        if n > best:
            best = n
    if best >= floor:
        return True
    # external-receipt-proven case (comment at _mutation_verified_harness_sources):
    # the harness this sidecar rides has a credited fuzz_campaign_receipt campaign
    # that met the floor - calls proven elsewhere, so the depth floor is cleared.
    hp = str(d.get("harness_path") or d.get("harness") or "")
    if hp:
        harness_dir = (ws / hp).parent
        try:
            if _receipt_calls_for_harness(ws, harness_dir) >= floor:
                return True
        except Exception:
            pass
    return False


def _fuzzed_cut_files(ws: Path) -> set[str]:
    """Set of value-moving CUT FILES that have a REAL harness: a
    fuzz_campaign_receipt campaign with a >=MIN_CALLS (>=MIN_CALLS_ECHIDNA for
    echidna) run, PLUS every mvc_sidecar source_file WHOSE OWN CAMPAIGN cleared the
    engine call floor (mutation-verification alone is NOT enough - fuzz-depth
    coverage requires depth evidence, see _sidecar_cleared_call_floor). Only
    campaigns whose executed call count clears the engine floor are credited so a
    500K medusa smoke, a 128k forge-invariant mutant harness, or a dry-run cut is
    NOT counted as covered."""
    covered: set[str] = set()
    # in-scope .sol rel-paths, for the never-false filename-fallback below
    _inscope: set[str] = set()
    _man = ws / ".auditooor" / "inscope_units.jsonl"
    if _man.is_file():
        for _ln in _read(_man).splitlines():
            _ln = _ln.strip()
            if not _ln:
                continue
            try:
                _u = json.loads(_ln)
            except ValueError:
                continue
            _f = _norm_rel(ws, str(_u.get("file") or ""))
            if _f and _f.endswith(".sol"):
                _inscope.add(_f)
    rec = ws / ".auditooor" / "fuzz_campaign_receipt.json"
    if rec.is_file():
        try:
            d = json.loads(rec.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            d = {}
        for c in (d.get("campaigns") or []):
            if not isinstance(c, dict):
                continue
            cut = _norm_rel(ws, str(c.get("cut") or ""))
            if not cut:
                continue
            calls = _int((c.get("result") or {}).get("calls")) if isinstance(c.get("result"), dict) else 0
            engine = str(c.get("engine") or "").lower()
            floor = MIN_CALLS_ECHIDNA if "echidna" in engine else MIN_CALLS
            if calls >= floor:
                covered.add(cut)
    sc_dir = ws / ".auditooor" / "mvc_sidecar"
    if sc_dir.is_dir():
        for sc in sc_dir.glob("*.json"):
            try:
                d = json.loads(sc.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            if not isinstance(d, dict):
                continue
            # DEPTH GATE (nuva 2026-07): fuzz-depth asset-coverage requires the
            # sidecar's OWN campaign to clear the engine call floor - a
            # mutation-verified-but-shallow harness (128k forge invariant / no-campaign
            # manual-mutant-harness) must NOT close a >=1M asset gap. It still credits
            # the MUTATION gates elsewhere; only this fuzz-DEPTH credit is withheld.
            if not _sidecar_cleared_call_floor(ws, d):
                continue
            # a mutation-verified sidecar proves the harness catches a behaviour
            # change on that source file - credit its source_file / cut.
            hit = False
            for key in ("source_file", "cut", "cut_files", "match_path", "contract"):
                v = d.get(key)
                for cand in (v if isinstance(v, list) else [v]):
                    f = _norm_rel(ws, str(cand or ""))
                    if f:
                        covered.add(f)
                        hit = True
            # SERVING-JOIN FALLBACK (Strata 2026-07-07): agents emit a real
            # mutation-verified mvc sidecar (mutation_verified/non-vacuous kill) but
            # sometimes with an EMPTY source_file/cut (SharesCooldown/StrataCDO fuzz
            # lanes), so the credit-join had nothing to map and a genuine >=1M
            # mutation-verified harness read as "no economic-invariant harness".
            # When no path field resolved, infer the CUT from the sidecar's harness/
            # function fields or its FILENAME stem, matched against an in-scope .sol
            # basename. NEVER-FALSE: only credits a sidecar that is genuinely
            # mutation-verified (or a non-vacuous behaviour-changing kill) AND whose
            # inferred token matches a REAL in-scope file basename - a stray name
            # credits nothing.
            if not hit:
                _bck = _int(d.get("behavior_changing_kill_count"))
                mv = bool(d.get("mutation_verified")) or (
                    str(d.get("verdict") or "").strip().lower() == "non-vacuous" and _bck >= 1)
                if mv:
                    tokens = []
                    for key in ("harness", "harness_path", "function", "target", "cut_primary"):
                        tokens.append(str(d.get(key) or ""))
                    tokens.append(sc.stem)  # mvc-src-<name> / mvc-<name> / mvc-orch-<fn>
                    stems = {re.sub(r"[^a-z0-9]", "", t.rsplit("/", 1)[-1].lower()) for t in tokens if t}
                    for rel in _inscope:
                        base = re.sub(r"\.sol$", "", Path(rel).name.lower())
                        base_n = re.sub(r"[^a-z0-9]", "", base)
                        if base_n and any(base_n in s for s in stems):
                            covered.add(rel)
    return covered


def _mutation_verified_harness_sources(ws: Path) -> list[Path]:
    """Harness .sol source paths whose mvc_sidecar is mutation-verified (mutation_verified
    True, or non-vacuous with >=1 behaviour-changing kill) AND whose medusa_campaign
    cleared the call floor. Only these harnesses can lend TRANSITIVE credit."""
    out: list[Path] = []
    sc_dir = ws / ".auditooor" / "mvc_sidecar"
    if not sc_dir.is_dir():
        return out
    for sc in sc_dir.glob("*.json"):
        try:
            d = json.loads(sc.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(d, dict):
            continue
        bck = _int(d.get("behavior_changing_kill_count"))
        mv = bool(d.get("mutation_verified")) or (
            str(d.get("verdict") or "").strip().lower() == "non-vacuous" and bck >= 1) or (
            str(d.get("verdict") or "").strip().lower() == "non-vacuous")
        if not mv:
            continue
        # accept ONLY if the sidecar's own campaign cleared the floor, OR the harness is
        # a credited receipt CUT (calls proven elsewhere) - the transitive credit rides
        # the SAME floor the direct-credit path enforces. A no-campaign sidecar no longer
        # vacuously passes (nuva 2026-07: floor_ok defaulted True when calls was absent,
        # lending transitive credit off a 128k mutant harness with no depth evidence).
        if not _sidecar_cleared_call_floor(ws, d):
            continue
        hp = str(d.get("harness_path") or d.get("harness") or "")
        cmd = str(d.get("runner_command") or "")
        blob = hp + " " + cmd
        resolved: Path | None = None
        # (1) a direct .sol path in the harness/command
        m = re.search(r"([\w./-]+\.sol)", blob)
        if m:
            cand = _norm_rel(ws, m.group(1))
            p = ws / cand if cand else None
            if p and p.is_file():
                resolved = p
        # (2) a directory-scoped forge runner: --match-path 'Dir/*' or chimera_harnesses/Dir
        if resolved is None:
            dm = re.search(r"chimera_harnesses/([A-Za-z][\w.-]+)", blob) or \
                 re.search(r"--match-path\s+['\"]?([A-Za-z][\w.-]+)/", blob) or \
                 re.search(r"--match-contract\s+([A-Za-z]\w+)", blob)
            if dm:
                dname = dm.group(1)
                cand = ws / "chimera_harnesses" / dname / f"{dname}.sol"
                if cand.is_file():
                    resolved = cand
        if resolved is not None:
            out.append(resolved)
    return out


def _transitively_covered_files(ws: Path, vm: set[str]) -> dict:
    """value-moving in-scope files covered TRANSITIVELY: a mutation-verified, floor-cleared
    harness that (a) imports the file AND (b) directly DEPLOYS its contract via `new <C>(`.

    NEVER-FALSE (Strata serving-join 2026-07-07): the invariant-fuzz gate credited only a
    harness's PRIMARY cut (the receipt/mvc `cut`), so a cooldown impl that a StrategyConservation
    harness imports + `new`-deploys + drives via an h_*Cooldown action (and names in its
    no-overclaim invariant) read as an uncovered gap. `new <Contract>(` is the anchor: it
    proves the REAL contract is deployed (a mock would be `new Mock<X>(`, a different stem),
    so the harness's floor-cleared mutation-verified campaign exercises that file's code. A
    file merely imported for a type (no `new`) is NOT credited."""
    credited: dict[str, str] = {}
    if not vm:
        return credited
    # in-scope value-moving files keyed by contract stem (basename w/o .sol)
    by_stem: dict[str, str] = {}
    for f in vm:
        stem = re.sub(r"\.sol$", "", Path(f).name)
        if stem:
            by_stem[stem] = f
    for hp in _mutation_verified_harness_sources(ws):
        try:
            src = hp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for stem, f in by_stem.items():
            if f in credited:
                continue
            # (a) imports a path ending in /<stem>.sol  AND  (b) `new <stem>(` deploy
            if re.search(r"import\b[^;]*?/" + re.escape(stem) + r"\.sol", src) and \
               re.search(r"\bnew\s+" + re.escape(stem) + r"\s*\(", src):
                try:
                    credited[f] = str(hp.relative_to(ws))
                except ValueError:
                    credited[f] = str(hp)
    return credited


def _campaign_log_texts(ws: Path, campaign: dict) -> list[tuple[str, str]]:
    """Collect (log_name, text) pairs that could be THIS campaign's runner log.

    A campaign's runner log lives under .auditooor/fuzz_logs/ (or fuzz-logs/,
    fuzz_runs/, or the receipt's evidence[] paths). We map a log to a campaign by
    (a) the harness/contract stem appearing in the log text or the log filename, or
    (b) the campaign name appearing in the log text/filename. Also always include
    the aggregate `_campaign_index.log` (the canonical per-campaign tail index),
    scoped later by the stem/name match on its text.

    Returns EVERY candidate log so the reconciler can take the max `Total calls`
    across all of them; a campaign with no candidate log yields []."""
    name = str(campaign.get("name") or "")
    hp = str(campaign.get("harness_path") or campaign.get("harness") or "")
    hstem = Path(hp).stem if hp else ""
    # a receipt often names the CUT contract inside the harness stem
    # (SSVClusterSolvencyMedusa -> matches contract=SSVClusterSolvencyMedusa in the
    # index log). Build a set of match tokens (lower-cased) for this campaign.
    tokens = {t.lower() for t in (name, hstem) if t}
    # also add the harness_contract if present (cluster-sidecar convention)
    hc = str(campaign.get("harness_contract") or "")
    if hc:
        tokens.add(hc.lower())
    log_dirs = [
        ws / ".auditooor" / "fuzz_logs",
        ws / ".auditooor" / "fuzz-logs",
        ws / ".auditooor" / "fuzz_runs",
    ]
    candidates: list[Path] = []
    for base in log_dirs:
        if base.is_dir():
            candidates.extend(sorted(base.glob("*.log")))
            candidates.extend(sorted(base.glob("*.txt")))
    # receipt evidence[] may point at a specific log file or dir. Only LOG-shaped
    # evidence counts (a .sol/.t.sol harness pointer is NOT a runner log; treating it
    # as a 0-count log would false-flag a campaign whose real log is named
    # differently - report that as no-log/advisory instead).
    for ev in (campaign.get("evidence") or []):
        if not isinstance(ev, str):
            continue
        p = (ws / ev) if not os.path.isabs(ev) else Path(ev)
        if p.is_file() and p.suffix.lower() in (".log", ".txt"):
            candidates.append(p)
        elif p.is_dir():
            candidates.extend(sorted(p.glob("*.log")))
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    # a per-campaign runner log is small (tens of KB). A multi-MB file is an
    # aggregate audit_deep.log / debug dump - skip it (reading a 36MB file per
    # campaign is slow and it carries no per-campaign `Total calls` summary anyway).
    _MAX_LOG_BYTES = 8 * 1024 * 1024
    for p in candidates:
        rp = str(p.resolve())
        if rp in seen or not p.is_file():
            continue
        seen.add(rp)
        try:
            if p.stat().st_size > _MAX_LOG_BYTES:
                continue
            txt = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        fname = p.name.lower()
        # aggregate campaign-index log: read ONLY this campaign's block (a
        # concatenation of many campaigns must not cross-credit another's count).
        block = _slice_index_block(txt, tokens)
        if block is not None:
            out.append((p.name, block))
            continue
        # single-campaign log: match by a campaign token in the filename OR text.
        matched = any(t in fname for t in tokens) or any(t in txt.lower() for t in tokens)
        if matched:
            out.append((p.name, txt))
    return out


def _max_logged_calls(text: str) -> int:
    """MAX engine call-count parsed from a runner log block.

    Takes the MAX (never the sum) of every `Total calls: N` (echidna/medusa final
    summary), medusa `call_sequences_tested`/`calls tested`, and echidna `fuzzing:
    N/LIMIT` progress counter. Deliberately does NOT reuse _executed_call_count,
    which SUMS the per-invariant forge `calls: N` lines - summing is correct for a
    single forge-invariant run but WRONG for an aggregate `_campaign_index.log` that
    concatenates many campaigns (summing would inflate a per-campaign reconciliation
    and mask an over-claim). Returns 0 when no counter is present."""
    if not text:
        return 0
    text = _strip_ansi(text)  # colored medusa TTY log -> parse like NO_COLOR
    vals: list[int] = [0]
    vals += [_int(m) for m in _TOTAL_CALLS_RE.findall(text)]
    vals += [_int(m) for m in _CALLS_TESTED_RE.findall(text)]
    vals += [_int(m) for m in _SEQ_TESTED_RE.findall(text)]
    # echidna progress line: `fuzzing: 500172/500000` -> the numerator is the
    # executed-so-far count; the final line carries the true total.
    for m in re.finditer(r"fuzzing:\s*([\d,]+)\s*/", text, re.I):
        vals.append(_int(m.group(1)))
    # medusa progress line: `⇾ fuzz: elapsed: 4m39s, calls: 1205872 (4203/sec)`.
    # medusa emits NO `Total calls:` summary line - only this cumulative+monotonic
    # per-tick counter - so without it a genuine >=1M-call medusa campaign reconciles
    # to 0 and its HONEST receipt is false-flagged fuzz-receipt-unreconciled (Strata
    # 2026-07-07: 6 real 1.2M-call medusa campaigns flagged). Scoped to lines carrying
    # `fuzz:` before `calls:` so it never matches forge's bare per-invariant `calls: N`
    # (which must be SUMMED, not maxed); MAX of a cumulative counter == the final total.
    for m in re.finditer(r"fuzz:[^\n]*?\bcalls:\s*([\d,]+)", text, re.I):
        vals.append(_int(m.group(1)))
    return max(vals)


# aggregate campaign-index block header: `=== [ts] campaign <slug> (contract=<C> limit=N) ===`
_INDEX_BLOCK_RE = re.compile(
    r"^===\s*(?:\[[^\]]*\]\s*)?campaign\s+(\S+)\s*\(contract=(\S+)", re.I | re.M)


def _slice_index_block(text: str, tokens: set[str]) -> str | None:
    """If `text` is an aggregate campaign-index log (>=2 `=== ... campaign ... ===`
    block headers), return ONLY the block whose slug or contract matches one of the
    campaign `tokens` (lower-cased) - so a per-campaign reconciliation never reads
    another campaign's `Total calls`. Returns None when the text is not an aggregate
    index (a single-campaign log is read whole) or no block matches this campaign."""
    headers = list(_INDEX_BLOCK_RE.finditer(text))
    if len(headers) < 2:
        return None
    for i, h in enumerate(headers):
        slug = (h.group(1) or "").lower().rstrip(")")
        contract = (h.group(2) or "").lower().rstrip(")")
        start = h.start()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        block = text[start:end]
        # match this campaign iff a token equals/contains the block slug or contract
        if any(t == slug or t == contract or t in contract or contract in t
               or t in slug or slug in t for t in tokens if t):
            return block
    return None


def _reconcile_fuzz_receipt(ws: Path) -> dict:
    """E1: reconcile each fuzz_campaign_receipt campaign's claimed call count against
    the max `Total calls: N` in that campaign's runner log(s).

    Returns {applicable, checked, unreconciled:[...], reason}. A campaign is
    `fuzz-receipt-unreconciled` when its claimed result.calls (or config.testLimit
    when result.calls is absent) is NEITHER within tolerance of ANY per-harness log
    count NOR <= the max logged count for that harness. A claim with a candidate log
    whose max count MATCHES (within tolerance) reconciles. A campaign with NO
    candidate log at all is reported separately as `no-log` (advisory - the run may
    predate log capture) and does NOT by itself flag unreconciled, so an older
    receipt with no logs on disk is never retro-failed."""
    rec = ws / ".auditooor" / "fuzz_campaign_receipt.json"
    if not rec.is_file():
        return {"applicable": False, "checked": 0, "unreconciled": [], "no_log": [], "reason": "no fuzz_campaign_receipt.json"}
    try:
        d = json.loads(rec.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {"applicable": False, "checked": 0, "unreconciled": [], "no_log": [], "reason": "receipt unparseable"}
    campaigns = d.get("campaigns") or []
    if not isinstance(campaigns, list) or not campaigns:
        return {"applicable": False, "checked": 0, "unreconciled": [], "no_log": [], "reason": "no campaigns in receipt"}
    unreconciled: list[dict] = []
    no_log: list[str] = []
    checked = 0
    for c in campaigns:
        if not isinstance(c, dict):
            continue
        result = c.get("result") if isinstance(c.get("result"), dict) else {}
        # a forge-unit-mutation campaign (mode=forge-unit-mutation, mutants_killed)
        # is NOT a coverage-guided fuzz campaign and has no `Total calls` log to
        # reconcile - skip it (result has no `calls` key).
        claimed = None
        if "calls" in result:
            claimed = _int(result.get("calls"))
        elif isinstance(c.get("config"), dict) and "testLimit" in c["config"]:
            claimed = _int(c["config"].get("testLimit"))
        if not claimed:
            continue
        checked += 1
        name = str(c.get("name") or c.get("harness_path") or c.get("harness") or "campaign")
        logs = _campaign_log_texts(ws, c)
        if not logs:
            no_log.append(name)
            continue
        log_counts = {ln: _max_logged_calls(txt) for ln, txt in logs}
        max_logged = max(log_counts.values()) if log_counts else 0
        # a claim reconciles when it is within tolerance of SOME log count, OR it is
        # <= the max logged count for the harness (a smaller claim than what the log
        # proves is not a fabrication - it under-states, which is safe).
        tol = max(_RECONCILE_ABS_TOL, int(claimed * _RECONCILE_FRAC_TOL))
        matches_a_log = any(abs(claimed - n) <= tol for n in log_counts.values() if n)
        within_logged = bool(max_logged) and claimed <= max_logged + tol
        if matches_a_log or within_logged:
            continue
        unreconciled.append({
            "campaign": name,
            "claimed_calls": claimed,
            "max_logged_calls": max_logged,
            "logs": sorted(log_counts.keys()),
            "detail": (f"receipt claims {claimed:,} calls but the max 'Total calls' in "
                       f"the runner log(s) is {max_logged:,} (claim appears in NO log "
                       "and exceeds the max logged count)"),
        })
    reason = "all campaigns reconcile" if not unreconciled else (
        f"{len(unreconciled)} campaign(s) fuzz-receipt-unreconciled")
    return {"applicable": True, "checked": checked, "unreconciled": unreconciled,
            "no_log": no_log, "reason": reason}


def _scope_preflight(ws: Path) -> dict:
    """Read .auditooor/invariant_scope_preflight.json (produced by
    invariant-scope-preflight.py). Returns {oos: set, review_dedup: set}. The OOS set is
    AUTHORITATIVE (scope_authority.is_inscope_file=False) and is dropped from the gap list
    with a cite - never-false, since a file the scope manifest calls OOS cannot owe an
    in-scope invariant lane. review_dedup is ADVISORY context only (assets with a prior /
    filed finding - verify-not-dupe before investing), NOT an exemption."""
    p = ws / ".auditooor" / "invariant_scope_preflight.json"
    oos: set[str] = set()
    review: set[str] = set()
    d = None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # SELF-WIRING (operator 2026-07-07): if the preflight artifact is absent, generate
        # it inline so the scope/dedup classification is ALWAYS applied - the enforcement
        # cannot be silently skipped by a missing pre-hunt step. Cheap (file reads +
        # scope_authority); fails open to no-exempt if the tool is unavailable.
        try:
            _isp = _ilu.spec_from_file_location(
                "isp", Path(__file__).resolve().parent / "invariant-scope-preflight.py")
            _m = _ilu.module_from_spec(_isp)
            _isp.loader.exec_module(_m)
            d = _m.check(ws)
        except Exception:  # noqa: BLE001
            return {"oos": oos, "review_dedup": review}
    if not isinstance(d, dict):
        return {"oos": oos, "review_dedup": review}
    for f in (d.get("exempt_oos_files") or []):
        r = _norm_rel(ws, str(f))
        if r:
            oos.add(r)
    for a in (d.get("assets") or []):
        if a.get("classification") == "REVIEW_DEDUP":
            r = _norm_rel(ws, str(a.get("asset") or ""))
            if r:
                review.add(r)
    return {"oos": oos, "review_dedup": review}


# ---------------------------------------------------------------------------
# LLM-hunt-only language coverage (Obyte Oscript AAs et al) - 2026-07-09.
# A language with NO static/fuzz engine (is_llm_hunt_only(lang) True, e.g. Obyte
# Oscript / .oscript / .aa) CANNOT be covered by a medusa/echidna campaign or a
# mutation-verified harness - none can be built for it. Demanding one would either
# false-fail every oscript asset or (worse) silently drop the units. Its coverage
# bar is an LLM HUNT VERDICT: a hunt_findings_sidecar anchored to the file that
# records a real disposition (applies_to_target yes/no/maybe = the unit was
# source-read and adjudicated). Credit such a file as `covered` so the
# asset-coverage denominator never demands an impossible fuzz campaign. FILE
# granularity, matching the rest of this gate. Default-ON; kill-switch
# AUDITOOOR_OSCRIPT_HUNT_COVERAGE=0. NEVER touches an engine language:
# is_llm_hunt_only('.sol')/('.go')/('.rs') is False, so an engine-language file is
# never credited here and Solidity/Go/Rust behaviour is byte-identical.
# ---------------------------------------------------------------------------
def _oscript_hunt_coverage_enabled() -> bool:
    return os.environ.get(
        "AUDITOOOR_OSCRIPT_HUNT_COVERAGE", "1"
    ).strip().lower() not in ("0", "false", "no")


def _llm_hunt_only_covered_files(ws: Path) -> set[str]:
    """In-scope FILES of an LLM-hunt-only language (Obyte Oscript et al) that carry
    a genuine hunt verdict: a hunt_findings_sidecar whose function_anchor.file is
    that file AND whose result has a non-empty applies_to_target. A file with NO
    such sidecar is NOT credited, so a value-moving oscript file that was never
    hunted stays an (advisory) asset gap - no over-credit."""
    covered: set[str] = set()
    if not _oscript_hunt_coverage_enabled():
        return covered
    sc_dir = ws / ".auditooor" / "hunt_findings_sidecars"
    if not sc_dir.is_dir():
        return covered
    for sc in sorted(sc_dir.glob("*.json")):
        try:
            d = json.loads(sc.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(d, dict):
            continue
        fa = d.get("function_anchor")
        if not isinstance(fa, dict):
            continue
        f = str(fa.get("file") or "").strip()
        if not f:
            continue
        lang = _reg_lang_of(f)
        # only an LLM-hunt-only language is credited here (never .sol/.go/.rs).
        if not (lang and _reg_is_llm_hunt_only(lang)):
            continue
        res = d.get("result")
        applies = str(res.get("applies_to_target", "")).strip() if isinstance(res, dict) else ""
        if not applies:
            continue  # a stub with no disposition is not a hunt verdict
        covered.add(_norm_rel(ws, f))
    return covered


def _vmf_stale(ws: Path) -> bool:
    """True when the on-disk value_moving_functions.json predates its PRODUCER
    (tools/value-moving-functions.py). A stale artifact can carry classifier
    false-positives that a later producer fix already dropped (nuva 2026-07-13:
    a Jul-11 artifact still flagged read-only query_server.go / events.go /
    types-genesis.go as value-moving because audit-deep had not re-run since the
    Jul-12 producer FP-fix). Surfaced as an advisory `vmf_stale` field so a gap
    driven by a stale FP is never silently trusted; regenerate via audit-deep
    (which runs value-moving-functions.py) to clear it."""
    vmf = ws / ".auditooor" / "value_moving_functions.json"
    producer = Path(__file__).resolve().with_name("value-moving-functions.py")
    try:
        if not (vmf.is_file() and producer.is_file()):
            return False
        return vmf.stat().st_mtime < producer.stat().st_mtime
    except OSError:
        return False


def _asset_coverage(ws: Path, dispositions: list) -> dict:
    """Compute value-moving in-scope files with no real harness and no typed
    per-asset disposition. Returns {applicable, gaps, value_moving, covered,
    dispositioned}. All-language: a no-op (applicable=False) when no
    value_moving_functions.json exists."""
    vm = _value_moving_inscope_files(ws)
    if not vm:
        return {"applicable": False, "gaps": [], "value_moving": [],
                "covered": [], "dispositioned": []}
    covered = _fuzzed_cut_files(ws)
    transitive = _transitively_covered_files(ws, vm)  # imported + `new`-deployed by a mv harness
    covered |= set(transitive)
    # LLM-hunt-only languages (Obyte Oscript et al) cannot be fuzzed; credit a
    # value-moving file that carries a genuine hunt verdict instead of demanding an
    # impossible medusa/echidna campaign. No-op for an engine-language workspace.
    covered |= _llm_hunt_only_covered_files(ws)
    pf = _scope_preflight(ws)
    residual = sorted(vm - covered)
    gaps: list[str] = []
    dispositioned: list[str] = []
    scope_exempt: list[str] = []
    review_dedup: list[str] = []
    for f in residual:
        if f in pf["oos"]:
            # AUTHORITATIVE scope exemption: an OOS file owes no in-scope invariant lane.
            scope_exempt.append(f)
            continue
        disp = None
        if _NED_MOD is not None and dispositions:
            try:
                disp = _NED_MOD.file_is_dispositioned(f, dispositions)
            except Exception:  # noqa: BLE001
                disp = None
        if disp is not None:
            dispositioned.append(f)
        else:
            gaps.append(f)
            if f in pf["review_dedup"]:
                review_dedup.append(f)  # advisory: dedup-check before investing a lane
    return {"applicable": True, "gaps": gaps, "value_moving": sorted(vm),
            "covered": sorted(covered & vm), "dispositioned": dispositioned,
            "scope_exempt": scope_exempt, "gaps_needing_dedup_review": review_dedup,
            "transitively_covered": transitive, "vmf_stale": _vmf_stale(ws)}


def _go_invariant_fuzz_evidence(ws: Path) -> dict:
    """Evidence that a Go/Cosmos workspace's invariant-fuzz bar is met by the Go arm.

    Returns {go_dominant, go_fraction, mutation_verified, fuzz_campaigns, strong}.
    - go_dominant: >=85% of in-scope units are .go (Solidity engines are N/A to the
      value-moving core). Read from inscope_units.jsonl; conservative False on absence.
    - mutation_verified: App-bound Go economic-invariant mvc_sidecars proven
      non-vacuous (mutation_verified/non_vacuous True, engine/lang go).
    - fuzz_campaigns: go-native coverage-guided fuzz campaigns (engine startswith
      'go-native'), with a real exec count OR coverage-growth evidence.
    - strong: >=3 mutation-verified App-bound invariants OR >=1 go-native fuzz campaign.
    FAIL-OPEN: any parse error yields a non-strong result (the Solidity path runs).
    """
    out = {"go_dominant": False, "go_fraction": 0.0, "mutation_verified": 0,
           "fuzz_campaigns": 0, "strong": False}
    # go-dominance from the in-scope unit manifest
    man = ws / ".auditooor" / "inscope_units.jsonl"
    go = sol = 0
    try:
        for ln in man.read_text(encoding="utf-8", errors="replace").splitlines():
            ls = ln.strip().lower()
            if not ls:
                continue
            if ".go" in ls and '"file"' in ls or ls.endswith('.go"'):
                go += 1
            elif ".sol" in ls:
                sol += 1
    except OSError:
        pass
    tot = go + sol
    if tot:
        out["go_fraction"] = go / tot
        out["go_dominant"] = (go / tot) >= 0.85
    # Go invariant evidence from the mvc_sidecar dir
    mv = 0
    fc = 0
    sdir = ws / ".auditooor" / "mvc_sidecar"
    if sdir.is_dir():
        for p in sorted(sdir.glob("*.json")):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(d, dict):
                continue
            engine = str(d.get("engine") or "").lower()
            lang = str(d.get("lang") or "").lower()
            is_go = "go" in engine or lang == "go"
            if not is_go:
                continue
            if engine.startswith("go-native"):
                # a real coverage-guided campaign: exec count OR growth/PASS evidence
                calls = d.get("campaign_calls") or 0
                if (isinstance(calls, int) and calls > 0) or d.get("fuzztime"):
                    fc += 1
            if d.get("mutation_verified") is True or str(d.get("verdict") or "").lower() == "non-vacuous":
                mv += 1
    out["mutation_verified"] = mv
    out["fuzz_campaigns"] = fc
    out["strong"] = (mv >= 3) or (fc >= 1)
    return out


def evaluate(ws: Path, *, min_invariants: int = MIN_INVARIANTS) -> dict:
    res = {"schema": SCHEMA, "gate": GATE, "workspace": str(ws),
           "verdict": "", "reason": "", "harnesses": []}
    if not ws.is_dir():
        res["verdict"] = "error"
        res["reason"] = f"workspace not found: {ws}"
        return res
    # GO/COSMOS ARM (SEI 2026-07-05): on a Go/Cosmos L1 the value-movers (x/bank,
    # x/staking, x/distribution, x/oracle, precompiles, IBC/wasm keepers) are Go, so
    # the invariant-fuzz bar is met by Go-NATIVE coverage-guided fuzz (go test -fuzz)
    # + mutation-verified App-bound Go economic-invariant harnesses (mvc_sidecar
    # engine go-native-*/go-test), NOT .sol Chimera harnesses. This gate was
    # Solidity-only, so a Go L1 either false-passed (no .sol harness) or hard-failed on
    # a lone vacuous OOS Solidity FIXTURE while ignoring genuine Go invariant work.
    # SAFETY (never false-greens a Solidity audit): fires ONLY when the workspace is
    # GO-DOMINANT (>=85% Go units) AND the Go evidence is genuine (>=3 mutation-verified
    # App-bound Go invariants OR >=1 go-native coverage-guided fuzz campaign). On a
    # Solidity-dominant ws it does nothing and the Solidity logic below runs unchanged.
    # Default-on; env kill-switch AUDITOOOR_GO_INVARIANT_FUZZ=0.
    if os.environ.get("AUDITOOOR_GO_INVARIANT_FUZZ", "1") not in ("0", "false", "no"):
        _ge = _go_invariant_fuzz_evidence(ws)
        if _ge.get("go_dominant") and _ge.get("strong"):
            res["verdict"] = "pass-go-native-invariant-fuzz"
            res["reason"] = (
                f"Go/Cosmos invariant-fuzz met by the Go arm: "
                f"{_ge['mutation_verified']} mutation-verified App-bound economic-invariant "
                f"harness(es) + {_ge['fuzz_campaigns']} go-native coverage-guided fuzz "
                f"campaign(s) over the real value-movers; workspace is "
                f"{_ge['go_fraction']:.0%} Go (Solidity engines N/A to the value-moving core).")
            res["go_invariant_evidence"] = _ge
            return res

    harness_dirs = _find_harness_dirs(ws)
    if not harness_dirs:
        # G1 fix (2026-06-27): the old unconditional pass-no-invariant-harness was
        # a closed-loop fail-open - core-coverage DEFERS the "must actually fuzz"
        # obligation here, so any Solidity ws with no (detected) harness reached
        # honest-0 with ZERO coverage-guided fuzzing. Now: no Solidity source ->
        # genuine advisory pass; Solidity source present but no harness -> a GAP.
        rebuttal = _invariant_fuzz_rebuttal(ws)
        if not _has_in_scope_solidity_source(ws):
            res["verdict"] = "pass-no-solidity-source"
            res["reason"] = "no in-scope Solidity source; no invariant harness applicable (advisory)"
            return res
        if rebuttal:
            res["verdict"] = "pass-no-invariant-harness"
            res["reason"] = f"no harness but rebuttal honored: {rebuttal}"
            return res
        enforce = os.environ.get("AUDITOOOR_INVARIANT_FUZZ_ENFORCE", "") not in ("", "0", "false", "no")
        if enforce:
            # reuse the EXISTING blocking verdict so audit-completeness-check's
            # invariant-fuzz signal hard-fails without any wiring change there.
            res["verdict"] = "fail-invariant-fuzz-incomplete"
            res["reason"] = ("in-scope Solidity source present but NO invariant harness found "
                             "(no .sol with a property_/echidna_/invariant_ fn) - honest-0 cannot "
                             "credit zero coverage-guided fuzzing. Author a Chimera/Recon harness or "
                             "add an invariant-fuzz-rebuttal.")
            return res
        res["verdict"] = "pass-no-invariant-harness"
        res["reason"] = ("WARN: in-scope Solidity source present but NO invariant harness detected; "
                         "honest-0 would credit ZERO fuzzing. Set AUDITOOOR_INVARIANT_FUZZ_ENFORCE=1 "
                         "to hard-fail (deliberate switch, not a silent retroactive re-fail).")
        return res

    failures = []
    genuine_harness_count = 0
    dispositions = _NED_MOD.load_dispositions(ws) if _NED_MOD is not None else []
    for hd in harness_dirs:
        # Skip an UNFILLED gen-invariants.sh scaffold (assert(true) placeholder,
        # CUT not wired): not a harness, must not block or credit. The
        # genuine_harness_count guard below fails the all-placeholder case.
        if _is_unfilled_scaffold_harness(hd):
            res["harnesses"].append({
                "dir": str(hd.relative_to(ws) if str(ws) in str(hd) else hd),
                "fail": "",
                "excluded_unfilled_scaffold": True,
                "invariant_count": 0,
                "mutation_verified": False,
                "engine_evidence": [],
            })
            continue
        # A gen-invariants.sh scaffold STAGING dir (every .sol header-stamped, e.g.
        # <ws>/test/Invariant_*.t.sol) is superseded by the canonical hand-authored
        # harnesses (chimera_harnesses/, header-free). Exclude like an unfilled scaffold:
        # not counted as a genuine harness (so the all-scaffold-only backstop below still
        # fires) and not failed (a mixed filled+unfilled staging dir no longer blocks).
        if _is_gen_invariants_scaffold_staging_dir(hd):
            res["harnesses"].append({
                "dir": str(hd.relative_to(ws) if str(ws) in str(hd) else hd),
                "fail": "",
                "excluded_scaffold_staging": True,
                "invariant_count": 0,
                "mutation_verified": False,
                "engine_evidence": [],
            })
            continue
        # Per-unit non-economic-surface disposition: a scaffold-only harness dir
        # over a documented non-economic / OOS contract is credited (not failed,
        # not a vacuous pass). Never-false-pass-guarded in the lib.
        _disp = _harness_dir_non_economic_disposition(ws, hd, dispositions)
        if _disp is not None:
            res["harnesses"].append({
                "dir": str(hd.relative_to(ws) if str(ws) in str(hd) else hd),
                "fail": "",
                "non_economic_disposition": {
                    "credit": _NED_MOD.CREDIT_LABEL,
                    "classification": _disp["classification"],
                    "rationale": _disp["rationale"][:240],
                    "repo": _disp.get("repo"),
                    "cut_path": _disp.get("cut_path"),
                },
            })
            continue
        genuine_harness_count += 1
        props: set[str] = set()
        mut = False
        for p in hd.glob("*.sol"):
            txt = _read(p)
            for m in _PROP_RE.finditer(txt):
                props.add(txt[m.start():m.end()].split()[-1])
            if _MUT_RE.search(txt):
                mut = True
        ev = _engine_evidence(ws, hd)
        # G8: also credit the durable mvc_sidecar (mutation-verify-coverage) + its
        # real baseline run for this harness (sound: genuine invariant-assertion
        # kill only). Additive - never downgrades an in-tree test_mutation_breaks_*.
        mvc_mut, mvc_ev = _mvc_sidecar_credit(ws, hd)
        if mvc_mut:
            mut = True
        if mvc_ev:
            ev = sorted(set(ev) | set(mvc_ev))
        seqlen, n_actions = _multistep_depth(hd)  # r36-rebuttal: lane FIX-INVARIANT-FUZZ-DEPTH
        # P1-d (modes 15, 10): executed-call floor, dry-run hard-fail, selfdestruct
        # engine-select. Only enforced once the harness has real engine evidence
        # (the call-count counters live in that same artifact); a harness with NO
        # evidence is already caught by the `not ev` branch below.
        exec_calls, dry_run = _campaign_call_metrics(ws, hd)
        needs_echidna = _cut_needs_echidna(hd, ws)
        used_echidna = _engine_is_echidna(hd, ev)
        h = {"dir": str(hd.relative_to(ws) if str(ws) in str(hd) else hd),
             "invariants": sorted(props), "invariant_count": len(props),
             "mutation_verified": mut, "engine_evidence": ev,
             "seqlen": seqlen, "action_count": n_actions,
             "executed_calls": exec_calls, "dry_run": dry_run,
             "cut_needs_echidna": needs_echidna, "used_echidna": used_echidna}
        if len(props) < min_invariants:
            h["fail"] = f"only {len(props)} invariant(s) (< {min_invariants})"
            failures.append(h["fail"])
        elif not mut:
            h["fail"] = "no mutation-verify test (harness non-vacuity unproven)"
            failures.append(h["fail"])
        elif dry_run:
            # P1-d (mode 15): a status=skipped / dry-run / engine-not-invoked
            # manifest is NOT a campaign - the engine never ran. Hard-fail.
            h["fail"] = "dry-run-not-a-campaign (status=skipped / engine NOT invoked - no real fuzz run)"
            failures.append(h["fail"])
        elif not ev:
            h["fail"] = "harness authored but NEVER FUZZED (no engine corpus/artifact/log)"
            failures.append(h["fail"])
        elif exec_calls and exec_calls < MIN_CALLS:
            # P1-d (mode 15): a 500K smoke campaign is under the >=1M floor. Only
            # enforced when the artifact exposes a call counter (exec_calls>0); a
            # corpus-only evidence with no counter is not penalised here (the run
            # happened, the count is just not machine-readable).
            h["fail"] = (f"under-budgeted: {exec_calls:,} executed calls < {MIN_CALLS:,} "
                         "(>=1M required for a credited step-2c campaign)")
            failures.append(h["fail"])
        elif (not exec_calls) and os.environ.get("AUDITOOOR_INVARIANT_FUZZ_CALLS_STRICT", "").strip().lower() in ("1", "true", "yes", "on"):
            # G-10/G-11 (enforcement-gap 2026-07-03): a harness with engine evidence but
            # NO machine-readable call counter (exec_calls==0) is otherwise credited as a
            # full >=1M campaign WITHOUT proving the floor - corpus-only-no-counter is
            # fuzz-depth theater (a 128k smoke run or a bare medusa-corpus/README.md
            # satisfies it). Under AUDITOOOR_INVARIANT_FUZZ_CALLS_STRICT (default OFF ->
            # legacy behavior, no retroactive re-fail), require a PARSEABLE count so the
            # >=1M floor is real: a forge `calls: N` / medusa `Total calls` line, or a
            # *_campaign_receipt.json carrying a numeric total_calls.
            h["fail"] = ("no machine-readable call count - the >=1M campaign floor is "
                         "UNVERIFIABLE (corpus-only evidence with no counter). Emit a forge "
                         "'calls: N' / medusa 'Total calls' line or a *_campaign_receipt.json "
                         "with a numeric total_calls >= 1,000,000.")
            failures.append(h["fail"])
        elif needs_echidna and not used_echidna:
            # P1-d (mode 10): the CUT force-sends ETH via selfdestruct/SafeSend;
            # medusa stack-underflows on these so a medusa-only campaign cannot be
            # credited - echidna(hevm) is required.
            h["fail"] = ("selfdestruct-needs-echidna (CUT force-sends via selfdestruct/SafeSend; "
                         "medusa stack-underflows - run echidna)")
            failures.append(h["fail"])
        elif seqlen and seqlen < MIN_SEQLEN:
            # r36-rebuttal: lane FIX-INVARIANT-FUZZ-DEPTH registered in .auditooor/agent_pathspec.json
            # only enforce when a seqlen is declared (config present); an absent config is
            # not penalised (engine-evidence already proves a run happened).
            h["fail"] = f"engine callSequenceLength/seqLen {seqlen} < {MIN_SEQLEN} (too shallow for sequence-fatal bugs)"
            failures.append(h["fail"])
        elif n_actions and n_actions < MIN_ACTIONS:
            h["fail"] = f"only {n_actions} fuzz action(s) (< {MIN_ACTIONS}) - cannot compose a multi-step exploit"
            failures.append(h["fail"])
        else:
            h["fail"] = ""
        res["harnesses"].append(h)

    # Guard the all-placeholder case: if EVERY detected harness was an excluded
    # unfilled scaffold (or non-economic disposition), there is no genuine
    # coverage-guided fuzzing - fail exactly like the zero-harness branch rather
    # than silently passing on an empty failures[] (never-false-pass).
    if genuine_harness_count == 0 and _has_in_scope_solidity_source(ws):
        res["verdict"] = "fail-invariant-fuzz-incomplete"
        res["reason"] = ("no genuine invariant harness: every detected harness was an "
                         "unfilled gen-invariants.sh scaffold (assert(true) placeholder) or "
                         "non-economic disposition - honest-0 cannot credit zero fuzzing")
        return res
    # Asset-centric coverage (2026-07-02): a harness-centric pass only proves the
    # harnesses that HAPPEN to exist are good; it cannot see a value-moving in-scope
    # FILE for which zero economic invariant was ever authored. Enumerate them and
    # report any gap. ADVISORY by default so it never retroactively bricks a prior
    # audit; hard-fail only under AUDITOOOR_INVARIANT_FUZZ_ASSET_STRICT.
    asset = _asset_coverage(ws, dispositions)
    res["asset_coverage"] = asset
    asset_strict = os.environ.get(_ASSET_STRICT_ENV, "") not in ("", "0", "false", "no")
    # E1: fuzz-receipt <-> runner-log reconciliation. Compute and ALWAYS attach the
    # result as a machine-readable field (additive, like asset_coverage) so the
    # fabrication is visible to any reader. NEVER-RETRO-RED: the verdict is only
    # altered when the named default-OFF env is set; env unset leaves the verdict
    # string byte-identical to before (the reconcile field is pure data).
    reconcile = _reconcile_fuzz_receipt(ws)
    res["fuzz_receipt_reconcile"] = reconcile
    receipt_strict = _receipt_reconcile_strict()
    if receipt_strict and reconcile.get("unreconciled"):
        # opted-in hard-fail: a receipt claim that appears in NO runner log (the
        # confirmed SSV 1,000,127-vs-500,172 fabrication). Takes precedence so an
        # operator running strict sees the fabrication over a downstream deficiency.
        u = reconcile["unreconciled"]
        res["verdict"] = "fail-fuzz-receipt-unreconciled"
        res["reason"] = (f"{len(u)} fuzz-receipt-unreconciled campaign(s) (strict): "
                         + "; ".join(f"{x['campaign']}: {x['detail']}" for x in u[:3]))
        return res
    if failures:
        res["verdict"] = "fail-invariant-fuzz-incomplete"
        res["reason"] = (f"{len(failures)} harness deficiency(ies): " + "; ".join(failures[:4]))
        return res
    if asset["applicable"] and asset["gaps"]:
        gap_msg = (f"{len(asset['gaps'])} value-moving in-scope file(s) with NO "
                   f"mutation-verified/>=1M harness and no typed per-asset disposition: "
                   + ", ".join(asset["gaps"][:6]))
        if asset.get("vmf_stale"):
            gap_msg += (" [WARN: value_moving_functions.json is STALE (older than its "
                        "producer) - some gaps may be classifier false-positives already "
                        "fixed; regenerate via audit-deep before trusting this gap]")
        if asset_strict:
            res["verdict"] = "fail-invariant-fuzz-asset-gap"
            res["reason"] = ("asset-coverage gap (strict): " + gap_msg)
        else:
            # advisory: existing harnesses are all good, so the harness-centric bar
            # is met - surface the asset gap as a WARN that does NOT block honest-0
            # unless the operator opts into the strict env.
            res["verdict"] = "warn-invariant-fuzz-asset-gap"
            res["reason"] = ("WARN asset-coverage gap (advisory; set "
                             f"{_ASSET_STRICT_ENV}=1 to hard-fail): " + gap_msg)
        return res
    res["verdict"] = "pass-invariant-fuzz-complete"
    res["reason"] = (f"{len(harness_dirs)} harness(es): each >= {min_invariants} invariants, "
                     "mutation-verified, and fuzzed with real engine evidence")
    if asset["applicable"]:
        res["reason"] += (f"; asset-coverage: {len(asset['covered'])}/{len(asset['value_moving'])} "
                          "value-moving in-scope files covered")
    return res


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--min-invariants", type=int, default=MIN_INVARIANTS)
    args = ap.parse_args(argv)
    ws = Path(os.path.expanduser(args.workspace)).resolve()
    r = evaluate(ws, min_invariants=args.min_invariants)
    if args.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"[{GATE}] verdict={r['verdict']}: {r['reason']}")
        for h in r.get("harnesses", []):
            tag = "FAIL: " + h["fail"] if h.get("fail") else "OK"
            print(f"  [{tag}] {h['dir']} ({h['invariant_count']} inv, "
                  f"mut={h['mutation_verified']}, evidence={len(h['engine_evidence'])})")
        # E1 advisory (default, env-unset): surface any fuzz-receipt-unreconciled
        # campaign as a WARN line without altering the verdict/exit code. Set
        # AUDITOOOR_FUZZ_RECEIPT_RECONCILE_STRICT=1 to hard-fail on it instead.
        rc = r.get("fuzz_receipt_reconcile") or {}
        for u in (rc.get("unreconciled") or []):
            if not r["verdict"].startswith("fail-fuzz-receipt"):
                print(f"  [WARN fuzz-receipt-unreconciled] {u['campaign']}: {u['detail']} "
                      f"(set {_RECEIPT_RECONCILE_STRICT_ENV}=1 to hard-fail)")
    if r["verdict"] == "error":
        return 2
    # An advisory warn (asset-gap without the strict env) is NOT a gate failure -
    # it exits 0 so it can never retroactively brick a prior audit. Only a real
    # fail-* verdict (including fail-invariant-fuzz-asset-gap under the strict env)
    # returns non-zero.
    if r["verdict"].startswith("pass") or r["verdict"].startswith("warn"):
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
