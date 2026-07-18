#!/usr/bin/env python3
"""randomness-unbiasability-screen.py - the RANDOMNESS-UNBIASABILITY screen (MQ-C03).

GENERAL crypto / trust-enforcement class (NEVER a bug SHAPE). It instantiates the
north-star method - "a value DELEGATED-and-TRUSTED to be fair/random whose private
unpredictability/unbiasability invariant an attacker breaks" - for one delegated
safety property no existing screen reaches: whether a value the protocol TRUSTS to
be fair/random, and CONSUMES in a SELECTION / ordering / lottery / tie-break /
leader-election / reward-gating decision, is actually sourced from something an
attacker who is still able to act cannot predict OR bias.

  DELEGATED-TRUSTED INVARIANT : a decision - who wins the raffle, which validator
    leads, which index is picked, whether a gate opens - is trusted to be FAIR: no
    party still able to act (miner/proposer/sequencer, a lottery entrant, the last
    revealer) can predict the outcome in advance or steer it in their favour.
  PRIVATE INVARIANT           : that trust holds ONLY if the randomness SOURCE is
    unpredictable AND unbiasable at the moment the deciding party can still act. A
    VRF (Chainlink VRF / drand beacon), crypto/rand with proper domain separation,
    or a commit-reveal seed made unbiasable by a BINDING PENALTY for non-reveal is
    the SILENT true-negative - the invariant is discharged.
  ATTACK / DEFECT ON THE INVARIANT : the source is a PREDICTABLE or POST-COMMIT-
    BIASABLE quantity -
      * EVM on-chain global entropy: block.timestamp / block.number /
        blockhash(...) / block.prevrandao / block.difficulty / block.coinbase (or a
        keccak of those) - a proposer chooses/withholds the block and re-rolls;
      * a commit-reveal with NO binding penalty for non-reveal - the last revealer
        computes the outcome and selectively aborts (last-revealer bias);
      * Go: a NON-VRF / non-DRBG weak PRNG (math/rand, incl. a clock-seeded
        rand.NewSource(time.Now()...)) feeding a leader / validator / shuffle /
        proposer / committee selection.
    The blast radius (stolen lottery, grindable leader schedule, gate bypass) is
    decided at RUN TIME, not here.

This is a GENERAL invariant CLASS, not a bug shape:
  - It enumerates the WHOLE randomness-consuming-enforcement-point family (every
    function where a fairness/randomness value flows into a selection decision) and
    asks ONE question of each: "is the source unpredictable AND unbiasable to any
    party still able to act, or is it a predictable / post-commit-biasable value?"
  - The IMPACT is left OPEN (verdict=needs-fuzz). Nothing here decides a tier.

Why the predicate is non-vacuous (see the tests):
  * HALF 1 `_sources` - the weak-randomness-source set (block globals / blockhash /
    time.Now / math/rand). Neutralize it (no source) and every row disappears.
  * HALF 2 `_consumer` - the SELECTION-consumer join: a source (or a value tainted
    by one) must flow into a selection op (a selection-named value, a modulo into a
    set count, or an index into a participant/candidate set). Neutralize it and
    every row disappears - a block.timestamp used only as a deadline never fires.
  * HALF 3 `_suppressed` - a strong source (VRF / drand / crypto rand) or a
    commit-reveal made unbiasable by a binding penalty makes the row SILENT.

It BIASES TOWARD SILENCE. RNG-for-selection is RARE: most fleet workspaces have NO
randomness-driven selection and are CORRECTLY SILENT true-negatives - that is the
expected, healthy outcome, not a miss. A row fires ONLY when a confirmed weak source
flows into a confirmed selection consumer AND no strong source / bound commit-reveal
is present. This is a precise screen, not an enumerator.

ADVISORY-FIRST: every emitted row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode. The
strict env AUDITOOOR_RANDOMNESS_UNBIASABILITY_STRICT (opt-in, or --strict) only
raises the exit code; it still emits no credit. EVM (.sol) + Go (.go); silent on
every other tree.

Usage:
  --workspace <ws>   scan <ws>/src (or <ws>) -> .auditooor/randomness_unbiasability_hypotheses.jsonl
  --source <dir>     scan an arbitrary dir (test / ad-hoc), print candidate rows JSON
  --file <f>         scan a single .sol / .go file, print candidate rows JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a firing hypothesis exists
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.randomness_unbiasability_hypotheses.v1"
CAPABILITY = "MQ-C03-randomness-unbiasability"
_SIDE_NAME = "randomness_unbiasability_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_RANDOMNESS_UNBIASABILITY_STRICT"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "forge-std", "mocks", "testdata", "certora", "audits",
              "prior_audits", "chimera_harnesses", "poc-tests", "reference",
              # Cosmos module SIMULATION uses math/rand by design (randomized
              # genesis / property-test fuzzing) - it is never a production fairness
              # decision, so it is excluded (bias to silence).
              "simulation", "simapp", "testutil", "testutils",
              # benchmark / load-test / block-sim / dev-tooling seeds math/rand on
              # purpose (never a production fairness decision).
              "bench", "benches", "benchmark", "benchmarks", "loadtest",
              "blocksim", "cryptosim", "rpc_bench", "tools",
              # dev-tooling / CLI entrypoints / e2e-smoke / fake-consensus test
              # harnesses seed math/rand on purpose (never a production fairness
              # decision): op cmd/check-derivation, interopsmoke, op-e2e/e2eutils,
              # fakepos consensus stub, sei filtertestgen workload generator.
              "cmd", "interopsmoke", "e2eutils", "fakepos", "filtertestgen"}
# test / mock / example trees are excluded: RNG there feeds synthetic fixtures, not a
# production fairness surface.
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|testutils?|mock|mocks|example|examples|script|"
    r"scripts|simulation|simapp|chimera_harnesses|poc-tests|certora|audits|"
    r"prior_audits)(/|$)", re.IGNORECASE)
_SOL_TEST_FILE = re.compile(r"(\.t\.sol$|\.s\.sol$|Mock|Harness|Test|PoC)")
# Go non-production files: *_test.go, generated *.pb.go, and test/fixture/mock helper
# files (`test_utils.go`, `*_mock.go`, `mock_*.go`) that carry deliberate PRNG.
_GO_SKIP_FILE = re.compile(
    r"(_test\.go$|\.pb\.go$|\.pb\.gw\.go$|test_?utils?\.go$|test_?random\.go$|"
    r"testonly\.go$|canned_random\.go$|simulation\.go$|_sim\.go$|_mock\.go$|"
    r"^mock_|_gen\.go$|fixtures?\.go$|filtertestgen\.go$|fakepos\.go$)",
    re.IGNORECASE)


# --- comment + string masking (length + newline preserving) -------------------
def _mask(text: str) -> str:
    """Blank `//` line, `/* */` block comments, "..." / '...' string+char literals
    and Go `...` raw strings, preserving newlines and per-line length so offsets stay
    source-aligned. Over-masking a token errs toward SILENCE (can only drop a would-be
    token, never invent one) - a source/consumer word inside a comment must not fire."""
    out = []
    i, n = 0, len(text)
    in_line = in_block = False
    in_str = None  # '"' | "'" | '`'
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            out.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1
        elif in_block:
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                in_block = False
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif in_str is not None:
            if c == "\\" and in_str != "`":
                out.append("  ")
                i += 2
                continue
            if c == in_str:
                in_str = None
            out.append("\n" if c == "\n" else " ")
            i += 1
        elif c == "/" and nxt == "/":
            in_line = True
            out.append("  ")
            i += 2
        elif c == "/" and nxt == "*":
            in_block = True
            out.append("  ")
            i += 2
        elif c in ('"', "'", "`"):
            in_str = c
            out.append(" ")
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _iter_source_files(root: Path):
    root_str = str(root)
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        rp = dp[len(root_str):].replace(os.sep, "/")
        if _TEST_HINT.search(rp):
            continue
        for f in fn:
            if f.endswith(".sol"):
                if _SOL_TEST_FILE.search(f):
                    continue
                yield Path(dp) / f
            elif f.endswith(".go"):
                if _GO_SKIP_FILE.search(f):
                    continue
                yield Path(dp) / f


def _lang_of(path: Path) -> str:
    return "go" if str(path).endswith(".go") else "solidity"


def _split_segments(ident: str):
    """Lowercase segments of an identifier across camelCase + `_` boundaries
    (`winnerIndex` -> ['winner','index'], `leader_seed` -> ['leader','seed'])."""
    parts = re.split(r"[_\W]+", ident)
    segs = []
    for p in parts:
        for s in re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+", p):
            segs.append(s.lower())
    return segs


# --- weak (predictable / biasable) randomness SOURCES -------------------------
# EVM on-chain global entropy: a proposer/miner chooses or withholds the block, so
# any of these is grindable / substitutable at the moment they can still act. A
# keccak of them is no better (it is a deterministic function of a chosen input).
_EVM_WEAK = re.compile(
    r"\bblock\.(?:timestamp|number|prevrandao|difficulty|coinbase)\b"
    r"|\bblockhash\s*\("
    r"|(?<![\w.$])now(?![\w])")

# Go NON-crypto randomness: the math/rand PRNG. Only the math/rand-EXCLUSIVE methods
# are matched (Intn/Shuffle/Perm/Float64/Seed/NewSource/... do NOT exist on
# crypto/rand), so this never mislabels crypto/rand without needing import parsing.
# NOTE bare `time.Now()` is deliberately NOT a source: a clock read is telemetry
# (`start := time.Now()`) in the overwhelming majority of Go code, so it is far too
# noisy to be a fairness source on its own. The genuinely dangerous pattern - a clock
# SEEDING a PRNG - is captured by `rand.Seed(time.Now()...)` / `rand.NewSource(...)`,
# both matched here, so the real risk is not lost (bias to silence).
_GO_WEAK = re.compile(
    r"\brand\.(?:Intn|Int31n|Int63n|Int31|Int63|Uint32|Uint64|Float64|Float32|"
    r"Shuffle|Perm|Seed|NewSource)\b")

# --- strong / unbiasable SOURCES (the SILENT true-negative) -------------------
# A committed-VRF / drand beacon / crypto DRBG discharges the unpredictability +
# unbiasability invariant. If one is present in the enforcement point, the fairness
# value comes from it and the block/clock tokens are incidental (a deadline, a log).
_EVM_STRONG = re.compile(
    r"\bfulfillRandomWords\b|\brawFulfillRandomWords\b|\brandomWords\b"
    r"|\brequestRandomWords\b|\brequestRandomness\b|\bVRFConsumerBase\w*"
    r"|\bVRFCoordinator\w*|\bIVRFCoordinator\w*|\bdrand\b", re.IGNORECASE)
_GO_STRONG = re.compile(
    r"\bcrypto/rand\b|\bcrand\.\w+|\brand\.Read\s*\(|\brand\.Prime\s*\("
    r"|\bdrand\b|\bvrf\b", re.IGNORECASE)

# An ALIASED strong-source import (`secureRand "crypto/rand"`, `beacon
# "github.com/drand/..."`) hides the `crypto/rand` / drand / vrf token from a
# body-only scan, so `_GO_STRONG` misses it. Resolve such aliases at FILE scope
# (from the RAW text - `_mask` blanks the import string literal). If the math/rand
# generator in a body is SEEDED from one of these strong sources, the seed is
# unpredictable/unbiasable and the row is SILENT (FP: op-node shufflePeers seeds
# `rand.NewSource` from `secureRand.Reader`).
_GO_STRONG_IMPORT = re.compile(
    r'(?m)^\s*(?:import\s+)?([A-Za-z_]\w*)\s+"([^"]*)"')
_GO_STRONG_PKG = re.compile(r"crypto/rand|drand|vrf", re.IGNORECASE)
# a math/rand generator being SEEDED (New / NewSource / Seed take the seed value).
_GO_RAND_SEED = re.compile(r"\brand\.(?:New|NewSource|Seed)\b")


def _strong_go_aliases(raw: str) -> set:
    """File-scope import aliases that bind a strong (crypto/rand / drand / vrf)
    package. Parsed from RAW source (masking blanks the import path literal)."""
    out = set()
    for m in _GO_STRONG_IMPORT.finditer(raw):
        name, path = m.group(1), m.group(2)
        if name in ("_", ".", "import"):
            continue
        if _GO_STRONG_PKG.search(path):
            out.add(name)
    return out


def _seeded_from_strong(body: str, aliases: set) -> bool:
    """True iff a math/rand generator in `body` is seeded from a strong-source
    alias - i.e. the body both SEEDS math/rand (New/NewSource/Seed) AND references
    an aliased crypto/rand / drand / vrf token (`secureRand.Reader`). Bias to
    silence: co-occurrence at function granularity is enough to treat the seed as
    unbiasable (the strong entropy flows into the PRNG seed)."""
    if not aliases or not _GO_RAND_SEED.search(body):
        return False
    alias_re = re.compile(
        r"\b(?:" + "|".join(re.escape(a) for a in aliases) + r")\.")
    return bool(alias_re.search(body))

# A commit-reveal made UNBIASABLE by a BINDING PENALTY for non-reveal (slash / forfeit
# / burn the stake / lose the deposit) removes the last-revealer's ability to abort
# for free -> SILENT. The penalty must co-occur with a reveal to count.
_REVEAL = re.compile(r"\breveal\w*\b", re.IGNORECASE)
_PENALTY = re.compile(
    r"\bslash\w*\b|\bforfeit\w*\b|\bpenal\w*\b|\bburn\w*\b|\bconfiscat\w*\b", re.IGNORECASE)

# --- SELECTION consumer signals ----------------------------------------------
# A fairness value is CONSUMED by a selection decision. Three precise signals; each
# is RNG-specific (generic time-accrual like `reward = rate*(block.timestamp-t0)` is
# NOT a member - it carries none of these and never fires).
_SELECT_SEG = frozenset({
    "winner", "winners", "random", "randomness", "rng", "seed", "entropy",
    "lottery", "lotteries", "raffle", "jackpot", "prize", "tiebreak", "tiebreaker",
    "shuffle", "shuffled", "leader", "proposer", "committee", "elect", "elected",
    "election", "dice",
})
# a modulo whose divisor is a SET COUNT is an index-into-a-set selection
# (`entropy % participants.length`); a modulo by a time constant (`block.timestamp %
# 86400`) is NOT (no count/length token) and stays silent.
_MODULO = re.compile(r"(?<![%/])%(?![%=])")
_COUNTISH = re.compile(
    r"\.length\b|\blen\s*\(|\b(?:count|total|size|num[A-Za-z0-9]*)\b"
    r"|\b(?:participants|candidates|players|validators|entries|tickets|nodes|"
    r"members|voters|holders|committee|addresses|accounts)\b", re.IGNORECASE)
# an index into a participant / candidate SET (`players[idx]`).
_INDEX_SET = re.compile(
    r"\b(?:participants|candidates|players|validators|entries|tickets|winners|"
    r"nodes|members|voters|holders|addresses|accounts|nominees)\s*\[", re.IGNORECASE)


# A random value feeding a TIMING / JITTER quantity (a backoff, retry delay, sleep
# duration) is NOT a fairness-relevant selection - randomized backoff is a benign,
# intended use of a weak PRNG. Exclude a statement that carries the random value into
# a duration/sleep/backoff context, and do NOT let a `random`-named timing var
# (`randomDelay`) satisfy the selection-named signal. FPs: op-conductor retryBackoff
# (`rand.Intn` -> Millisecond backoff), sei pruning manager (`rand.Float64` sleep).
_TIMING = re.compile(
    r"\btime\.(?:Duration|Sleep|After|AfterFunc|Tick|NewTimer|NewTicker|Since|Until)\b"
    r"|\b(?:Nanosecond|Microsecond|Millisecond)\b"
    r"|\b\w*(?:delay|jitter|backoff|sleep|cooldown|timeout)\w*\b", re.IGNORECASE)
# The STRICT duration-construct subset, used ONLY for the FUNCTION-SCOPE cross-statement
# sink check (`_has_timing_sink`). The loose `_TIMING` var-name heuristic above is safe
# per-statement (random value + timing token in ONE statement) but would over-match at
# function scope where taint over-approximates a reused name (`if peer.didTimeout` on a
# coincidentally-tainted `peer` is NOT a duration sink). A real duration construct
# (`time.Duration(...)`, `time.Sleep(...)`, a Millisecond unit) is required there.
_TIMING_SINK = re.compile(
    r"\btime\.(?:Duration|Sleep|After|AfterFunc|Tick|NewTimer|NewTicker)\b"
    r"|\b(?:Nanosecond|Microsecond|Millisecond)\b", re.IGNORECASE)


# GENERIC-randomness words describe the SOURCE, not a selection TARGET. A statement
# whose only selection signal is one of these (a var literally named `random*` /
# `rng*` / `seed`) is WEAK evidence: if that value flows into a TIMING sink (a jitter
# fraction that becomes a sleep duration) it is NOT a fairness selection. The real
# selection nouns (winner/lottery/leader/proposer/shuffle/...) are never treated this
# way. FP: sei pruning manager `randomPercentage := rand.Float64()` -> sleep interval.
_GENERIC_RAND_SEG = frozenset({"random", "randomness", "rng", "seed", "entropy"})


def _has_select_seg(stmt: str) -> str | None:
    for m in re.finditer(r"[A-Za-z_]\w*", stmt):
        for seg in _split_segments(m.group(0)):
            if seg in _SELECT_SEG:
                return seg
    return None


def _has_timing_sink(body, weak_re, tainted, lang):
    """True iff the random value (a weak-source token OR a tainted var) reaches a
    TIMING sink (`time.Duration`/`Sleep`/`After` or a *delay/*jitter/*backoff/*sleep
    var) somewhere in the body. Used to suppress a generic-random selection-named fire
    whose value is really a sleep/backoff jitter, not a fairness pick - the timing use
    can span statements (`p := rand.Float64(); d := interval*p; time.Sleep(d)`)."""
    for stmt, _ in _statements(body, lang):
        if not _TIMING_SINK.search(stmt):
            continue
        if weak_re.search(stmt) or any(
                re.search(r"\b" + re.escape(t) + r"\b", stmt) for t in tainted):
            return True
    return False


# --- function-unit extraction (Solidity + Go) ---------------------------------
_SOL_FN = re.compile(r"\b(?:function\s+([A-Za-z_]\w*)|(constructor)\b|(receive)\s*\(|"
                     r"(fallback)\s*\()")
_GO_FN = re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(")


def _brace_body(text, start_scan):
    """From `start_scan`, find the first `{` at paren-depth<=0 (or `;` first = a
    bodyless decl) and brace-match it. Return (body_start, body_end_inclusive) or
    None."""
    n = len(text)
    j = start_scan
    depth_paren = 0
    while j < n:
        c = text[j]
        if c == "(":
            depth_paren += 1
        elif c == ")":
            depth_paren -= 1
        elif c == ";" and depth_paren <= 0:
            return None
        elif c == "{" and depth_paren <= 0:
            break
        j += 1
    if j >= n:
        return None
    depth, k = 0, j
    while k < n:
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                return j, k
        k += 1
    return None


def _fn_units(text, lang):
    pat = _GO_FN if lang == "go" else _SOL_FN
    for m in pat.finditer(text):
        if lang == "go":
            name = m.group(1)
        else:
            name = m.group(1) or m.group(2) or m.group(3) or m.group(4) or "?"
        span = _brace_body(text, m.end())
        if span is None:
            continue
        j, k = span
        yield name, j, text[j:k + 1]


# --- taint: values derived from a weak source within a function ---------------
_ASSIGN = re.compile(r"(?<![<>=!%+\-*/&|^~])([A-Za-z_]\w*)\s*:?=(?!=)\s*([^;{}]+)")


def _tainted_vars(body, weak_re, lang="solidity"):
    """Simple names whose defining RHS references a weak source, or (transitively) an
    already-tainted name. Fixpoint over a few passes. Errs toward SILENCE (only weak
    provenance taints). The `_ASSIGN` RHS runs to the next `;`/`{`/`}`; a Go body has
    no `;`, so a body-wide scan would let one assignment's RHS swallow every following
    line. Extract Go assignments PER LINE (Go's statement terminator) so each `x := ...`
    is captured; Solidity keeps the `;`-terminated body-wide scan."""
    tainted = set()
    if lang == "go":
        assigns = [(m.group(1), m.group(2))
                   for line in body.split("\n")
                   for m in _ASSIGN.finditer(line)]
    else:
        assigns = [(m.group(1), m.group(2)) for m in _ASSIGN.finditer(body)]
    for _ in range(6):
        grew = False
        for lhs, rhs in assigns:
            if lhs in tainted:
                continue
            if weak_re.search(rhs) or any(
                    re.search(r"\b" + re.escape(t) + r"\b", rhs) for t in tainted):
                tainted.add(lhs)
                grew = True
        if not grew:
            break
    return tainted


def _statements(body, lang="solidity"):
    """Yield (stmt_text, offset_in_body). Solidity statements terminate with `;`; Go
    statements terminate with a NEWLINE (Go rarely uses `;` - splitting a Go body on
    `;` degrades to ONE whole-function statement, collapsing the source->consumer join
    into loose per-function co-occurrence). Splitting Go on `\\n` keeps the
    randomness-source -> selection-consumer join at tight per-statement locality. The
    separator (`;` or `\\n`) is 1 char either way, so the offset math is unchanged.
    Masked input guarantees the separator never falls inside a string/comment."""
    sep = "\n" if lang == "go" else ";"
    off = 0
    for chunk in body.split(sep):
        yield chunk, off
        off += len(chunk) + 1


def _consumer(stmt, weak_re, tainted):
    """Does this statement carry a randomness value INTO a selection op? Returns a
    short consumer label, or None. The value must be present (a weak source token OR
    a tainted var) AND a selection signal must apply."""
    has_value = bool(weak_re.search(stmt)) or any(
        re.search(r"\b" + re.escape(t) + r"\b", stmt) for t in tainted)
    if not has_value:
        return None
    # a random value feeding a timing / jitter / backoff quantity is NOT a fairness
    # selection - benign randomized backoff (bias to silence).
    if _TIMING.search(stmt):
        return None
    seg = _has_select_seg(stmt)
    if seg:
        return f"selection-named:{seg}"
    if _MODULO.search(stmt) and _COUNTISH.search(stmt):
        return "modulo-into-set-count"
    if _INDEX_SET.search(stmt):
        return "index-into-participant-set"
    return None


def _suppressed(fn, body, lang):
    """The enforcement point is SILENT (unbiasable source discharged the invariant):
    a VRF / drand / crypto-rand strong source, OR a commit-reveal bound by a penalty.
    The reveal / VRF-callback signal frequently lives in the FUNCTION NAME
    (`fulfillRandomWords`, `reveal`), so both the name and the body are inspected."""
    scope = (fn or "") + " " + body
    if lang == "go":
        if _GO_STRONG.search(scope):
            return "go-strong-source"
    else:
        if _EVM_STRONG.search(scope):
            return "vrf-or-drand-source"
    # a binding non-reveal penalty (slash/forfeit/burn) makes the committed seed
    # unbiasable - the last revealer can no longer abort for free.
    if _REVEAL.search(scope) and _PENALTY.search(scope):
        return "commit-reveal-with-binding-penalty"
    return None


def _weak_source_label(body, weak_re):
    m = weak_re.search(body)
    if not m:
        return None
    tok = m.group(0).rstrip("(").strip()
    return tok


def _stable_id(rel, fn, line, source, consumer):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{line}|{source}|{consumer}".encode())
    return h.hexdigest()[:16]


def scan_file(path: Path, rel: str, file_text: str = None, lang: str = None):
    """Return candidate randomness-selection rows for one file, each with a `fires`
    bool. A row FIRES iff a weak randomness source flows into a selection consumer in
    a function AND no strong source / bound commit-reveal is present."""
    if lang is None:
        lang = _lang_of(path)
    if lang not in ("solidity", "go"):
        return []
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask(raw)
    weak_re = _GO_WEAK if lang == "go" else _EVM_WEAK
    # aliased crypto/rand / drand / vrf imports must be resolved from RAW (masking
    # blanks the import path literal) so a body that SEEDS math/rand from a strong
    # source is recognised as SILENT.
    strong_aliases = _strong_go_aliases(raw) if lang == "go" else set()
    rows = []
    for fn, fn_off, body in _fn_units(text, lang):
        if not weak_re.search(body):
            continue  # HALF 1: no weak source -> not a candidate
        supp = _suppressed(fn, body, lang)
        if supp is None and lang == "go" and _seeded_from_strong(body, strong_aliases):
            supp = "go-strong-seed"  # math/rand seeded from aliased crypto/rand/drand/vrf
        tainted = _tainted_vars(body, weak_re, lang)
        source = _weak_source_label(body, weak_re)
        # a random value that reaches a timing/jitter sink is a benign backoff/delay,
        # not a fairness pick (checked function-wide because the sink can be a later
        # statement than the generic-random assignment).
        timing_bound = _has_timing_sink(body, weak_re, tainted, lang)
        for stmt, stmt_off in _statements(body, lang):
            consumer = _consumer(stmt, weak_re, tainted)
            if consumer is None:
                continue  # HALF 2: no selection consumer -> silent
            if (timing_bound and consumer.startswith("selection-named:")
                    and consumer.split(":", 1)[1] in _GENERIC_RAND_SEG):
                continue  # generic-random value bound to a timing sink -> not selection
            abs_off = fn_off + stmt_off
            line_no = text[:abs_off].count("\n") + 1
            fires = supp is None
            rows.append({
                "schema": HYP_SCHEMA,
                "capability": CAPABILITY,
                "id": _stable_id(rel, fn, line_no, source, consumer),
                "file": rel,
                "function": fn,
                "line": line_no,
                "lang": lang,
                "randomness_source": source,
                "consumer": consumer,
                "fires": fires,
                "suppressed_reason": supp,
                # advisory-first contract (never auto-credit, never fail-close)
                "verdict": "needs-fuzz",
                "advisory": True,
                "auto_credit": False,
                "question": (
                    f"`{fn}` derives a fairness/random value from `{source}` and "
                    f"consumes it in a selection ({consumer}). Is that source "
                    "unpredictable AND unbiasable to every party still able to act "
                    "(proposer/sequencer, entrant, last revealer), or is it a "
                    "predictable / post-commit-biasable quantity - so the selection "
                    "can be grinded, withheld, or re-rolled in the attacker's favour?"),
            })
            break  # one hypothesis per enforcement point (bias to silence)
    return rows


def scan_tree(root: Path):
    rows = []
    for p in _iter_source_files(root):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        try:
            rows.extend(scan_file(p, rel))
        except Exception:
            continue
    return rows


def _emit_sidecar(ws: Path, rows):
    """Emit ONLY the firing hypotheses to the sidecar (mkdir parent)."""
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    fired = [r for r in rows if r.get("fires")]
    with out.open("w") as fh:
        for r in fired:
            fh.write(json.dumps(r) + "\n")
    return out, fired


def _summary(rows):
    fired = [r for r in rows if r.get("fires")]
    by_lang = {}
    for r in fired:
        by_lang[r["lang"]] = by_lang.get(r["lang"], 0) + 1
    return {
        "schema": HYP_SCHEMA,
        "capability": CAPABILITY,
        "candidates": len(rows),
        "fired": len(fired),
        "by_lang": by_lang,
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "note": ("no randomness-driven selection found - correctly SILENT "
                 "true-negative" if not fired else
                 "weak-source selection(s) found; confirm source unbiasability by fuzz"),
        "advisory": True,
        "auto_credit": False,
    }


def _resolve_ws(arg):
    ws = Path(arg)
    if not ws.is_absolute():
        cand = Path("/Users/wolf/audits") / arg
        if cand.exists():
            ws = cand
    return ws


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="MQ-C03 randomness-unbiasability screen (advisory, EVM+Go)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(_STRICT_ENV, "").strip() not in ("", "0", "false")

    if args.file:
        p = Path(args.file)
        rows = scan_file(p, p.name)
        print(json.dumps(rows, indent=2))
        return 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 0

    if not args.workspace:
        ap.error("one of --workspace / --source / --file is required")

    ws = _resolve_ws(args.workspace)
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
        summ = {
            "schema": HYP_SCHEMA, "capability": CAPABILITY,
            "fired": len(rows), "source": "sidecar",
            "verdict": "needs-fuzz" if rows else "clean-advisory",
            "advisory": True, "auto_credit": False,
        }
        print(json.dumps(summ, indent=2))
        return 1 if (strict and rows) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    # ADVISORY-FIRST: default exit 0; strict elevates only when a hypothesis fired
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
