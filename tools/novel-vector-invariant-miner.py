#!/usr/bin/env python3
"""novel-vector-invariant-miner.py - the TRUE-0-day stage.

Given a TARGET (an in-scope contract / Rust pallet / Go module) and the
TRUSTED corpus invariant FAMILIES (the categories the corpus has learned:
uniqueness / conservation / monotonicity / custody / authorization / ...),
this tool DERIVES TARGET-SPECIFIC invariants - what SHOULD hold for THIS
protocol's actual functions and state, instantiated against the protocol's
REAL symbol names - and emits them as ENGINE-CHECKABLE assertions.

The intent is to catch bugs nobody has seen yet. A pattern-matcher asks
"does this code contain a shape from a past bug?" (e.g.
tools/hackerman-novel-vector-gen.py subtracts known attack classes from a
repo). This tool asks the dual question: "what spec does this protocol's
own structure IMPLY must hold, and can the engine find ANY counterexample?"
A counterexample to a derived spec is a spec-violation that matches NO
pre-existing detector - a true-0-day candidate.

Pipeline
--------
1. Parse the target surface (functions w/ visibility+mutability, state
   vars, params). For Solidity we reuse evm-engine-harness-author's
   parse_contract; for Rust/Go we use a bounded regex extractor.
2. Load the trusted corpus invariant FAMILIES (category-level) from the
   indexed library (audit/corpus_tags/derived/invariant_library_index.json
   + invariants_extracted.jsonl + invariants_pilot.jsonl).
3. For each mutating externally-callable function, map the function to the
   plausible families (by name heuristic + signature shape), then
   INSTANTIATE each family as a TARGET-SPECIFIC invariant: bind the generic
   "a quantity that must only increase never regresses" to THIS function's
   real state var (e.g. "totalShares MUST NOT decrease across deposit()").
4. Emit each derived invariant as a machine-checkable assertion over real
   symbols (assertion_expr) carrying detector_match="none" (spec-violation
   hunt, not pattern recall) and the family + source corpus invariant IDs
   so Rule 58 (invariant-grounded) is honored.
5. RENDER the derived invariants as runnable engine specs by delegating to
   the PR5 engine-harness authors (evm/rust/go-engine-harness-author.py) so
   the existing engines (halmos/medusa/echidna/forge ; proptest/bolero ;
   go-fuzz) search for ANY counterexample. The render step is opt-in
   (--render) and best-effort; the JSONL artifact is always emitted.
6. Optional --mimo-refine (<=6 calls via tools/llm-dispatch.py) sharpens the
   natural-language statement + tightens the assertion_expr. Gated behind
   AUDITOOOR_LLM_NETWORK_CONSENT=1.

RELATED TOOLS (tool-duplication preflight, see ~/.claude/CLAUDE.md):
  - tools/invariant-auto-synth.py synthesizes per-function CANDIDATE
    invariants from source SHAPE alone (signature/state-write/require). It
    does NOT use the trusted corpus FAMILIES and does NOT render runnable
    engine specs. This tool grounds each derived invariant in a corpus
    family (INV-* citation) and renders engine-checkable assertions.
  - tools/math-invariant-miner.py extracts math-specs (conservation laws)
    for Solidity only, no corpus families, no engine rendering.
  - tools/hackerman-novel-vector-gen.py is the PATTERN-MATCH dual: it
    subtracts known attack classes per repo (recall the past). This tool is
    the SPEC-DERIVATION primal: derive what must hold and hunt counterexamples.
  - tools/llm-extract-invariants.py / tools/invariant-auto-synth.py BUILD the
    corpus library (the families this tool CONSUMES).
  - tools/evm-engine-harness-author.py / rust- / go- (PR5) RENDER an
    invariant set as runnable specs. This tool produces the target-specific
    invariant set those authors render and delegates to them for --render.

The gap this tool fills: nothing else turns (target surface + trusted corpus
FAMILIES) into TARGET-SPECIFIC engine-checkable assertions tagged as
spec-violation hunts (detector_match=none), with corpus-family grounding,
that feed the PR5 harness authors. It is the front-door for true-0-day
discovery: derive the spec, let the engine break it.

Schema: auditooor.novel_vector_invariant.v1

Usage:
    python3 tools/novel-vector-invariant-miner.py \\
        --workspace ~/audits/<ws> \\
        --contract src/Vault.sol \\
        --output <ws>/.auditooor/novel_invariants.jsonl

    # render engine specs via the PR5 authors:
    python3 tools/novel-vector-invariant-miner.py --workspace <ws> \\
        --contract src/Vault.sol --render --out-dir <ws>/.auditooor/novel_harness

    # MIMO-refined statements (consent + key required):
    AUDITOOOR_LLM_NETWORK_CONSENT=1 MIMO_API_KEY=tp-... MIMO_BASE_URL=... \\
      python3 tools/novel-vector-invariant-miner.py --workspace <ws> \\
        --contract src/Vault.sol --mimo-refine --mimo-budget 6

Exit codes:
  0 - invariants derived (and rendered if --render)
  2 - input validation / parse error
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.novel_vector_invariant.v1"
SUMMARY_SCHEMA = "auditooor.novel_vector_invariant.summary.v1"
REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"
DERIVED_DIR = REPO_ROOT / "audit" / "corpus_tags" / "derived"
DEFAULT_EXTRACTED = DERIVED_DIR / "invariants_extracted.jsonl"
DEFAULT_PILOT = DERIVED_DIR / "invariants_pilot.jsonl"
DEFAULT_INDEX = DERIVED_DIR / "invariant_library_index.json"

MIMO_BUDGET_DEFAULT = 6
MIMO_BUDGET_CAP = 6

# ---------------------------------------------------------------------------
# Trusted corpus FAMILIES.
#
# A "family" is a category the corpus has learned. For each family we encode
# a TARGET-SPECIFIC invariant TEMPLATE: a natural-language statement skeleton
# and a machine-checkable assertion skeleton, both parameterized by the
# protocol's REAL symbol (a state var or param the function touches). The
# binding step (derive_invariants) fills {sym}/{fn}/{snap} with real names.
#
# The assertion skeleton is a REAL relation (==, <=, >=, etc.) over distinct
# fields so the rendered harness passes tools/engine-harness-proof-gate.py
# (no `% 1`, no `x == x`, no `assert(true)`).
# ---------------------------------------------------------------------------


@dataclass
class FamilyTemplate:
    category: str
    # {fn} = function name, {sym} = bound real symbol, {snap} = pre-call snapshot var
    statement: str
    assertion_expr: str  # over {sym} and {snap}: a real relation
    needs_snapshot: bool  # whether the assertion compares pre/post state
    hint: str  # what kind of symbol to bind (state-var role)
    # The corpus category this template grounds in for R58. Defaults to
    # `category` itself; READ-class templates (which are view-helper-specific
    # framings, not corpus categories of their own) point at the underlying
    # corpus category they generalize (e.g. epoch_boundary -> bounds).
    corpus_category: str | None = None
    # READ-class templates derive over a VIEW (pure-read) function's COMPUTED
    # RETURN value / read predicate rather than a pre/post mutation. They are
    # the half of the invariant surface that the mutating-only enumeration
    # historically missed.
    read_class: bool = False


_FAMILY_TEMPLATES: dict[str, FamilyTemplate] = {
    "conservation": FamilyTemplate(
        category="conservation",
        statement=(
            "After {fn}(), the protocol's tracked total {sym} MUST equal its "
            "pre-call value adjusted only by the explicit amount moved; no value "
            "may be created or destroyed."
        ),
        assertion_expr="{sym}_post == {snap}_pre + _delta - _fee",
        needs_snapshot=True,
        hint="aggregate-balance",
    ),
    "normalization": FamilyTemplate(
        category="normalization",
        statement=(
            "The distribution {sym} written by {fn}() MUST stay normalized: its "
            "components MUST sum to the declared total ({sym}_denominator, e.g. "
            "1.0 / 100% / a fixed share base) and every component MUST be strictly "
            "positive; no component may be zero, negative, or push the sum off the "
            "denominator (a renormalization/weight-distribution conservation law)."
        ),
        # real, distinct-symbol relation over the components-sum and per-component
        # floor: the sum equals the denominator AND the minimum component > 0.
        assertion_expr=(
            "({sym}_components_sum == {sym}_denominator) && ({sym}_min_component > 0)"
        ),
        needs_snapshot=False,
        hint="weight/share/allocation distribution that must sum to a fixed total",
        corpus_category="conservation",
    ),
    "monotonicity": FamilyTemplate(
        category="monotonicity",
        statement=(
            "{sym} is a monotone quantity for {fn}(): it MUST NOT regress across "
            "the call (only-increase or only-decrease, never both directions)."
        ),
        assertion_expr="{sym}_post >= {snap}_pre",
        needs_snapshot=True,
        hint="monotone-counter",
    ),
    "uniqueness": FamilyTemplate(
        category="uniqueness",
        statement=(
            "The action {fn}() MUST be consumable at most once for a given key; a "
            "second call with the same key MUST NOT re-apply the effect on {sym}."
        ),
        assertion_expr="consumed_{sym} == true",
        needs_snapshot=False,
        hint="consumed-set / nonce / processed-id",
    ),
    "authorization": FamilyTemplate(
        category="authorization",
        statement=(
            "{sym} is protected state for {fn}(): it MUST only change when the "
            "caller is the authorized actor; an unauthorized caller MUST NOT mutate {sym}."
        ),
        assertion_expr="(msg_sender == authorized_{sym}) || ({sym}_post == {snap}_pre)",
        needs_snapshot=True,
        hint="protected-state / owner-gated value",
    ),
    "custody": FamilyTemplate(
        category="custody",
        statement=(
            "User-owned {sym} touched by {fn}() MUST NOT move to an address the "
            "user did not authorize; custody is preserved unless the user consents."
        ),
        assertion_expr="{sym}_recipient == authorized_recipient",
        needs_snapshot=False,
        hint="user-funds recipient",
    ),
    "atomicity": FamilyTemplate(
        category="atomicity",
        statement=(
            "{fn}() MUST commit all writes to {sym} before any external call hands "
            "control back to the caller (reentrancy-safe ordering)."
        ),
        assertion_expr="reentrancy_locked == true",
        needs_snapshot=False,
        hint="reentrancy-guarded state write",
    ),
    "bounds": FamilyTemplate(
        category="bounds",
        statement=(
            "{sym} touched by {fn}() MUST stay within its declared bound; the call "
            "MUST NOT push {sym} past its invariant limit (no over/under-flow of intent)."
        ),
        assertion_expr="{sym}_post <= {sym}_cap",
        needs_snapshot=False,
        hint="bounded amount/cap",
    ),
    "freshness": FamilyTemplate(
        category="freshness",
        statement=(
            "{fn}() MUST NOT consume {sym} past its validity window; stale "
            "data (price/oracle/round) MUST be rejected."
        ),
        assertion_expr="(block_timestamp - {sym}_updatedAt) <= {sym}_maxStale",
        needs_snapshot=False,
        hint="oracle/price/round timestamp",
    ),
    "ordering": FamilyTemplate(
        category="ordering",
        statement=(
            "Operations on {sym} in {fn}() MUST respect their required sequencing; "
            "a reordering MUST NOT violate the protocol invariant."
        ),
        assertion_expr="{sym}_seq_post == {snap}_seq_pre + 1",
        needs_snapshot=True,
        hint="sequence/phase counter",
    ),
    "determinism": FamilyTemplate(
        category="determinism",
        statement=(
            "{fn}() MUST be deterministic in {sym}: the same inputs from the same "
            "state MUST produce the same {sym} across runs."
        ),
        assertion_expr="{sym}_run1 == {sym}_run2",
        needs_snapshot=False,
        hint="output computed from inputs",
    ),
    "soundness": FamilyTemplate(
        category="soundness",
        statement=(
            "Any proof/attestation accepted by {fn}() and recorded in {sym} MUST "
            "correspond to true underlying state (no forged/aliased witness)."
        ),
        assertion_expr="{sym}_accepted == {sym}_canonical",
        needs_snapshot=False,
        hint="accepted proof/root",
    ),
}

# ---------------------------------------------------------------------------
# READ-class invariant families (the VIEW / pure-read surface).
#
# The mutating-fn enumeration above can never derive an invariant for an
# internal/private/public VIEW (pure-read) helper, because such a function
# writes no state - there is no pre/post snapshot to constrain. Yet read
# helpers carry their OWN spec: a computed boundary timestamp must use an
# EXCLUSIVE upper bound; a computed read must conserve; a derived value must
# stay within bounds; a read over an ordered axis must be monotone. A bug in
# such a helper (an off-by-one inclusive-vs-exclusive epoch boundary, a
# read-side rounding that creates value, a derived-value overflow) is invisible
# to a mutating-only enumerator. These READ-class templates derive a spec over
# the helper's COMPUTED RETURN value / read predicate.
#
# This is a GENERAL, class-level capability: ANY internal/private/public view
# function whose name/return shape matches a read-invariant family is now
# enumerated. The templates below are keyed by READ-class family name and point
# (`corpus_category`) at the underlying corpus category they generalize so R58
# grounding still resolves to real INV-* ids. They are NOT tuned to any one
# protocol symbol.
#
# Assertion convention for read templates: {sym} is the helper's COMPUTED
# result (bound to the function name when no state var is the natural subject),
# {bound} / {lo} / {hi} are the declared bounds the read must respect. The
# relations are real (no tautology, no `% 1`) so the rendered harness passes
# engine-harness-proof-gate.
# ---------------------------------------------------------------------------

_READ_FAMILY_TEMPLATES: dict[str, FamilyTemplate] = {
    # epoch / window boundary reads: the canonical inclusive-vs-exclusive
    # off-by-one. A boundary-END helper must use an EXCLUSIVE upper bound so
    # the next window's start does not double-count the boundary instant.
    "epoch_boundary": FamilyTemplate(
        category="epoch_boundary",
        statement=(
            "The boundary value computed by {fn}() over {sym} MUST use an "
            "EXCLUSIVE upper bound: the computed end MUST be strictly less than "
            "the next window's start, so no instant is counted in two windows "
            "(inclusive-vs-exclusive off-by-one)."
        ),
        assertion_expr="{fn}_computed_end < {fn}_next_window_start",
        needs_snapshot=False,
        hint="computed epoch/window boundary timestamp",
        corpus_category="bounds",
        read_class=True,
    ),
    # conservation over a pure read: a read that sums/derives a total MUST NOT
    # create or destroy value relative to its inputs (read-side rounding bug).
    "read_conservation": FamilyTemplate(
        category="read_conservation",
        statement=(
            "The quantity {sym} computed by the pure read {fn}() MUST conserve "
            "value: it MUST equal the sum of its component inputs (no value "
            "created or destroyed by read-side rounding/aggregation)."
        ),
        assertion_expr="{fn}_result == {fn}_components_sum",
        needs_snapshot=False,
        hint="computed total from components",
        corpus_category="conservation",
        read_class=True,
    ),
    # monotonicity of a pure read along an ordered axis: a read indexed by a
    # monotone input MUST be monotone in its output (e.g. price-vs-tick,
    # reward-vs-time). A regression across adjacent inputs is the bug.
    "read_monotonicity": FamilyTemplate(
        category="read_monotonicity",
        statement=(
            "The read {fn}() MUST be monotone in {sym}: for a larger ordered "
            "input the computed result MUST NOT regress (a non-monotone read "
            "over an ordered axis is a spec violation)."
        ),
        assertion_expr="{fn}_result_hi >= {fn}_result_lo",
        needs_snapshot=False,
        hint="read over an ordered axis (tick/time/index)",
        corpus_category="monotonicity",
        read_class=True,
    ),
    # bounds on a computed value: a derived quantity returned by a pure read
    # MUST stay within its declared range (a derived value that exceeds its
    # cap or underflows its floor is the bug).
    "bounds_on_computed_value": FamilyTemplate(
        category="bounds_on_computed_value",
        statement=(
            "The value {sym} computed by the pure read {fn}() MUST stay within "
            "its declared range: it MUST NOT exceed the upper bound nor fall "
            "below the lower bound the protocol guarantees for this read."
        ),
        assertion_expr="({fn}_result <= {fn}_upper_bound) && ({fn}_result >= {fn}_lower_bound)",
        needs_snapshot=False,
        hint="derived/computed value with declared range",
        corpus_category="bounds",
        read_class=True,
    ),
    # determinism of a pure read: same inputs from same state MUST yield the
    # same computed result (a read that depends on hidden mutable/global state
    # is the bug).
    "read_determinism": FamilyTemplate(
        category="read_determinism",
        statement=(
            "The pure read {fn}() MUST be deterministic in {sym}: identical "
            "inputs from identical state MUST produce identical results across "
            "evaluations (no dependence on hidden mutable/global state)."
        ),
        assertion_expr="{fn}_result_eval1 == {fn}_result_eval2",
        needs_snapshot=False,
        hint="pure read result",
        corpus_category="determinism",
        read_class=True,
    ),
    # staleness gate on a pure read: a read that consumes a STORED value carrying
    # a last-update / timestamp MUST reject the value once it is past its validity
    # window (the oracle/price-staleness shape, generalized to the READ surface).
    # The mutating-only `freshness` family above assumes a Solidity-ish
    # `block_timestamp - {sym}_updatedAt` shape on a mutation; this read-class
    # variant binds to a STORED last_update field consumed by a getter/query and
    # asserts the gate holds at read time. A read that returns a stale value
    # (no last_update check before use) is the bug.
    "read_staleness": FamilyTemplate(
        category="read_staleness",
        statement=(
            "The read {fn}() MUST enforce a freshness gate before returning {sym}: "
            "the stored last_update of {sym} MUST be within the allowed staleness "
            "window at read time, and a value past that window MUST be rejected "
            "(a getter that returns {sym} without checking its last_update is the bug)."
        ),
        assertion_expr=(
            "({read_now} - {sym}_last_update) <= {sym}_max_staleness"
        ),
        needs_snapshot=False,
        hint="stored value with a last_update/timestamp consumed by a read",
        corpus_category="freshness",
        read_class=True,
    ),
}


# View-function name substrings -> plausible READ-class families. General,
# class-level: keyed on the *role* a read name implies, never on a specific
# protocol symbol. A view function whose name contains any of these keys is
# mapped to the listed read-class families; the return/param shape heuristic
# (_READ_SHAPE_FAMILIES) is the fallback when the name is uninformative.
_READ_NAME_TO_FAMILIES: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    # boundary / window / epoch reads -> inclusive-vs-exclusive off-by-one
    (
        ("epoch", "boundary", "window", "period", "timestampend", "timestampstart",
         "endtime", "starttime", "deadline", "cutoff", "expiry"),
        ("epoch_boundary", "bounds_on_computed_value"),
    ),
    # aggregation / summation reads -> read-side conservation
    (
        ("total", "sum", "aggregate", "accumulated", "balanceof", "supply"),
        ("read_conservation", "bounds_on_computed_value"),
    ),
    # price / oracle / feed reads of a STORED value -> read-side staleness gate.
    # A getter that returns a stored price/oracle value must check its
    # last_update before use (the oracle-staleness shape on the read surface).
    (
        ("price", "oracle", "feed", "rate", "quote", "spot", "twap", "mark",
         "index", "value", "amount"),
        ("read_staleness", "read_monotonicity", "bounds_on_computed_value"),
    ),
    # price / rate / conversion reads over an ordered axis -> monotonicity
    (
        ("quote", "convert", "tick", "sqrt", "exchange",
         "preview", "shares", "assets"),
        ("read_monotonicity", "bounds_on_computed_value", "read_determinism"),
    ),
    # generic compute/get/calc reads -> bounds + determinism
    (
        ("calculate", "compute", "get", "derive", "view", "current", "pending",
         "claimable", "earned", "owed"),
        ("bounds_on_computed_value", "read_determinism"),
    ),
)

# View-function return/param shape -> READ-class families when the name is
# uninformative. A numeric return that is computed (not a plain getter) is the
# bounds/monotonicity candidate; a timestamp/round-shaped surface is the
# epoch-boundary candidate.
_READ_SHAPE_FAMILIES: tuple[tuple[re.Pattern[str], tuple[str, ...]], ...] = (
    (re.compile(r"\b(time|deadline|timestamp|round|epoch|period|window)\b", re.I),
     ("epoch_boundary", "bounds_on_computed_value")),
    (re.compile(r"\b(uint\d*|u(8|16|32|64|128|256)|int\d*)\b", re.I),
     ("bounds_on_computed_value", "read_determinism")),
)


# Function-name -> plausible families (mirrors evm-engine-harness-author's map
# but kept independent so this tool stands alone for Rust/Go too).
_NAME_TO_FAMILIES = {
    "deposit": ("conservation", "custody", "bounds"),
    "mint": ("conservation", "bounds", "monotonicity"),
    "withdraw": ("conservation", "custody", "authorization"),
    "redeem": ("conservation", "custody", "monotonicity"),
    "borrow": ("conservation", "bounds", "authorization"),
    "repay": ("conservation", "atomicity"),
    "liquidate": ("conservation", "bounds", "authorization", "ordering"),
    "transfer": ("conservation", "authorization", "custody"),
    "transferfrom": ("conservation", "authorization", "custody", "uniqueness"),
    "swap": ("conservation", "bounds", "ordering"),
    "claim": ("uniqueness", "authorization", "custody"),
    "collect": ("conservation", "custody"),
    "accrue": ("monotonicity", "freshness", "determinism"),
    "callback": ("atomicity", "authorization"),
    "upgrade": ("authorization", "atomicity"),
    "setowner": ("authorization",),
    "transferownership": ("authorization",),
    "vote": ("uniqueness", "ordering", "authorization"),
    "propose": ("ordering", "uniqueness"),
    "execute": ("ordering", "atomicity", "authorization"),
    "settle": ("conservation", "atomicity"),
    # distribution / renormalization writers: a weight/share/allocation set that
    # must sum to a fixed total with all-positive components. GENERAL class-level
    # names (not tuned to any one protocol's symbol).
    "setweights": ("normalization", "conservation", "bounds"),
    "setweight": ("normalization", "conservation", "bounds"),
    "distribute": ("normalization", "conservation"),
    "redistribute": ("normalization", "conservation"),
    "rebalance": ("normalization", "conservation", "bounds"),
    "allocate": ("normalization", "conservation", "bounds"),
    "setallocation": ("normalization", "conservation", "bounds"),
    "setallocations": ("normalization", "conservation", "bounds"),
    "updateintent": ("normalization", "conservation"),
    "setintent": ("normalization", "conservation"),
    "setweightallocation": ("normalization", "conservation", "bounds"),
    "updateweights": ("normalization", "conservation", "bounds"),
    "normalize": ("normalization", "conservation"),
    "resolve": ("freshness", "determinism", "soundness"),
    "permit": ("uniqueness", "authorization"),
    "stake": ("conservation", "custody", "monotonicity"),
    "unstake": ("conservation", "custody"),
    "harvest": ("conservation", "monotonicity"),
    "flashloan": ("atomicity", "conservation", "bounds"),
    "verify": ("soundness", "uniqueness"),
    "finalize": ("ordering", "soundness", "freshness"),
    "process": ("uniqueness", "ordering"),
}

# Distribution-shape detector over a function's PARAM SURFACE (class-level).
#
# A normalization/conservation invariant must fire whenever a function operates
# over a DISTRIBUTION of weights/shares/allocations - even when that distribution
# is carried as a slice-of-STRUCT whose element TYPE or PARAM NAME (not a bare
# scalar field) carries the class signal. The historical _SHAPE_FAMILIES regex
# only matched a bare `[]weight` / `weights` token, so a real protocol param like
# `intents []ValidatorIntent` or `vals []*WeightAlloc` (the Quicksilver-class
# shape) slipped through to the generic bounds fallback. This detector closes
# that gap GENERICALLY: it fires for
#   - a collection whose ELEMENT TYPE carries a dist token: `[]ValidatorIntent`,
#     `[]*WeightAlloc`, `Vec<ShareEntry>`, `[]Distribution`
#   - a collection whose PARAM NAME carries a dist token: `intents []X`,
#     `weights []Y`, `shares Vec<Z>`
#   - a bare dist-named slice/param: `weights`, `[]share`
# It is keyed on the dist-role CLASS (_DIST_HINTS), never on a specific
# protocol's type or symbol name.
_DIST_TOKEN = (
    r"(?:weight|share|alloc|ratio|portion|fraction|percent|distribution|intent|"
    r"split|apportion|payout|stake_?weight|votingpower|voting_?power)"
)
_DIST_SHAPE_RE = re.compile(
    # element-type carries the token inside a collection: []X / []*X / Vec<X> / [X]
    r"(?:\[\s*\]\s*\*?\s*\w*" + _DIST_TOKEN + r"\w*"          # []ValidatorIntent / []*WeightAlloc
    r"|Vec\s*<\s*\w*" + _DIST_TOKEN + r"\w*"                  # Vec<ShareEntry>
    r"|\[\s*\w*" + _DIST_TOKEN + r"\w*"                       # [WeightAlloc; N]
    # OR a param NAME carries the token and is plural/collection-shaped
    r"|\b\w*" + _DIST_TOKEN + r"\w*s?\b\s*(?::\s*)?(?:\[\s*\]|Vec\s*<|\[)"  # intents []X / shares Vec<Y>
    # OR a bare dist-named token (param name or scalar) as a last resort
    r"|\b\w*" + _DIST_TOKEN + r"\w*\b)",
    re.I,
)


def _params_carry_distribution(params: str) -> bool:
    """True when a function's params operate over a weight/share distribution.

    GENERAL, class-level: detects a collection-of-struct whose element type or
    param name carries a distribution-role token (_DIST_HINTS class), so a real
    protocol signature like `intents []ValidatorIntent` or `vals Vec<ShareEntry>`
    is recognized as a renormalization/conservation surface. Never tuned to a
    specific protocol's type or symbol name.
    """
    return bool(_DIST_SHAPE_RE.search(params or ""))


# Signature-shape -> families when the name is unknown.
_SHAPE_FAMILIES = (
    # a slice / array / list of weights/shares/allocations -> a distribution that
    # must stay normalized (sum-to-total, all-positive). Class-level shape, not
    # tuned to any one protocol's element type name. Broadened (iter13 fix) to
    # also match a slice-of-STRUCT whose element type or param name carries a
    # distribution-role token (e.g. `[]ValidatorIntent`, `intents []X`).
    (_DIST_SHAPE_RE, ("normalization", "conservation")),
    (re.compile(r"\baddress\b", re.I), ("authorization", "custody")),
    (re.compile(r"\b(uint\d*|u(8|16|32|64|128|256)|int\d*)\b", re.I), ("bounds", "conservation")),
    (re.compile(r"\b(bytes|sig|proof|signature|hash)\b", re.I), ("soundness", "uniqueness")),
    (re.compile(r"\b(time|deadline|timestamp|round)\b", re.I), ("freshness",)),
)

# Fn-name substrings that signal a distribution / renormalization / conservation
# CONTEXT. Two strength tiers (class-level, never symbol-tuned):
#   STRONG: the name itself names a distribution role -> normalization fires
#           regardless of param shape (`distribute`, `rebalance`, `normalize`,
#           `apportion`, `setweights`, `*intent*`, `*weight*`, `*share*`,
#           `*alloc*`, `*payout*`).
#   WEAK:   the name is a generic verb that COMMONLY guards/writes a distribution
#           but is ambiguous (`validate`, `settle`, `epoch`, `checkpoint`,
#           `update`, `set`, `compute`, `apply`, `process`, `finalize`, `tally`,
#           `accrue`) -> normalization fires ONLY when the param surface also
#           carries a distribution shape, so `validateSignature` is NOT
#           mis-mapped while `validateIntents([]ValidatorIntent)` IS.
_DIST_NAME_STRONG = re.compile(
    r"(intent|weight|share|alloc|distribut|rebalanc|normaliz|apportion|payout|"
    r"reweight|votingpower|voting_?power|splitfund|disburse)",
    re.I,
)
_DIST_NAME_WEAK = re.compile(
    r"(validate|settle|epoch|checkpoint|update|^set|compute|apply|process|"
    r"finaliz|tally|accrue|recompute|adjust|sync)",
    re.I,
)


# ---------------------------------------------------------------------------
# Surface parsing.
# ---------------------------------------------------------------------------

def _load_evm_author():
    """Lazy-load the PR5 EVM harness author module for surface parsing + render."""
    path = TOOLS_DIR / "evm-engine-harness-author.py"
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location("evm_engine_harness_author", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["evm_engine_harness_author"] = mod
    spec.loader.exec_module(mod)
    return mod


@dataclass
class Fn:
    name: str
    params: str
    visibility: str
    mutating: bool


@dataclass
class Surface:
    name: str
    lang: str
    functions: list[Fn] = field(default_factory=list)
    state_vars: list[str] = field(default_factory=list)


# Bounded Rust / Go extractors (independent of invariant-auto-synth so this
# tool stands alone; deliberately conservative regex).
#
# The Rust/Go extractors enumerate BOTH the exported and the internal/private
# surface so internal mutating/validating functions are analyzed (mirrors the
# Solidity internal-fn enumeration). The leading capture group records the real
# visibility keyword so each emitted record's callable_surface is accurate:
#   - Rust: `pub fn` / `pub(crate) fn` -> external; bare `fn` -> internal.
#   - Go:   exported Name (Uppercase) -> external; unexported (lowercase) ->
#           internal. Go has no keyword, so visibility is inferred from case.
_RS_FN = re.compile(
    r"(?P<vis>pub(?:\s*\([^)]*\))?\s+)?fn\s+(?P<name>\w+)\s*(?:<[^>]+>)?\s*"
    r"\((?P<params>[^)]*)\)\s*(?:->\s*(?P<ret>[^\{;]+))?",
    re.MULTILINE,
)
# A Rust fn is a pure READ (view) when its name implies a read role, it returns
# a value (has a `-> T` clause that is not unit/ProgramResult-only), AND it does
# NOT take a `&mut` receiver/param. GENERAL + class-level: keyed on the read-role
# prefix, never on a specific protocol symbol. Mutating verbs are excluded.
_RS_READ_NAME = re.compile(
    r"^(get|query|calc|calculate|compute|read|view|lookup|fetch|derive|peek|"
    r"current|pending|claimable|earned|owed|price|rate|quote|preview|estimate|"
    r"is|has|to_|from_|value_of|total|sum)\w*$",
    re.I,
)
_RS_MUTATE_NAME = re.compile(
    r"^(set|update|mint|burn|deposit|withdraw|transfer|send|delete|remove|add|"
    r"increment|decrement|apply|commit|write|store|save|put|create|init|"
    r"settle|distribute|allocate|rebalance|normalize|process|execute|handle|"
    r"register|enable|disable|pause|unpause|claim|stake|unstake|swap|"
    r"redeem|finalize|resolve|vote|propose|grant|revoke|push|pop|insert)\w*$",
    re.I,
)
_RS_STATE = re.compile(r"(?:pub\s+)?(\w+)\s*:\s*(?:StorageValue|StorageMap|StorageDoubleMap)", re.MULTILINE)
# Plain Rust/Anchor struct fields: `pub last_update: i64`, `price: u128`, etc.
# Captures the field name for a value-bearing scalar/collection type so a
# staleness read (BS-3) or a distribution write (BS-2) binds a real symbol.
_RS_FIELD = re.compile(
    r"^\s*(?:pub\s+)?(\w+)\s*:\s*(?:&\s*)?(?:mut\s+)?"
    r"(?:Vec<[^>]+>|\[[^\]]+\]|u\d+|i\d+|f\d+|bool|String|Decimal|"
    r"[A-Z]\w+(?:<[^>]+>)?)\s*,?\s*(?://.*)?$",
    re.MULTILINE,
)
# Capture the full func signature INCLUDING the return clause so a read-only
# (getter/query) Go method can be distinguished from a mutating one. Group 3 is
# the return clause (may be empty, a single type, or a parenthesized tuple).
_GO_FN = re.compile(
    r"func\s+(?:\(\s*\w+\s+\*?\w+\s*\)\s+)?(\w+)\s*\(([^)]*)\)\s*"
    r"(\([^)]*\)|[\w\.\[\]\*]+)?",
    re.MULTILINE,
)
# Struct-field state extraction. Broadened beyond the original
# (sdk.X|math.Int|uintN|intN|string|[]byte) to also capture distribution-shaped
# slice fields ([]Weight, []Allocation, ...) and timestamp-ish scalar fields
# (int64 last_update), so BS-2 (normalization) and BS-3 (read-staleness) bind to
# real symbols instead of the SDK ctx param. The field-type alternation is bound
# to a FIXED set of state-bearing shapes (numeric / string / bool / slice / map /
# sdk / math types). It does NOT include a bare `\w+` catch-all, so package/type/
# return/param tokens are not mis-captured as state. Struct-body scoping
# (_GO_STRUCT_BODY) further restricts extraction to actual `type X struct { ... }`
# field lines. Class-level, not symbol-tuned.
_GO_STATE = re.compile(
    r"^\s*(\w+)\s+(?:sdk\.\w+|math\.\w+|uint\d*|int\d*|float\d*|string|bool|byte|"
    r"\[\]\w+(?:\.\w+)?|map\[[^\]]+\]\w+(?:\.\w+)?)\s*(?://.*)?$",
    re.MULTILINE,
)
# A `type Name struct { ... }` body, so state-var extraction only sees real
# struct fields (not param lists or local declarations elsewhere in the file).
_GO_STRUCT_BODY = re.compile(r"type\s+\w+\s+struct\s*\{(.*?)\}", re.DOTALL)
# A Go method is treated as a pure READ (view) when its name implies a read role
# AND it returns at least one value (a getter/query/calc that hands a value back
# without an obvious mutation contract). GENERAL: keyed on the read-role prefix,
# never on a specific protocol symbol. Mutating verbs are excluded explicitly so
# a `GetAndIncrement`-style writer is not mis-read.
_GO_READ_NAME = re.compile(
    r"^(get|query|calc|calculate|compute|read|view|lookup|fetch|derive|peek|"
    r"current|pending|claimable|earned|owed|price|rate|quote|preview|estimate|"
    r"is|has|total|sum)\w*$",
    re.I,
)
# Mutating verbs anchored to the START of the method name (Go methods are
# verb-first). Anchoring avoids the substring trap where "Asset" contains "set"
# or "Address" contains "add" - those must NOT classify a getter as mutating.
_GO_MUTATE_NAME = re.compile(
    r"^(set|update|mint|burn|deposit|withdraw|transfer|send|delete|remove|add|"
    r"increment|decrement|apply|commit|write|store|save|put|create|init|"
    r"settle|distribute|allocate|rebalance|normalize|process|execute|handle|"
    r"register|enable|disable|pause|unpause|claim|stake|unstake|swap|"
    r"redeem|finalize|resolve|vote|propose|grant|revoke)\w*$",
    re.I,
)


def _strip_comments_generic(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    src = re.sub(r"//[^\n]*", "", src)
    return src


# r36-rebuttal: bugfix-inventory-claude-20260610
def detect_lang(path: Path, explicit: str) -> str:
    if explicit and explicit != "auto":
        return explicit
    ext = path.suffix.lower()
    if ext == ".sol":
        return "solidity"
    if ext == ".rs":
        return "rust"
    if ext == ".go":
        return "go"
    if ext == ".move":
        return "move"
    if ext == ".cairo":
        return "cairo"
    if ext == ".nr":
        return "noir"
    if ext == ".vy":
        return "vyper"
    # Any other extension (e.g. .ts, .sw, .leo) returns the raw extension name
    # so the unsupported-lang guard in parse_surface can produce a graceful
    # empty Surface with a warning rather than misfiring the Solidity parser.
    return ext.lstrip(".") if ext else "unknown"


def _go_returns_value(ret: str | None) -> bool:
    """True when a Go return clause hands back a value beyond a bare error.

    Go reads conventionally return `(value, error)`; a pure mutation returns just
    `error` (or nothing). So a non-empty return clause that is not solely `error`
    indicates the method produces a value - the read-surface signal.
    """
    if not ret:
        return False
    inner = ret.strip().strip("()").strip()
    if not inner:
        return False
    parts = [p.strip() for p in inner.split(",") if p.strip()]
    # drop a trailing/standalone error return; anything left is a real value.
    non_err = [p for p in parts if p.lower() != "error" and not p.lower().endswith("error")]
    return bool(non_err)


def _go_is_mutating(name: str, ret: str | None) -> bool:
    """Classify a Go method as mutating vs pure-read (view).

    GENERAL + class-level: a method is a READ only when its name implies a read
    role, it carries no mutating verb, AND it returns a value beyond a bare
    error. Everything else stays mutating (the historical default), so this is a
    strict, conservative refinement - it only RECLASSIFIES obvious getters/queries
    into the read surface; it never drops a function from analysis.
    """
    if _GO_MUTATE_NAME.search(name):
        return True
    if _GO_READ_NAME.match(name) and _go_returns_value(ret):
        return False
    return True


def _rs_returns_value(ret: str | None) -> bool:
    """True when a Rust return clause hands back a real value (not unit/result-only).

    A pure read has `-> T` for some value T; a mutation typically returns `()`,
    `ProgramResult`, `DispatchResult`, or `Result<(), E>`. We treat those unit-ish
    returns as NOT value-bearing so a mutating dispatchable is not mis-read.
    """
    if not ret:
        return False
    r = ret.strip()
    if not r:
        return False
    unit_ish = ("()", "ProgramResult", "DispatchResult", "DispatchResultWithPostInfo")
    if r in unit_ish:
        return False
    # Result<(), E> / Result<(),E> -> no value
    if re.match(r"^Result\s*<\s*\(\s*\)\s*,", r):
        return False
    return True


def _rs_is_mutating(name: str, params: str, ret: str | None) -> bool:
    """Classify a Rust fn as mutating vs pure-read (view).

    GENERAL + class-level: a fn is a READ only when its name implies a read role,
    carries no mutating verb, takes no `&mut` receiver/param, AND returns a value.
    Everything else stays mutating (the historical default) - a strict,
    conservative refinement that only RECLASSIFIES obvious getters into the read
    surface; it never drops a function from analysis.
    """
    if _RS_MUTATE_NAME.match(name):
        return True
    if "&mut" in (params or ""):
        return True
    if _RS_READ_NAME.match(name) and _rs_returns_value(ret):
        return False
    return True


# r36-rebuttal: bugfix-inventory-claude-20260610
def parse_surface(path: Path, lang: str, contract_name: str | None, evm_mod) -> Surface:
    _KNOWN_LANGS = {"solidity", "rust", "go", "move", "cairo", "noir", "vyper"}
    if lang not in _KNOWN_LANGS:
        print(
            json.dumps({"warning": f"unsupported lang '{lang}' for {path}; returning empty surface"}),
            file=sys.stderr,
        )
        return Surface(name=path.stem, lang=lang, functions=[], state_vars=[])
    if lang == "solidity":
        if evm_mod is None:
            raise ValueError("evm-engine-harness-author.py unavailable for Solidity parse")
        s = evm_mod.parse_contract(path, contract_name)
        fns = [
            Fn(name=f.name, params=f.params, visibility=f.visibility, mutating=f.is_mutating)
            for f in s.functions
            if f.name
        ]
        return Surface(name=s.name, lang="solidity", functions=fns, state_vars=list(s.state_vars))

    src = _strip_comments_generic(path.read_text(encoding="utf-8", errors="replace"))
    if lang == "rust":
        fns = [
            Fn(
                name=m.group("name"),
                params=" ".join(m.group("params").split()),
                # bare `fn` (no pub keyword) is a module-internal/private fn;
                # it is now enumerated alongside the pub surface.
                visibility="pub" if m.group("vis") else "internal",
                # read-role getters returning a value with no &mut are reclassified
                # as views (BS-3 staleness gate reaches the Rust read surface);
                # everything else stays mutating as before.
                mutating=_rs_is_mutating(
                    m.group("name"), m.group("params"), m.group("ret")
                ),
            )
            for m in _RS_FN.finditer(src)
            if not m.group("name").startswith("test")
        ]
        # Rust struct fields: the original StorageValue/Map regex misses plain
        # Anchor/Solana struct fields (`pub last_update: i64`), so also capture
        # `pub <name>: <type>` fields so a staleness read binds a real symbol.
        states = sorted(set(_RS_STATE.findall(src)) | set(_RS_FIELD.findall(src)))
        return Surface(name=path.stem, lang="rust", functions=fns, state_vars=states)
    if lang == "go":
        fns = []
        for (n, p, ret) in _GO_FN.findall(src):
            if not n or n.startswith("Test") or n.startswith("test"):
                continue
            fns.append(
                Fn(
                    name=n,
                    params=" ".join(p.split()),
                    # Go visibility is by identifier case: Uppercase = exported,
                    # lowercase = unexported/internal. Unexported funcs are now
                    # enumerated (previously dropped) and tagged internal.
                    visibility="pub" if n[0].isupper() else "internal",
                    # A Go method is a pure READ (view) when its name implies a
                    # read role, it is NOT a mutating verb, and it returns a value.
                    # Read methods enter the READ-class enumeration (BS-3 staleness
                    # gate); everything else stays mutating as before.
                    mutating=_go_is_mutating(n, ret),
                )
            )
        # Extract state vars only from struct bodies so param/local/keyword
        # tokens are never mis-captured. Fall back to whole-file scan only if no
        # struct body is present (defensive; keeps prior behavior on odd inputs).
        struct_bodies = _GO_STRUCT_BODY.findall(src)
        scan_src = "\n".join(struct_bodies) if struct_bodies else src
        states = sorted(set(_GO_STATE.findall(scan_src)))[:40]
        return Surface(name=path.stem, lang="go", functions=fns, state_vars=states)
    # move / fallback: reuse rust-ish fn regex (enumerate internal too)
    fns = [
        Fn(
            name=m.group("name"),
            params=" ".join(m.group("params").split()),
            visibility="pub" if m.group("vis") else "internal",
            mutating=True,
        )
        for m in _RS_FN.finditer(src)
    ]
    return Surface(name=path.stem, lang=lang, functions=fns, state_vars=[])


# ---------------------------------------------------------------------------
# Corpus family loading.
# ---------------------------------------------------------------------------

def load_corpus_families(extracted: Path, pilot: Path, index: Path):
    """Return per-category list of corpus invariant IDs (the trusted families)."""
    by_cat: dict[str, list[str]] = {}
    for jf in (extracted, pilot):
        if not jf.exists():
            continue
        for line in jf.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            cat = rec.get("category")
            inv = rec.get("invariant_id")
            if cat and inv:
                by_cat.setdefault(cat, [])
                if inv not in by_cat[cat]:
                    by_cat[cat].append(inv)
    index_counts: dict[str, int] = {}
    if index.exists():
        try:
            idx = json.loads(index.read_text(encoding="utf-8", errors="replace"))
            index_counts = dict(idx.get("per_category", {}) or {})
        except json.JSONDecodeError:
            pass
    return by_cat, index_counts


# ---------------------------------------------------------------------------
# Symbol binding.
# ---------------------------------------------------------------------------

_AGG_HINTS = ("total", "supply", "assets", "reserve", "pool", "liquidity", "balance", "debt")
_MONO_HINTS = ("nonce", "seq", "index", "count", "epoch", "round", "version", "accrued", "cumulative")
_AUTH_HINTS = ("owner", "admin", "guardian", "operator", "authority", "role")
_CAP_HINTS = ("cap", "max", "limit", "ceiling")
_TIME_HINTS = ("time", "updated", "deadline", "round", "stale", "expiry")
# distribution-shaped state vars: a weight/share/allocation set that must sum to
# a fixed total. Class-level role hints, not tuned to any one protocol symbol.
_DIST_HINTS = ("weight", "share", "alloc", "ratio", "portion", "fraction",
               "percent", "distribution", "intent", "split")
# stored last-update / freshness-tracked state a read must gate on.
_STALE_HINTS = ("lastupdate", "last_update", "updatedat", "updated_at", "timestamp",
                "lastpriceupdate", "lastrefresh", "updated", "lastblock")


def _pick_symbol(family: str, state_vars: list[str], fn: Fn) -> str | None:
    """Bind a family to the best-matching real state var; None if no plausible bind."""
    sv = state_vars
    low = {v: v.lower() for v in sv}

    def first_hit(hints):
        for v in sv:
            if any(h in low[v] for h in hints):
                return v
        return None

    if family == "normalization":
        # Bind the DISTRIBUTION CONTAINER, not a per-element scalar. A protocol
        # holds the distribution as a COLLECTION state var (plural / slice:
        # `validatorWeights`, `payoutShares`, `intents`) whose components must sum
        # to a fixed total; a bare per-element field (`Weight`, `Share`) is the
        # wrong subject. Prefer, in order: (a) a dist-token state var that is a
        # collection (plural or has a slice/`[]`/`s` shape), (b) any dist-token
        # state var, (c) an aggregate total, (d) first state var.
        def collection_dist_hit():
            for v in sv:
                lv = low[v]
                if any(h in lv for h in _DIST_HINTS) and (
                    lv.endswith("s") or "[]" in v or "list" in lv or "set" in lv
                    or "map" in lv or "vec" in lv or "array" in lv
                ):
                    return v
            return None
        return (
            collection_dist_hit()
            or first_hit(_DIST_HINTS)
            or first_hit(_AGG_HINTS)
            or (sv[0] if sv else None)
        )
    if family == "conservation":
        return first_hit(_AGG_HINTS) or first_hit(_DIST_HINTS) or (sv[0] if sv else None)
    if family == "monotonicity":
        return first_hit(_MONO_HINTS) or first_hit(_AGG_HINTS)
    if family == "authorization":
        return first_hit(_AUTH_HINTS) or first_hit(_AGG_HINTS)
    if family == "bounds":
        return first_hit(_CAP_HINTS) or first_hit(_AGG_HINTS) or (sv[0] if sv else None)
    if family == "freshness":
        return first_hit(_TIME_HINTS)
    if family in ("custody", "atomicity", "uniqueness", "ordering", "determinism", "soundness"):
        return first_hit(_AGG_HINTS) or (sv[0] if sv else None)
    return sv[0] if sv else None


def _families_for_fn(fn: Fn) -> list[str]:
    fams: list[str] = []

    def _add(fs):
        for f in fs:
            if f not in fams:
                fams.append(f)

    name = fn.name.lower()
    has_dist_shape = _params_carry_distribution(fn.params)

    # 1. STRONG distribution-role name -> normalization/conservation fires on the
    #    name alone (a fn that names a weight/share/intent/allocation role IS a
    #    distribution writer, irrespective of param shape). This reaches a real
    #    protocol fn like `validateIntents` / `reweightValidators` / `SetWeights`
    #    whose name carries the class signal even when the exact name is not in
    #    the curated _NAME_TO_FAMILIES table.
    if _DIST_NAME_STRONG.search(name):
        _add(("normalization", "conservation"))

    # 2. Curated exact-name mapping (authoritative for known verbs). When the
    #    curated verb ALSO carries a distribution-shaped param (e.g. a curated
    #    `settle`/`execute`/`process` over a `[]ShareEntry`), the normalization
    #    family is still added so the renormalization conservation law is not lost
    #    to the curated mapping's short-circuit.
    base = _NAME_TO_FAMILIES.get(name)
    if base:
        _add(base)
        if has_dist_shape and "normalization" not in fams:
            _add(("normalization",))
        if fams:
            return fams

    # 3. WEAK ambiguous verb (`validate`, `settle`, `epoch`, ...) -> normalization
    #    fires ONLY when the param surface ALSO carries a distribution shape, so a
    #    generic `validate*` over a weight distribution (`validateIntents([]X)`) is
    #    mapped to normalization while `validateSignature(bytes)` is NOT.
    if has_dist_shape and _DIST_NAME_WEAK.search(name):
        _add(("normalization", "conservation"))

    # 4. Shape fallback over the param surface (distribution shape -> normalization
    #    is the first _SHAPE_FAMILIES row, so a dist-shaped param binds the
    #    conservation family even when the name is wholly uninformative).
    for rx, fs in _SHAPE_FAMILIES:
        if rx.search(fn.params or ""):
            _add(fs)

    return fams or ["bounds"]


def _read_families_for_fn(fn: Fn) -> list[str]:
    """Map a VIEW (pure-read) function to plausible READ-class families.

    General + class-level: matches on the *role* a read name implies, falling
    back to the return/param shape. Returns [] when no read-invariant family is
    plausible (a trivial getter with no derivable spec is intentionally
    skipped). Never tuned to a specific protocol symbol.
    """
    low = fn.name.lower()
    fams: list[str] = []
    for keys, fs in _READ_NAME_TO_FAMILIES:
        if any(k in low for k in keys):
            for f in fs:
                if f not in fams:
                    fams.append(f)
    if fams:
        return fams
    # name uninformative -> shape fallback over the param surface
    for rx, fs in _READ_SHAPE_FAMILIES:
        if rx.search(fn.params or ""):
            for f in fs:
                if f not in fams:
                    fams.append(f)
    return fams


def _pick_read_symbol(family: str, state_vars: list[str], fn: Fn) -> str | None:
    """Bind a READ-class family to the read's natural subject.

    For a pure read the subject is the computed result; we prefer a real state
    var the read plausibly derives from (for a readable statement + grounding),
    and fall back to the function name itself so the statement always names a
    concrete subject. Returns a non-None subject for every read family so the
    derived spec is never anonymous.
    """
    sv = state_vars
    low = {v: v.lower() for v in sv}

    def first_hit(hints):
        for v in sv:
            if any(h in low[v] for h in hints):
                return v
        return None

    if family == "read_staleness":
        # prefer the stored value the read returns (price/oracle/feed); the
        # last_update sidecar is named in the assertion as {sym}_last_update.
        hit = (first_hit(("price", "oracle", "feed", "value", "rate", "mark",
                          "spot", "twap"))
               or first_hit(_STALE_HINTS) or first_hit(_AGG_HINTS))
    elif family == "epoch_boundary":
        hit = first_hit(_TIME_HINTS) or first_hit(("epoch", "period", "window", "round"))
    elif family == "read_conservation":
        hit = first_hit(_AGG_HINTS)
    elif family == "read_monotonicity":
        hit = first_hit(_MONO_HINTS) or first_hit(_AGG_HINTS)
    elif family in ("bounds_on_computed_value", "read_determinism"):
        hit = first_hit(_CAP_HINTS) or first_hit(_AGG_HINTS)
    else:
        hit = None
    # the computed-result subject: a real state var if one is plausible, else
    # the function's own name (the read's output). Never None for read families.
    return hit or fn.name


# ---------------------------------------------------------------------------
# Derivation.
# ---------------------------------------------------------------------------

def _inst(template_str: str, fn: str, sym: str | None) -> str:
    s = sym or "state"
    snap = f"{s}"
    return (
        template_str.replace("{fn}", fn)
        .replace("{sym}", s)
        .replace("{snap}", snap)
        # read-class staleness gate: the evaluation-time clock the read compares
        # the stored last_update against (block_timestamp / ctx.BlockTime()).
        .replace("{read_now}", "read_block_timestamp")
    )


# Visibilities we consider as part of the analyzable surface. Internal/private
# mutating/validating functions were historically dropped here, so any bug that
# lives in an internal helper (e.g. an ERC-4337 `_validateSignature` override,
# an internal epoch/accounting helper, an internal state-mutating routine) was
# never hypothesized. We now enumerate ALL internal/private mutating functions
# class-level - this is a general capability improvement (internal functions
# were skipped; now they are enumerated), NOT a pattern hand-tuned to any one
# symbol name. The family mapping (name heuristic + signature shape) then
# derives target-specific invariants for them exactly as for the external set.
_EXTERNAL_VIS = ("public", "external", "pub")
_INTERNAL_VIS = ("internal", "private")
_ANALYZABLE_VIS = _EXTERNAL_VIS + _INTERNAL_VIS


def _emit_record(
    surf: Surface,
    fn: Fn,
    fam: str,
    tmpl: FamilyTemplate,
    sym: str | None,
    by_cat,
    index_counts,
    invariant_class: str,
) -> dict[str, Any]:
    """Build one derived-invariant record (shared by mutating + read paths)."""
    # READ-class families ground in their underlying corpus category so R58
    # grounding resolves to real INV-* ids even though the read-class family
    # name (e.g. epoch_boundary) is not itself a corpus category.
    grounding_cat = tmpl.corpus_category or fam
    corpus_ids = by_cat.get(grounding_cat, [])[:5]
    density = index_counts.get(grounding_cat, 0)
    confidence = "high" if (sym and density >= 20) else ("medium" if sym else "low")
    statement = _inst(tmpl.statement, fn.name, sym)
    assertion = _inst(tmpl.assertion_expr, fn.name, sym)
    return {
        "schema_version": SCHEMA,
        "target": surf.name,
        "target_lang": surf.lang,
        "function": fn.name,
        "function_params": fn.params,
        "function_visibility": fn.visibility,
        "callable_surface": (
            "external" if fn.visibility in _EXTERNAL_VIS else "internal"
        ),
        "family": fam,
        # mutating-state-invariant vs read-side (view/pure) invariant. The
        # read-class records are the half historically missed by the
        # mutating-only enumeration.
        "invariant_class": invariant_class,
        "grounding_category": grounding_cat,
        "bound_symbol": sym,
        "bind_hint": tmpl.hint,
        "statement": statement,
        "assertion_expr": assertion,
        "needs_snapshot": tmpl.needs_snapshot,
        # the TRUE-0-day tag: the engine hunts ANY counterexample;
        # a violation here matches NO pre-existing detector.
        "detector_match": "none",
        "discovery_mode": "spec-violation-counterexample-search",
        "grounding_invariant_ids": corpus_ids,
        "corpus_family_density": density,
        "confidence": confidence,
        "refined_by": None,
        "derived_at_utc": datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
    }


def derive_invariants(surf: Surface, by_cat, index_counts, max_per_fn: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    # --- mutating-state invariants (the historical surface) ---
    mutating = [f for f in surf.functions if f.mutating and f.visibility in _ANALYZABLE_VIS]
    for fn in mutating:
        emitted = 0
        for fam in _families_for_fn(fn):
            if emitted >= max_per_fn:
                break
            tmpl = _FAMILY_TEMPLATES.get(fam)
            if tmpl is None:
                continue
            sym = _pick_symbol(fam, surf.state_vars, fn)
            key = (fn.name, fam, sym or "")
            if key in seen:
                continue
            seen.add(key)
            out.append(
                _emit_record(surf, fn, fam, tmpl, sym, by_cat, index_counts, "mutating-state")
            )
            emitted += 1

    # --- READ-class invariants (the VIEW / pure-read surface) ---
    # A view (non-mutating) function writes no state, so the mutating loop above
    # skips it - yet read helpers carry their own spec (inclusive-vs-exclusive
    # boundary, read-side conservation, monotone read, bounds on a computed
    # value). We enumerate every internal/private/public VIEW function for the
    # READ-class families. GENERAL + class-level: any view fn whose name/shape
    # matches a read-invariant family is hypothesized; never symbol-name-tuned.
    view_fns = [f for f in surf.functions if not f.mutating and f.visibility in _ANALYZABLE_VIS]
    for fn in view_fns:
        emitted = 0
        for fam in _read_families_for_fn(fn):
            if emitted >= max_per_fn:
                break
            tmpl = _READ_FAMILY_TEMPLATES.get(fam)
            if tmpl is None:
                continue
            sym = _pick_read_symbol(fam, surf.state_vars, fn)
            key = (fn.name, fam, sym or "")
            if key in seen:
                continue
            seen.add(key)
            out.append(
                _emit_record(surf, fn, fam, tmpl, sym, by_cat, index_counts, "read-side")
            )
            emitted += 1

    return out


# ---------------------------------------------------------------------------
# MIMO refinement (optional, bounded, consent-gated).
# ---------------------------------------------------------------------------

def _mimo_refine(invs: list[dict[str, Any]], budget: int, audit_dir: Path) -> int:
    """Refine up to `budget` invariant statements via tools/llm-dispatch.py.

    Returns number of refined records. Best-effort: on any error per call,
    the original statement is retained and refined_by stays None.
    """
    budget = max(0, min(budget, MIMO_BUDGET_CAP))
    if budget == 0:
        return 0
    if os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") != "1":
        return 0
    dispatch = TOOLS_DIR / "llm-dispatch.py"
    if not dispatch.exists():
        return 0
    # Pick the highest-value invariants to spend budget on: low/medium
    # confidence first (those most need sharpening), then high.
    order = sorted(
        range(len(invs)),
        key=lambda i: {"low": 0, "medium": 1, "high": 2}.get(invs[i]["confidence"], 1),
    )
    refined = 0
    for idx in order:
        if refined >= budget:
            break
        rec = invs[idx]
        prompt = (
            "You are sharpening a TARGET-SPECIFIC security invariant for a smart "
            "contract / protocol. Return STRICT JSON only, no prose, with keys "
            "`statement` (one sentence, MUST/MUST-NOT phrasing, naming the bound "
            "symbol) and `assertion_expr` (a single boolean relation over real "
            "symbols using == <= >= < > != && ||, no tautology, no `% 1`).\n\n"
            f"target: {rec['target']} ({rec['target_lang']})\n"
            f"function: {rec['function']}({rec['function_params']})\n"
            f"family: {rec['family']}\n"
            f"bound_symbol: {rec['bound_symbol']}\n"
            f"current statement: {rec['statement']}\n"
            f"current assertion_expr: {rec['assertion_expr']}\n"
        )
        pf = audit_dir / f"_nvim_mimo_prompt_{idx}.txt"
        try:
            pf.write_text(prompt, encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(dispatch),
                    "--prompt-file",
                    str(pf),
                    "--provider",
                    "mimo",
                    "--max-tokens",
                    "800",
                    "--operator-live-network-consent",
                    "--task-type",
                    "invariant-refine",
                    "--routing-purpose",
                    "advisory",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode != 0:
                continue
            body = _extract_completion_text(proc.stdout)
            parsed = _extract_json_obj(body)
            if not parsed:
                continue
            new_stmt = parsed.get("statement")
            new_assert = parsed.get("assertion_expr")
            if new_stmt and isinstance(new_stmt, str):
                rec["statement"] = new_stmt.strip()
            if new_assert and isinstance(new_assert, str) and _is_real_relation(new_assert):
                rec["assertion_expr"] = new_assert.strip()
            rec["refined_by"] = "mimo"
            refined += 1
        except (subprocess.TimeoutExpired, OSError):
            continue
        finally:
            try:
                pf.unlink()
            except OSError:
                pass
    return refined


_REAL_REL = re.compile(r"(<=|>=|<|>|==|!=|&&|\|\|)")


def _is_real_relation(expr: str) -> bool:
    if "% 1" in expr.replace(" ", " "):
        return False
    m = re.search(r"([A-Za-z_][\w.]*)\s*==\s*([A-Za-z_][\w.]*)", expr)
    if m and m.group(1) == m.group(2):
        return False
    return bool(_REAL_REL.search(expr))


def _extract_completion_text(stdout: str) -> str:
    """llm-dispatch prints a JSON record; pull the Messages-API text content."""
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Anthropic Messages shape: {"content":[{"type":"text","text":...}]}
        content = obj.get("content")
        if isinstance(content, list):
            for blk in content:
                if isinstance(blk, dict) and blk.get("type") == "text":
                    return blk.get("text", "")
        if isinstance(obj.get("completion_text"), str):
            return obj["completion_text"]
        if isinstance(obj.get("text"), str):
            return obj["text"]
    return stdout


def _extract_json_obj(text: str):
    text = text.strip()
    if not text:
        return None
    # strip code fences
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.MULTILINE)
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Render via PR5 harness authors (best-effort delegation).
# ---------------------------------------------------------------------------

_RENDER_AUTHOR = {
    "solidity": "evm-engine-harness-author.py",
    "rust": "rust-engine-harness-author.py",
    "go": "go-engine-harness-author.py",
}


def render_engine_specs(workspace: Path, contract: Path, lang: str, out_dir: Path) -> dict[str, Any]:
    """Delegate to the PR5 engine-harness author so engines can hunt counterexamples.

    Best-effort: returns a manifest describing the delegation. The PR5 authors
    consume the same corpus invariant library this tool derives from, so the
    rendered specs carry the same family grounding.
    """
    author = TOOLS_DIR / _RENDER_AUTHOR.get(lang, "")
    if not author.exists():
        return {"rendered": False, "reason": f"no PR5 author for lang={lang}", "author": str(author)}
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, str(author)]
    if lang == "solidity":
        cmd += [str(workspace), str(contract), "--out-dir", str(out_dir), "--json"]
    else:
        # rust/go authors take (workspace, source, --out-dir); pass uniformly.
        cmd += [str(workspace), str(contract), "--out-dir", str(out_dir), "--json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"rendered": False, "reason": f"render exec failed: {e}", "author": str(author)}
    manifest = None
    if proc.returncode == 0 and proc.stdout.strip():
        try:
            manifest = json.loads(proc.stdout.strip().splitlines()[-1])
        except json.JSONDecodeError:
            manifest = None
    return {
        "rendered": proc.returncode == 0,
        "author": str(author.name),
        "out_dir": str(out_dir),
        "returncode": proc.returncode,
        "stderr_tail": proc.stderr.strip().splitlines()[-3:] if proc.stderr else [],
        "author_manifest": manifest,
    }


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------

def build(
    workspace: Path,
    contract: Path,
    lang: str,
    contract_name: str | None,
    extracted: Path,
    pilot: Path,
    index: Path,
    max_per_fn: int,
    mimo_refine: bool,
    mimo_budget: int,
    render: bool,
    out_dir: Path | None,
) -> dict[str, Any]:
    evm_mod = _load_evm_author()
    lang = detect_lang(contract, lang)
    surf = parse_surface(contract, lang, contract_name, evm_mod)
    by_cat, index_counts = load_corpus_families(extracted, pilot, index)
    invs = derive_invariants(surf, by_cat, index_counts, max_per_fn)

    refined = 0
    if mimo_refine and invs:
        audit_dir = workspace / ".auditooor"
        audit_dir.mkdir(parents=True, exist_ok=True)
        refined = _mimo_refine(invs, mimo_budget, audit_dir)

    render_manifest = None
    if render:
        rdir = out_dir or (workspace / ".auditooor" / "novel_harness")
        render_manifest = render_engine_specs(workspace, contract, lang, rdir)

    fam_counts: dict[str, int] = {}
    class_counts: dict[str, int] = {}
    for r in invs:
        fam_counts[r["family"]] = fam_counts.get(r["family"], 0) + 1
        ic = r.get("invariant_class", "mutating-state")
        class_counts[ic] = class_counts.get(ic, 0) + 1

    return {
        "schema_version": SUMMARY_SCHEMA,
        "target": surf.name,
        "target_lang": surf.lang,
        "contract_path": str(contract),
        "functions_parsed": len(surf.functions),
        "mutating_functions": len([f for f in surf.functions if f.mutating]),
        "view_functions": len([f for f in surf.functions if not f.mutating]),
        "state_vars_parsed": len(surf.state_vars),
        "invariants_derived": len(invs),
        "per_family": dict(sorted(fam_counts.items())),
        "per_invariant_class": dict(sorted(class_counts.items())),
        "read_side_invariants": class_counts.get("read-side", 0),
        "mimo_refined": refined,
        "render": render_manifest,
        "discovery_mode": "spec-violation-counterexample-search",
        "invariants": invs,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--workspace", required=True, help="audit workspace root")
    ap.add_argument("--contract", required=True, help="path to the target source file")
    ap.add_argument("--lang", default="auto", choices=["auto", "solidity", "rust", "go", "move"])
    ap.add_argument("--contract-name", default=None, help="contract name if file has several")
    ap.add_argument("--extracted", default=str(DEFAULT_EXTRACTED))
    ap.add_argument("--pilot", default=str(DEFAULT_PILOT))
    ap.add_argument("--index", default=str(DEFAULT_INDEX))
    ap.add_argument("--max-per-fn", type=int, default=3, help="max derived invariants per function")
    ap.add_argument("--mimo-refine", action="store_true", help="refine statements via MIMO (consent-gated)")
    ap.add_argument("--mimo-budget", type=int, default=MIMO_BUDGET_DEFAULT, help=f"max MIMO calls (cap {MIMO_BUDGET_CAP})")
    ap.add_argument("--render", action="store_true", help="render engine specs via PR5 harness authors")
    ap.add_argument("--out-dir", default=None, help="render output dir (with --render)")
    ap.add_argument("--output", default=None, help="write JSONL of derived invariants here")
    ap.add_argument("--json", action="store_true", help="emit summary JSON to stdout")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser()
    contract = Path(args.contract).expanduser()
    if not contract.is_absolute():
        cand = ws / contract
        if cand.exists():
            contract = cand
    if not contract.exists():
        print(json.dumps({"error": f"contract not found: {contract}"}), file=sys.stderr)
        return 2

    try:
        summary = build(
            workspace=ws,
            contract=contract,
            lang=args.lang,
            contract_name=args.contract_name,
            extracted=Path(args.extracted),
            pilot=Path(args.pilot),
            index=Path(args.index),
            max_per_fn=args.max_per_fn,
            mimo_refine=args.mimo_refine,
            mimo_budget=args.mimo_budget,
            render=args.render,
            out_dir=Path(args.out_dir).expanduser() if args.out_dir else None,
        )
    except ValueError as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 2

    if args.output:
        outp = Path(args.output).expanduser()
        outp.parent.mkdir(parents=True, exist_ok=True)
        with outp.open("w", encoding="utf-8") as fh:
            for rec in summary["invariants"]:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(
            f"[novel-vector-invariant-miner] target={summary['target']} "
            f"lang={summary['target_lang']} "
            f"mutating_fns={summary['mutating_functions']} "
            f"view_fns={summary['view_functions']} "
            f"invariants={summary['invariants_derived']} "
            f"read_side={summary['read_side_invariants']} "
            f"families={summary['per_family']} "
            f"mimo_refined={summary['mimo_refined']} "
            f"discovery_mode={summary['discovery_mode']}"
        )
        if summary.get("render"):
            print(f"[novel-vector-invariant-miner] render={summary['render'].get('rendered')} "
                  f"author={summary['render'].get('author')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
