#!/usr/bin/env python3
# <!-- r36-rebuttal: lane-B-CROSS-FUNCTION-INVARIANT registered in .auditooor/agent_pathspec.json -->
# r36-rebuttal: funnel-generic-fixes-wave3
"""cross-function-invariant-coverage.py - the CROSS-FUNCTION / composition
invariant coverage axis (the final L37 completeness signal).

Background / root cause
-----------------------
Every existing coverage axis is PER-UNIT:

  - ``coverage-map`` (L37 signal o) asks "did every SURFACE get a hypothesis
    token?".
  - ``function-coverage-completeness.py`` (L37 signal s) asks "did every
    in-scope FUNCTION get a REAL attack with a recorded verdict?".
  - ``depth-certificate-check.py`` (R81) asks "did we audit each UNIT deeply -
    per-guard negative-space + sibling-path guard-diff?".

None of them asks the COMPOSITION question: "is there a MUTATION-VERIFIED test
asserting the invariant that spans TWO-OR-MORE functions?". A protocol can have
100% per-function coverage and still be broken because:

  (a) ``deposit`` and ``withdraw`` are each individually fine, but the round-
      trip invariant (``deposit(x); withdraw(x)`` returns the user whole) is
      never asserted - a rounding-direction bug only shows when the two run
      back-to-back.
  (b) a multi-step state machine (``open -> fund -> close``, ``propose ->
      queue -> execute``, ``lock -> claim -> unlock``) preserves a GLOBAL
      invariant (total supply, escrow balance, accounting identity) that no
      single-function harness can express.

This tool makes that axis a first-class L37 completeness signal. It generically
enumerates the cross-function invariant REQUIREMENTS for any workspace and any
language, then checks - for each requirement - whether the workspace has a
MUTATION-VERIFIED (non-vacuous) test asserting that cross-function invariant.
``--check`` passes only when every requirement is covered by a non-vacuous
cross-function test.

Requirement enumeration (generic, language-aware)
-------------------------------------------------
(1) L30 sibling pairs. Reuses ``tools/sibling-path-guard-diff.py``'s pairing
    core (the canonical L30 pair list: deposit/withdraw, mint/burn,
    claim/finalize, supply/borrow, propose/execute, lock/unlock,
    escrow/release, vote/tally, stake/unstake, ...). Each PAIR THAT EXISTS in
    the in-scope tree is a cross-function requirement: the two arms move the
    same resource in opposite directions, so a round-trip / conservation
    invariant must be asserted across BOTH.

(2) Multi-function state-machine sequences. Generically detected: a SHARED
    MUTABLE STATE FIELD written by THREE-OR-MORE in-scope functions implies a
    sequence whose composition must preserve a global invariant. The tool
    extracts per-function written-state tokens (assignments to ``state.X`` /
    ``self.X`` / ``s_X`` / storage writes) and groups functions by the field
    they co-mutate; any field co-mutated by >= the sequence threshold (default
    3) yields a state-machine requirement over those functions.

Both strategies are TARGET-AGNOSTIC and rely only on the language-aware
function / write extraction (Solidity now; Rust/Go/Move/Cairo via extensible
runner / operator tables and env hooks below).

Coverage check (anti-stub, mutation-verified)
---------------------------------------------
For each requirement (a set of >=2 function names), the tool looks for a TEST /
HARNESS artifact in the workspace that:

  (i)  references ALL (or, for large sequences, at least
       ``AUDITOOOR_XFI_MIN_SEQUENCE_OVERLAP``, default 2) of the requirement's
       functions in a single test unit (a test function / harness file), AND
  (ii) is MUTATION-VERIFIED NON-VACUOUS - i.e. a mutation-kill is recorded for
       at least one of the requirement's functions, OR a cross-function
       mutation record names the test.

A test that references the functions but is NOT mutation-verified (no kill on
disk, OR a recorded ``vacuous`` verdict) counts as UNCOVERED - exactly the
anti-stub discipline of ``function-coverage-completeness.py`` and R80: a green
cross-function test that passes both with AND without an injected bug proves
nothing.

Mutation verdicts are read from the SAME cached artifact the sibling gates use
(``<ws>/.auditooor/mutation_verify_coverage.json`` /
``mutation-verify-coverage.json``), produced by
``tools/mutation-verify-coverage.py``. This tool NEVER re-implements mutation
testing (per the tool-duplication charter); it consumes the cached verdicts. If
no mutation backend output exists, every requirement that has a referencing
test is conservatively UNVERIFIED -> uncovered (a missing backend can never
silently PASS a cross-function requirement).

Output
------
``<ws>/.auditooor/cross_function_invariant_coverage.json`` (schema
``auditooor.cross_function_invariant_coverage.v1``), and per-requirement rows.

Verdict vocabulary
------------------
- ``pass-cross-function-covered``   every requirement has a non-vacuous test.
- ``pass-no-requirements``          no cross-function requirement found in tree.
- ``pass-no-source``                no in-scope source found.
- ``ok-rebuttal``                   a bounded xfi-rebuttal accepted.
- ``fail-cross-function-uncovered`` >=1 requirement has no mutation-verified
                                    cross-function test (lists the uncovered).
- ``error``                         unreadable workspace / internal error.

Override
--------
Visible bounded line ``xfi-rebuttal: <reason>`` (<=200 chars) OR HTML-comment
form ``<!-- xfi-rebuttal: <reason> -->`` in
``<ws>/.auditooor/cross_function_invariant_coverage_rebuttal.txt``. A non-empty,
in-bounds reason flips the fail to ``ok-rebuttal``. Empty / oversized reasons
are ignored. Reserved for genuinely-N/A workspaces (a single-function target
with no composition surface, or a target whose cross-function invariants are
proven out-of-band - cite the artifact in the reason).

Env hooks (extensibility - ZERO workspace hardcoding)
-----------------------------------------------------
- ``AUDITOOOR_XFI_NAMING_PAIRS``         newline-separated ``a|b|hint`` rows
                                         appended to the L30 pair list.
- ``AUDITOOOR_XFI_SEQUENCE_THRESHOLD``   min functions co-mutating a field to
                                         form a state-machine requirement
                                         (default 3).
- ``AUDITOOOR_XFI_MIN_SEQUENCE_OVERLAP`` min requirement-functions a single
                                         test must reference (default 2).
- ``AUDITOOOR_XFI_WRITE_PATTERNS_<LANG>`` newline-separated regex (with a
                                         capture group for the field token)
                                         appended to the per-language
                                         state-write detector (LANG in
                                         SOL/RS/GO/MOVE/CAIRO).
- ``AUDITOOOR_XFI_TEST_HINTS``           newline-separated extra path
                                         substrings treated as test/harness
                                         files.

CLI
---
    python3 tools/cross-function-invariant-coverage.py --workspace <ws> \
        [--check] [--emit-worklist] [--json]

Exit code
---------
- 0 on pass-* / ok-rebuttal / pass-no-* .
- 1 on ``fail-cross-function-uncovered`` (only in ``--check`` mode).
- 2 on ``error``.

Dependency-free: stdlib only, offline-safe, never executes target code. Reuses
the L30 sibling-pair core via ``sibling-path-guard-diff.py`` (imported by path),
falling back to an in-file copy of the canonical pair list if that tool is
absent, so this gate is resilient to the sibling tool's presence.
"""
from __future__ import annotations

import argparse
import glob
import importlib.util
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA = "auditooor.cross_function_invariant_coverage.v1"
GATE = "CROSS-FUNCTION-INVARIANT-COVERAGE"


# --------------------------------------------------------------------------
# Shared scope-exclusion helper (single source of truth for OOS / vendored /
# generated classification, shared across every coverage / depth gate). Loaded
# by path (tools/lib has no __init__.py), mirroring the sibling-tool / resolver
# loaders already used below. If the helper is somehow unavailable the tool
# degrades to its dir-segment _SKIP_DIRS pass alone (fail-safe toward MORE
# coverage - a missing helper never silently drops in-scope source).
# --------------------------------------------------------------------------
def _load_scope_exclusion():
    try:
        tool_path = Path(__file__).resolve().with_name("lib") / "scope_exclusion.py"
        if not tool_path.is_file():
            return None
        spec = importlib.util.spec_from_file_location("_xfi_scope_exclusion", tool_path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_xfi_scope_exclusion"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


_SCOPE_EXCL = _load_scope_exclusion()


# --------------------------------------------------------------------------
# Per-unit non-economic-surface disposition (single source of truth in
# tools/lib/non_economic_disposition.py). A cross-function requirement whose
# constituent functions ALL live in DOCUMENTED non-economic / OOS contracts has
# no fund/share conservation invariant to assert; it is credited as
# non-economic-surface-dispositioned rather than fail-cross-function-uncovered.
# Never-false-pass-guarded (bounded class, real rationale, on-disk CUT, rejected
# for any transfer-mover) - NOT a blanket scope-out. See the lib docstring.
# --------------------------------------------------------------------------
def _load_non_economic_disposition():
    try:
        tool_path = Path(__file__).resolve().with_name("lib") / "non_economic_disposition.py"
        if not tool_path.is_file():
            return None
        spec = importlib.util.spec_from_file_location("non_economic_disposition", tool_path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules["non_economic_disposition"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


_NED_MOD = _load_non_economic_disposition()


def _is_vendored_oos(rel: str) -> bool:
    """True iff ``rel`` is a vendored dependency / build artifact per the shared
    scope-exclusion table (the single source of truth that subsumes the former
    in-file ``interchaintest`` / ``@openzeppelin`` literals). The test/non-test
    split is intentionally NOT delegated here - that axis is owned by
    ``_is_test_path`` + the ``include_tests`` flag, so this uses ``is_vendored``
    (vendored + build-artifact) rather than the broader ``is_oos`` (which would
    also fold in test files and break the test-ref scan). Returns False when the
    helper is unavailable (fail-safe: keep the file in scope)."""
    if _SCOPE_EXCL is None:
        return False
    try:
        return bool(_SCOPE_EXCL.is_vendored(rel))
    except Exception:
        return False

_REBUTTAL_MAX = 200
_REBUTTAL_RE = re.compile(
    r"(?:<!--\s*)?xfi-rebuttal:\s*(?P<reason>.+?)(?:\s*-->)?\s*$",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------
# Canonical L30 sibling pair list (fallback copy - the authoritative source is
# tools/sibling-path-guard-diff.py::_NAMING_PAIRS, imported by path when
# present). Kept in sync deliberately; if the sibling tool is on disk we use
# ITS list so there is a single source of truth at runtime.
# --------------------------------------------------------------------------
_FALLBACK_NAMING_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("deposit", "withdraw", "deposit/withdraw round-trip must conserve user balance"),
    ("mint", "burn", "mint/burn must conserve total supply"),
    ("claim", "finalize", "claim/finalize must conserve leaf/state accounting"),
    ("supply", "borrow", "supply/borrow must conserve collateral accounting"),
    ("propose", "execute", "propose/execute must preserve authorization/timelock"),
    ("lock", "unlock", "lock/unlock must conserve locked balance"),
    ("escrow", "release", "escrow/release must conserve custody balance"),
    ("vote", "tally", "vote/tally must conserve eligibility/weight"),
    ("stake", "unstake", "stake/unstake must conserve staked balance"),
    ("freeze", "unfreeze", "freeze/unfreeze must preserve authorization state"),
    ("add", "remove", "add/remove must conserve membership set"),
    ("enable", "disable", "enable/disable must preserve authorization state"),
    ("open", "close", "open/close must preserve lifecycle state"),
    ("wrap", "unwrap", "wrap/unwrap must conserve wrapped balance"),
)

_LANG_BY_EXT = {".sol": "sol", ".rs": "rs", ".go": "go", ".move": "move", ".cairo": "cairo"}

# Function/method declaration extractors per language.
_FN_RES = {
    "sol": re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\("),
    "rs": re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*[<(]"),
    "go": re.compile(r"\bfunc\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\("),
    "move": re.compile(r"\bfun\s+([A-Za-z_]\w*)\s*[<(]"),
    "cairo": re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*[<(]"),
}

# ---------------------------------------------------------------------------
# Go bare-assignment write. The optional `(?:k\.|s\.|app\.)?` prefix means this
# ALSO matches an UNQUALIFIED assignment `vaults = append(vaults, v)` /
# `vaults[a] = true` on a LOCAL variable in a read-only query / pure constructor /
# validator. In Go there is no bare package-level mutable storage the way Solidity
# has storage fields - real ledger state is written through a keeper/store receiver
# (`k.`/`s.`/`app.`) or a store method (`.Set(`), so an unqualified bare assignment
# is a LOCAL variable, never a ledger write. `_go_bare_assign_is_local` gates it in
# the write-scan loop (Go-scoped) so a local slice/map build (esp. a NAMED-RETURN
# `vaults` that _collect_go_locals does not see) stops forming a phantom cross-fn
# `state:<local>` requirement. A qualified write (`k.balances[addr] = x`) keeps the
# prefix and still counts. Mirrors value-moving-functions.py commit 9250f04f6b.
# ---------------------------------------------------------------------------
_GO_BARE_ASSIGN_RE = re.compile(
    r"(?<![.\w])(?:k\.|s\.|app\.)?([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?<![=!<>:])[-+*/|&^%]?=(?!=)"
)


def _go_bare_assign_is_local(m: "re.Match") -> bool:
    """True iff a Go `_GO_BARE_ASSIGN_RE` hit is an UNQUALIFIED local variable
    assignment (no `k.`/`s.`/`app.` store/keeper receiver). Such a hit is a local
    slice/map/scalar build in a read-only query, pure constructor, or validator -
    it moves no value and must NOT count as a co-mutated state field. Conservative
    + Go-scoped: a qualified keeper/store write (`k.field = x`) keeps its prefix and
    still counts. Mirror of the same-named helper in value-moving-functions.py."""
    g0 = m.group(0)
    return not (
        g0.startswith("k.") or g0.startswith("s.") or g0.startswith("app.")
    )


# Per-language state-WRITE detectors. Each regex's first capture group names the
# mutated state field. Conservative on purpose: only patterns that strongly
# indicate a persistent / shared-state write, so a state-machine requirement is
# only formed when 3+ functions write the SAME field.
#
# Mirrors _WRITE_RES in value-moving-functions.py - KEEP IN SYNC. The Go table has
# ONE deliberate, now-consistent divergence shared with the sibling (both fixed in
# lockstep): (a) the bare-assignment regex is named `_GO_BARE_ASSIGN_RE` and gated
# by `_go_bare_assign_is_local` in the write-scan loop so an unqualified local
# `vaults = append(...)` is not a state write, and (b) a cosmos collections
# `.Set/.Remove/.Append` store-write pattern is added. Other languages byte-identical.
_WRITE_RES = {
    "sol": [
        # bare storage field assignment: `foo = ...;` / `foo += ...;` /
        # `foo[...] = ...;`. NOT anchored to line-start (same-line bodies like
        # `function f() { totalAssets = ...; }` must still be caught), but the
        # token must be at a word boundary preceded by a non-member-access
        # char so we do not capture the RHS of `a.b = c`. The negative
        # lookahead on `=` rejects comparison ops (== <= >= !=).
        re.compile(r"(?<![.\w])([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?<![=!<>])[-+*/|&^%]?=(?!=)"),
        re.compile(r"\bthis\.([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?<![=!<>])[-+*/|&^%]?=(?!=)"),
    ],
    "rs": [
        re.compile(r"\bself\.([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?<![=!<>])[-+*/|&^%]?=(?!=)"),
        # Substrate-style storage: `Foo::<T>::put(...)` /
        # `Foo::insert(...)` / `Foo::mutate(...)`. Require a type-like
        # leading token so helper calls such as `std::mem::take(...)` are not
        # misclassified as persistent state writes to field `mem`.
        re.compile(r"\b([A-Z][A-Za-z0-9_]*)::(?:<[^>]*>::)?(?:put|set|insert|mutate|kill|take|remove)\s*\("),
    ],
    "go": [
        _GO_BARE_ASSIGN_RE,
        # cosmos keeper setters: `k.SetFoo(ctx, ...)` -> field "Foo".
        re.compile(r"\.Set([A-Z]\w*)\s*\("),
        # Cosmos collections / keeper STORE write: `k.Vaults.Set(ctx, addr, v)`,
        # `k.Balances.Remove(...)`, `seq.Append(...)`. The bare `.Set(`/`.Remove(`/
        # `.Append(` method (no capital suffix) is invisible to the `.Set([A-Z]...)`
        # pattern above, so a genuine collections store write went uncredited.
        # Capture the RECEIVER name; it is value-filtered downstream via the same
        # _FIELD_STOPWORDS / _is_local_var_decl / local_names checks as every other
        # token, so a non-ledger receiver (`params.Set(`, `header.Set(`) is dropped
        # while a value-named store (`vaults`/`balances`/`Vaults`) counts. Go-scoped.
        re.compile(r"\b([A-Za-z_]\w*)\.(?:Set|Remove|Append)\s*\("),
    ],
    "move": [
        re.compile(r"\bmove_to\b[^;]*<\s*([A-Za-z_]\w*)"),
        re.compile(r"\bborrow_global_mut\b[^;]*<\s*([A-Za-z_]\w*)"),
    ],
    "cairo": [
        re.compile(r"\bself\.([A-Za-z_]\w*)\.write\s*\("),
        re.compile(r"\b([A-Za-z_]\w*)::write\s*\("),
    ],
}

# Auditooor-infra / build-artifact dirs pruned from BOTH the source-enumeration
# walk and the test-ref scan. The build/vendor entries here overlap the shared
# helper (scope_exclusion.is_vendored) and are kept as a fast, dependency-free
# first pass; the .git / .auditooor-family infra dirs are NOT a scope_exclusion
# concern (they are tool bookkeeping, never protocol source) so they stay here.
#
# MIGRATED (funnel single-source-of-truth): the former ad-hoc additions
# ``interchaintest`` and ``@openzeppelin`` are GONE from this literal set - the
# OOS classification of those (and the wider vendored/build-artifact universe:
# OZ namespaces, cosmos-sdk/ibc-go/cosmwasm deps, solmate/solady/forge-std, ...)
# is now delegated to ``scope_exclusion.is_vendored(rel)`` in the walk loops, so
# there is ONE canonical OOS table shared across every gate. Behaviour is
# preserved: ``is_vendored`` matches ``interchaintest`` (bare-word path segment)
# and ``@openzeppelin`` (``/@openzeppelin/`` substring marker) exactly as the
# old literals did, and is a harmless no-op on workspaces that lack them.
_SKIP_DIRS = {
    ".git", "node_modules", "vendor", "target", "dist", "build", "out",
    "lib", "cache", ".auditooor", ".audit_logs", "submissions", "prior_audits",
    "mining_rounds", "reports", "docs",
}
_TEST_HINTS = ("/test/", "/tests/", "_test.go", ".t.sol", "test_", "/mock", "/mocks/",
               "_test.rs", "tests.rs", ".spec.", "/spec/", "/harness", "echidna",
               "halmos", "medusa", "/poc", "poc_", "_poc")
# r36-rebuttal: lane FIX-XFI-TEST-PATH registered
# Conservative test-file BASENAME conventions (zero false-positives on normal src):
# Foo.t.sol (foundry), foo_test.<ext>, and a `test.<ext>` segment at a word boundary.
_TEST_BASENAME_RE = re.compile(r"\.t\.sol$|_test\.[a-z0-9]+$|(?:^|[^a-z0-9])test\.[a-z0-9]+$")

# Solidity / Rust / Move / Cairo keywords that are NOT real state fields when the
# bare-assignment heuristic fires. Filters local-variable noise.
#
# Extended (funnel-generic-fixes-wave3): added common single-use local / math
# temporaries that the Solidity write regex was incorrectly classifying as shared
# protocol state.  All entries are lowercase because the check is:
#   tl = tok.lower(); tl not in _FIELD_STOPWORDS
#
# Defence-in-depth: the primary gate is _is_local_var_decl() below; these
# stopwords catch short / generic names that slip through any declaration
# heuristic.
_FIELD_STOPWORDS = {
    "return", "let", "var", "const", "if", "for", "while", "uint", "int",
    "bool", "address", "bytes", "string", "memory", "storage", "mut", "self",
    "this", "result", "ok", "err", "true", "false", "i", "j", "k", "n", "x",
    "y", "z", "tmp", "temp", "_", "out", "data", "value", "amount", "msg",
    "require", "assert", "emit", "new", "type",
    # common local / math temporaries that are never shared protocol state
    # (all lowercase; comparison is tl = tok.lower(); tl not in _FIELD_STOPWORDS)
    "name", "symbol", "href", "imageuri", "ibyte",
    "msb", "shift", "exponent", "xexponent", "yexponent",
    "capexponent", "resultexponent", "downcasted",
    "rx", "ss", "ep", "ds",
}

# Go-specific noise for the `.Set([A-Z]\w*)\s*\(` cosmos-keeper-setter regex.
# That regex captures the CALLEE method-name suffix after any receiver, so it
# also fires on non-keeper `.SetX(...)` calls that are not a domain field
# write at all: math/big-style numeric conversions (`new(big.Int).SetUint64(
# ...)`, `.SetInt64(...)`, `.SetBytes(...)`) and the generic low-level
# KVStore raw-byte accessors (`store.SetRaw(...)`, `store.SetRawNew(...)`)
# that are reused across many semantically-unrelated keys/queues. Neither is
# a genuine coupled keeper field, so both classes produced phantom
# `state:Uint64` / `state:Raw` / `state:RawNew` cross-function requirements
# (axelar-dlt over-detection, confirmed against source 2026-07-12). Lowercase
# comparison, matching the `tl = tok.lower()` convention used at the call site.
_GO_SETTER_NOISE = {
    "raw", "rawnew", "uint64", "int64", "uint32", "int32", "uint8", "int8",
    "bytes", "string", "bit", "prec", "rat", "mode", "float64", "float32",
    # generic "store a validated/typed blob at this key" KVStore helper -
    # `k.getStore(ctx).SetNewValidated(prefix.Append(...), ...)` - reused
    # verbatim across axelarnet/evm/vote keepers for entirely unrelated
    # fields (ibc-path, cosmos-chain, transfer, seq-mapping, poll, tallied
    # vote, ...); the shared method-name suffix is infra, not a coupled
    # domain field (axelar-dlt state:NewValidated over-detection).
    "newvalidated",
}

# Per-language regex: matches the type-keyword prefix immediately before a variable
# name on a local declaration line.  Used by _is_local_var_decl() to suppress tokens
# that are clearly stack variables, not persistent storage fields.
#
# Solidity: `uint256 foo = ...`, `string memory foo = ...`,
#            `AppStorage storage ds = ...`
# Rust:     `let foo = ...`, `let mut foo = ...`
# Go:       `:=` short-var-decl or `var foo type = ...`
_LOCAL_DECL_PREFIX_RE: dict = {
    # Solidity: keyword followed by at least one space (not '(' to avoid
    # suppressing function call args that follow e.g. `sqrt(value = ...)`).
    "sol": re.compile(
        r"(?:uint\d*|int\d*|bool|address|bytes\d*|string|mapping"
        r"|memory|storage|calldata|payable|immutable|constant"
        r"|private|public|internal|external"
        r"|struct|enum|contract|interface|library"
        r"|override|virtual|pure|view|returns?"
        r"|indexed|anonymous|unchecked)\s+$",
        re.IGNORECASE,
    ),
    # Rust: `let [mut] foo = ...`
    "rs": re.compile(r"let\s+(?:mut\s+)?$"),
    # Go: named-type local: `var foo Type = ...` (short-decl := handled separately)
    "go": re.compile(r"var\s+\w+\s+\S+\s*$"),
    # Move / Cairo: `let` keyword
    "move": re.compile(r"let\s+(?:mut\s+)?$"),
    "cairo": re.compile(r"let\s+(?:mut\s+)?$"),
}

# Solidity type-paren context: a token immediately after `mapping(` or inside
# a tuple-decl `(T a, T b) = ...` is a type parameter, not a state field.
# e.g. `mapping(uint256 => mapping(address => Balance))` - `uint256` and
# `address` must be suppressed.
_SOL_TYPE_PAREN_CONTEXT_RE = re.compile(
    r"(?:"
    r"(?:mapping|returns?)\s*\(\s*"   # mapping( or returns(
    r"|^\s*\(\s*"                        # tuple decl at line start
    r")$",
    re.IGNORECASE,
)


def _is_local_var_decl(lang: str, line: str, match_start: int) -> bool:
    """Return True when the token at *match_start* looks like a local variable
    being declared rather than a persistent storage field being written.

    Checks three patterns:
    1. The text on the same line BEFORE the token ends with a type/qualifier
       keyword (Solidity: `uint256 name = ...`; Rust: `let foo = ...`).
    2. Solidity type-paren context: token is a type parameter inside
       `mapping(T => ...)` or a tuple decl `(T a, ...) = ...`.
    3. Go short variable declaration: the suffix starting at match_start
       matches `identifier :=` (`:=` declares a new local).
    """
    prefix = line[:match_start]
    stripped_prefix = prefix.lstrip()
    pat = _LOCAL_DECL_PREFIX_RE.get(lang)
    if pat and pat.search(stripped_prefix):
        return True
    if lang == "sol" and _SOL_TYPE_PAREN_CONTEXT_RE.search(stripped_prefix):
        return True
    # Go: short-var-decl uses := so the token is followed by :=
    if lang == "go":
        tail = line[match_start:]
        if re.match(r"[A-Za-z_]\w*\s*:=", tail):
            return True
    return False


_BROAD_PAIR_LABELS = {"add|remove", "enable|disable", "open|close"}
_PAIR_NOUN_STOPWORDS = {
    "new", "base", "assign", "assignment", "constant", "const", "array",
    "comments", "comment", "forward", "declarations", "declaration", "snark",
    "lib", "import", "imports", "padding", "padded", "size", "flat",
}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except (ValueError, TypeError):
        return default


def _sequence_threshold() -> int:
    return max(3, _env_int("AUDITOOOR_XFI_SEQUENCE_THRESHOLD", 3))


def _min_sequence_overlap() -> int:
    return max(2, _env_int("AUDITOOOR_XFI_MIN_SEQUENCE_OVERLAP", 2))


def _extra_test_hints() -> tuple[str, ...]:
    raw = os.environ.get("AUDITOOOR_XFI_TEST_HINTS", "")
    return tuple(h.strip().lower() for h in raw.splitlines() if h.strip())


def _naming_pairs() -> list[tuple[str, str, str]]:
    """Authoritative L30 pair list. Prefer the sibling tool's _NAMING_PAIRS
    (single source of truth); fall back to the in-file copy. Then append any
    env-supplied pairs."""
    pairs: list[tuple[str, str, str]] = []
    sib = _load_sibling_module()
    if sib is not None and hasattr(sib, "_NAMING_PAIRS"):
        try:
            for row in sib._NAMING_PAIRS:
                if isinstance(row, (list, tuple)) and len(row) >= 2:
                    a, b = str(row[0]), str(row[1])
                    hint = str(row[2]) if len(row) > 2 else f"{a}/{b} composition invariant"
                    pairs.append((a, b, hint))
        except Exception:
            pairs = []
    if not pairs:
        pairs = list(_FALLBACK_NAMING_PAIRS)
    # env extension
    raw = os.environ.get("AUDITOOOR_XFI_NAMING_PAIRS", "")
    for line in raw.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 2 and parts[0] and parts[1]:
            hint = parts[2] if len(parts) > 2 and parts[2] else f"{parts[0]}/{parts[1]} composition invariant"
            pairs.append((parts[0], parts[1], hint))
    return pairs


def _load_sibling_module():
    """Load tools/sibling-path-guard-diff.py by path (single-source-of-truth
    for the L30 pair list). Returns the module or None."""
    tool_path = Path(__file__).resolve().with_name("sibling-path-guard-diff.py")
    if not tool_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_xfi_sibling_guard_diff", tool_path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_xfi_sibling_guard_diff"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def _write_res_for(lang: str) -> list:
    res = list(_WRITE_RES.get(lang, []))
    raw = os.environ.get(f"AUDITOOOR_XFI_WRITE_PATTERNS_{lang.upper()}", "")
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            res.append(re.compile(line))
        except re.error:
            continue
    return res


@dataclass
class FnDef:
    name: str
    file: str
    line: int
    writes: set = field(default_factory=set)
    privileged: bool = False


@dataclass
class Requirement:
    kind: str  # "sibling-pair" | "state-machine"
    label: str
    invariant_hint: str
    functions: list  # list of {name, file, line}
    function_names: set

    def to_record(self) -> dict:
        return {
            "kind": self.kind,
            "label": self.label,
            "invariant_hint": self.invariant_hint,
            "functions": self.functions,
        }


def _is_test_path(rel: str) -> bool:
    # r36-rebuttal: lane FIX-XFI-TEST-PATH registered in .auditooor/agent_pathspec.json
    # rel is relative to the SRC ROOT (e.g. src/), so a top-level test dir arrives as
    # "test/Foo.sol" (no leading slash) and the "/test/" hint silently misses it -
    # every src/test/*Test.sol file then counts as an in-scope cross-function
    # requirement (the morpho-midnight false-red: 60/60 uncovered were all src/test).
    # Normalise with a leading slash so a leading "test/" matches "/test/", and also
    # catch the PascalCase *Test.sol / *_test.* basename convention the substring
    # hints do not cover.
    low = "/" + rel.lower().lstrip("/")
    hints = _TEST_HINTS + _extra_test_hints()
    if any(h in low for h in hints):
        return True
    base = low.rsplit("/", 1)[-1]
    if _TEST_BASENAME_RE.search(base):
        return True
    # Delegate to the shared single-source test classifier so Cosmos-SDK harness
    # conventions (/simulation/, /simapp/, /testutils/) and any future markers are
    # recognised here too, instead of drifting against the local _TEST_HINTS copy
    # (NUVA 2026-06-30: deposit|withdraw@vault/simulation was enumerated as a
    # cross-function mutation-verify requirement on OOS sim code).
    if _SCOPE_EXCL is not None:
        try:
            if _SCOPE_EXCL.is_test(rel):
                return True
        except Exception:
            pass
    return False


def _is_interface_like(p: Path) -> bool:
    """Return True for Solidity interface / abstract-only files whose function
    declarations have no bodies (;-terminated only).  Cross-function requirements
    generated from these files can never be mutation-verified because there is no
    mutable operator to kill - porting the same predicate from
    cross-function-harness-producer.py (single source of logic, replicated here
    to keep cross-function-invariant-coverage.py dependency-free at runtime).

    Heuristic (matches the producer's predicate exactly):
      - path contains ``/interfaces/`` or ``/interface/`` (case-insensitive), OR
      - file stem matches the I<Upper> convention (e.g. IVault.sol, IERC20.sol).

    Only fires for Solidity (``.sol``).  Other languages have explicit
    implementations even in interface/trait files, so the predicate is sol-only.
    """
    if p.suffix != ".sol":
        return False
    low = p.as_posix().lower()
    if "/interfaces/" in low or "/interface/" in low:
        return True
    stem = p.stem
    if len(stem) >= 2 and stem[0] == "I" and stem[1].isupper():
        return True
    return False


def _iter_source_files(root: Path, include_tests: bool):
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        lang = _LANG_BY_EXT.get(p.suffix)
        if lang is None:
            continue
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        # Shared-helper OOS prune: vendored deps / build artifacts the dir-segment
        # _SKIP_DIRS pass does not catch (OZ namespaces, cosmos-sdk/ibc-go,
        # solmate/solady/forge-std, interchaintest, ...). Test/non-test split is
        # handled below by _is_test_path, so we intentionally use is_vendored (not
        # is_oos) to avoid folding test files into the vendored bucket here.
        if _is_vendored_oos(rel):
            continue
        is_test = _is_test_path(rel)
        if is_test and not include_tests:
            continue
        if (not is_test) and include_tests:
            continue
        # Skip Solidity interface-only files: function declarations with no
        # bodies generate cross-function requirements that can never be
        # mutation-verified (no mutable operator exists to kill).  Skipping
        # them removes un-verifiable requirements honestly - no bar-lowering.
        if _is_interface_like(p):
            continue
        yield p, lang, rel, is_test


def _extract_body_span(lines: list, decl_idx: int) -> tuple:
    n = len(lines)
    open_idx = None
    for i in range(decl_idx, min(decl_idx + 12, n)):
        if "{" in lines[i]:
            open_idx = i
            break
    if open_idx is None:
        return decl_idx, decl_idx
    depth = 0
    started = False
    for i in range(open_idx, n):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
        if started and depth <= 0:
            return open_idx, i
    return open_idx, n - 1


_READONLY_SOL_RE = re.compile(r"\b(view|pure)\b")
_READONLY_VY_RE = re.compile(r"@(view|pure)\b")

# Access-control modifiers that gate a function to a privileged caller. A
# cross-function requirement whose constituent functions are ALL privileged is
# not UNPRIVILEGED-reachable (R24/R48 + the universal "privileged-only paths are
# OOS" scope rule), so it is not a required cross-function invariant - an external
# attacker cannot drive the composition. Generic across Solidity access-control
# conventions (OZ Ownable/AccessControl, Solmate auth, governance gates).
_PRIVILEGED_MODIFIER_RE = re.compile(
    r"\b(only[A-Z]\w*|requiresAuth|auth|onlyRole|onlyGov\w*|onlyAdmin\w*"
    r"|governanceOnly|restricted)\b"
)


def _is_privileged_fn(lang: str, lines: list, decl_idx: int, body_start: int) -> bool:
    """True iff the function signature carries a privileged access-control
    modifier (onlyOwner/onlyRole/auth/...). Scans the signature header only."""
    if lang not in ("sol", "vy", "solidity", "vyper"):
        return False
    hi = max(decl_idx, min(body_start, len(lines) - 1))
    header = " ".join(lines[decl_idx:hi + 1]).split("{", 1)[0]
    return bool(_PRIVILEGED_MODIFIER_RE.search(header))

# Solidity local/param DECLARATION: a (possibly array/mapping/custom) type,
# optional data-location/visibility, then the declared name. Captures the NAME so
# we can build a per-function local+param set and exclude assignments to those
# names from the "co-mutated storage field" tally. Without this, a local declared
# on one line and re-assigned later (e.g. `bytes memory payload; ... payload =
# ...`), a loop/length local (`uint256 _len = a.length`), or a mapping KEY used as
# an index (`m[messageId] = x` capturing `messageId`) were mis-counted as storage
# fields, producing phantom `state:<local>` cross-function requirements.
_SOL_LOCAL_DECL_RE = re.compile(
    r"(?:uint\d*|int\d*|bool|address|bytes\d*|string|mapping\s*\([^)]*\)"
    r"|[A-Z]\w+)(?:\[\s*\])?"                       # value/array/custom type
    r"\s+(?:(?:memory|storage|calldata|payable)\s+)?"  # optional data-location (space-terminated)
    r"(?:(?:public|private|internal)\s+)?"          # optional visibility
    r"(_?[A-Za-z]\w*)\b\s*(?:=|;|,|\)|$)"           # the declared name
)


def _collect_sol_locals(lines: list, decl_idx: int, body_end: int) -> set:
    """Per-function local + parameter names for a Solidity function (signature +
    body). Used to exclude assignments to locals/params from the co-mutated
    storage-field tally. Over-inclusion is safe: a param shadowing a storage field
    means writes to that name in this function are to the param, not storage."""
    names: set = set()
    hi = min(body_end, len(lines) - 1)
    for k in range(decl_idx, hi + 1):
        for mm in _SOL_LOCAL_DECL_RE.finditer(lines[k]):
            nm = mm.group(1)
            if nm and nm.lower() not in _FIELD_STOPWORDS:
                names.add(nm)
    return names


# Go short-variable-declaration LHS: `foo := ...` / `foo, bar := ...`. Captures
# everything left of `:=` on a line so the caller can split on commas. Used to
# exclude `:=`-declared locals (and their later `=`/`+=` reassignments) from
# the co-mutated storage-field tally - without this, a local declared via
# `total, index, virtualArgs := 0, 0, 0` and later reassigned with
# `total += words` is mis-counted as a persistent state write.
_GO_SHORTDECL_RE = re.compile(r"([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*:=")


def _collect_go_locals(lines: list, decl_idx: int, body_start: int, body_end: int) -> set:
    """Per-function local + parameter + named-return names for a Go function.

    Covers two sources of false `state:X` requirements:
      1. `:=` short-var-decls anywhere in the body (single or multi-assign).
      2. named parameters/returns in the signature, e.g.
         `func (k Keeper) GetChains(ctx sdk.Context) (chains []exported.Chain)`
         - the `chains` named return is later assigned with a bare `=`
           (`chains = append(chains, chain)`), which is NOT a storage write.
    """
    names: set = set()
    hi_sig = max(decl_idx, min(body_start, len(lines) - 1))
    header = " ".join(lines[decl_idx:hi_sig + 1]).split("{", 1)[0]
    for grp in re.findall(r"\(([^()]*)\)", header):
        for item in grp.split(","):
            item = item.strip()
            if not item:
                continue
            parts = item.split()
            # `name Type` / `name *Type` / `name []Type` - only a 2+-token
            # item carries a NAME (a bare `Type` item, common for unnamed
            # returns, has nothing to exclude).
            if len(parts) >= 2:
                nm = parts[0].lstrip("*")
                if nm.isidentifier() and nm != "_":
                    names.add(nm)
    hi_body = min(body_end, len(lines) - 1)
    for k in range(decl_idx, hi_body + 1):
        for mm in _GO_SHORTDECL_RE.finditer(lines[k]):
            for nm in mm.group(1).split(","):
                nm = nm.strip()
                if nm.isidentifier() and nm != "_":
                    names.add(nm)
    return names


# Cosmos/Go convention: `GetX`/`getX` (and bare `Get`/`get`) are read-only
# accessors that only build and return a local value from iterating the
# store - they never mutate keeper state, so any `=` assignment inside them
# is to a local (usually a named return), never a co-mutated field.
_GO_GETTER_NAME_RE = re.compile(r"^(?:Get|get)(?:[A-Z]|$)")


def _is_go_readonly_fn(lang: str, name: str) -> bool:
    return lang == "go" and bool(_GO_GETTER_NAME_RE.match(name))


def _is_readonly_fn(lang: str, lines: list, decl_idx: int, body_start: int) -> bool:
    """True iff the function signature declares it read-only (Solidity/Vyper
    view|pure). The signature spans the decl line through the body-open line, so
    we scan that header region only (never the body, where 'view'/'pure' could
    appear as an identifier). Generic no-op for languages without view/pure.

    NOTE: the workspace lang key is the bare extension (`sol`/`vy`), not
    `solidity`/`vyper` - matching the keys in _FN_RES/_WRITE_RES."""
    if lang not in ("sol", "vy", "solidity", "vyper"):
        return False
    hi = max(decl_idx, min(body_start, len(lines) - 1))
    header = " ".join(lines[decl_idx:hi + 1])
    # cut at the body brace so a later same-line statement is not scanned
    header = header.split("{", 1)[0]
    rx = _READONLY_VY_RE if lang in ("vy", "vyper") else _READONLY_SOL_RE
    return bool(rx.search(header))


def _extract_fn_defs(path: Path, lang: str, rel: str) -> list:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return []
    lines = text.splitlines()
    fn_re = _FN_RES.get(lang)
    if fn_re is None:
        return []
    write_res = _write_res_for(lang)
    out: list = []
    for i, ln in enumerate(lines):
        # finditer (not search): a single line can declare MULTIPLE functions
        # (e.g. two one-line functions on the same physical line, common in
        # minified / generated fixtures). Capturing only the first drops the
        # sibling arm. Body-span extraction still starts from the decl line, so
        # multiple same-line decls share the span lookahead (acceptable: the
        # guard/write set is line-scoped and the function NAMES are what the
        # requirement enumeration keys on).
        names_on_line = [mm.group(1) for mm in fn_re.finditer(ln)]
        if not names_on_line:
            continue
        start, end = _extract_body_span(lines, i)
        _priv = _is_privileged_fn(lang, lines, i, start)
        # A read-only (Solidity/Vyper view|pure) function CANNOT write storage, so
        # every assignment in its body is a LOCAL, never a co-mutated state field.
        # Counting those locals (e.g. `_digest`/`_salt`/`_body`/`_len`/`_signer`
        # in multisig digest/verify, ICA message decoders, TypedMemView) produced
        # phantom `state:<local>` cross-function requirements that no real cross-fn
        # invariant could ever satisfy. Skip the write-scan for read-only funcs.
        # Go mirror of the above: `GetX`/`getX` accessors only build and return
        # a local from iterating the store, never mutate keeper state (confirmed
        # against axelar-dlt GetChains/GetTokens/getTransfers/getTokensMetadata -
        # each just appends into a local/named-return slice). Skip the write-scan
        # for all matching names on the line (all(...): a shared-line multi-decl
        # is only skipped when EVERY declared name is itself a getter).
        if _is_readonly_fn(lang, lines, i, start) or all(
            _is_go_readonly_fn(lang, nm) for nm in names_on_line
        ):
            for name in names_on_line:
                out.append(FnDef(name=name, file=rel, line=i + 1, writes=set(),
                                 privileged=_priv))
            continue
        # Per-function local + parameter names: assignments to these are NOT
        # storage writes, so they cannot form a co-mutated state-machine field.
        if lang == "sol":
            local_names = _collect_sol_locals(lines, i, end)
        elif lang == "go":
            local_names = _collect_go_locals(lines, i, start, end)
        else:
            local_names = set()
        writes: set = set()
        for j in range(start, min(end + 1, len(lines))):
            body_line = lines[j]
            for rx in write_res:
                # finditer (not search): a single line can carry MULTIPLE state
                # writes (e.g. `bal[x] += a; totalAssets = totalAssets + a;` on a
                # one-line body). Capturing only the first miss-classifies the
                # function's written-field set.
                for wm in rx.finditer(body_line):
                    # Go: an UNQUALIFIED bare assignment is a local variable, not a
                    # state write (e.g. `vaults = append(vaults, v)` in a read-only
                    # query / pure constructor / validator). Drop it; a qualified
                    # keeper/store write (`k.field = x`) still counts. Mirrors the
                    # guard in value-moving-functions.py commit 9250f04f6b.
                    if (
                        lang == "go"
                        and rx is _GO_BARE_ASSIGN_RE
                        and _go_bare_assign_is_local(wm)
                    ):
                        continue
                    tok = (wm.group(1) if wm.groups() else "").strip()
                    tl = tok.lower()
                    if not tok or tl in _FIELD_STOPWORDS or len(tok) <= 1:
                        continue
                    # Go-only: `.SetX(...)` captured suffix is a math/big
                    # numeric-conversion method or a generic low-level KVStore
                    # raw accessor, not a domain keeper field (see
                    # _GO_SETTER_NOISE docstring).
                    if lang == "go" and tl in _GO_SETTER_NOISE:
                        continue
                    # Primary local-var filter: skip tokens that appear to be
                    # the LHS of a typed local declaration (e.g.
                    # `uint256 name = ...`, `let foo = ...`, `mapping(T => ...)`).
                    # Such tokens are stack variables or type parameters, NOT
                    # persistent storage fields.
                    if _is_local_var_decl(lang, body_line, wm.start(1)):
                        continue
                    # Skip assignments to a name declared as a local/param anywhere
                    # in this function (handles declare-then-reassign + mapping keys).
                    if tok in local_names:
                        continue
                    writes.add(tok)
        for name in names_on_line:
            out.append(FnDef(name=name, file=rel, line=i + 1, writes=set(writes),
                             privileged=_priv))
    return out


def _name_has_token(name: str, token: str) -> bool:
    return token.lower() in _name_tokens(name)


def _name_tokens(name: str) -> list[str]:
    """Split snake/camel names into lowercase tokens for exact token matching.

    This intentionally avoids substring matches such as ``padded`` -> ``add``
    or ``memory_address`` -> ``add``. Cross-function requirements should be
    formed from semantic arm names, not accidental substrings.
    """
    chunks = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).replace("-", "_")
    return [t.lower() for t in re.split(r"[^A-Za-z0-9]+", chunks) if t]


def _top_module(path: str) -> str:
    parts = list(Path(path).parts)
    if "crates" in parts:
        i = parts.index("crates")
        crate = parts[i + 1] if i + 1 < len(parts) else ""
        if "src" in parts[i + 2:]:
            j = parts.index("src", i + 2)
            sub = parts[j + 1] if j + 1 < len(parts) - 1 else ""
            return "/".join(p for p in ("crates", crate, sub) if p)
        return "/".join(p for p in ("crates", crate) if p)
    for anchor in ("modules", "pallets", "apps", "clients", "consensus"):
        if anchor in parts:
            i = parts.index(anchor)
            if i + 1 < len(parts):
                return "/".join(parts[i:i + 2])
    return "/".join(parts[:-1][-2:])


def _pair_nouns(fn_name: str, arm_token: str) -> set[str]:
    toks = _name_tokens(fn_name)
    try:
        idx = toks.index(arm_token.lower())
    except ValueError:
        return set()
    return {t for t in toks[idx + 1:] if t and t not in _PAIR_NOUN_STOPWORDS}


def _broad_pair_nouns_overlap(a_fns: list[FnDef], b_fns: list[FnDef], tok_a: str, tok_b: str) -> bool:
    a_nouns: set[str] = set()
    b_nouns: set[str] = set()
    for f in a_fns:
        a_nouns |= _pair_nouns(f.name, tok_a)
    for f in b_fns:
        b_nouns |= _pair_nouns(f.name, tok_b)
    return bool(a_nouns and b_nouns and (a_nouns & b_nouns))


# --------------------------------------------------------------------------
# Requirement enumeration
# --------------------------------------------------------------------------
def _enumerate_sibling_pair_requirements(fn_defs: list) -> list:
    """For each L30 pair where BOTH arms exist in the tree, emit a requirement
    over the (a-arm, b-arm) function set. One requirement per (tok_a, tok_b)
    pair, listing all matching functions on each side."""
    out: list = []
    for tok_a, tok_b, hint in _naming_pairs():
        a_fns = [f for f in fn_defs if _name_has_token(f.name, tok_a)]
        b_fns = [f for f in fn_defs if _name_has_token(f.name, tok_b)]
        # Exclude cross-contamination (e.g. "deposit" matching both rarely, but
        # guard names that contain both tokens are dropped from the opposite arm).
        a_fns = [f for f in a_fns if not _name_has_token(f.name, tok_b)]
        b_fns = [f for f in b_fns if not _name_has_token(f.name, tok_a)]
        if not a_fns or not b_fns:
            continue
        by_module: dict[str, dict[str, list[FnDef]]] = {}
        for f in a_fns:
            by_module.setdefault(_top_module(f.file), {"a": [], "b": []})["a"].append(f)
        for f in b_fns:
            by_module.setdefault(_top_module(f.file), {"a": [], "b": []})["b"].append(f)

        for module, arms in sorted(by_module.items()):
            a_mod = arms["a"]
            b_mod = arms["b"]
            if not a_mod or not b_mod:
                continue
            label = f"{tok_a}|{tok_b}"
            if label in _BROAD_PAIR_LABELS and not _broad_pair_nouns_overlap(a_mod, b_mod, tok_a, tok_b):
                continue
            # All-privileged pair (e.g. owner-only addQuoteSigner/removeQuoteSigner)
            # is not unprivileged-reachable (R24/R48 + privileged-only=OOS) - drop.
            if all(getattr(f, "privileged", False) for f in (a_mod + b_mod)):
                continue
            functions = []
            names: set = set()
            seen: set = set()
            for f in a_mod + b_mod:
                if (f.name, f.file) in seen:
                    continue
                seen.add((f.name, f.file))
                functions.append({"name": f.name, "file": f.file, "line": f.line, "arm": tok_a if _name_has_token(f.name, tok_a) else tok_b})
                names.add(f.name)
            suffix = f"@{module}" if len(by_module) > 1 else ""
            out.append(Requirement(
                kind="sibling-pair",
                label=f"{label}{suffix}",
                invariant_hint=hint,
                functions=functions,
                function_names=names,
            ))
    return out


def _enumerate_state_machine_requirements(fn_defs: list) -> list:
    """A field co-mutated by >= threshold in-scope functions implies a multi-
    function state-machine sequence whose composition must preserve a global
    invariant over that field."""
    threshold = _sequence_threshold()
    by_field: dict = {}
    for f in fn_defs:
        for fld in f.writes:
            by_field.setdefault((fld, _top_module(f.file)), []).append(f)
    modules_by_field: dict[str, set[str]] = {}
    for fld, module in by_field:
        modules_by_field.setdefault(fld, set()).add(module)
    out: list = []
    seen_sets: set = set()
    for (fld, module), fns in sorted(by_field.items()):
        # de-dup functions by (name, file)
        uniq: dict = {}
        for f in fns:
            uniq[(f.name, f.file)] = f
        fns_u = list(uniq.values())
        if len(fns_u) < threshold:
            continue
        # All-privileged co-mutation is owner/governance-only - not unprivileged-
        # reachable (R24/R48 + privileged-only=OOS), so not a required cross-fn
        # invariant. Drop only when EVERY co-mutator is privileged.
        if fns_u and all(getattr(f, "privileged", False) for f in fns_u):
            continue
        names = frozenset(f.name for f in fns_u)
        # Avoid emitting the same function-set twice for two co-mutated fields.
        if names in seen_sets:
            continue
        seen_sets.add(names)
        functions = [{"name": f.name, "file": f.file, "line": f.line} for f in fns_u]
        label_suffix = f"@{module}" if len(modules_by_field.get(fld, set())) > 1 else ""
        out.append(Requirement(
            kind="state-machine",
            label=f"state:{fld}{label_suffix}",
            invariant_hint=(
                f"functions co-mutating shared state '{fld}' form a multi-step "
                f"sequence; their composition must preserve a global invariant "
                f"over '{fld}'"
            ),
            functions=functions,
            function_names=set(names),
        ))
    return out


# --------------------------------------------------------------------------
# Mutation-verdict loading (cached artifact only - never re-run; the sibling
# tool tools/mutation-verify-coverage.py owns execution).
# --------------------------------------------------------------------------
_MUT_KILL_VERDICTS = {"killed", "non-vacuous", "nonvacuous", "real", "mutation-killed"}


# --------------------------------------------------------------------------
# mvc_sidecar cross-function harness credit (serving-join fix, NUVA 2026-06-30)
# --------------------------------------------------------------------------
# A mutation-verified chimera/medusa invariant HANDLER (.auditooor/mvc_sidecar/*.json
# - schema mvc_sidecar_v1 or auditooor.mutation_verify_coverage.v1) records its kill
# keyed to the HANDLER name (e.g. "NuvaVaultHandler") and/or the CUT file, NOT to the
# individual cross-function arms (deposit/withdraw) the handler exercises. The standard
# join below keys on killed_fns / killed_tests, so a genuine 1.2M-call medusa handler
# that drives deposit AND withdraw under a conservation oracle (property_no_free_roundtrip)
# never credits the deposit|withdraw requirement -> a permanent false-RED. The handler
# source is also not in _scan_test_function_refs (it lives under chimera_harnesses/).
#
# This is the same serving-join class already fixed in core-coverage / engine-harness /
# audit-honesty: a durable mvc_sidecar schema must be taught to EVERY gate's reader. Here
# we read the harness SOURCE named by each non-vacuous sidecar and credit a requirement
# whose >= `need` functions are exercised by that single mutation-verified harness.
#
# NEVER-FALSE-PASS: a sidecar credits ONLY when (1) it is mutation_verified True OR its
# verdict is in _MUT_KILL_VERDICTS (a real kill, not a vacuous/no-baseline scaffold), AND
# (2) its harness/test source EXISTS on disk and textually exercises >= `need` of the
# requirement's functions (the same >=2-arms bar the standard join uses). A vacuous
# engine-harness scaffold (verdict vacuous/no-baseline) is rejected by (1).
def _harness_files_from_command(cmd: str, ws: Path) -> list:
    """Resolve the on-disk harness file(s) a flat mutation_verify_coverage.v1 sidecar
    proves when it carries NO *_path key - only a runner COMMAND
    ``cd <DIR> && forge test --match-path '<REL>'``. Returns the match-path file plus
    every sibling *.sol in its campaign directory (the .t.sol and the handler .sol
    split the cross-function references). Empty list when nothing resolves on disk
    (a bare marker credits nothing). Mirrors engine-harness-proof's
    _resolve_sidecar_harness_file - same v1-schema serving-join class."""
    if not isinstance(cmd, str) or not cmd:
        return []
    mp = re.search(r"--match-path\s+(['\"])(.+?)\1", cmd) or re.search(
        r"--match-path\s+(\S+)", cmd)
    if not mp:
        return []
    rel = mp.group(2) if (mp.lastindex and mp.lastindex >= 2) else mp.group(1)
    cdm = re.search(r"\bcd\s+(\S+)", cmd)
    base = Path(cdm.group(1)) if cdm else ws
    if not base.is_dir():
        base = ws
    out: list = []
    cand = base / rel
    if cand.is_file():
        out.append(cand)
    else:
        out += [Path(h) for h in glob.glob(str(base / rel)) if Path(h).is_file()]
    # add the campaign-dir siblings (the harness handler .sol next to the .t.sol)
    for f in out[:1]:
        try:
            for sib in f.parent.glob("*.sol"):
                if sib.is_file() and sib not in out:
                    out.append(sib)
        except OSError:
            pass
    return out


def _mvc_sidecar_verified_harness_refs(ws: Path) -> list:
    """Return [{file, referenced:set[str], sidecar:str}] - one row per non-vacuous
    mvc_sidecar harness, with the identifier tokens its harness/test source references."""
    out: list = []
    for _sd in ("mvc_sidecar", "cross-function-coverage"):
        sidecar_dir = ws / ".auditooor" / _sd
        if not sidecar_dir.is_dir():
            continue
        for cand in sorted(sidecar_dir.glob("*.json")):
            try:
                rec = json.loads(cand.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            if not isinstance(rec, dict):
                continue
            verified = bool(rec.get("mutation_verified")) or (
                str(rec.get("verdict") or "").strip().lower() in _MUT_KILL_VERDICTS
            )
            if not verified:
                continue
            # collect the harness/test source the sidecar names - the code that
            # ACTUALLY EXERCISES the functions. Deliberately EXCLUDE ``cut`` (the
            # CUT source DEFINES every function in the contract, so reading it would
            # textually "reference" all of them and falsely credit any requirement
            # whose arms live in that contract regardless of what the harness drives).
            src_keys = ("harness_path", "test_path", "mutant_test_path",
                        "baseline_harness_path")
            refs: set = set()
            files_read: list = []
            harness_files: list = []
            for k in src_keys:
                val = rec.get(k)
                if not val or not isinstance(val, str):
                    continue
                p = Path(val)
                if not p.is_absolute():
                    p = ws / val
                if p.is_file():
                    harness_files.append(p)
            # SERVING-JOIN fix (strata 2026-07-01, same class as engine-harness-proof
            # _resolve_sidecar_harness_file): the flat mutation_verify_coverage.v1 schema
            # has NONE of the *_path keys above - it stores the harness as a runner
            # COMMAND `cd <DIR> && forge test --match-path '<REL>'`. Without this fallback
            # a genuinely non-vacuous v1 harness is never read, so its cross-function
            # references are invisible and the requirement reads "no test unit references
            # the set" despite a real mutation-verified harness on disk. Resolve the
            # match-path file (+ its campaign-dir siblings, where the .t.sol and the
            # handler .sol split the references) from the command.
            if not harness_files:
                harness_files = _harness_files_from_command(
                    rec.get("harness") or rec.get("runner_command") or "", ws)
            for p in harness_files:
                if p.is_file() and p.suffix in _LANG_BY_EXT:
                    try:
                        text = p.read_text(encoding="utf-8", errors="replace")
                    except (OSError, UnicodeError):
                        continue
                    refs |= set(re.findall(r"[A-Za-z_]\w*", text))
                    files_read.append(str(p))
            if refs and files_read:
                out.append({"file": files_read[0], "referenced": refs, "sidecar": cand.name})
    return out


def _requirement_covered_by_mvc_harness(req, mvc_refs: list, need: int) -> tuple:
    """(covered, evidence). True iff a single mutation-verified mvc_sidecar harness
    source exercises >= `need` of the requirement's functions.

    MODULE-SCOPED CREDIT (false-green fix, axelar-sc 2026-07-12): the function-name
    overlap alone is matched against EVERY identifier token in the harness source, so
    a requirement `mint|burn@axelar-cgp-solidity` (fns mintToken/burnToken on
    AxelarGateway) could be falsely credited by an ITS-only harness that merely
    contains the tokens `mintToken`/`burnToken` for a DIFFERENT contract in a
    DIFFERENT module. To scope the credit to the right module we ALSO require the
    harness to reference at least one of the requirement's CONTRACT names (the stem
    of each function's source file) - a genuine mutation-verified harness over a
    contract always instantiates/imports it by name, so this never false-REDs a real
    harness, but an adjacent-module harness that never names the requirement's
    contract no longer credits it. Advisory-first: when the requirement carries NO
    file info (contract set empty), the legacy name-only behaviour is preserved."""
    import os as _os
    req_names_lower = {n.lower() for n in req.function_names}
    req_contracts = {
        _os.path.splitext(_os.path.basename(str(f.get("file"))))[0].lower()
        for f in (getattr(req, "functions", None) or [])
        if isinstance(f, dict) and f.get("file")
    }
    req_contracts.discard("")
    for h in mvc_refs:
        ref_lower = {r.lower() for r in h["referenced"]}
        hit = req_names_lower & ref_lower
        if len(hit) < need:
            continue
        # Module scope: if the requirement is file-anchored, the harness must name
        # one of the requirement's contracts. Empty req_contracts => legacy behaviour.
        if req_contracts and not (req_contracts & ref_lower):
            continue
        return True, {
            "reason": "mutation-verified mvc_sidecar cross-function harness",
            "sidecar": h["sidecar"],
            "harness_source": h["file"],
            "matched_functions": sorted(hit),
            "matched_contracts": sorted(req_contracts & ref_lower) if req_contracts else [],
        }
    return False, {}


def _unmutatable_function_names(ws: Path) -> set:
    """Set of function names for which mutation-verify-coverage produced verdict
    'no-mutants' - the generator found ZERO mutable operators in the body (e.g. a pure
    `x = block.timestamp` / `y = f()` assignment). Such a function can NEVER earn a
    mutation kill, so a cross-function requirement whose ENTIRE function set is
    un-mutatable can never meet the mutation-verified bar - the gate would demand the
    impossible. Only a genuine, on-disk no-mutants sidecar counts (proof the generator
    ran and found nothing), so this cannot be faked by simply omitting a test."""
    out: set = set()
    for _sd in ("mvc_sidecar", "cross-function-coverage"):
        d = ws / ".auditooor" / _sd
        if not d.is_dir():
            continue
        for cand in d.glob("*.json"):
            try:
                rec = json.loads(cand.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            if not isinstance(rec, dict):
                continue
            fn = rec.get("function")
            if fn and str(rec.get("verdict") or "").strip().lower() == "no-mutants":
                out.add(str(fn))
    return out


def _state_var_from_label(label: str) -> str:
    """`state:indexTimestamp` -> `indexTimestamp` (empty for non state-machine labels)."""
    lab = (label or "").strip()
    if lab.lower().startswith("state:"):
        return lab.split(":", 1)[1].split("@", 1)[0].strip()
    return ""


def _requirement_unmutatable_but_exercised(req, ws: Path, mvc_refs: list) -> tuple:
    """A state-machine requirement whose EVERY function is confirmed no-mutants (pure
    assignment, nothing to mutate) is credited ONLY when the state variable it guards is
    still exercised by a non-vacuous mvc harness. Honest terminal for a genuinely
    un-mutatable state-writer (e.g. `indexTimestamp = block.timestamp`); never a blanket
    pass - it requires a real no-mutants sidecar per function AND a real referencing
    harness for the state var."""
    if getattr(req, "kind", "") != "state-machine":
        return False, {}
    var = _state_var_from_label(getattr(req, "label", ""))
    if not var:
        return False, {}
    unmut = _unmutatable_function_names(ws)
    fns = set(req.function_names)
    if not fns or not fns.issubset(unmut):
        return False, {}
    var_l = var.lower()
    for h in mvc_refs:
        if any(r.lower() == var_l for r in h["referenced"]):
            return True, {
                "reason": ("all requirement functions are no-mutants (pure assignment, "
                           "no mutable operators); the state variable is exercised by a "
                           "non-vacuous mvc harness - mutation-kill bar inapplicable"),
                "unmutatable_functions": sorted(fns),
                "exercising_harness": h["file"],
            }
    return False, {}


def _records_from_payload(payload) -> list:
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("results", "verdicts", "harnesses", "functions", "mutations", "records"):
        v = payload.get(key)
        if isinstance(v, list):
            return [r for r in v if isinstance(r, dict)]
    # a single mutation-verify-coverage.py record is itself a dict with a verdict.
    if payload.get("verdict") is not None and payload.get("function") is not None:
        return [payload]
    return []


def _record_verdict(rec: dict) -> str:
    for key in ("mutation_verdict", "verdict", "status", "disposition"):
        v = rec.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
    for key in ("killed", "mutation_killed", "non_vacuous"):
        if rec.get(key) is True:
            return "killed"
    return "unknown"


def _record_fn_name(rec: dict) -> str | None:
    for key in ("function", "fn", "function_name", "target_function", "name"):
        v = rec.get(key)
        if isinstance(v, str) and v.strip():
            # mutation-verify-coverage.py stores fn name possibly as "file::fn"
            tok = v.strip()
            if "::" in tok:
                tok = tok.rsplit("::", 1)[-1]
            return tok
    return None


def _record_test_names(rec: dict) -> set:
    """Collect any test/harness identifiers a mutation record references."""
    out: set = set()
    for key in ("harness", "test", "test_name", "harness_name", "harness_basename"):
        v = rec.get(key)
        if isinstance(v, str) and v.strip():
            out.add(Path(v.strip()).name)
            out.add(v.strip())
    return out


def _string_values(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        out: list[str] = []
        for v in obj.values():
            out.extend(_string_values(v))
        return out
    if isinstance(obj, list):
        out: list[str] = []
        for v in obj:
            out.extend(_string_values(v))
        return out
    return []


def _trace_refs_from_record(rec: dict) -> set[str]:
    refs: set[str] = set()
    for text in _string_values(rec):
        for tok in re.findall(r"[A-Za-z_]\w*", text):
            refs.add(tok.lower())
    return refs


def _load_mutation_state(ws: Path) -> dict:
    """Return {"available": bool, "killed_fns": set, "killed_tests": set}.
    Reads ONLY the cached artifact (offline, no re-run)."""
    killed_fns: set = set()
    killed_tests: set = set()
    killed_trace_refs: set = set()
    killed_requirement_labels: set = set()
    available = False
    candidates = [
        ws / ".auditooor" / "mutation_verify_coverage.json",
        ws / ".auditooor" / "mutation-verify-coverage.json",
    ]
    for _sd in ("cross-function-coverage", "mvc_sidecar"):
        sidecar_dir = ws / ".auditooor" / _sd
        if sidecar_dir.is_dir():
            # premade-mutant records (mutation-verify-coverage.py --out) may be
            # named anything, not just mutation*.json (e.g.
            # ethlockbox_unlock_auth_premade_mutant.json) - glob *.json and let the
            # verdict/function checks below gate. Misses here = uncredited real kills.
            candidates.extend(sorted(sidecar_dir.glob("*.json")))
    for cand in candidates:
        if not (cand.is_file() and cand.stat().st_size > 0):
            continue
        try:
            payload = json.loads(cand.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        available = True
        for rec in _records_from_payload(payload):
            verdict = _record_verdict(rec)
            if verdict in _MUT_KILL_VERDICTS:
                fn = _record_fn_name(rec)
                if fn:
                    killed_fns.add(fn.lower())
                    # Records store the function as "path:name" or "path:line:name"
                    # (mutation-verify-coverage.py --function src/X.sol:fn). The
                    # requirement matches BARE function names, so also add the bare
                    # basename - else a genuine path-qualified kill (ETHLockbox.sol:
                    # unlockETH) never credits the requirement's bare `unlockETH`.
                    bare = fn.split(":")[-1].strip()
                    if bare and bare.lower() != fn.lower():
                        killed_fns.add(bare.lower())
                killed_tests |= {t.lower() for t in _record_test_names(rec)}
                killed_trace_refs |= _trace_refs_from_record(rec)
                # A fork-etch cross-function record is keyed by the EXACT
                # requirement label this gate enumerates (e.g.
                # "deposit|withdraw@silo/SiloFacet"); its `function` field holds
                # the FACET name (SiloFacet), not the requirement's arm names
                # (deposit/withdraw), so the killed_fns/killed_tests joins below
                # never match it. Collect the requirement label for a direct,
                # exact, false-green-safe join - but ONLY when the record is also
                # flagged non-vacuous (mutation_verified True), so a bare
                # verdict string can never silently credit a requirement.
                if rec.get("mutation_verified") is True:
                    for lk in ("requirement", "test"):
                        lv = rec.get(lk)
                        if isinstance(lv, str) and lv.strip():
                            killed_requirement_labels.add(lv.strip().lower())
    return {
        "available": available,
        "killed_fns": killed_fns,
        "killed_tests": killed_tests,
        "killed_trace_refs": killed_trace_refs,
        "killed_requirement_labels": killed_requirement_labels,
    }


# --------------------------------------------------------------------------
# Test reference scan: which test units reference which functions
# --------------------------------------------------------------------------
def _scan_test_function_refs(ws: Path) -> list:
    """Return a list of {file, referenced: set[str]} - one row per test/harness
    file with the set of in-scope function names it textually references.

    Test / harness files routinely live OUTSIDE the in-scope src roots (a
    sibling ``test/`` / ``tests/`` dir, an ``.auditooor/echidna`` harness dir, a
    ``poc-tests/`` tree). So this scan walks the WHOLE workspace for test-class
    files (identified by ``_is_test_path``), not just the src roots. Tooling /
    vendored dirs are still pruned via ``_SKIP_DIRS``, except the auditooor
    harness dirs which we explicitly allow because generated harnesses live
    under ``.auditooor/``."""
    out: list = []
    seen: set = set()
    # Walk the whole tree; classify by suffix + test-path heuristic.
    for p in sorted(ws.rglob("*")):
        if not p.is_file():
            continue
        if _LANG_BY_EXT.get(p.suffix) is None:
            continue
        # Prune vendored/tooling dirs, but ALLOW .auditooor (generated harnesses
        # live there) and poc/test dirs.
        parts = set(p.parts)
        pruned = (parts & _SKIP_DIRS) - {".auditooor"}
        if pruned:
            continue
        try:
            rel = str(p.relative_to(ws))
        except ValueError:
            rel = str(p)
        # Shared-helper OOS prune (same single source of truth as the source walk):
        # a test/harness file living under a VENDORED dep tree (a strangelove
        # interchaintest harness, an OZ-bundled test) is OOS test infra and must
        # not be mined for in-scope cross-function references. is_vendored (not
        # is_oos) is used deliberately - an in-scope test/poc file is the very
        # thing this scan is looking for, so it must not be dropped just for being
        # a test.
        if _is_vendored_oos(rel):
            continue
        if not _is_test_path(rel):
            continue
        if rel in seen:
            continue
        seen.add(rel)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            continue
        ids = set(re.findall(r"[A-Za-z_]\w*", text))
        out.append({"file": rel, "referenced": ids})
    return out


def _requirement_has_mutation_verified_test(
    req: Requirement, test_refs: list, mut: dict, min_overlap: int
) -> tuple:
    """Return (covered: bool, evidence: dict). A requirement is covered iff some
    test unit references >= min(overlap_needed) of the requirement's functions
    AND mutation-verification shows a kill on one of the requirement's functions
    (or the referencing test). Anti-stub: no kill => not covered."""
    req_names_lower = {n.lower() for n in req.function_names}
    need = min(len(req.function_names), max(min_overlap, 2))
    if req.kind == "sibling-pair":
        # a sibling pair has 2 logical arms; require references to BOTH arms.
        need = min(len(req.function_names), 2)

    # Direct requirement-label join: a fork-etch cross-function record carries
    # this requirement's EXACT label and a non-vacuous mutation_verified kill.
    # That IS coverage of this requirement - the producer authored a differential
    # harness over the live fork that exercises the composed arms and the kill
    # proves it is non-vacuous. Matched by label (not arm-name) because the
    # record's `function` field is the facet, not the arms. False-green-safe:
    # _load_mutation_state only adds a label when verdict in _MUT_KILL_VERDICTS
    # AND mutation_verified is True.
    if mut.get("available"):
        req_label_lower = (getattr(req, "label", "") or "").strip().lower()
        if req_label_lower and req_label_lower in mut.get("killed_requirement_labels", set()):
            return True, {
                "reason": "mutation-verified non-vacuous fork-etch cross-function kill (requirement-label match)",
                "referencing_tests": [],
                "matched_requirement_label": req_label_lower,
            }

    referencing_tests: list = []
    for tr in test_refs:
        ref_lower = {r.lower() for r in tr["referenced"]}
        hit = req_names_lower & ref_lower
        if len(hit) >= need:
            referencing_tests.append({"file": tr["file"], "matched_functions": sorted(hit)})

    if not mut["available"]:
        if not referencing_tests:
            return False, {"reason": "no test unit references the cross-function set", "referencing_tests": []}
        return False, {
            "reason": (
                "a referencing test exists but NO mutation-verify backend output "
                "on disk; cross-function test is UNVERIFIED (anti-stub: treat as "
                "uncovered until a mutation kill is shown)"
            ),
            "referencing_tests": referencing_tests,
        }

    # mutation-verified iff a kill is recorded for one of the requirement's
    # functions, OR a kill is recorded for one of the referencing test files.
    killed_fn_hit = req_names_lower & mut["killed_fns"]
    trace_hit = req_names_lower & mut.get("killed_trace_refs", set())
    if not referencing_tests and len(trace_hit) >= need and killed_fn_hit:
        return True, {
            "reason": "mutation-verified non-vacuous cross-function trace",
            "referencing_tests": [],
            "killed_functions": sorted(killed_fn_hit),
            "trace_functions": sorted(trace_hit),
        }
    if not referencing_tests:
        return False, {"reason": "no test unit references the cross-function set", "referencing_tests": []}

    test_files_lower = {Path(t["file"]).name.lower() for t in referencing_tests} | {
        t["file"].lower() for t in referencing_tests
    }
    killed_test_hit = test_files_lower & mut["killed_tests"]
    if killed_fn_hit or killed_test_hit:
        return True, {
            "reason": "mutation-verified non-vacuous cross-function test",
            "referencing_tests": referencing_tests,
            "killed_functions": sorted(killed_fn_hit),
            "killed_tests": sorted(killed_test_hit),
        }
    if len(trace_hit) >= need and (req_names_lower & mut["killed_fns"]):
        return True, {
            "reason": "mutation-verified non-vacuous cross-function trace",
            "referencing_tests": referencing_tests,
            "killed_functions": sorted(req_names_lower & mut["killed_fns"]),
            "trace_functions": sorted(trace_hit),
        }
    return False, {
        "reason": (
            "a referencing test exists but mutation-verify shows NO kill for any "
            "of the requirement's functions (vacuous/unverified cross-function "
            "test = uncovered)"
        ),
        "referencing_tests": referencing_tests,
    }


# --------------------------------------------------------------------------
# Workspace resolution
# --------------------------------------------------------------------------
def _resolve_src_roots(ws: Path) -> list:
    # Canonical source-root resolution: pick the DEEPEST candidate dir that
    # contains ALL the workspace source, so a Cargo workspace (crates/*) is not
    # mis-resolved to a thin src/src stub. See tools/lib/source_root_resolver.py.
    import importlib.util as _ilu
    _p = Path(__file__).resolve().parent / "lib" / "source_root_resolver.py"
    _s = _ilu.spec_from_file_location("auditooor_source_root_resolver", _p)
    _m = _ilu.module_from_spec(_s)
    _s.loader.exec_module(_m)
    return list(_m.resolve_src_roots(ws))

def _load_inscope_file_set(ws: Path):
    """Return the AUTHORITATIVE in-scope file set from ``.auditooor/inscope_units.jsonl``
    (the manifest the hunt-worklist + heatmap gates already treat as scope truth), or
    ``None`` when no manifest exists (then no filtering - preserves legacy behavior).

    WHY: ``_resolve_src_roots`` walks the whole workspace, so on a multi-package monorepo
    with an authoritative scope (OP Stack: contracts-bedrock/src + op-node + op-dispute-mon
    + in-scope op-reth crates) the denominator was polluted with OUT-OF-SCOPE packages
    (kona, cannon, op-batcher, op-devstack, upstream reth crates, ...), inflating the
    requirement count and making the gate unwinnable for the wrong reason. Honoring the
    in-scope manifest restores a scope-correct denominator. Disable with
    AUDITOOOR_XFI_NO_SCOPE_FILTER=1 or AUDITOOOR_FCC_NO_SCOPE_FILTER=1.
    """
    if os.environ.get("AUDITOOOR_FCC_NO_SCOPE_FILTER") or os.environ.get("AUDITOOOR_XFI_NO_SCOPE_FILTER"):
        return None
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file():
        return None
    files: set = set()
    for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        f = str(row.get("file") or "").strip().lstrip("./").replace("\\", "/")
        if f:
            files.add(f)
    return files or None


def _collect_fn_defs(ws: Path) -> tuple:
    """Return (fn_defs, any_source, scope_filter_info)."""
    roots = _resolve_src_roots(ws)
    fn_defs: list = []
    any_source = False
    for root in roots:
        for path, lang, _rel, _is_test in _iter_source_files(root, include_tests=False):
            any_source = True
            try:
                rel = str(path.relative_to(ws))
            except ValueError:
                rel = str(path)
            fn_defs.extend(_extract_fn_defs(path, lang, rel))

    # SCOPE-AUTHORITATIVE filter: when an in-scope manifest exists, the denominator is the
    # in-scope file set only (drop OOS packages walked from src_roots).
    _inscope = _load_inscope_file_set(ws)
    scope_filtered_out = 0
    if _inscope is not None:
        def _norm(p: str) -> str:
            return str(p or "").strip().lstrip("./").replace("\\", "/")
        kept = [f for f in fn_defs if _norm(f.file) in _inscope]
        scope_filtered_out = len(fn_defs) - len(kept)
        if scope_filtered_out > 0:
            print(
                f"[{GATE}] scope-filter: dropped {scope_filtered_out} fn_defs from "
                f"OOS packages (inscope_units.jsonl has {len(_inscope)} files)",
                file=sys.stderr,
            )
        fn_defs = kept

    scope_filter_info = {
        "applied": _inscope is not None,
        "source": ".auditooor/inscope_units.jsonl" if _inscope is not None else None,
        "in_scope_files": (len(_inscope) if _inscope is not None else None),
        "out_of_scope_dropped": scope_filtered_out,
    }
    return fn_defs, any_source, scope_filter_info


# --------------------------------------------------------------------------
# Rebuttal
# --------------------------------------------------------------------------
def _load_rebuttal(ws: Path) -> str | None:
    rb_path = ws / ".auditooor" / "cross_function_invariant_coverage_rebuttal.txt"
    try:
        txt = rb_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None
    for line in txt.splitlines():
        m = _REBUTTAL_RE.search(line.strip())
        if not m:
            continue
        reason = m.group("reason").strip()
        if reason and len(reason) <= _REBUTTAL_MAX:
            return reason
    return None


# --------------------------------------------------------------------------
# Evaluate
# --------------------------------------------------------------------------
def _go_conservation_requirement(ws):
    """G-1: derive a Go/Cosmos value-CONSERVATION requirement from the bank/module-
    account fund-movement surface (SendCoins* / MintCoins / BurnCoins / Delegate via a
    bankKeeper), so a Go ws with real fund movement but no sibling-pair requirement is
    NOT WARN-passed with zero conservation coverage. Returns a Requirement over the
    fund-moving functions (>= 2, so the conservation invariant is meaningful), or None
    when no such surface exists (fail-safe - no requirement invented)."""
    root = ws / "src" if (ws / "src").is_dir() else ws
    _move_re = re.compile(
        r"\b(SendCoins(?:FromModuleToAccount|FromAccountToModule|FromModuleToModule)?|"
        r"MintCoins|BurnCoins|DelegateCoins|UndelegateCoins)\s*\(")
    _bank_re = re.compile(r"\bbankKeeper\b|\bBankKeeper\b")
    _func_re = re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(", re.MULTILINE)
    funcs, names, seen = [], set(), 0
    for p in root.rglob("*.go"):
        if p.name.endswith("_test.go"):
            continue
        if seen >= 500:
            break
        seen += 1
        try:
            t = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not (_bank_re.search(t) and _move_re.search(t)):
            continue
        decls = [(m.start(), m.group(1), t[:m.start()].count("\n") + 1)
                 for m in _func_re.finditer(t)]
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        for mm in _move_re.finditer(t):
            enc = None
            for (dpos, dname, dline) in decls:
                if dpos <= mm.start():
                    enc = (dname, dline)
                else:
                    break
            if enc and enc[0] not in names:
                names.add(enc[0])
                funcs.append({"name": enc[0], "file": rel, "line": enc[1]})
    if len(names) < 2:
        return None
    return Requirement(
        kind="go-conservation", label="go-value-conservation",
        invariant_hint=("sum of module-account balances conserved across all fund-moving "
                        "fns (SendCoins/MintCoins/BurnCoins) - no value created/destroyed"),
        functions=funcs, function_names=names)


# --------------------------------------------------------------------------
# ADVISORY axis A8: migration re-establishment hypotheses.
#
# A distinct cross-function completeness question from the sibling-pair /
# state-machine requirements above: does a MIGRATION / REINITIALIZER sequence
# re-establish the steady-state invariant at each intermediate step, and is it
# atomic-on-revert? Concretely: an entry function that reaches BOTH a
# ``_migrate*`` / reinitializer step AND a same-tx VALUE-MOVE via internal call
# edges. The composition can corrupt accounting if an intermediate state (after
# the migrate write, before the value-move - or vice-versa) is OBSERVABLE
# (external call / lazy per-entity guard / non-atomic revert) yet the steady-
# state invariant is not re-established there.
#
# NO-AUTO-CREDIT: every emitted row carries verdict="needs-fuzz" - a hypothesis
# to fuzz, never a proven claim and never a coverage credit. Advisory-first:
# emitted ONLY under AUDITOOOR_XFI_MIGRATION_REESTABLISH (default OFF), so it
# can never retroactively red a parked audit or feed the enforced requirement
# set. Distinct from the END-STATE composed-invariant requirements above (those
# ask "is there a mutation-verified test?"; this asks "is this migrate+move
# sequence's intermediate re-establishment fuzzed?").
#
# FP-guard: an idempotent OZ initializer / one-shot deploy-time init is NOT a
# re-establishment obligation - it runs once, atomically, with no observable
# intermediate. A hit is KEPT only when an intermediate OBSERVABLE exists (an
# external call, an event emit, a lazy per-entity one-shot guard implying cross-
# tx re-entry, or a non-atomic revert path). Bare ``initialize`` callees are not
# treated as migrate steps.
#
# DEDUP (A1 lesson): each hit is tagged ``covered_by_xfi_requirement`` iff its
# entry / migrate-callee already appears in the sibling-pair / state-machine
# requirement enumeration above - we do NOT re-derive the mutation covered_by
# signal, only dedup the emitted advisory hits against the named existing
# detector's requirement set.
# --------------------------------------------------------------------------
MR_SCHEMA = "auditooor.migration_reestablish_hypothesis.v1"

# migrate / reinitializer STEP callee names (NOT bare ``initialize`` - that is
# the idempotent one-shot init the FP-guard excludes).
_MR_MIGRATE_RE = re.compile(r"(?i)(?:migrate|reinit|initializev\d|upgradeto)")
# value-MOVE callee names (conservation-relevant transfers of funds/shares).
_MR_MOVE_RE = re.compile(
    r"(?i)(?:^|_)(?:claim|deposit|withdraw|transfer|mint|burn|redeem|stake|"
    r"unstake|payout|sweep|settle|send|repay|borrow|supply|release|unlock|"
    r"increment|decrement)")
# callee-extraction: identifier immediately followed by '('.
_MR_CALLEE_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
# non-callee keywords / type-casts that _MR_CALLEE_RE would otherwise capture.
_MR_CALL_STOP = {
    "if", "for", "while", "require", "assert", "return", "emit", "revert",
    "else", "catch", "try", "new", "uint", "uint256", "uint128", "uint96",
    "uint8", "int", "int256", "address", "bool", "bytes", "bytes32", "string",
    "abi", "keccak256", "sha256", "ecrecover", "type", "payable", "memory",
    "storage", "calldata", "function", "modifier", "mapping",
}
# external-call receiver names that are language builtins (not a real external
# contract observable).
_MR_BUILTIN_RECV = {"msg", "block", "tx", "abi", "address", "this", "super",
                    "type", "bytes", "string"}
_MR_EXTCALL_RE = re.compile(r"\b([A-Za-z_]\w*)\.[A-Za-z_]\w*\s*\(")
_MR_EMIT_RE = re.compile(r"\bemit\s+[A-Za-z_]")
# a lazy PER-ENTITY one-shot guard: `if (... version/initialized/migrated ...) return;`
# implies the step is re-enterable across txs on other entities -> intermediate
# state IS observable between txs.
_MR_LAZY_GUARD_RE = re.compile(
    r"(?i)if\s*\([^)]*\b(?:version|initialized|migrated|_migrated|status|phase|"
    r"stage|state)\b[^)]*\)\s*\{?\s*return\b")
# non-atomic revert path: try/catch or a low-level call whose failure need not revert.
_MR_NONATOMIC_RE = re.compile(r"\btry\s+|\.call\s*[({]|\.staticcall\s*\(|\.delegatecall\s*\(")


_MR_EMIT_PREFIX_RE = re.compile(r"emit\s+$")


def _mr_callees(body: str) -> set:
    out: set = set()
    for m in _MR_CALLEE_RE.finditer(body):
        nm = m.group(1)
        if nm in _MR_CALL_STOP:
            continue
        # `emit EventName(...)` - the event NAME is not a call. A migration event
        # (e.g. `FundsMigrated`) captured as a migrate callee is a false positive.
        pre = body[max(0, m.start(1) - 12):m.start(1)]
        if _MR_EMIT_PREFIX_RE.search(pre):
            continue
        out.add(nm)
    return out


def _mr_observable(body: str) -> list:
    ev: list = []
    for m in _MR_EXTCALL_RE.finditer(body):
        if m.group(1) not in _MR_BUILTIN_RECV:
            ev.append("external-call")
            break
    if _MR_EMIT_RE.search(body):
        ev.append("event-emit")
    if _MR_LAZY_GUARD_RE.search(body):
        ev.append("lazy-oneshot-guard")
    if _MR_NONATOMIC_RE.search(body):
        ev.append("non-atomic-revert-path")
    return ev


def _mr_entry_fns(lines: list, lang: str) -> list:
    """Return [(name, decl_idx, body_start, body_end, header, body_text)] for
    every Solidity function declaration in ``lines`` (visibility filtering is
    done by the caller)."""
    fn_re = _FN_RES.get(lang)
    if fn_re is None:
        return []
    out: list = []
    for i, ln in enumerate(lines):
        for mm in fn_re.finditer(ln):
            name = mm.group(1)
            start, end = _extract_body_span(lines, i)
            header = " ".join(lines[i:max(i, start) + 1]).split("{", 1)[0]
            body = "\n".join(lines[start:end + 1])
            out.append((name, i, start, end, header, body))
    return out


def _migration_reestablish_hypotheses(ws, requirements) -> list:
    """Enumerate migration re-establishment hypotheses (see block comment).

    Read-only, stdlib-only. Returns a list of hypothesis dicts (verdict=needs-
    fuzz). Empty when the ws has no migrate+move entry sequence."""
    ws = Path(ws)
    inscope = _load_inscope_file_set(ws)

    # dedup index: function names already inside an enumerated requirement.
    req_names: set = set()
    for r in requirements or []:
        try:
            req_names |= set(r.function_names)
        except Exception:
            pass

    hits: list = []
    for root in _resolve_src_roots(ws):
        for path, lang, _rel, _is_test in _iter_source_files(root, include_tests=False):
            if lang != "sol":
                continue
            try:
                rel = str(path.relative_to(ws))
            except ValueError:
                rel = str(path)
            if inscope is not None:
                norm = rel.strip().lstrip("./").replace("\\", "/")
                if norm not in inscope:
                    continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except (OSError, UnicodeError):
                continue
            fns = _mr_entry_fns(lines, lang)
            # per-file name -> body map for the one-hop observable follow.
            body_by_name = {name: body for (name, _i, _s, _e, _h, body) in fns}
            for (name, i, start, _end, header, body) in fns:
                # entry = externally callable, not read-only.
                if not re.search(r"\b(public|external)\b", header):
                    continue
                if re.search(r"\b(internal|private)\b", header):
                    continue
                if _is_readonly_fn(lang, lines, i, start):
                    continue
                callees = _mr_callees(body)
                callees.discard(name)
                migrate_cs = sorted(c for c in callees if _MR_MIGRATE_RE.search(c)
                                    and c.lower() != "initialize")
                move_cs = sorted(c for c in callees if _MR_MOVE_RE.search(c))
                # a value-move that is ALSO the migrate step does not count as a
                # distinct same-tx move.
                move_cs = [c for c in move_cs if c not in migrate_cs]
                if not migrate_cs or not move_cs:
                    continue
                # FP-guard: require an intermediate OBSERVABLE in the entry body
                # OR in the migrate-step callee body (one internal hop).
                obs = _mr_observable(body)
                for mc in migrate_cs:
                    if mc in body_by_name:
                        obs += _mr_observable(body_by_name[mc])
                obs = sorted(set(obs))
                if not obs:
                    # idempotent one-shot atomic init - no re-establishment
                    # obligation. Dropped by FP-guard.
                    continue
                covered = (name in req_names) or any(m in req_names for m in migrate_cs)
                hits.append({
                    "schema": MR_SCHEMA,
                    "id": f"migration-reestablish::{rel}::{name}",
                    "verdict": "needs-fuzz",
                    "kind": "migration-reestablish",
                    "file": rel,
                    "line": i + 1,
                    "function": name,
                    "migrate_step": migrate_cs,
                    "value_move": move_cs,
                    "observables": obs,
                    "predicate": ("entry reaches a _migrate*/reinit step AND a "
                                  "same-tx value-move via internal call edges"),
                    "invariant_hint": ("steady-state invariant (fund/share "
                                       "conservation) re-established at each "
                                       "intermediate migrate step AND atomic-on-revert"),
                    "fp_guard": "intermediate-observable-present",
                    "covered_by_xfi_requirement": covered,
                    "fuzz_oracle_hint": (
                        f"Fuzz {name}: assert the conservation invariant holds "
                        f"AFTER the migrate step {migrate_cs} and AFTER the value-"
                        f"move {move_cs} (each intermediate), and that a revert in "
                        f"either arm rolls back BOTH (atomic). A surviving mutant "
                        f"that skips re-establishment at an observable intermediate "
                        f"is the bug."),
                })
    return hits


def _write_migration_reestablish_jsonl(ws: Path, hits: list) -> Path:
    out_dir = Path(ws) / ".auditooor"
    out_path = out_dir / "migration_reestablish_hypotheses.jsonl"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as fh:
            for h in hits:
                fh.write(json.dumps(h, sort_keys=True) + "\n")
    except OSError:
        pass
    return out_path


def _migration_reestablish_enabled() -> bool:
    return os.environ.get("AUDITOOOR_XFI_MIGRATION_REESTABLISH", "").strip().lower() \
        in ("1", "true", "yes", "on")


def evaluate(ws) -> dict:
    ws = Path(ws)
    if not ws.exists() or not ws.is_dir():
        return {
            "schema": SCHEMA, "gate": GATE, "verdict": "error",
            "reason": f"workspace not a directory: {ws}",
            "requirements": [], "uncovered": [], "covered": [],
            "requirement_count": 0, "covered_count": 0, "uncovered_count": 0,
        }

    fn_defs, any_source, scope_filter_info = _collect_fn_defs(ws)
    if not any_source:
        return {
            "schema": SCHEMA, "gate": GATE, "verdict": "pass-no-source",
            "reason": "no in-scope source found (.sol/.rs/.go/.move/.cairo)",
            "requirements": [], "uncovered": [], "covered": [],
            "requirement_count": 0, "covered_count": 0, "uncovered_count": 0,
            "scope_filter": scope_filter_info,
        }

    requirements: list = []
    requirements.extend(_enumerate_sibling_pair_requirements(fn_defs))
    requirements.extend(_enumerate_state_machine_requirements(fn_defs))

    # G-1 (enforcement-gap 2026-07-03): a Go/Cosmos ws with a real bank/module-account
    # fund-movement surface (SendCoins* / MintCoins / BurnCoins via a bankKeeper) but no
    # sibling-pair / state-machine requirement WARN-passed (pass-no-requirements) with
    # ZERO conservation coverage. Derive a value-CONSERVATION requirement so its
    # non-satisfaction fails. ADVISORY-FIRST: always surfaced as `go_conservation_surface`;
    # added to the enforced requirement set ONLY under AUDITOOOR_XFI_GO_CONSERVATION_STRICT
    # (default OFF -> never retroactively reds a parked audit).
    _go_cons = _go_conservation_requirement(ws)
    _go_cons_strict = os.environ.get("AUDITOOOR_XFI_GO_CONSERVATION_STRICT", "").strip().lower() in ("1", "true", "yes", "on")
    if _go_cons and _go_cons_strict:
        requirements.append(_go_cons)

    # ADVISORY axis A8 (default OFF): migration re-establishment hypotheses.
    # NO-AUTO-CREDIT (verdict=needs-fuzz), never feeds the enforced verdict.
    _mr_hits: list = []
    _mr_summary = None
    if _migration_reestablish_enabled():
        _mr_hits = _migration_reestablish_hypotheses(ws, requirements)
        _mr_path = _write_migration_reestablish_jsonl(ws, _mr_hits)
        _mr_summary = {
            "enabled": True,
            "count": len(_mr_hits),
            "distinct_of_xfi": sum(1 for h in _mr_hits
                                   if not h.get("covered_by_xfi_requirement")),
            "jsonl": str(_mr_path),
            "verdict": "needs-fuzz",
        }

    if not requirements:
        return {
            "schema": SCHEMA, "gate": GATE, "verdict": "pass-no-requirements",
            "migration_reestablish": _mr_summary,
            "reason": (
                "no cross-function invariant requirement found (no L30 sibling "
                "pair both-arms-present, no field co-mutated by >= the sequence "
                "threshold)"
                + ("; NOTE a Go value-conservation surface WAS detected - set "
                   "AUDITOOOR_XFI_GO_CONSERVATION_STRICT=1 to enforce a conservation "
                   "requirement over it" if _go_cons else "")
            ),
            "requirements": [], "uncovered": [], "covered": [],
            "requirement_count": 0, "covered_count": 0, "uncovered_count": 0,
            "scope_filter": scope_filter_info,
            "go_conservation_surface": _go_cons.to_record() if _go_cons else None,
        }

    test_refs = _scan_test_function_refs(ws)
    mut = _load_mutation_state(ws)
    mvc_harness_refs = _mvc_sidecar_verified_harness_refs(ws)
    min_overlap = _min_sequence_overlap()
    dispositions = _NED_MOD.load_dispositions(ws) if _NED_MOD is not None else []

    covered: list = []
    uncovered: list = []
    for req in requirements:
        # Per-unit non-economic-surface disposition: a requirement whose every
        # constituent function lives in a documented non-economic/OOS contract has
        # no conservation invariant to assert - credit it (never-false-pass-guarded
        # in the lib), do not demand a mutation-verified cross-function test.
        if dispositions and _NED_MOD is not None:
            req_files = [f.get("file") for f in req.functions if isinstance(f, dict)]
            if _NED_MOD.all_files_dispositioned(req_files, dispositions):
                _disp = _NED_MOD.file_is_dispositioned(req_files[0], dispositions)
                row = req.to_record()
                row["status"] = "covered"
                row["evidence"] = {
                    "reason": _NED_MOD.CREDIT_LABEL,
                    "classification": _disp["classification"] if _disp else "",
                    "rationale": (_disp["rationale"][:240] if _disp else ""),
                    "referencing_tests": [],
                }
                covered.append(row)
                continue
        ok, evidence = _requirement_has_mutation_verified_test(
            req, test_refs, mut, min_overlap
        )
        # Serving-join credit: a mutation-verified mvc_sidecar chimera/medusa handler
        # whose source exercises >= need of this requirement's functions IS a
        # mutation-verified cross-function test (the standard join misses it because
        # the kill is keyed to the handler name, not the arms). NUVA 2026-06-30.
        if not ok and mvc_harness_refs:
            _need = min(len(req.function_names), 2) if req.kind == "sibling-pair" \
                else min(len(req.function_names), max(min_overlap, 2))
            mvc_ok, mvc_ev = _requirement_covered_by_mvc_harness(req, mvc_harness_refs, _need)
            if mvc_ok:
                ok, evidence = True, mvc_ev
        # Un-mutatable-but-exercised: a state-machine requirement whose every function is
        # a pure assignment (no-mutants) can never earn a mutation kill; credit it when
        # the state var is exercised by a non-vacuous harness (proof-gated, not a blanket).
        if not ok:
            um_ok, um_ev = _requirement_unmutatable_but_exercised(req, ws, mvc_harness_refs)
            if um_ok:
                ok, evidence = True, um_ev
        row = req.to_record()
        row["evidence"] = evidence
        if ok:
            row["status"] = "covered"
            covered.append(row)
        else:
            row["status"] = "uncovered"
            uncovered.append(row)

    requirement_count = len(requirements)
    rebuttal = _load_rebuttal(ws)
    if uncovered:
        if rebuttal:
            verdict = "ok-rebuttal"
            reason = (
                f"{len(uncovered)}/{requirement_count} cross-function requirement(s) "
                f"uncovered; xfi-rebuttal accepted: {rebuttal}"
            )
        else:
            verdict = "fail-cross-function-uncovered"
            labels = ", ".join(r["label"] for r in uncovered[:8])
            reason = (
                f"{len(uncovered)}/{requirement_count} cross-function invariant "
                f"requirement(s) lack a MUTATION-VERIFIED cross-function test: "
                f"{labels}{' ...' if len(uncovered) > 8 else ''}"
            )
    else:
        verdict = "pass-cross-function-covered"
        reason = (
            f"all {requirement_count} cross-function invariant requirement(s) have "
            f"a mutation-verified non-vacuous test"
        )

    return {
        "schema": SCHEMA, "gate": GATE, "verdict": verdict, "reason": reason,
        "requirements": [r.to_record() for r in requirements],
        "covered": covered, "uncovered": uncovered,
        "requirement_count": requirement_count,
        "covered_count": len(covered), "uncovered_count": len(uncovered),
        "mutation_backend_available": mut["available"],
        "migration_reestablish": _mr_summary,
        "rebuttal": rebuttal,
        "scope_filter": scope_filter_info,
    }


# --------------------------------------------------------------------------
# Reusable entrypoint for L37 (mirrors depth-certificate-check.check_depth).
# --------------------------------------------------------------------------
def check(ws) -> dict:
    """Reusable entrypoint importable by L37. Returns evaluate() with a
    ``report_path`` written. Never raises on a malformed workspace - it returns
    an ``error`` verdict instead."""
    ws = Path(ws)
    try:
        res = evaluate(ws)
    except Exception as exc:  # pragma: no cover (defensive)
        return {
            "schema": SCHEMA, "gate": GATE, "verdict": "error",
            "reason": f"cross-function-invariant-coverage raised: {exc}",
            "requirements": [], "uncovered": [], "covered": [],
            "requirement_count": 0, "covered_count": 0, "uncovered_count": 0,
        }
    if res["verdict"] != "error":
        out_path = _write_report(ws, res)
        res["report_path"] = str(out_path)
    return res


def _write_report(ws: Path, result: dict) -> Path:
    out_dir = ws / ".auditooor"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "cross_function_invariant_coverage.json"
        out_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        return out_path
    except OSError:
        return out_dir / "cross_function_invariant_coverage.json"


def _emit_worklist(result: dict) -> list:
    """Advisory worklist: the cross-function invariants a worker should write a
    mutation-verified test for (the uncovered requirements)."""
    work: list = []
    for row in result.get("uncovered", []):
        work.append({
            "label": row["label"],
            "kind": row["kind"],
            "invariant_hint": row["invariant_hint"],
            "functions": [f"{f['file']}:{f['line']} {f['name']}" for f in row["functions"]],
            "action": (
                "write a test exercising these functions together and assert the "
                "composition invariant; then mutation-verify it is non-vacuous "
                "via tools/mutation-verify-coverage.py"
            ),
        })
    return work


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Cross-function / composition invariant coverage gate "
                    "(the final L37 completeness axis).")
    ap.add_argument("--workspace", required=True, help="audit workspace path")
    ap.add_argument("--check", action="store_true",
                    help="emit verdict; exit 1 on fail-cross-function-uncovered")
    ap.add_argument("--emit-worklist", action="store_true",
                    help="emit the advisory cross-function-invariant worklist")
    ap.add_argument("--json", action="store_true", help="emit full JSON result")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser()
    result = check(ws)

    if args.emit_worklist:
        worklist = _emit_worklist(result)
        if args.json:
            print(json.dumps({"schema": SCHEMA + ".worklist", "worklist": worklist}, indent=2))
        else:
            if not worklist:
                print(f"[{GATE}] no uncovered cross-function requirements; worklist empty")
            for w in worklist:
                print(f"  - [{w['kind']}] {w['label']}: {w['invariant_hint']}")
                for fn in w["functions"]:
                    print(f"      * {fn}")
        return 0 if result["verdict"] != "error" else 2

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"[{GATE}] verdict={result['verdict']} "
              f"covered={result['covered_count']}/{result['requirement_count']} "
              f"uncovered={result['uncovered_count']} -- {result['reason']}")
        if args.check and result.get("uncovered"):
            for row in result["uncovered"]:
                print(f"  - UNCOVERED [{row['kind']}] {row['label']}: {row['evidence'].get('reason','')}")

    if result["verdict"] == "error":
        return 2
    if args.check and result["verdict"] == "fail-cross-function-uncovered":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
