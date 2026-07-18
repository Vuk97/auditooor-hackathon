#!/usr/bin/env python3
"""harness_vacuity.py - SENTINEL-ONLY harness detector (fail-closed vacuity gate).

PRINCIPLE
---------
A per-function harness whose ONLY assertion is a sentinel tautology
(`assert(true)`, `assert!(true)`, `assert(true, ...)`, `assert True`,
`Test.assert(true)`, a `return true` boolean property, or NO assertion at all)
proves nothing. It must NEVER be counted as coverage. This module is the single
shared predicate that both the GENERATOR
(tools/per-function-invariant-gen.py) and the COVERAGE ORACLE
(tools/mutation-verify-coverage.py) consult so a sentinel harness cannot be
credited - the generator stamps every emitted row with `is_sentinel`, and the
oracle refuses to enter the (expensive) mutation loop for a sentinel-only
harness, returning a typed `no-property-discovered` verdict instead of ever
reaching `non-vacuous`.

SEED
----
The detector is seeded directly from the 254+ optimism Halmos scaffolds emitted
by per-function-invariant-gen.py, e.g.

    contract Halmos_OptimismMintableERC20_mint {
        function check_mint_does_not_break_core_invariant() public {
            assert(true);
        }
    }

and the equivalent rust (`assert!(true)`), go (sentinel comment, `_ = t`), move
(`assert!(true, 0)`), vyper (`assert True`), cadence (`Test.assert(true)`) and
cairo (`assert(true, 'invariant placeholder')`) forms the generator renders.

CONTRACT
--------
`is_sentinel_only_harness(text)` -> bool
  True  iff the harness body contains NO genuine (non-tautological) property:
        every assertion present is a sentinel tautology, OR there is no
        assertion / property expression at all.
  False iff the harness contains at least one real, source-grounded property
        (a comparison/relation assertion, a `return <relation>` boolean
        property, an `expect_revert`-shaped negative control, etc.).

This is deliberately CONSERVATIVE in the fail-closed direction for the gen
output: a freshly emitted scaffold (only a sentinel) is rejected; a harness a
worker has filled with a real predicate passes. It does NOT replace the
mutation-kill oracle (mutation-verify-coverage.py) - it is the cheap STATIC
pre-filter that stops a sentinel from ever being credited or from wasting a
full mutation loop.
"""
from __future__ import annotations

import re

# A genuine relational/operator assertion is the witness of a real property.
# Sentinel tautologies that prove nothing.  Covers solidity/move/cairo
# `assert(true ...)`, rust/move `assert!(true ...)`, foundry `assertTrue(true)`,
# rust `assert_eq!(true, true)` and `require(true ...)`.
_SENTINEL_ASSERT_RE = re.compile(
    r"\b(?:assert|assertTrue|assertEq|require|assert!|assert_eq!|prop_assert!|"
    r"prop_assume!|Test\.assert)\s*"
    r"\(\s*true\s*(?:,[^)]*)?\)",
    re.IGNORECASE,
)
# Python/vyper bare `assert True` (no parens).
_SENTINEL_PY_ASSERT_RE = re.compile(r"\bassert\s+True\b")

# Any assertion-shaped call at all (used to decide whether a body asserts
# *something*).  Names cover solidity/foundry, rust, go(testify) and python
# idioms.  The go testify family (require.* / assert.* / s.Require()/s.Assert())
# is THE cosmos-SDK assertion lib; without it a real testify relational assert
# was previously false-rejected as sentinel-only (it matched no assert shape).
_ANY_ASSERT_RE = re.compile(
    r"\b(?:assert|assertTrue|assertEq|assertGe|assertLe|assertGt|assertLt|"
    r"assert_eq!|assert_ne!|assert!|require|prop_assert|prop_assert_eq!|"
    r"prop_assert_ne!|prop_assume!|Test\.assert)\s*\(|"
    r"\b(?:require|assert)\s*\.\s*[A-Za-z_]\w*\s*\(|"
    r"\bs\s*\.\s*(?:Require|Assert)\s*\(\s*\)\s*\.\s*[A-Za-z_]\w*\s*\(",
    re.IGNORECASE,
)
# python bare `assert <expr>` where <expr> is NOT just `True`.
_PY_REAL_ASSERT_RE = re.compile(r"\bassert\s+(?!True\b)\S")

# ---------------------------------------------------------------------------
# Go / testify support
# ---------------------------------------------------------------------------
# testify relational/method assertions (the cosmos-SDK lib): require.Equal,
# assert.Greater, require.NotEqual, s.Require().Equal, ... A bare-method form
# (require.True(t,true) / require.Equal(t,X,X)) is still vacuous - handled by
# _GO_TESTIFY_SENTINEL_RE below.
_GO_TESTIFY_ASSERT_RE = re.compile(
    r"\b(?:require|assert)\s*\.\s*[A-Za-z_]\w*\s*\(|"
    r"\bs\s*\.\s*(?:Require|Assert)\s*\(\s*\)\s*\.\s*[A-Za-z_]\w*\s*\(",
)
# A go-style failure assertion (t.Fatalf / t.Errorf / panic). This is a real
# property ONLY when guarded by a relational condition (`if a != b { t.Fatalf }`);
# an UNCONDITIONAL t.Fatalf("todo") / panic("unimplemented") is a stub, NOT a
# property (the prior unconditional short-circuit false-accepted those).
_GO_FAIL_RE = re.compile(r"\bt\.(?:Errorf|Error|Fatal|Fatalf|Fail|FailNow)\b|\bpanic\s*\(")
# A go `if <relation> { ... }` whose condition carries a real relational/error
# operator. Used to decide whether a t.Fatalf inside the block is genuine.
_GO_REL_IF_RE = re.compile(
    r"\bif\b[^\n{]*(?:!=|==|<=|>=|<[^=]|>[^=]|&&|\|\||err\b|\.Err\b|!\s*[A-Za-z_])"
)

# testify SENTINEL forms: require.True(t,true)/assert.True(t,true),
# require.Equal(t,X,X) (same first/second value arg), require.Nil(t,nil),
# require.False(t,false). These assert a literal tautology - vacuous.
_GO_TESTIFY_TRUE_SENTINEL_RE = re.compile(
    r"\b(?:require|assert)\s*\.\s*True\s*\(\s*[A-Za-z_]\w*\s*,\s*true\s*[,)]",
    re.IGNORECASE,
)
_GO_TESTIFY_FALSE_SENTINEL_RE = re.compile(
    r"\b(?:require|assert)\s*\.\s*False\s*\(\s*[A-Za-z_]\w*\s*,\s*false\s*[,)]",
    re.IGNORECASE,
)
_GO_TESTIFY_NIL_SENTINEL_RE = re.compile(
    r"\b(?:require|assert)\s*\.\s*Nil\s*\(\s*[A-Za-z_]\w*\s*,\s*nil\s*[,)]",
    re.IGNORECASE,
)
# require.Equal(t, X, X) where the two value args are the SAME token -> tautology.
_GO_TESTIFY_EQUAL_RE = re.compile(
    r"\b(?:require|assert)\s*\.\s*(?:Equal|NotEqual|EqualValues)\s*\("
    r"\s*[A-Za-z_]\w*\s*,\s*([^,()]+?)\s*,\s*([^,()]+?)\s*[,)]",
)

# ---------------------------------------------------------------------------
# Offline constant-foldable-assertion detector (toolchain-free)
# ---------------------------------------------------------------------------
# An assertion whose operands are ALL literals/addresses/consts is decidable at
# write time and proves nothing about the CUT, e.g. require(1>0), assert(2!=3),
# x==x, len(x)>=0, Move `assert!(@0x1 != @0x0, E)`. These are vacuous even though
# they carry a relational operator.
_INT_LIT = r"-?\d+"
_HEX_LIT = r"0x[0-9a-fA-F]+"
_ADDR_LIT = r"@0x[0-9a-fA-F]+"
_LIT_OPERAND = rf"(?:{_ADDR_LIT}|{_HEX_LIT}|{_INT_LIT}|true|false)"
# require(<lit> <relop> <lit>) / assert(<lit> <relop> <lit>) / assert!(<addr> != <addr>, ...)
_CONST_FOLD_RELATION_RE = re.compile(
    rf"\b(?:assert|assertTrue|assertEq|assertGe|assertLe|assertGt|assertLt|"
    rf"require|assert!|assert_eq!|assert_ne!|Test\.assert)\s*\(\s*"
    rf"{_LIT_OPERAND}\s*(?:<=|>=|<|>|==|!=)\s*{_LIT_OPERAND}\s*(?:,[^)]*)?\)",
    re.IGNORECASE,
)
# len(...) >= 0 is always true (an unsigned/length is never negative) -> vacuous.
_CONST_FOLD_LEN_RE = re.compile(r"\blen\s*\([^)]*\)\s*>=\s*0\b")
# x == x / x.foo() == x.foo() inside an assertion -> reflexive tautology.
_CONST_FOLD_SELF_EQ_RE = re.compile(
    r"\b(?:assert|assertEq|require|assert!|assert_eq!|Test\.assert)\s*\(\s*"
    r"([A-Za-z_][A-Za-z0-9_.()]*)\s*==\s*([A-Za-z_][A-Za-z0-9_.()]*)\s*(?:,[^)]*)?\)"
)

# ---------------------------------------------------------------------------
# zk soundness-vacuity detector
# ---------------------------------------------------------------------------
# A circuit test that feeds ONLY a happy-path witness and never asserts a
# forged/extra/out-of-range witness is REJECTED proves nothing about soundness
# (the canonical zk false-green: a circuit compiles + proves a valid witness
# while a constraint is missing). A genuine circuit test names a negative
# witness it expects to fail.
_ZK_NEG_WITNESS_RE = re.compile(
    r"\b(?:should_fail|should_panic|expect_constraint_violation|"
    r"expect(?:ed)?_fail(?:ure)?|assert_fails|witness_should_be_rejected|"
    r"expect_revert|constraint_violation|under_constrain|underconstrain|"
    r"invalid_witness|forged_witness|malicious_witness|negative_witness)\b",
    re.IGNORECASE,
)
# A zk-shaped harness body (circuit / witness vocabulary present).
_ZK_CONTEXT_RE = re.compile(
    r"\b(?:circuit|witness|constraint|r1cs|template\s+|signal\s+|main\s*\{|"
    r"groth16|plonk|snark|prove\b|verify_proof|circom|noir|cairo)\b",
    re.IGNORECASE,
)

# A negative control / revert expectation is a real property even without a
# relational assert.
_NEG_CONTROL_RE = re.compile(
    r"\b(?:expectRevert|expect_revert|vm\.expectRevert|should_panic|catch_unwind)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# DEEP-MODE STATIC DETECTORS (modes 1, 4, 4b, 5 subterm/skeleton, 6)
# ---------------------------------------------------------------------------
# These mirror the _CONST_FOLD arm: each is a cheap, toolchain-free structural
# detector for a harness that is structurally non-vacuous (carries a real-looking
# relational assert / a real CUT interface) yet proves nothing about the CUT.
# They do NOT change the is_sentinel_only_harness True/False contract (a freshly
# emitted scaffold stays sentinel-only); they are ADDITIONAL predicates surfaced
# through deep_vacuity_modes(text) -> list[str] + deep_vacuity_reasons.
#
# Mode-name constants (resolve against HARNESS_FAILURE_TAXONOMY.md).
MODE_SETUP_MAX_BOUND = "setUp-max-bound"          # mode 1 (unlimited-params)
MODE_DEAD_CUT_GUARD = "dead-CUT-guard"            # mode 4b
MODE_MODEL_COUNTER_INVARIANT = "model-counter-invariant"  # mode 4
MODE_TAUTOLOGICAL_SUBTERM_AND = "tautological-subterm-AND"  # mode 5 (subterm)
MODE_SENTINEL_SKELETON = "sentinel-skeleton"      # mode 5 (assertTrue(false, ...skeleton))
MODE_MOCK_CALLPATH_VACUITY = "mock-callpath-vacuity"  # mode 6

# --- mode 1: setUp assigns type(uintN).max / 2**256-1 to a cap/bound/limit name
# that a later require/assert compares against. ----------------------------
# type(uintN).max in any width, or 2**256-1 / 2**N-1, or a literal all-Fs mask.
_MAX_VALUE_RE = re.compile(
    r"type\s*\(\s*u?int\d*\s*\)\s*\.\s*max"
    r"|\b2\s*\*\*\s*\d+\s*-\s*1\b"
    r"|\b0x[fF]{8,}\b",
)
# A cap/bound/limit-shaped lvalue name (the variable the guard tests against).
_CAP_NAME = r"[A-Za-z_]\w*?(?:[Cc]ap|[Bb]ound|[Ll]imit|[Mm]ax(?:imum)?|[Cc]eiling|[Tt]hreshold)\w*"
# An assignment `<capName> = type(uint).max;` (declaration or plain assign).
_SETUP_MAX_ASSIGN_RE = re.compile(
    rf"\b(?:uint\d*\s+)?(?:public\s+|internal\s+|private\s+)?({_CAP_NAME})\s*="
    rf"\s*(?:type\s*\(\s*u?int\d*\s*\)\s*\.\s*max|2\s*\*\*\s*\d+\s*-\s*1|0x[fF]{{8,}})",
)
# A require/assert that compares against a cap/bound name (the guard under test).
_GUARD_USES_CAP_RE = re.compile(
    rf"\b(?:require|assert|assertLe|assertGe|assertLt|assertGt)\s*\([^)]*?"
    rf"(?:<=|>=|<|>)\s*({_CAP_NAME})",
)
_GUARD_USES_CAP_LHS_RE = re.compile(
    rf"\b(?:require|assert|assertLe|assertGe|assertLt|assertGt)\s*\(\s*"
    rf"({_CAP_NAME})\s*(?:<=|>=|<|>)",
)

# --- mode 4b: dead-CUT-guard. Only real-call sites live inside ------------
# `if(address(x)!=address(0))` while setUp never assigns x / never calls bindTarget().
_BIND_TARGET_CALL_RE = re.compile(r"\bbindTarget\s*\(")
_BIND_TARGET_DEF_RE = re.compile(r"\bfunction\s+bindTarget\b")
# `if (address(target) != address(0))` guard around CUT calls.
_NONZERO_ADDR_GUARD_RE = re.compile(
    r"\bif\s*\(\s*address\s*\(\s*([A-Za-z_]\w*)\s*\)\s*!=\s*address\s*\(\s*0\s*\)\s*\)",
)
# A setUp body (used to check whether target is ever bound/assigned there).
_SETUP_BODY_RE = re.compile(r"\bfunction\s+setUp\s*\(\s*\)[^{]*\{(.*?)\n\s*\}", re.DOTALL)

# --- mode 4: model-counter invariant. All invariant operands are harness ---
# state vars mutated by an in-harness mutate*/drive*, never a target.<view>() read.
# A handler that maintains ghost counters.
_MUTATE_HANDLER_RE = re.compile(r"\bfunction\s+(mutate\w*|drive\w*|h_\w*|handler_\w*)\s*\(")
# A ghost var written inside a mutate/drive handler: `totalIn += ...`, `tracked = ...`.
_GHOST_WRITE_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?:\+=|-=|=)\s*[^=]")
# A read of the real CUT through a typed view: `target.foo()`, `t.balance()`,
# `SSVStorageStaking.load()`, `cut.totalSupply()`. Heuristic: an identifier
# followed by `.<name>(` where the receiver is NOT a known harness-local helper.
# A genuine CUT read is `recv.name(...)` whether the getter takes ARGS or not -
# argumented getters (mapping reads `urd.claimed(a,b)`, `token.balanceOf(x)`,
# `morpho.supplyShares(id,actor)`) are just as real as a zero-arg `totalSupply()`.
# The original regex matched only `()` (zero-arg), which mislabelled any harness
# whose invariants read the CUT through an argumented getter as a model-counter
# (mode 4) false-positive. Recognising argumented reads only ever FLIPS
# saw_real_read False->True (relaxes a vacuity flag), so it is false-green-safe:
# a truly vacuous model-counter harness has NO recv.name(...) real-CUT read at all.
_TARGET_VIEW_READ_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(\s*\)",
)
# A CUT read through a getter that takes one or more arguments (mapping / indexed
# getter / balanceOf). Receiver captured for the same non-ghost check as above.
_TARGET_VIEW_READ_ARGS_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(\s*[^)]+\)",
)
# invariant_/property_/echidna_/check_ function bodies (where the assertion lives).
_INVARIANT_FN_RE = re.compile(
    r"\bfunction\s+(?:invariant_|property_|echidna_|check_)\w*\s*\([^)]*\)"
    r"[^{]*\{(.*?)\n\s*\}",
    re.DOTALL,
)

# --- mode 5: tautological-subterm-AND. `(<reflexive/always-true>) && <expr>` --
# `(a>=b || b>=a) && real`  /  `(x==x) && real`  /  `(true) && real`.
_TAUT_OR_SUBTERM_RE = re.compile(
    r"\(\s*([A-Za-z_]\w*)\s*>=\s*([A-Za-z_]\w*)\s*\|\|\s*([A-Za-z_]\w*)\s*>=\s*([A-Za-z_]\w*)\s*\)\s*&&",
)
_TAUT_REFLEX_AND_RE = re.compile(
    r"\(\s*([A-Za-z_][\w.()]*)\s*==\s*([A-Za-z_][\w.()]*)\s*\)\s*&&",
)
_TAUT_TRUE_AND_RE = re.compile(r"\(\s*true\s*\)\s*&&", re.IGNORECASE)

# --- mode 5: sentinel-skeleton. assertTrue(false, "...materialized-skeleton/TODO...") --
_SENTINEL_SKELETON_RE = re.compile(
    r"\bassert(?:True)?\s*\(\s*false\s*,\s*[\"'][^\"']*"
    r"(?:materialized-skeleton|materialized skeleton|TODO|not yet proven|placeholder)"
    r"[^\"']*[\"']\s*\)",
    re.IGNORECASE,
)

# --- mode 6: mock-callpath-vacuity. ---------------------------------------
# A mock/test subclass of the CUT: `contract XMock is CUT { ... }`.
_MOCK_SUBCLASS_RE = re.compile(
    r"\bcontract\s+([A-Za-z_]\w*(?:Mock|Test|Harness|Stub)\w*)\s+is\s+"
    r"([A-Za-z_]\w*)\b[^{]*\{",
    re.IGNORECASE,
)
# A value-delivery path overridden in the subclass body.
_VALUE_DELIVERY_RE = re.compile(
    r"\.\s*call\s*\{[^}]*value\s*:|"
    r"\.\s*(?:transfer|send)\s*\(|"
    r"\bfunction\s+receive\b|"
    r"\breceive\s*\(\s*\)\s*external|"
    r"\bfunction\s+fallback\b|"
    r"\bfallback\s*\(\s*\)\s*external",
)
# prod force-send constructs (need NO receive() on the recipient).
_FORCE_SEND_RE = re.compile(r"\bselfdestruct\s*\(|\bSafeSend\b|\bforceSend\b")
# Does the mock subclass define receive()/fallback() to accept value?
_HAS_RECEIVE_RE = re.compile(
    r"\breceive\s*\(\s*\)\s*external\s+payable|"
    r"\bfallback\s*\(\s*\)\s*external(?:\s+payable)?",
)
# A value-moving handler (sends ETH out) whose witness counter we expect >0.
_VALUE_MOVING_HANDLER_RE = re.compile(
    r"\.\s*call\s*\{[^}]*value\s*:|"
    r"\.\s*(?:transfer|send)\s*\(|"
    r"\bselfdestruct\s*\(|\bSafeSend\b",
)
# A witness/ghost counter asserted >0 (the reachability proof a value-moving fn ran).
_WITNESS_ASSERT_GT0_RE = re.compile(
    r"\b(?:assert|assertGt|require|assertTrue)\s*\(\s*"
    r"(?:w[A-Z]\w*|witness\w*|[A-Za-z_]\w*[Ww]itness)\s*(?:>\s*0|,\s*0)",
)

# Boolean-property `return <expr>;` (echidna/medusa convention).  A `return true`
# / `return false` / `return x == x` is vacuous; a real relation is genuine.
_RETURN_BOOL_RE = re.compile(r"\breturn\s+(.+?);", re.DOTALL)
_RELATION_RE = re.compile(r"(<=|>=|<|>|==|!=|&&|\|\|)")


def _strip_comments(src: str) -> str:
    """Remove // line comments, /* */ block comments and # line comments.

    Sentinel scaffolds carry a long comment preamble (and the example/commented
    proptest forms) that MUST NOT be mistaken for real assertions.  We strip all
    three comment styles so only executable lines are inspected.
    """
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.DOTALL)
    src = re.sub(r"//[^\n]*", " ", src)
    # Strip python/vyper '#' comments line-wise (leave '#[...]' rust attributes
    # alone: those start with '#[' and are not line comments).
    out_lines = []
    for line in src.splitlines():
        if "#" in line and "#[" not in line:
            line = line.split("#", 1)[0]
        out_lines.append(line)
    return "\n".join(out_lines)


def _return_bool_is_genuine(code: str) -> bool:
    """True iff a `return <expr>;` is a genuine relational boolean property."""
    for m in _RETURN_BOOL_RE.finditer(code):
        expr = m.group(1).strip()
        if re.fullmatch(r"(?:true|false)", expr, re.IGNORECASE):
            continue  # return true / return false -> vacuous
        m_self = re.fullmatch(
            r"([A-Za-z_][A-Za-z0-9_.()]*)\s*==\s*([A-Za-z_][A-Za-z0-9_.()]*)", expr
        )
        if m_self and m_self.group(1) == m_self.group(2):
            continue  # return x == x -> vacuous
        if _RELATION_RE.search(expr):
            return True
    return False


def _go_fatal_is_genuine(code: str) -> bool:
    """True iff a go t.Fatalf/t.Errorf/panic is guarded by a real relational
    `if` condition. An UNCONDITIONAL t.Fatalf("todo")/panic("unimplemented") is
    a stub, NOT a property: we require a relational `if` to appear in the body
    alongside the fail call. (This replaces the prior unconditional short-circuit
    that false-accepted a bare `t.Fatalf("todo")` as genuine.)"""
    if not _GO_FAIL_RE.search(code):
        return False
    return bool(_GO_REL_IF_RE.search(code))


def _testify_sentinel_only(code: str) -> bool:
    """True iff EVERY testify assertion present is a sentinel tautology
    (require.True(t,true) / require.Equal(t,X,X) same-arg / require.Nil(t,nil) /
    require.False(t,false)). False if a real testify relational assertion exists.

    Caller has already established there is >=1 testify-shaped assertion.
    """
    n_testify = len(_GO_TESTIFY_ASSERT_RE.findall(code))
    if n_testify == 0:
        return False
    n_sentinel = (
        len(_GO_TESTIFY_TRUE_SENTINEL_RE.findall(code))
        + len(_GO_TESTIFY_FALSE_SENTINEL_RE.findall(code))
        + len(_GO_TESTIFY_NIL_SENTINEL_RE.findall(code))
    )
    # require.Equal(t, X, X) with identical value args is a tautology.
    for m in _GO_TESTIFY_EQUAL_RE.finditer(code):
        if m.group(1).strip() == m.group(2).strip():
            n_sentinel += 1
    return n_sentinel >= n_testify


def _is_constant_foldable_only(code: str) -> bool:
    """True iff EVERY relational assertion in the body is constant-foldable
    (operands all literals/addresses, len(x)>=0, or x==x reflexive). These
    decide at write time and prove nothing about the CUT.

    Returns False when at least one assertion has a non-literal operand (a real
    property) OR when there is no relational assertion at all (the caller's other
    arms decide that case).
    """
    rel_asserts = 0
    folded = 0
    # constant-literal relations (require(1>0), assert!(@0x1 != @0x0, E), ...)
    for _ in _CONST_FOLD_RELATION_RE.finditer(code):
        rel_asserts += 1
        folded += 1
    # len(x) >= 0
    for _ in _CONST_FOLD_LEN_RE.finditer(code):
        rel_asserts += 1
        folded += 1
    # x == x reflexive
    for m in _CONST_FOLD_SELF_EQ_RE.finditer(code):
        rel_asserts += 1
        if m.group(1).strip() == m.group(2).strip():
            folded += 1
    if rel_asserts == 0:
        return False
    return folded >= rel_asserts


# ---------------------------------------------------------------------------
# DEEP-MODE public predicates (each mirrors _is_constant_foldable_only's shape:
# cheap, comment-stripped, returns a bool; surfaced through deep_vacuity_modes).
# ---------------------------------------------------------------------------
def is_setup_max_bound(text: str) -> bool:
    """Mode 1. True iff setUp assigns type(uintN).max / 2**256-1 to a
    cap/bound/limit name that a later require/assert compares against, so the
    guard the invariant tests can never bind (a guard-removal mutant survives).

    Defeated by FINITE binding caps (morpho EconInvariant_MetaMorpho CAP_A=1e20).
    """
    if not text:
        return False
    code = _strip_comments(text)
    capped = set()
    for m in _SETUP_MAX_ASSIGN_RE.finditer(code):
        capped.add(m.group(1))
    if not capped:
        return False
    # Only vacuous if such a max-assigned cap is actually USED by a guard.
    for m in _GUARD_USES_CAP_RE.finditer(code):
        if m.group(1) in capped:
            return True
    for m in _GUARD_USES_CAP_LHS_RE.finditer(code):
        if m.group(1) in capped:
            return True
    return False


def is_dead_cut_guard(text: str) -> bool:
    """Mode 4b. True iff every real-CUT call site is behind an
    `if(address(x)!=address(0))` guard while setUp never assigns x / never calls
    bindTarget() - so target stays address(0) and only harness ghost state is
    asserted (beanstalk SiloFacet_Invariant.t.sol, morpho VaultV2_Invariant.t.sol).
    """
    if not text:
        return False
    code = _strip_comments(text)
    guards = list(_NONZERO_ADDR_GUARD_RE.finditer(code))
    if not guards:
        return False
    guarded_vars = {m.group(1) for m in guards}
    # Extract the setUp body (if any).
    m_setup = _SETUP_BODY_RE.search(code)
    setup_body = m_setup.group(1) if m_setup else ""
    for var in guarded_vars:
        # Bound if setUp calls bindTarget() OR assigns the guarded var directly.
        if _BIND_TARGET_CALL_RE.search(setup_body):
            return False
        assign_re = re.compile(rf"\b{re.escape(var)}\s*=")
        if assign_re.search(setup_body):
            return False
    # A guarded var exists, no setUp binds it -> dead CUT guard.
    return True


def is_model_counter_invariant(text: str) -> bool:
    """Mode 4. True iff every operand of every invariant/property body is a
    harness state var mutated by an in-harness mutate*/drive*/h_* handler, and
    NONE is a `target.<view>()` real read - i.e. the invariant asserts
    harness-maintained ghost counters no source mutant can flip
    (beanstalk totalIn==totalOut+fees, etherfi CashModuleCore_FuzzProps).
    """
    if not text:
        return False
    code = _strip_comments(text)
    inv_bodies = [m.group(1) for m in _INVARIANT_FN_RE.finditer(code)]
    if not inv_bodies:
        return False
    # Collect ghost vars written inside any mutate*/drive*/h_* handler.
    ghost_vars = set()
    for hm in _MUTATE_HANDLER_RE.finditer(code):
        start = hm.end()
        # crude body slice: from handler start to next 'function ' or EOF.
        nxt = code.find("function ", start)
        body = code[start:nxt] if nxt != -1 else code[start:]
        for gm in _GHOST_WRITE_RE.finditer(body):
            ghost_vars.add(gm.group(1))
    if not ghost_vars:
        return False
    saw_real_read = False
    saw_ghost_operand = False
    for body in inv_bodies:
        # A target.<view>() read inside the invariant body = genuine. Both
        # zero-arg getters AND argumented getters (mapping/balanceOf/indexed)
        # count: a read whose receiver is NOT a ghost var is a real CUT read.
        for rgx in (_TARGET_VIEW_READ_RE, _TARGET_VIEW_READ_ARGS_RE):
            for rm in rgx.finditer(body):
                recv, _name = rm.group(1), rm.group(2)
                if recv not in ghost_vars:
                    saw_real_read = True
        for gv in ghost_vars:
            if re.search(rf"\b{re.escape(gv)}\b", body):
                saw_ghost_operand = True
    # Vacuous iff invariants reference ghost vars and NEVER a real CUT read.
    return saw_ghost_operand and not saw_real_read


def is_tautological_subterm_and(text: str) -> bool:
    """Mode 5 (subterm). True iff an assertion's predicate is
    `(<reflexive/always-true>) && <expr>` - `(a>=b||b>=a) && real`,
    `(x==x) && real`, `(true) && real` - where the always-true subterm is
    smuggled in to defeat the pure-tautology check (etherfi
    CashModuleCore_FuzzProps controlCase && realInvariant).
    """
    if not text:
        return False
    code = _strip_comments(text)
    if _TAUT_TRUE_AND_RE.search(code):
        return True
    for m in _TAUT_REFLEX_AND_RE.finditer(code):
        if m.group(1).strip() == m.group(2).strip():
            return True
    for m in _TAUT_OR_SUBTERM_RE.finditer(code):
        a, b, c, d = (g.strip() for g in m.groups())
        # (a>=b || b>=a) is a reflexive total-order tautology.
        if {a, b} == {c, d}:
            return True
    return False


def is_sentinel_skeleton(text: str) -> bool:
    """Mode 5 (skeleton). True iff the body carries an
    assertTrue(false, "...materialized-skeleton/TODO/not yet proven...")
    sentinel-skeleton. Distinct from sentinel-TRUE: this fails baseline so it
    does not false-green, but it is a placeholder that must be EXCLUDED from the
    coverage denominator AND re-queued (morpho/etherfi/polygon eq_* PoCs).
    """
    if not text:
        return False
    code = _strip_comments(text)
    return bool(_SENTINEL_SKELETON_RE.search(code))


def is_mock_callpath_vacuity(text: str) -> bool:
    """Mode 6. True iff a mock/test subclass of the CUT overrides a value-
    delivery path (.call{value}/transfer/send/receive/fallback) OR a prod CUT
    force-sends (selfdestruct/SafeSend) while the mock subclass lacks
    receive()/fallback(), AND it is paired with a value-moving handler whose
    reachability witness counter is never asserted >0 - so the value-moving fn
    silently never executes (etherfi LiquidityController mutant SURVIVED).
    """
    if not text:
        return False
    code = _strip_comments(text)
    mock = _MOCK_SUBCLASS_RE.search(code)
    has_force_send = bool(_FORCE_SEND_RE.search(code))
    has_value_delivery_override = bool(_VALUE_DELIVERY_RE.search(code))
    # Structural signature requires a mock subclass of a CUT.
    if not mock:
        # A bare prod-force-send body with no mock subclass is not this mode.
        return False
    has_receive = bool(_HAS_RECEIVE_RE.search(code))
    # Trigger condition: prod force-sends but mock lacks receive()/fallback(),
    # OR the mock overrides a value-delivery path (.call/transfer/send) but
    # provides no receive()/fallback() to accept value back.
    delivery_risk = (has_force_send and not has_receive) or (
        has_value_delivery_override and not has_receive
    )
    if not delivery_risk:
        return False
    # Paired with a value-moving handler whose witness is never asserted >0.
    has_value_moving = bool(_VALUE_MOVING_HANDLER_RE.search(code))
    if not has_value_moving:
        return False
    if _WITNESS_ASSERT_GT0_RE.search(code):
        # A reachability witness >0 proves the value-moving fn executed -> clean.
        return False
    return True


# Reason strings for each deep mode (manifests / logs / accept-gate output).
deep_vacuity_reasons = {
    MODE_SETUP_MAX_BOUND: (
        "setUp assigns type(uintN).max / 2**256-1 to a cap/bound/limit name a "
        "later guard compares against (mode 1: the guard can never bind, a "
        "guard-removal mutant survives); use FINITE binding caps"
    ),
    MODE_DEAD_CUT_GUARD: (
        "every real-CUT call is behind if(address(x)!=address(0)) while setUp "
        "never binds x / never calls bindTarget() (mode 4b: target stays "
        "address(0), only harness ghost state is asserted)"
    ),
    MODE_MODEL_COUNTER_INVARIANT: (
        "all invariant operands are harness ghost counters mutated by an "
        "in-harness mutate*/drive*/h_* handler, never a target.<view>() real "
        "read (mode 4: no source mutant can flip them)"
    ),
    MODE_TAUTOLOGICAL_SUBTERM_AND: (
        "assertion predicate is (<reflexive/always-true>) && <expr> - a "
        "controlCase/(a>=b||b>=a)/(x==x)/(true) subterm smuggled in to defeat "
        "the pure-tautology check (mode 5 subterm)"
    ),
    MODE_SENTINEL_SKELETON: (
        "assertTrue(false, \"...materialized-skeleton/TODO/not yet proven...\") "
        "placeholder (mode 5 skeleton: exclude from the coverage denominator "
        "AND re-queue, do not credit)"
    ),
    MODE_MOCK_CALLPATH_VACUITY: (
        "a mock CUT subclass overrides a value-delivery path (.call/transfer/"
        "send) OR prod force-sends (selfdestruct/SafeSend) while the mock lacks "
        "receive()/fallback(), paired with a value-moving handler whose witness "
        "counter is never asserted >0 (mode 6: the value-moving fn never executes)"
    ),
}


def deep_vacuity_modes(text: str) -> list[str]:
    """Return the list of deep-vacuity mode names that fire on this harness body.

    This is the ADDITIONAL detector surface (modes 1, 4, 4b, 5-subterm,
    5-skeleton, 6) layered on top of the backward-compatible
    is_sentinel_only_harness True/False contract. A caller (the author-accept
    gate, the coverage oracle) treats a non-empty list as a vacuity FAIL and
    looks each name up in deep_vacuity_reasons for the human-readable cause.

    Order is stable (taxonomy mode order) for deterministic FAIL lists.
    """
    if not text:
        return []
    modes: list[str] = []
    if is_setup_max_bound(text):
        modes.append(MODE_SETUP_MAX_BOUND)
    if is_model_counter_invariant(text):
        modes.append(MODE_MODEL_COUNTER_INVARIANT)
    if is_dead_cut_guard(text):
        modes.append(MODE_DEAD_CUT_GUARD)
    if is_tautological_subterm_and(text):
        modes.append(MODE_TAUTOLOGICAL_SUBTERM_AND)
    if is_sentinel_skeleton(text):
        modes.append(MODE_SENTINEL_SKELETON)
    if is_mock_callpath_vacuity(text):
        modes.append(MODE_MOCK_CALLPATH_VACUITY)
    return modes


def is_zk_soundness_vacuous(text: str) -> bool:
    """True iff a circuit/zk harness feeds only a happy-path witness and never
    asserts a forged/extra/out-of-range witness is REJECTED.

    Only fires on a zk-shaped body (circuit/witness/constraint vocabulary). A
    state-diff oracle in a non-circuit body is NOT a circuit soundness harness
    and returns False here (the generic arms decide it). This is the canonical
    zk false-green guard: a circuit that compiles + proves a valid witness while
    a constraint is missing passes both a real-assert check and an executed-test
    probe.
    """
    if not text:
        return False
    code = _strip_comments(text)
    if not _ZK_CONTEXT_RE.search(code):
        return False
    # A negative-witness rejection assertion is the soundness witness.
    return not _ZK_NEG_WITNESS_RE.search(code)


def is_sentinel_only_harness(text: str) -> bool:
    """Return True when the harness asserts NOTHING real (a sentinel scaffold).

    A harness is sentinel-only when, after stripping comments, EITHER
      (a) it contains no assertion, no go-style fail, no python real-assert, no
          negative-control and no genuine return-bool property; OR
      (b) every assertion it does contain is a sentinel tautology
          (`assert(true)` / `assert!(true)` / `assert True` / ...).

    It returns False as soon as ONE genuine property is found.
    """
    if not text:
        return True
    code = _strip_comments(text)

    # zk soundness handling (circuit-shaped bodies only):
    if _ZK_CONTEXT_RE.search(code):
        # A negative-witness rejection assertion IS the soundness property,
        # even when expressed via a should_fail!/expect_constraint_violation
        # marker that the generic assert arms below would not recognise.
        if _ZK_NEG_WITNESS_RE.search(code):
            return False
        # No negative-witness rejection -> a happy-path-only circuit test is
        # vacuous EVEN IF it carries a real-looking state assertion (a valid
        # witness proves nothing about a missing constraint).
        return True

    # A genuine negative control is a real property.
    if _NEG_CONTROL_RE.search(code):
        return False
    # A genuine relational boolean-property return is a real property.
    if _return_bool_is_genuine(code):
        return False

    # A go testify assertion: vacuous iff EVERY testify assert is a sentinel
    # tautology (require.True(t,true)/require.Equal(t,X,X)/require.Nil(t,nil)).
    # A real testify relational assert (require.Equal(t, after, before+amt)) is
    # genuine. THE cosmos-SDK assertion lib - previously false-rejected wholesale.
    if _GO_TESTIFY_ASSERT_RE.search(code):
        if not _testify_sentinel_only(code):
            # A real testify assert can still be constant-foldable
            # (require.Equal(t,1,1) is caught above; require.True(t, 1>0) is not
            # testify-sentinel but is constant-fold). Defer to the const-fold arm.
            if not _is_constant_foldable_only(code):
                return False
    # A go-style failure assertion (t.Fatalf/panic) is genuine ONLY when guarded
    # by a relational `if`. An unconditional t.Fatalf("todo")/panic is a stub.
    if _go_fatal_is_genuine(code):
        return False
    # A python bare `assert <non-True>` is a real property (unless const-fold).
    if _PY_REAL_ASSERT_RE.search(code) and not _is_constant_foldable_only(code):
        return False

    n_assert = (
        len(_ANY_ASSERT_RE.findall(code))
        + len(_SENTINEL_PY_ASSERT_RE.findall(code))
    )
    if n_assert == 0:
        # No assertion of any shape -> proves nothing (sentinel / stub).
        return True

    # Every relational assertion is constant-foldable (require(1>0), x==x,
    # len>=0, assert!(@0x1!=@0x0)) -> vacuous.
    if _is_constant_foldable_only(code):
        return True

    n_sentinel = len(_SENTINEL_ASSERT_RE.findall(code)) + len(
        _SENTINEL_PY_ASSERT_RE.findall(code)
    )
    # testify sentinel forms also count toward the sentinel tally so a body whose
    # ONLY assertion is require.True(t,true) is vacuous.
    n_sentinel += (
        len(_GO_TESTIFY_TRUE_SENTINEL_RE.findall(code))
        + len(_GO_TESTIFY_FALSE_SENTINEL_RE.findall(code))
        + len(_GO_TESTIFY_NIL_SENTINEL_RE.findall(code))
    )
    for m in _GO_TESTIFY_EQUAL_RE.finditer(code):
        if m.group(1).strip() == m.group(2).strip():
            n_sentinel += 1
    # Every assertion is a sentinel tautology -> vacuous.
    return n_assert <= n_sentinel


def sentinel_reason(text: str) -> str:
    """Human-readable reason for a sentinel verdict (for manifests / logs)."""
    code = _strip_comments(text)
    if is_zk_soundness_vacuous(code):
        return ("circuit/zk harness feeds only a happy-path witness and never "
                "asserts a forged/out-of-range witness is rejected "
                "(no should_fail/expect_constraint_violation)")
    n_assert = len(_ANY_ASSERT_RE.findall(code)) + len(_SENTINEL_PY_ASSERT_RE.findall(code))
    if n_assert == 0:
        return "no assertion or property expression of any shape (stub body)"
    if _is_constant_foldable_only(code):
        return ("every relational assertion is constant-foldable "
                "(require(1>0)/x==x/len>=0/assert!(@0x1!=@0x0) - decided at "
                "write time, proves nothing about the CUT)")
    if _GO_TESTIFY_ASSERT_RE.search(code) and _testify_sentinel_only(code):
        return ("every testify assertion is a sentinel tautology "
                "(require.True(t,true)/require.Equal(t,X,X)/require.Nil(t,nil))")
    return "every assertion is a sentinel tautology (assert(true)/assert!(true)/assert True/...)"


__all__ = [
    "is_sentinel_only_harness",
    "sentinel_reason",
    "is_zk_soundness_vacuous",
    # deep-mode static detectors (modes 1, 4, 4b, 5-subterm, 5-skeleton, 6)
    "deep_vacuity_modes",
    "deep_vacuity_reasons",
    "is_setup_max_bound",
    "is_dead_cut_guard",
    "is_model_counter_invariant",
    "is_tautological_subterm_and",
    "is_sentinel_skeleton",
    "is_mock_callpath_vacuity",
    "MODE_SETUP_MAX_BOUND",
    "MODE_DEAD_CUT_GUARD",
    "MODE_MODEL_COUNTER_INVARIANT",
    "MODE_TAUTOLOGICAL_SUBTERM_AND",
    "MODE_SENTINEL_SKELETON",
    "MODE_MOCK_CALLPATH_VACUITY",
]
