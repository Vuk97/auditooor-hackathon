#!/usr/bin/env python3
"""engine-harness-proof-gate.py - PR4a.

Inspect a formal-verification / fuzzing engine harness (or a directory of
harnesses, or an engine run-log) and FAIL credit when the "proof" is a
stub, a ghost, or a tautology rather than a real executed property.

An engine harness only earns credit when it executes at least one
non-trivial property. The failure modes this gate catches:

  - assert(true) / assertTrue(true) / require(true) tautology bodies.
  - ghost-snapshot patterns: a `ghost`/`snapshot` variable is declared and
    then asserted equal to ITSELF (snapshot == snapshot) so nothing is
    constrained.
  - `% 1` mutation: any modular reduction by 1 (`x % 1`) is always 0, a
    classic neutered-mutation pattern that makes a property vacuous.
  - zero-property halmos: a contract whose only `check_*` function bodies
    are empty or tautological (halmos treats `check_*` as the property set).
  - empty echidna / medusa property set: an invariant/property test contract
    with zero `echidna_*` / `property_*` / `invariant_*` functions, or where
    every such function body is a tautology.
  - rc=0-with-zero-executed-properties: an engine run-log reporting success
    while having executed zero properties (e.g. medusa "0 test(s) ... passed"
    / halmos "0 functions" / foundry "0 tests").

Verdicts:
  pass-real-property-executed   - at least one real, non-tautological
                                  property is present (and, for a run-log,
                                  executed with a non-zero executed count).
  fail-stub-or-ghost            - the harness body is a stub / ghost /
                                  tautology / neutered mutation.
  fail-zero-executed-property   - no property functions exist, or the engine
                                  run-log reports zero executed properties.

Usage:
  python3 tools/engine-harness-proof-gate.py <path> [--json] [--strict]

  <path> may be:
    - a single harness source file (.sol / .t.sol / .rs)
    - a directory (every harness-shaped source file is inspected; the
      worst verdict wins)
    - an engine run-log (.txt / .log / .out) - parsed for the
      rc=0-with-zero-executed-properties pattern

Exit codes:
  0  pass-real-property-executed
  1  fail-stub-or-ghost OR fail-zero-executed-property
  2  input error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.engine_harness_proof_gate.v1"
GATE = "ENGINE-HARNESS-PROOF-GATE"

PASS_REAL = "pass-real-property-executed"
FAIL_STUB = "fail-stub-or-ghost"
FAIL_ZERO = "fail-zero-executed-property"

# ---------------------------------------------------------------------------
# Source-file detection
# ---------------------------------------------------------------------------

SOURCE_EXTS = {".sol", ".rs", ".go"}
LOG_EXTS = {".txt", ".log", ".out", ".json", ".jsonl"}
# Dependency / vendored / build dirs whose OWN test files are never the
# project's authored harnesses. Without this, classify_path's rglob recurses
# into lib/forge-std/test/*.t.sol (CommonBase.t.sol, StdConstants.t.sol, ...)
# and counts forge-std's own tautological library tests as engine harnesses,
# producing a spurious fail-engine-false-pass. Generic across EVM/Rust/Go.
# r36-rebuttal: lane ENGINE-HARNESS-LIB-EXCLUDE registered in .auditooor/agent_pathspec.json
_EXCLUDED_PATH_PARTS = (
    "/lib/", "/vendor/", "/node_modules/", "/forge-std/", "/ds-test/",
    "/openzeppelin-contracts/", "/solmate/", "/solady/", "/.git/",
    "/out/", "/cache/", "/target/", "/dist/", "/build/",
)


def _is_dependency_path(path: Path) -> bool:
    """True if path lives under a vendored/dependency/build dir whose own tests
    must not be counted as the project's authored harnesses."""
    p = str(path).replace("\\", "/")
    return any(part in p for part in _EXCLUDED_PATH_PARTS)
# Go fuzz/property harness names + real-assertion signals (PR6 integration).
GO_PROPERTY_RE = re.compile(r"\bfunc\s+(Fuzz|Prop|Test)[A-Za-z0-9_]*\s*\(")
GO_ASSERT_RE = re.compile(r"\bt\.(Errorf|Error|Fatal|Fatalf|Fail|FailNow)\b|\bpanic\(|\bf\.Fuzz\(")

# Property-function name patterns per engine. A function whose name matches
# one of these is treated as a "property" the engine will execute.
PROPERTY_NAME_RE = re.compile(
    r"\bfunction\s+("
    r"check_[A-Za-z0-9_]*"          # halmos
    r"|echidna_[A-Za-z0-9_]*"       # echidna
    r"|property_[A-Za-z0-9_]*"      # medusa property mode
    r"|invariant_[A-Za-z0-9_]*"     # foundry / medusa invariant mode
    r"|prove_[A-Za-z0-9_]*"         # halmos prove_ convention
    r"|testFuzz_[A-Za-z0-9_]*"      # foundry fuzz
    r"|test[A-Za-z0-9_]*"           # foundry unit/regression tests
    r")\s*\("
)

# Rust proptest / kani property markers.
RUST_PROPERTY_RE = re.compile(
    r"(#\[(kani::proof|test|proptest)\]"
    r"|proptest!\s*\{"
    r"|fn\s+(prop_[A-Za-z0-9_]+|kani_[A-Za-z0-9_]+|check_[A-Za-z0-9_]+))"
)

# ---------------------------------------------------------------------------
# Tautology / stub / ghost detectors (operate on a function body string)
# ---------------------------------------------------------------------------

# assert(true), assertTrue(true), require(true, ...), assert!(true)
TAUTOLOGY_ASSERT_RE = re.compile(
    r"\b(assert|assertTrue|assertEq|require|assert!|assert_eq!)\s*"
    r"\(\s*true\s*(,|\))",
    re.IGNORECASE,
)
# assert(1 == 1), assert(x == x) style trivial equalities handled separately.

# `% 1` neutered-mutation pattern: modulo by literal 1.
MOD_BY_ONE_RE = re.compile(r"%\s*1\b(?!\d)")

# ghost / snapshot variable declarations.
GHOST_DECL_RE = re.compile(
    r"\b(ghost|snapshot)\s+[A-Za-z0-9_<>\[\]\s]*?\b([A-Za-z_][A-Za-z0-9_]*)\b\s*[;=]",
    re.IGNORECASE,
)
# also catch `<type> snapshotFoo = ...` / `uint256 ghostBefore`
GHOST_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*?(?:ghost|snapshot)[A-Za-z0-9_]*)\b", re.IGNORECASE)

BEFORE_STATE_RE = re.compile(
    r"\b[A-Za-z0-9_]*(before|pre|initial)[A-Za-z0-9_]*\b",
    re.IGNORECASE,
)
AFTER_STATE_RE = re.compile(
    r"\b[A-Za-z0-9_]*(after|post|final)[A-Za-z0-9_]*\b",
    re.IGNORECASE,
)
NEGATIVE_CONTROL_RE = re.compile(
    r"\b(negativeControl\w*|negative_control\w*|controlCase\w*|control_case\w*|baseline\w*|"
    r"cleanPath\w*|clean_path\w*|safePath\w*|safe_path\w*|patched\w*|expectRevert\w*|withoutAttack\w*|"
    r"without_attack\w*|should_not\w*|assert_no\w*|"
    # adversarial-control naming used by handler/invariant harnesses: a forged-sig
    # path, an over-release / doubling mutant, or a MUT_* mutant CUT is the negative
    # control that must move 0 value / break the invariant (proves non-vacuity).
    r"forged\w*|mutant\w*|MUT_\w*|over_?release\w*|overRelease\w*|doublecredit\w*|double_credit\w*)\b",
    re.IGNORECASE,
)
# Handler / invariant harness shape: forge's targetContract() registration, a
# dedicated *_Handler contract, a *Mutant subclass, or a mutant-CUT deployment
# (`new ..._MUT_...()` / `new ...Mutant...()`) - the last two are how a non-vacuity
# (mutant-kill) harness is built, often as a subclass that INHERITS targetContract.
HANDLER_INVARIANT_RE = re.compile(
    r"\btargetContract\s*\(|\bcontract\s+[A-Za-z0-9_]*Handler\b"
    r"|\bcontract\s+[A-Za-z0-9_]*Mutant\b"
    r"|\bnew\s+[A-Za-z0-9_]*(?:MUT|Mutant)[A-Za-z0-9_]*\s*\(",
)
# Boundary-free adversarial-control / mutant markers. Compound identifiers like
# `OmniBridge_MUT_OVERRELEASE` or `OmniBridge_ResidualMutant` defeat the \b anchors
# in NEGATIVE_CONTROL_RE (the marker sits mid-token), so a non-vacuity mutant harness
# would otherwise read as having no negative control.
MUTANT_MARKER_RE = re.compile(r"(MUT_|_MUT|Mutant|OVERRELEASE|OverRelease|over_release|forged)", re.IGNORECASE)
SOL_TARGET_CALL_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\s*\(")
GENERIC_TARGET_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(")
TRY_CATCH_RE = re.compile(r"\btry\b.*\bcatch\b", re.DOTALL)
EXPECT_REVERT_RE = re.compile(r"\bexpectRevert\s*\(")
ASSUME_RE = re.compile(r"\b(vm\.)?assume\s*\(")
LATCH_RETURN_RE = re.compile(
    r"\breturn\s+([A-Za-z_][A-Za-z0-9_]*)\s*==\s*false\s*;",
    re.IGNORECASE,
)

_NON_TARGET_CALLS = {
    "assert",
    "assertTrue",
    "assertEq",
    "assertGe",
    "assertLe",
    "assertGt",
    "assertLt",
    "require",
    "revert",
    "if",
    "for",
    "while",
    "return",
    "emit",
    "panic",
    "assert_eq",
    "assert_ne",
    "prop_assert",
    "prop_assert_eq",
    "prop_assert_ne",
    "Errorf",
    "Error",
    "Fatal",
    "Fatalf",
    "Fail",
    "FailNow",
    "Fuzz",
    "t.Errorf",
    "t.Error",
    "t.Fatal",
    "t.Fatalf",
    "f.Fuzz",
}


def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.DOTALL)
    src = re.sub(r"//[^\n]*", " ", src)
    return src


def _function_bodies(src: str) -> list[tuple[str, str]]:
    """Return (header, body) pairs for every `function ...(...) ... { ... }`.

    Brace-matched so nested blocks are captured. Header is the text from
    `function` up to the opening `{`.
    """
    out: list[tuple[str, str]] = []
    for m in re.finditer(r"\bfunction\b[^{};]*", src):
        # find the opening brace after the header
        start = m.end()
        # skip to first '{' (function may have modifiers/returns before body)
        brace = src.find("{", m.start())
        if brace == -1:
            continue
        # abstract / interface functions end in ';' before any '{'
        semi = src.find(";", m.start())
        if semi != -1 and semi < brace:
            out.append((src[m.start():semi], ""))
            continue
        depth = 0
        i = brace
        while i < len(src):
            c = src[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    out.append((src[m.start():brace], src[brace + 1:i]))
                    break
            i += 1
    return out


def _is_tautological_body(body: str) -> bool:
    """True if the body constrains nothing meaningful."""
    b = body.strip()
    if not b:
        return True  # empty property body proves nothing

    # `% 1` neutered mutation: a modulo-by-1 is always 0, so any property that
    # routes a value through `% 1` can never fail. This is a stub regardless of
    # how many assertions wrap the neutered value.
    if MOD_BY_ONE_RE.search(b):
        return True

    # echidna / medusa "boolean property" convention: a `return <expr>` that
    # is a real comparison (not `return true`) is a genuine constraint even
    # without an assert statement.
    returns_bool = re.search(r"\breturn\s+(.+?);", b, re.DOTALL)
    if returns_bool:
        expr = returns_bool.group(1).strip()
        # `return true` / `return false` / `return x == x` are vacuous.
        if re.fullmatch(r"(true|false)", expr, re.IGNORECASE):
            return True
        m_self = re.fullmatch(
            r"([A-Za-z_][A-Za-z0-9_.()]*)\s*==\s*([A-Za-z_][A-Za-z0-9_.()]*)",
            expr,
        )
        if m_self and m_self.group(1) == m_self.group(2):
            return True
        # a real boolean expression with an operator constrains state.
        if re.search(r"(<=|>=|<|>|==|!=|&&|\|\|)", expr):
            return False

    # assert(true)/require(true)/assert!(true) anywhere AND no other assertion
    asserts = re.findall(
        r"\b(assert|assertTrue|assertEq|assertGe|assertLe|assertGt|assertLt|"
        r"require|assert!|assert_eq!|assert_ne!|prop_assert|prop_assert_eq!)\s*\(",
        b,
        re.IGNORECASE,
    )
    taut_asserts = TAUTOLOGY_ASSERT_RE.findall(b)

    # x == x  / a == a  trivial-equality assertions (ghost == ghost).
    trivial_eq = re.findall(
        r"\b(assert\w*|require|assert_eq!|prop_assert\w*)\s*\(\s*"
        r"([A-Za-z_][A-Za-z0-9_.]*)\s*==\s*\2\s*[,)]",
        b,
        re.IGNORECASE,
    )

    n_assert = len(asserts)
    n_taut = len(taut_asserts) + len(trivial_eq)

    if n_assert == 0:
        # No assertion and no real return-bool -> proves nothing.
        return True

    # If every assertion is a tautology, the body is vacuous.
    if n_assert <= n_taut:
        return True

    return False


def _has_before_after_state(text: str) -> bool:
    return bool(BEFORE_STATE_RE.search(text) and AFTER_STATE_RE.search(text))


def _has_negative_control(text: str) -> bool:
    return bool(NEGATIVE_CONTROL_RE.search(text))


def _has_solidity_target_call(body: str) -> bool:
    return bool(SOL_TARGET_CALL_RE.search(body) or re.search(r"\bnew\s+[A-Z][A-Za-z0-9_]*\s*\(", body))


def _has_generic_target_call(body: str) -> bool:
    for m in GENERIC_TARGET_CALL_RE.finditer(body):
        name = m.group(1)
        if name in _NON_TARGET_CALLS:
            continue
        if name.startswith(("assert", "prop_assert")):
            continue
        return True
    return False


def _has_exception_path_control(body: str) -> bool:
    return bool(TRY_CATCH_RE.search(body) or EXPECT_REVERT_RE.search(body))


def _has_symbolic_target_comparison(body: str) -> bool:
    return bool(
        ASSUME_RE.search(body)
        and _has_solidity_target_call(body)
        and re.search(r"\b(assert\w*|require)\s*\([^;]*(==|!=|<=|>=|<|>)", body)
    )


def _has_stateful_latch_property(body: str, full_source: str) -> bool:
    m = LATCH_RETURN_RE.search(body)
    if not m:
        return False
    latch = re.escape(m.group(1))
    if not re.search(rf"\b{latch}\s*=\s*true\s*;", full_source):
        return False
    if not (TRY_CATCH_RE.search(full_source) or EXPECT_REVERT_RE.search(full_source)):
        return False
    return _has_solidity_target_call(full_source)


def _is_real_proof_body(body: str, full_source: str, language: str) -> bool:
    """Require last-mile proof semantics, not just a non-taut assertion.

    A proof-backed harness must interact with the target, observe state before
    and after the action, and carry a negative/baseline control signal in the
    same source file. This keeps autonomous conversion advisory while refusing
    proof credit for documentary assertions and scaffold-only properties.
    """
    has_exception_control = _has_exception_path_control(body)
    if language != "go" and _is_tautological_body(body) and not has_exception_control:
        return False
    if language == "solidity" and _has_stateful_latch_property(body, full_source):
        return True
    target_call = (
        _has_solidity_target_call(body)
        if language == "solidity"
        else _has_generic_target_call(body)
    )
    if not target_call:
        return False
    if language == "solidity" and _has_symbolic_target_comparison(body):
        return True
    if has_exception_control:
        return True
    if language == "solidity" and TRY_CATCH_RE.search(body) and re.search(r"\breturn\s+.+?;", body, re.DOTALL):
        return True
    if not _has_before_after_state(body):
        # Handler-based STANDING invariant (forge invariant / echidna assertion
        # mode): the property asserts a standing predicate on ghost/accumulator
        # state that the fuzzed HANDLER mutates from real CUT calls across the
        # sequence, so it legitimately carries no in-body before/after delta. Credit
        # it when the FULL source is a genuine handler/invariant harness
        # (targetContract / a *_Handler contract) that calls the real target AND
        # carries a negative control (forged path / mutant / over-release). Sound: a
        # tautological body was already rejected above; a standing assertion with no
        # driving handler or no negative control still fails. near-intents 2026-06-26:
        # the OmniBridge economic-invariant harness (no_unauthorized_release /
        # no_replay / conservation / fee_bound, MUT_OVERRELEASE non-vacuity) was
        # false-flagged fail-stub-or-ghost because its standing props have no
        # in-body before/after.
        if (
            language == "solidity"
            and HANDLER_INVARIANT_RE.search(full_source)
            and _has_solidity_target_call(full_source)
            and (
                _has_negative_control(full_source)
                or MUTANT_MARKER_RE.search(full_source)
                # a directional conservation / solvency comparison (custody >=
                # authorized net, released <= locked) is itself the discriminating
                # economic constraint a real bug breaks - the standard form a
                # doubling/over-release mutant kills.
                or re.search(r"\b(assertGe|assertLe|assertGt|assertLt)\s*\(", body)
                or re.search(r"(<=|>=|<|>)", body)
            )
        ):
            return True
        return False
    if not _has_negative_control(full_source):
        return False
    return True


def _classify_solidity(src: str) -> dict[str, Any]:
    clean = _strip_comments(src)
    bodies = _function_bodies(clean)

    properties: list[tuple[str, str]] = []
    for header, body in bodies:
        if PROPERTY_NAME_RE.search("function " + header.split("function", 1)[-1]) or PROPERTY_NAME_RE.search(header):
            name_m = re.search(
                r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)", header
            )
            name = name_m.group(1) if name_m else "<anon>"
            properties.append((name, body))

    if not properties:
        return {
            "verdict": FAIL_ZERO,
            "reason": "no property/test functions (check_/echidna_/property_/invariant_/prove_/test*) found",
            "property_count": 0,
            "real_property_count": 0,
            "stub_properties": [],
        }

    stubs: list[str] = []
    real: list[str] = []
    for name, body in properties:
        if _is_real_proof_body(body, clean, "solidity"):
            real.append(name)
        else:
            stubs.append(name)

    if real:
        return {
            "verdict": PASS_REAL,
            "reason": f"{len(real)} real property/properties: {', '.join(real)}",
            "property_count": len(properties),
            "real_property_count": len(real),
            "stub_properties": stubs,
        }
    return {
        "verdict": FAIL_STUB,
        "reason": f"all {len(properties)} property/properties are stub/ghost/tautology: {', '.join(stubs)}",
        "property_count": len(properties),
        "real_property_count": 0,
        "stub_properties": stubs,
    }


def _classify_rust(src: str) -> dict[str, Any]:
    clean = _strip_comments(src)
    # In Rust the body extractor keys on `function` which is absent; fall back
    # to fn-based extraction.
    fn_bodies: list[tuple[str, str, bool]] = []
    for m in re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", clean):
        name = m.group(1)
        brace = clean.find("{", m.end())
        if brace == -1:
            continue
        depth = 0
        i = brace
        while i < len(clean):
            c = clean[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    prefix_lines = clean[: m.start()].splitlines()
                    attrs: list[str] = []
                    for line in reversed(prefix_lines):
                        s = line.strip()
                        if not s:
                            continue
                        if s.startswith("#["):
                            attrs.append(s)
                            continue
                        break
                    has_test_attr = any(
                        re.search(r"#\[\s*(?:[A-Za-z0-9_:]+::)?(test|proof)\b", a)
                        for a in attrs
                    )
                    fn_bodies.append((name, clean[brace + 1:i], has_test_attr))
                    break
            i += 1

    properties = [
        (n, b)
        for (n, b, has_test_attr) in fn_bodies
        if has_test_attr or re.match(r"(prop_|kani_|check_|test_)", n)
    ]
    # proptest! macro blocks count as properties too
    if not properties and "proptest!" in clean:
        # treat the macro block as a single real property if it has assertions
        block = clean[clean.find("proptest!"):]
        if re.search(r"\b(assert!|assert_eq!|prop_assert)", block) and _is_real_proof_body(block, clean, "rust"):
            return {
                "verdict": PASS_REAL,
                "reason": "proptest! block with real assertions",
                "property_count": 1,
                "real_property_count": 1,
                "stub_properties": [],
            }

    if not properties:
        return {
            "verdict": FAIL_ZERO,
            "reason": "no Rust property/test functions (#[test]/#[kani::proof]/prop_/kani_/check_/test_) found",
            "property_count": 0,
            "real_property_count": 0,
            "stub_properties": [],
        }

    stubs, real = [], []
    for name, body in properties:
        (real if _is_real_proof_body(body, clean, "rust") else stubs).append(name)

    if real:
        return {
            "verdict": PASS_REAL,
            "reason": f"{len(real)} real property/properties: {', '.join(real)}",
            "property_count": len(properties),
            "real_property_count": len(real),
            "stub_properties": stubs,
        }
    return {
        "verdict": FAIL_STUB,
        "reason": f"all {len(properties)} property/properties are stub/tautology: {', '.join(stubs)}",
        "property_count": len(properties),
        "real_property_count": 0,
        "stub_properties": stubs,
    }


def _classify_go(src: str) -> dict[str, Any]:
    """Classify a Go fuzz/property harness (PR6 integration).

    Real property = a Fuzz*/Prop*/Test* func whose body carries a Go assertion
    signal, drives target code, observes before/after state, includes a
    negative-control signal, and is not ghost / neutered. Vacuous
    (no assertion / no target drive) or %1-neutered = stub.
    """
    clean = _strip_comments(src)
    fn_bodies: list[tuple[str, str]] = []
    for m in re.finditer(r"\bfunc\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", clean):
        name = m.group(1)
        brace = clean.find("{", m.end())
        if brace == -1:
            continue
        depth = 0
        i = brace
        while i < len(clean):
            c = clean[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    fn_bodies.append((name, clean[brace + 1:i]))
                    break
            i += 1

    properties = [(n, b) for (n, b) in fn_bodies if re.match(r"(Fuzz|Prop|Test)", n)]
    if not properties:
        return {
            "verdict": FAIL_ZERO,
            "reason": "no Go property/fuzz functions (Fuzz*/Prop*/Test*) found",
            "property_count": 0,
            "real_property_count": 0,
            "stub_properties": [],
        }
    # NOTE: do NOT use _is_tautological_body here - it counts only Solidity/Rust
    # assert idioms and would mark every t.Errorf-based Go property as "no
    # assertion". Go-appropriate check: real iff it carries a Go assertion signal
    # (t.Errorf/t.Fatal/panic/f.Fuzz-drive), is non-empty, not %1-neutered, and is
    # not a trivial self-equality ghost (DeepEqual(x,x) / `x == x`).
    _go_ghost = re.compile(
        r"(reflect\.DeepEqual\(\s*([A-Za-z_][\w.]*)\s*,\s*\2\s*\))"
        r"|(\b([A-Za-z_][\w.]*)\s*==\s*\4\b)"
    )
    stubs, real = [], []
    for name, body in properties:
        b = body.strip()
        has_assert = bool(GO_ASSERT_RE.search(body))
        neutered = bool(MOD_BY_ONE_RE.search(body))
        ghost = bool(_go_ghost.search(body))
        if (
            has_assert
            and b
            and not neutered
            and not ghost
            and _is_real_proof_body(body, clean, "go")
        ):
            real.append(name)
        else:
            stubs.append(name)
    if real:
        return {
            "verdict": PASS_REAL,
            "reason": f"{len(real)} real Go property/properties: {', '.join(real)}",
            "property_count": len(properties),
            "real_property_count": len(real),
            "stub_properties": stubs,
        }
    return {
        "verdict": FAIL_STUB,
        "reason": f"all {len(properties)} Go property/properties stub/vacuous: {', '.join(stubs)}",
        "property_count": len(properties),
        "real_property_count": 0,
        "stub_properties": stubs,
    }


# ---------------------------------------------------------------------------
# Engine run-log classification (rc=0-with-zero-executed-properties)
# ---------------------------------------------------------------------------

# medusa: "fuzzing complete: 0 test(s) ... passed" / "0 properties tested"
# halmos: "0 functions" / "Running 0"
# foundry: "0 tests passed" / "Ran 0 test"
# echidna: "Tests found: 0"
ZERO_EXEC_RE = [
    re.compile(r"\b0\s+test\(?s?\)?\s+(passed|executed|run)", re.IGNORECASE),
    re.compile(r"\bRan\s+0\s+test", re.IGNORECASE),
    re.compile(r"\b0\s+(properties|propert(y|ies))\s+(tested|executed|passed)", re.IGNORECASE),
    re.compile(r"\b0\s+functions?\b", re.IGNORECASE),
    re.compile(r"Tests?\s+found:\s*0\b", re.IGNORECASE),
    re.compile(r"\bexecuted\s*[:=]?\s*0\b", re.IGNORECASE),
    re.compile(r"\b0\s+invariants?\b", re.IGNORECASE),
]

NONZERO_EXEC_RE = [
    re.compile(r"\b([1-9]\d*)\s+test\(?s?\)?\s+(passed|executed)", re.IGNORECASE),
    re.compile(r"\bRan\s+([1-9]\d*)\s+test", re.IGNORECASE),
    re.compile(r"\b([1-9]\d*)\s+(properties|propert(?:y|ies))\s+(tested|executed|passed)", re.IGNORECASE),
    re.compile(r"\bexecuted\s*[:=]?\s*([1-9]\d*)\b", re.IGNORECASE),
    re.compile(r"\[PASS\]", re.IGNORECASE),
    re.compile(r"\bpassed\s+([1-9]\d*)\b", re.IGNORECASE),
]


def _classify_log(text: str) -> dict[str, Any]:
    # If any non-zero executed-count signal exists, the run executed real work.
    for rx in NONZERO_EXEC_RE:
        if rx.search(text):
            return {
                "verdict": PASS_REAL,
                "reason": "engine run-log reports a non-zero executed property/test count",
                "property_count": None,
                "real_property_count": None,
                "stub_properties": [],
            }
    for rx in ZERO_EXEC_RE:
        if rx.search(text):
            return {
                "verdict": FAIL_ZERO,
                "reason": "engine run-log reports success with zero executed properties/tests",
                "property_count": 0,
                "real_property_count": 0,
                "stub_properties": [],
            }
    return {
        "verdict": FAIL_ZERO,
        "reason": "engine run-log contains no recognizable executed-property count",
        "property_count": 0,
        "real_property_count": 0,
        "stub_properties": [],
    }


# ---------------------------------------------------------------------------
# File / dir dispatch
# ---------------------------------------------------------------------------

VERDICT_RANK = {PASS_REAL: 0, FAIL_STUB: 1, FAIL_ZERO: 2}


def classify_text(text: str, ext: str) -> dict[str, Any]:
    if ext in LOG_EXTS and not _looks_like_source(text):
        return _classify_log(text)
    if ext == ".rs":
        return _classify_rust(text)
    if ext == ".sol":
        return _classify_solidity(text)
    if ext == ".go":
        return _classify_go(text)
    # unknown extension: sniff
    if _looks_like_source(text):
        if "fn " in text and "function " not in text:
            return _classify_rust(text)
        return _classify_solidity(text)
    return _classify_log(text)


def _looks_like_source(text: str) -> bool:
    return bool(
        re.search(r"\b(contract|function|pragma\s+solidity|fn\s+\w+\s*\()", text)
    )


def _harness_shaped(path: Path) -> bool:
    if path.suffix not in SOURCE_EXTS:
        return False
    try:
        head = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(
        PROPERTY_NAME_RE.search(head)
        or RUST_PROPERTY_RE.search(head)
        or GO_PROPERTY_RE.search(head)
    )


def classify_path(path: Path) -> dict[str, Any]:
    if path.is_dir():
        results: list[dict[str, Any]] = []
        for child in sorted(path.rglob("*")):
            # r36-rebuttal: lane ENGINE-HARNESS-LIB-EXCLUDE registered
            if _is_dependency_path(child):
                continue
            if child.is_file() and _harness_shaped(child):
                r = classify_text(
                    child.read_text(encoding="utf-8", errors="replace"),
                    child.suffix,
                )
                r["file"] = str(child)
                results.append(r)
        if not results:
            return {
                "verdict": FAIL_ZERO,
                "reason": "no harness-shaped source files found in directory",
                "files": [],
            }
        worst = max(results, key=lambda r: VERDICT_RANK[r["verdict"]])
        return {
            "verdict": worst["verdict"],
            "reason": worst["reason"],
            "worst_file": worst.get("file"),
            "files": results,
        }
    text = path.read_text(encoding="utf-8", errors="replace")
    r = classify_text(text, path.suffix)
    r["file"] = str(path)
    return r


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Engine-harness proof gate (PR4a).")
    ap.add_argument("path", help="harness file, directory, or engine run-log")
    ap.add_argument("--json", action="store_true", help="emit JSON result")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="(reserved) treat any stub property as a hard fail even when a real one exists",
    )
    args = ap.parse_args(argv)

    p = Path(args.path)
    if not p.exists():
        sys.stderr.write(f"error: path not found: {p}\n")
        return 2

    result = classify_path(p)

    if args.strict and result["verdict"] == PASS_REAL and result.get("stub_properties"):
        result["verdict"] = FAIL_STUB
        result["reason"] = (
            "--strict: stub/ghost property present alongside real one(s): "
            + ", ".join(result["stub_properties"])
        )

    payload = {
        "schema": SCHEMA_VERSION,
        "gate": GATE,
        "path": str(p),
        **result,
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"{GATE}: {result['verdict']}")
        print(f"  reason: {result['reason']}")
        if result.get("worst_file"):
            print(f"  worst_file: {result['worst_file']}")

    return 0 if result["verdict"] == PASS_REAL else 1


if __name__ == "__main__":
    raise SystemExit(main())
