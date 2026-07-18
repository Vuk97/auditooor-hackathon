"""
DRAFT_modular_inverse_of_zero_defined_as_zero.py

# DRAFT: auto-generated sibling for modular-inverse-of-zero-defined-as-zero (source side: solidity).
# Review required before enabling. Do NOT add to test_detectors.sh yet.

BUG_CLASS: modular-inverse-of-zero-defined-as-zero
description: Fermat-based modular inverse `a^(p-2) mod p` silently returns 0 for input 0, breaking `inv * x == 1` invariants in Plonk/KZG/BLS verifiers (Solodit #26821 Linea Plonk Verifier)

Auto-translated from: reference/patterns.dsl/modular-inverse-of-zero-defined-as-zero.yaml

This is a REVIEWER PROMPT — translation is best-effort from the Solidity
DSL regex/precondition shape into a tree-sitter-rust heuristic. Human must:
  1. Confirm the bug-class actually manifests on the Rust side (Soroban /
     Solana / Move / Sway / FunC / TON / CosmWasm). If not, delete this file
     and leave the class `solidity_only`.
  2. Replace the naive regex scan below with AST-level predicates matching
     the actual Rust shape of the bug (see e.g. delegatecall_to_user_address.py
     which ports EVM delegatecall → Soroban SEP-41 transfer-from spoof).
  3. Add fixtures: test_fixtures/DRAFT_modular_inverse_of_zero_defined_as_zero_positive.rs
     and _negative.rs, then register in test_detectors.sh.
"""
from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    line_col,
    snippet_of,
)


_FN_NAME_RE = re.compile(r"(?i)(inverse|invert|inv|mod_inv|field_inv)")
_FERMAT_EXP_RE = re.compile(
    r"(?i)(\.pow_mod\s*\(|\.modpow\s*\(|\.pow\s*\(|pow_mod\s*\(|modpow\s*\()"
)
_P_MINUS_TWO_RE = re.compile(
    r"(?i)(modulus|field_modulus|prime|p|q|MODULUS|P)\s*(?:-|\.checked_sub\s*\()\s*2|"
    r"P_MINUS_2|MODULUS_MINUS_2|FIELD_MODULUS_MINUS_2"
)
_ZERO_GUARD_RE = re.compile(
    r"(?i)(assert!\s*\([^)]*(?:!=\s*0|!\s*[^)]*\.is_zero\s*\()|"
    r"require!\s*\([^)]*(?:!=\s*0|!\s*[^)]*\.is_zero\s*\()|"
    r"if\s+[^{};]*(?:==\s*0|\.is_zero\s*\(\s*\))\s*\{[^{};]*(?:return|panic!|Err\s*\())"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _FERMAT_EXP_RE.search(body_nc):
            continue
        if not _P_MINUS_TWO_RE.search(body_nc):
            continue
        if _ZERO_GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source),
            "message": (
                f"fn `{name}` computes a Fermat-style modular inverse with "
                "`p - 2` exponentiation but has no explicit zero-input guard. "
                "For input 0 this returns 0 and can break verifier field "
                "invariants that expect x * inv(x) == 1."
            ),
        })
    return hits


# --- Source-side excerpt (reference only) ------------------------------------
# pattern: modular-inverse-of-zero-defined-as-zero | source: solodit-26821-consensys-linea-plonk-verifier | severity: HIGH | confidence: MEDIUM | tier: A | preconditions: |   - contract.source_matches_regex: '(Verifier|Plonk|Groth16|Bn254|BN256|BLS|Pairing|Field|Fr|Fp|KZG)' | match: |   - function.kind: internal_or_p
