"""_util.py — shared helpers for arkworks_wave1 regex-based detectors.

Arkworks (https://github.com/arkworks-rs) is a modular Rust ZK library
ecosystem. These helpers extract Arkworks-specific shape info from Rust
source WITHOUT requiring tree-sitter-rust.

Key Arkworks API surfaces:
  - ark_ff: Fp256, Fp384, BigInteger, Field trait, field arithmetic
  - ark_ec: AffineCurve, ProjectiveCurve, pairing::PairingEngine
  - ark_r1cs_std: fields::fp::FpVar, FpVar::new_witness, alloc
  - ark_groth16: constraints::Groth16VerifierGadget
  - ConstraintSynthesizer<F> trait
"""
from __future__ import annotations

import re

_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)


def strip_comments(source: str) -> str:
    return _COMMENT_RE.sub("", source)


def line_col(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    last_newline = source.rfind("\n", 0, offset)
    col = offset + 1 if last_newline < 0 else offset - last_newline
    return line, col


def block_end(source: str, open_brace_offset: int) -> int:
    depth = 0
    for idx in range(open_brace_offset, len(source)):
        ch = source[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx + 1
    return len(source)


def is_arkworks_file(source: str) -> bool:
    """Heuristic: Arkworks sources import ark_* crates."""
    if re.search(r"\buse\s+ark_(?:ff|ec|r1cs_std|groth16|poly|serialize)\s*::", source):
        return True
    if re.search(r"\bConstraintSynthesizer\s*<", source):
        return True
    if re.search(r"\bFpVar\s*::\s*new_witness\b", source):
        return True
    if re.search(r"\bPairingEngine\b", source):
        return True
    return False


def find_fp_add_sites(source: str) -> list[tuple[str, int]]:
    """Return (op_text, offset) for field arithmetic add calls that
    use raw `+` or `.add` without a `% modulus` / `.into_repr()` /
    `.reduce()` guard nearby."""
    results: list[tuple[str, int]] = []
    pat = re.compile(
        r"(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*(?P<rhs>[A-Za-z_][A-Za-z0-9_]*)\s*;",
        re.M,
    )
    for m in pat.finditer(source):
        # Check that the surrounding context has ark_ff field types
        ctx = source[max(0, m.start() - 200) : m.start()]
        if re.search(r"\b(?:Fp256|Fp384|BigInteger|FpVar|Fr|Fq)\b", ctx):
            results.append((m.group(0), m.start()))
    return results


def find_pairing_calls(source: str) -> list[tuple[str, int]]:
    """Return (call_text, offset) for pairing / miller_loop calls."""
    results: list[tuple[str, int]] = []
    pat = re.compile(
        r"\b(?:E\s*::\s*)?(?:pairing|miller_loop|final_exponentiation)\s*\(",
        re.M,
    )
    for m in pat.finditer(source):
        results.append((m.group(0), m.start()))
    return results


def has_on_curve_check_near(source: str, offset: int, window: int = 400) -> bool:
    """Check if there is an is_on_curve / is_in_correct_subgroup_assuming_on_curve
    / into_affine / check call within `window` chars before `offset`."""
    ctx = source[max(0, offset - window) : offset]
    return bool(
        re.search(
            r"\b(?:is_on_curve|is_in_correct_subgroup_assuming_on_curve"
            r"|check|is_valid|into_affine|assert_on_curve)\s*[(\.]",
            ctx,
        )
    )
