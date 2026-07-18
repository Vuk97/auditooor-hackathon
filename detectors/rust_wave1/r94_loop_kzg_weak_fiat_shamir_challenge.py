"""
r94_loop_kzg_weak_fiat_shamir_challenge.py

Flags KZG batch-verify / commitment challenge derivation fns that
build a Fiat-Shamir transcript missing critical binding inputs
(cell count, cell index, domain separator, commitment list) —
attacker remixes cells into a different claim with same challenge.

Source: Solodit #64105 (Sherlock Fusaka Upgrade c-kzg-4844
verify_cell_kzg_proof_batch).
Class: kzg-weak-fiat-shamir-challenge (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(verify_cell_kzg_proof_batch|verify_kzg_batch|"
    r"compute_challenge|derive_challenge|fiat_shamir|"
    r"compute_r_powers|verify_kzg_proof_batch)"
)
_FS_RE = re.compile(
    r"(?i)(hash_to_field|hash_to_bls_field|"
    r"transcript\s*\.\s*(append|absorb|update)|"
    r"keccak\w*\s*\(|sha256\s*\(|poseidon\s*\(|blake\w*\s*\()"
)
# Must bind cell_count / cell_indices / commitments / domain_sep to be safe.
_BINDING_RE = re.compile(
    r"(?i)(cell_?indices|cell_?count|num_?cells|row_?indices|"
    r"column_?indices|domain_?sep|DST|dst\b|"
    r"FIAT_SHAMIR_PROTOCOL|commitments\s*\.\s*len)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _FS_RE.search(body_nc):
            continue
        if _BINDING_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` derives a KZG batch-verify challenge "
                f"via Fiat-Shamir without binding cell_indices / "
                f"cell_count / domain_sep — attacker remixes cells "
                f"into a different claim with same challenge "
                f"(kzg-weak-fiat-shamir-challenge). "
                f"See Solodit #64105 (Sherlock Fusaka c-kzg-4844)."
            ),
        })
    return hits
