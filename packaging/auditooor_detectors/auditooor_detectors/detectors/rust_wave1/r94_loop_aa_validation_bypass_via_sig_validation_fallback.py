"""
r94_loop_aa_validation_bypass_via_sig_validation_fallback.py

Flags 4337 validation entry-points that dispatch to either a
user-op validation module OR a signature-validation module based
on a flag — *without* running pre-validation hooks on both paths.
If sig-validation is enabled, attacker triggers the sig path to
skip the pre-validation hooks that guard the user-op path.

Source: Solodit #58887 (Quantstamp Alchemy Modular Account V2).
Class: aa-validation-bypass-via-sig-validation-fallback (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(validate_user_op|validateUserOp|"
    r"is_valid_signature|isValidSignature|"
    r"validate_signature|validate_via_module|"
    r"dispatch_validation)"
)
# Module has both paths — look for a fork based on a flag.
_DUAL_PATH_RE = re.compile(
    r"(?i)(signature_validation_enabled|sig_validation_enabled|"
    r"is_sig_validation|is_signature_validation|"
    r"uses_sig_validation|has_sig_validation|"
    r"validation_flags\s*&|validation_mode\s*==)"
)
# Safe: pre-validation hooks invoked on BOTH branches.
_HOOK_ON_BOTH_RE = re.compile(
    r"(?i)pre_validation_hook[\s\S]{0,400}?pre_validation_hook",
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
        if not _DUAL_PATH_RE.search(body_nc):
            continue
        # If pre-validation hooks appear at least twice, one for each branch, skip.
        if _HOOK_ON_BOTH_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` dispatches between userOp-validation "
                f"and signature-validation paths but pre-validation "
                f"hooks are not invoked on both branches — attacker "
                f"triggers the sig path to skip the guards on the "
                f"user-op path "
                f"(aa-validation-bypass-via-sig-validation-fallback). "
                f"See Solodit #58887 (Quantstamp Alchemy Modular V2)."
            ),
        })
    return hits
