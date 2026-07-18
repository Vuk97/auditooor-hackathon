"""
r94_loop_mint_based_on_pre_transfer_input_amount_fot.py

Flags deposit/fund fns that safeTransferFrom(user, this, amount) and
mint/credit `amount` shares — without measuring balance delta —
fee-on-transfer tokens deliver less than `amount`, over-crediting.

Source: Solodit #37356 (Interplanetary IPC GatewayManagerFacet).
Class: mint-based-on-pre-transfer-input-amount-fot (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(fund|deposit|mint_shares|wrap|bridge_in|lock_and_mint)")
_TRANSFER_IN_RE = re.compile(
    r"(safe_transfer_from|safeTransferFrom|token\.transfer_from)\s*\(\s*\w+\s*,\s*"
    r"(self|this|address\(this\)|self\.addr|env\.current_contract_address|vault_address)"
)
_MINT_INPUT_RE = re.compile(
    r"(_mint|mint_shares|credit|mint_to)\s*\(\s*\w+\s*,\s*(amount|_amount|input_amount)\b"
)
_DELTA_MEASURE_RE = re.compile(
    fr"(balance_before|prev_balance|before_bal|initial_bal)\s*=\s*{IDENT}balance\w*\s*\(|"
    fr"(received|actual_received|delta)\s*=\s*{IDENT}balance\w*\s*\([^;]*\)\s*-\s*{IDENT}(balance_before|prev_balance)|"
    fr"balance_of\s*\([^)]+\)\s*-\s*(balance_before|prev_balance|before)"
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
        if not _TRANSFER_IN_RE.search(body_nc):
            continue
        if not _MINT_INPUT_RE.search(body_nc):
            continue
        if _DELTA_MEASURE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` mints shares from input `amount` "
                f"without measuring balance delta post-transferFrom "
                f"— fee-on-transfer tokens deliver less, over-credits "
                f"user (mint-based-on-pre-transfer-input-amount-fot). "
                f"See Solodit #37356 (IPC GatewayManagerFacet)."
            ),
        })
    return hits
