"""
r94_loop_royalty_distribution_rounding_dust_siphon.py

Flags royalty / revenue-share payout fns that iterate a list of
recipients and compute each recipient's share via integer
division (`amount * bps / TOTAL`) without sending the truncation
residual anywhere — dust accumulates in the contract and the
last / privileged caller can sweep it.

Source: Solodit #48857 (OtterSec Monument royalty distribution).
Class: royalty-distribution-rounding-dust-siphon (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(distribute_royalties|pay_royalties|payout_royalties|"
    r"distribute_revenue|split_revenue|distribute_fees|"
    r"payout_shares|distribute_shares)"
)
# Per-recipient integer division.
_DIV_RE = re.compile(
    fr"(?i)(amount\s*\*\s*{IDENT}(bps|permyriad|share|weight)\s*\/|"
    fr"amount\s*\*\s*{IDENT}numerator\s*\/\s*{IDENT}denominator|"
    fr"amount\s*\*\s*recipients\s*\[\s*\w+\s*\]\s*\.\s*{IDENT}share\s*\/|"
    fr"amount\s*\.\s*mul\s*\(\s*{IDENT}share\s*\)\s*\.\s*div\s*\(|"
    fr"total\s*\*\s*{IDENT}share\s*\/\s*{IDENT}(TOTAL|ten_thousand|10000))"
)
# Safe: dust handled (sent to treasury, last recipient, or subtracted from last share).
_DUST_HANDLED_RE = re.compile(
    fr"(?i)(dust\s*=|residual\s*=|leftover\s*=\s*amount\s*-|"
    fr"remaining\s*=\s*amount\s*-|"
    fr"last_share\s*=\s*amount\s*-|"
    fr"send_dust_to_treasury|send_residual|"
    fr"recipients\[\s*last\s*\]\.share\s*=\s*amount\s*-|"
    fr"accumulated_dust\s*\+=|"
    fr"if\s+{IDENT}i\s*==\s*{IDENT}len\s*-\s*1|"
    fr"if\s+{IDENT}i\s*==\s*{IDENT}last_idx|"
    fr"if\s+{IDENT}i\s*==\s*{IDENT}last_index|"
    fr"last_recipient\s*=\s*amount\s*-|"
    fr"if\s+i\s*==\s*recipients\.len\s*\(\s*\)\s*-\s*1)"
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
        if not _DIV_RE.search(body_nc):
            continue
        if _DUST_HANDLED_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` distributes royalties via per-"
                f"recipient integer division without routing the "
                f"truncation residual — accumulated dust sits in the "
                f"contract, eventually siphonable "
                f"(royalty-distribution-rounding-dust-siphon). "
                f"See Solodit #48857 (OtterSec Monument)."
            ),
        })
    return hits
