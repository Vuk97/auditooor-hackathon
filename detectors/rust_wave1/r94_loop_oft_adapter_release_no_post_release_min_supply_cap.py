"""
r94_loop_oft_adapter_release_no_post_release_min_supply_cap.py

Flags OFT/LayerZero adapter receive fns that release tokens from the
adapter's inventory (safe_transfer / token.transfer) without enforcing
a per-message cap, rate-limit, or post-release min-supply floor —
a single crafted cross-chain message can drain the entire adapter.

Source: Kelp rsETH $220M exploit (2026-04-18).
Class: oft-adapter-release-no-post-release-min-supply-cap (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(lz_receive|lzReceive|_lz_receive|_lzReceive|"
    r"oft_receive|receive_oft|credit_to|_credit_to|"
    r"release_from_inventory|release_tokens_to)"
)
_RELEASE_RE = re.compile(
    r"(safe_transfer\s*\(|safeTransfer\s*\(|"
    r"token\.transfer\s*\(|underlying\.transfer\s*\()"
)
_CAP_RE = re.compile(
    fr"(require\s*\(\s*{IDENT}amount\s*<=\s*{IDENT}(maxPerMessage|max_per_message|MAX_RELEASE|dailyLimit|MAX_PER_TX)|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}amount\s*<=\s*{IDENT}MAX|"
    fr"balance_after\s*>=\s*{IDENT}(MIN_RESERVE|min_reserve|MIN_SUPPLY)|"
    fr"require\s*\(\s*{IDENT}(balance|adapter_balance)\s*>=\s*{IDENT}(min_reserve|MIN_RESERVE|reserve_floor)|"
    r"_check_rate_limit|check_rate_limit|rate_limiter\.|"
    r"invariant_min_supply|post_release_invariant)"
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
        if not _RELEASE_RE.search(body_nc):
            continue
        if _CAP_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} releases tokens from adapter inventory "
                f"with no per-message cap, rate-limit, or post-release "
                f"min-supply floor — Kelp rsETH allowed 116,500 rsETH "
                f"drain in one message "
                f"(oft-adapter-release-no-post-release-min-supply-cap). "
                f"Kelp rsETH $220M exploit 2026-04-18."
            ),
        })
    return hits
