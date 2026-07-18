"""
r94_loop_chainlink_getTokenPrice_lookback_param_ignored.py

Flags `get_token_price` / `price_with_lookback` fns that accept a
`lookback` seconds parameter but the body never uses it — just calls
`latestRoundData` / `latest_round_data`. Caller believes they got
TWAP, they get spot.

Source: Solodit #36221 (Codehawks Beanstalk LibChainlinkOracle).
Class: chainlink-getTokenPrice-lookback-param-ignored (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(get_token_price|price_with_lookback|twap_price|get_twap)")
_LOOKBACK_ARG_RE = re.compile(
    r"fn\s+\w+\s*\([^)]*\b(lookback|twap_window|window_seconds|lookback_secs)\s*:"
)
_BODY_USES_LOOKBACK_RE = re.compile(
    r"\b(lookback|twap_window|window_seconds|lookback_secs)\b"
)
_LATEST_ROUND_ONLY_RE = re.compile(
    r"latest_round_data|latestRoundData|\.latest_answer\s*\(|latestAnswer"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        sig_text = snippet_of(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _LOOKBACK_ARG_RE.search(sig_text):
            continue
        if not _LATEST_ROUND_ONLY_RE.search(body_nc):
            continue
        # Body references the lookback var at most 0-1 times (not used for iteration)
        if len(_BODY_USES_LOOKBACK_RE.findall(body_nc)) >= 2:
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": sig_text[:200],
            "message": (
                f"pub fn `{name}` accepts a `lookback` parameter but "
                f"the body just calls latestRoundData — lookback is "
                f"silently ignored, caller gets spot not TWAP "
                f"(chainlink-getTokenPrice-lookback-param-ignored). "
                f"See Solodit #36221 (Beanstalk)."
            ),
        })
    return hits
