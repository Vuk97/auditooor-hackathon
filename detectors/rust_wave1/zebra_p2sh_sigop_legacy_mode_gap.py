"""
zebra_p2sh_sigop_legacy_mode_gap.py

Flags Zebra P2SH sigop counters that route a P2SH redeem script through a
legacy sigop counting path. This is the public GHSA-2prc-cj5x-4443 class:
the incomplete GHSA-gf9r fix in Zebra 4.5.0 used the legacy counting mode for
P2SH redeem scripts, causing Zebra to reject some zcashd-valid blocks.

This detector is intentionally Zebra-shaped. It is an originality baseline and
recall aid: a hit on Zebra 4.5.0 is a known public advisory, not a new filing
unless there is extension-distinct source evidence.
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
    text_of,
)


DETECTOR_ID = "rust_wave1.zebra_p2sh_sigop_legacy_mode_gap"

_FN_NAME_RE = re.compile(
    r"(?i)(p2sh|sigop|sigops|script|redeem|transaction|block|verify|check)"
)

_P2SH_CONTEXT_RE = re.compile(
    r"(?i)(p2sh|pay_to_script_hash|is_pay_to_script_hash|scriptSig|"
    r"redeem(?:ed)?_script|redeemed_bytes|GetP2SHSigOpCount)"
)

_SIGOP_CONTEXT_RE = re.compile(
    r"(?i)(sigop|sigops|MAX_BLOCK_SIGOPS|block verifier|consensus|zcashd|"
    r"transparent::Input|transparent::Output)"
)

_LEGACY_MODE_RE = re.compile(
    r"(?i)(legacy_sigop_count_script\s*\(|GetSigOpCount\s*\(\s*false\s*\)|"
    r"sig_op_count\s*\(\s*false\s*\)|fAccurate\s*[:=]\s*false|"
    r"accurate\s*[:=]\s*false)"
)

_EXPLICIT_ACCURATE_RE = re.compile(
    r"(?i)(GetSigOpCount\s*\(\s*true\s*\)|sig_op_count\s*\(\s*true\s*\)|"
    r"accurate\s*[:=]\s*true|accurate_p2sh_sigop_count\s*\()"
)


def _is_repo_test_file(filepath: str) -> bool:
    normalized = filepath.replace("\\", "/")
    if "/test_fixtures/" in normalized:
        return False
    return normalized.endswith("/tests.rs") or "/tests/" in normalized


def _compact(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def run(tree, source: bytes, filepath: str):
    hits = []
    if _is_repo_test_file(filepath):
        return hits

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue

        fn_text = text_of(fn, source)
        body_nc = body_text_nocomment(body, source)
        haystack = f"{filepath}\n{name}\n{fn_text}"

        legacy_match = _LEGACY_MODE_RE.search(body_nc)
        if not legacy_match:
            continue
        if not _P2SH_CONTEXT_RE.search(haystack):
            continue
        if not _SIGOP_CONTEXT_RE.search(haystack):
            continue

        # If a local wrapper only mentions legacy terms but immediately dispatches
        # to an explicit accurate P2SH counter, treat it as a safe adapter.
        if (
            "legacy_sigop_count_script" not in body_nc
            and _EXPLICIT_ACCURATE_RE.search(body_nc)
        ):
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "critical",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"fn `{name}` appears to count P2SH redeem-script sigops "
                    f"through legacy mode evidence `{_compact(legacy_match.group(0))}`. "
                    "GHSA-2prc-cj5x-4443 says Zebra 4.5.0 undercounted this "
                    "path after the incomplete GHSA-gf9r fix; treat Zebra v4.5.0 "
                    "hits as known public advisory baseline unless an "
                    "extension-distinct variant is proven."
                ),
            }
        )

    return hits
