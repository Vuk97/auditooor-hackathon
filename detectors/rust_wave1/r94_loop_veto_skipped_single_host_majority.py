"""
r94_loop_veto_skipped_single_host_majority.py

Flags `execute` / `skip_veto` fns that skip the veto delay based on
an all-hosts-support flag computed FROM PARTIAL host-vote count —
single host votes yes and flips the flag.

Source: Solodit #29546 (C4 Party Protocol).
Class: veto-skipped-single-host-majority (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(execute|skip_veto|process_proposal|force_execute|finalize_proposal)")
_SKIP_FLAG_RE = re.compile(
    r"(all_hosts_accept|unanimous_host|all_hosts_approve|skip_veto_delay|"
    r"skipVetoDelay|hosts_majority|hosts_support)"
)
_FULL_COUNT_CHECK_RE = re.compile(
    r"host_yes_count\s*==\s*total_host_count|"
    r"accept_count\s*==\s*num_hosts|"
    r"unanimous_check\s*\(|"
    r"require\s*\(\s*host_yes_count\s*==\s*total_host_count"
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
        if not _SKIP_FLAG_RE.search(body_nc):
            continue
        if _FULL_COUNT_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` skips veto delay on an all-hosts-"
                f"accept flag without requiring `yes_count == "
                f"total_host_count` — single host can flip the flag "
                f"(veto-skipped-single-host-majority). See Solodit "
                f"#29546 (Party Protocol)."
            ),
        })
    return hits
