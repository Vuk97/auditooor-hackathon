"""
r94_loop_queue_intake_permissionless_no_fee.py

Flags permissionless intake paths that append to a queue/vec/map whose
size is load-bearing on future processing, without charging a fee, a
rate-limit, or a per-caller cap.

Source: Solodit #55248 (Sherlock / SEDA Protocol).
Rust side of `queue-spam-dos` canonical class.

Heuristic:
  1. Function is pub / external.
  2. Body contains an append-style call on a queue-like target:
     `.push(`, `.push_back(`, `.insert(`, `.append(`, `.enqueue(`,
     `.add_to_queue(`, map/vec `.set(` with an auto-incrementing key.
  3. Body does NOT contain any of:
     - a fee-payment call (`.pay_fee(`, `token.transfer(..., fee`,
       `env.transfer(..., fee`)
     - a rate-limit check (`rate_limit`, `last_call_ts`, `cooldown`,
       `requests_per_block`)
     - a per-caller cap check (`pending_count`, `user_quota`,
       `requests_by.get(`)
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_APPEND_RE = re.compile(
    r"\.(push|push_back|insert|append|enqueue|add_to_queue)\s*\(",
    re.MULTILINE,
)

_FEE_GUARD_RE = re.compile(
    r"pay_fee\s*\(|"
    r"\.transfer\s*\(\s*[^,)]*,\s*[^,)]*fee|"
    r"charge_fee|require_fee|require_payment|"
    r"require!\s*\([^)]*(fee|payment)",
    re.MULTILINE | re.IGNORECASE,
)

_RATE_LIMIT_RE = re.compile(
    r"rate_limit|last_call_ts|cooldown|requests_per_block|throttle|"
    r"pending_count|user_quota|requests_by\.get|per_user_cap",
    re.MULTILINE,
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)

        if not _APPEND_RE.search(body_nc):
            continue
        if _FEE_GUARD_RE.search(body_nc):
            continue
        if _RATE_LIMIT_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` appends to a queue/list with no fee, "
                f"no rate-limit, no per-caller cap. Permissionless intake "
                f"is a DoS vector — attacker can bloat storage and jam "
                f"the processing pipeline. See Solodit #55248 (SEDA)."
            ),
        })
    return hits
