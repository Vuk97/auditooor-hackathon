"""
rewards_claim_double_settle.py

Looks for a contract that exposes BOTH a narrow `claim_*` (single reserve)
and a broad `claim_all` / `claim_all_rewards`, where the broad version does
NOT mark per-reserve accrual state updated — so a caller can claim through
the narrow path AND then through the broad path and be paid twice for the
same accrual.

Heuristic (same impl block, or same file):
  1. We find set A = pub fns whose name starts with `claim_rewards` /
     `claim_reward` (for a single reserve/market).
  2. We find set B = pub fns named `claim_all*` / `claim_all_rewards*`.
  3. For each fn in B, its body must call a function from A OR update an
     accrual storage key (`accrued_rewards`, `user_accrual`, `last_index`)
     to ZERO for each reserve iterated.
  4. If B's body contains a loop but never calls an A-like helper and
     never sets `*index*`/`*accrual*` to 0 — flag B.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name, is_pub, text_of,
    walk_no_nested_fn, line_col, snippet_of,
)


_SINGLE_PREFIX = ("claim_reward", "claim_rewards")
_BROAD_PREFIX = ("claim_all", "claim_all_rewards")

_ACCRUAL_KEYS = (
    "accrued_rewards", "user_accrual", "last_index",
    "user_reward_index", "claimed_amount", "reward_index",
)


def _has_loop(body):
    for n in walk_no_nested_fn(body):
        if n.type in ("for_expression", "while_expression", "loop_expression"):
            return True
    return False


def _calls_helper(body, source, helper_names):
    for n in walk_no_nested_fn(body):
        if n.type != "call_expression":
            continue
        t = text_of(n, source)
        for h in helper_names:
            if re.search(r"\b" + h + r"\s*\(", t):
                return True
    return False


def run(tree, source: bytes, filepath: str):
    hits = []
    # Collect candidate fns per impl so we treat them as a group
    by_impl = {}
    for fn, impl in functions_in_contractimpl(tree.root_node, source):
        by_impl.setdefault(id(impl), []).append(fn)

    for _k, fns in by_impl.items():
        singles = [f for f in fns
                   if is_pub(f, source)
                   and any(fn_name(f, source).startswith(p)
                           for p in _SINGLE_PREFIX)]
        broads = [f for f in fns
                  if is_pub(f, source)
                  and any(fn_name(f, source).startswith(p)
                          for p in _BROAD_PREFIX)]
        if not singles or not broads:
            continue
        single_names = [fn_name(f, source) for f in singles]
        for b in broads:
            body = fn_body(b)
            if body is None:
                continue
            body_text = text_of(body, source)

            # Does broad delegate to the per-reserve path?
            if _calls_helper(body, source, single_names):
                continue
            # Does it zero-out / reset any accrual key?
            resets_accrual = any(
                re.search(r"(" + k + r")[^\n]*=\s*0\b", body_text) or
                re.search(r"\.set\([^\n]*" + k + r"[^\n]*,\s*&0", body_text)
                for k in _ACCRUAL_KEYS
            )
            if resets_accrual:
                continue
            # Does it call any Self::helper that has "update"/"settle" name
            # pattern? treat as ok.
            if re.search(r"Self::(update|settle|accrue)_", body_text):
                continue
            # Must have a loop to qualify (iterating reserves)
            if not _has_loop(body):
                continue

            line, col = line_col(b)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(b, source, 160),
                "message": (
                    f"pub fn `{fn_name(b, source)}` looks like a broad "
                    f"claim-all but does not delegate to the per-reserve "
                    f"claim helper nor reset an accrual/index key — same "
                    f"reward can be paid again via `{single_names[0]}`."
                ),
            })
    return hits
