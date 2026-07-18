"""
r94_loop_hook_bypasses_reentrancy_guard_cross_pool.py

Flags hub/router fns that (a) use a simple nonReentrant / reentrancy
guard, (b) invoke a caller-supplied hook (e.g., Uniswap V4 hook,
CoW hook), and (c) the hook has capability to call the underlying
pool_manager directly — bypassing the hub's guard.

Source: Solodit #56965 (Cyfrin Bunni BunniHub).
Class: hook-bypasses-reentrancy-guard-cross-pool (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(deposit|withdraw|swap|add_liquidity|remove_liquidity|process_hook)")
_REENTRANCY_GUARD_RE = re.compile(
    r"non_reentrant|nonReentrant|ReentrancyGuard|reentrancy_lock|reentrancy_guard"
)
_HOOK_INVOKE_RE = re.compile(
    r"(hook\.\w+|hook_data|before_swap|after_swap|before_add_liquidity|before_remove_liquidity|pool\.hook|hooks\.\w+)"
)
_DIRECT_POOL_MANAGER_RE = re.compile(
    r"(pool_manager|PoolManager|raw_pool_manager|v4_pool_manager)\s*\.\s*(swap|unlock|modify_liquidity)"
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
        if not _REENTRANCY_GUARD_RE.search(body_nc):
            continue
        if not _HOOK_INVOKE_RE.search(body_nc):
            continue
        if not _DIRECT_POOL_MANAGER_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` has a ReentrancyGuard, invokes "
                f"caller-supplied hook, AND calls pool_manager "
                f"directly — hook can re-enter pool_manager path "
                f"bypassing the guard on this hub (hook-bypasses-"
                f"reentrancy-guard-cross-pool). See Solodit #56965 "
                f"(Bunni)."
            ),
        })
    return hits
