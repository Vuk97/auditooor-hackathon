"""
r94_loop_stake_activation_epoch_mismatch.py

Flags staking merge/join fns that check same-node/state/withdraw_epoch
but NOT activation_epoch. Reward math uses activation_epoch so
omitting its equality check lets attackers merge stakes with different
activation epochs and over-accrue rewards.

Source: Solodit #53197 (OtterSec Walrus Contracts).
Class: stake-epoch-mismatch-reward-drift (both).
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_FN_NAME_RE = re.compile(r"(?i)(join|merge|combine|add_to_stake|unify)")

_NODE_EQ_RE = re.compile(
    r"node_id\s*==|self\.node_id\s*==\s*other\.node_id|"
    r"require!?\s*\([^)]*node_id\s*=="
)

_ACTIVATION_EQ_RE = re.compile(
    r"activation_epoch\s*==|self\.activation_epoch\s*==|"
    r"require!?\s*\([^)]*activation_epoch\s*=="
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)

        # Must check node_id (otherwise fn is not a stake-merge)
        if not _NODE_EQ_RE.search(body_nc):
            continue
        # If activation_epoch is also checked — OK
        if _ACTIVATION_EQ_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` (stake merge/join) checks `node_id` "
                f"equality but does NOT enforce `activation_epoch` "
                f"equality. Reward math keyed on activation_epoch drifts. "
                f"See Solodit #53197 (Walrus)."
            ),
        })
    return hits
