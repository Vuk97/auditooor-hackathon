"""
flashloan_callback_state_mutation_before_repay.py

A flash-loan entrypoint executes a borrower-controlled callback
(`execute_operation` / callback closure). If callback runs AND state
mutation (e.g. `set_user_configuration`, `update_index`) runs AND the
repayment verification runs AFTERWARDS, an attacker can write state
inside the callback that the post-check cannot detect.

Heuristic:
  1. Function name contains `flash_loan` / `flashloan` / `flash_`.
  2. Body calls one of:  `execute_operation` / `receiver.callback` /
     `.call_flashloan_receiver` / `.invoke_contract(` (with a user-supplied
     target address).
  3. Body ALSO contains a state-mutation call
     (`.set(`, `set_user_configuration`, `update_index`) between the
     callback and a `verify_repayment` / `ensure_repaid` / `check_balance`
     OR no repayment verification at all.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_FN_RE = re.compile(r"(flash_loan|flashloan|^flash_|^flash$)", re.IGNORECASE)

_CALLBACK_PATTERNS = (
    r"execute_operation\s*\(",
    r"receiver\.callback\s*\(",
    r"call_flashloan_receiver\s*\(",
    r"\.invoke_contract\s*\(",
    r"receiver_client\.\w+\s*\(",
)

_STATE_MUTATION_PATTERNS = (
    r"\.set\s*\(",
    r"set_user_configuration",
    r"update_index\s*\(",
    r"update_state\s*\(",
)

_VERIFY_TOKENS = (
    "verify_repayment", "ensure_repaid", "check_balance_after",
    "assert_repaid", "require_repaid", "balance_after",
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        # Find a callback call
        callback_pos = None
        for pat in _CALLBACK_PATTERNS:
            m = re.search(pat, body_text)
            if m:
                callback_pos = m.start()
                break
        if callback_pos is None:
            continue

        # Find a state mutation AFTER callback
        mut_after_cb = False
        for pat in _STATE_MUTATION_PATTERNS:
            for m in re.finditer(pat, body_text):
                if m.start() > callback_pos:
                    mut_after_cb = True
                    break
            if mut_after_cb:
                break
        if not mut_after_cb:
            continue

        # Is there a verification AFTER the callback?
        has_verify = False
        for tok in _VERIFY_TOKENS:
            idx = body_text.find(tok)
            if idx > callback_pos:
                has_verify = True
                break
        # if verify runs AFTER the mutation we still flag — callback can
        # corrupt state that verify cannot detect.  Being strict: only drop
        # the hit if there's NO mutation at all after cb.
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source, 200),
            "message": (
                f"fn `{name}` invokes a flash-loan callback and then mutates "
                f"protocol state before / concurrent with repayment "
                f"verification — callback can corrupt state the post-check "
                f"doesn't cover."
            ),
        })
    return hits
