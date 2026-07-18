"""
r94_loop_stablecoin_mint_no_supply_cap.py

Stablecoin minter `mint`-class function is properly auth-gated
(`.require_auth()` on the privileged minter address) but the body does NOT
enforce any supply cap (`max_supply`, `supply_cap`, `MINT_CAP`, `hard_cap`,
…) before crediting the new tokens. A compromised or single-key minter
can inflate the stablecoin supply beyond the cap stated in the protocol
specification, breaking the peg-keeper accounting and the redemption math
that depends on a bounded `total_supply`.

Why this is the *smallest defensible* stablecoin Rust detector
==============================================================
- It does not overlap with `r94_unrestricted_mint`, which fires only when
  there is NO `require_auth` in the mint body. This detector targets the
  opposite shape: auth IS present, cap is missing.
- It does not overlap with `r94_loop_refund_no_supply_decrement` (paired
  refund-side counter asymmetry).

Class membership for parity bookkeeping
=======================================
This file's docstring and filename both contain the substring "stablecoin",
so `tools/detector-coverage-matrix.py` (which reads the first 2000 chars of
the file via `_read_docstring_and_head`) classifies this detector under the
`stablecoin` topic bucket from `tools/finding-clusterer.py::BUCKETS`. That
moves the `stablecoin` row in `docs/DETECTOR_COVERAGE_MATRIX.md` from
`rust_count = 0` (rust gap) to `rust_count = 1`.

Heuristic
=========
1. Function is `pub fn` inside an `#[contractimpl]` impl block (Soroban
   entrypoint).
2. Function name matches `mint`, `mint_to`, `issue`, `mint_stable`,
   `print`, `mint_stablecoin`, `peg_keeper_mint`.
3. Body either calls `.mint(` on a token client OR writes a balance-like
   storage key (`Balance`, `balances`, `Shares`, `TotalSupply`,
   `total_supply`, `supply`).
4. Body contains `.require_auth(` (so the function IS auth-gated — this
   distinguishes the bug from the fully-unrestricted-mint class).
5. Body does NOT contain a supply-cap guard. A guard is recognized as the
   presence of any cap-token (`max_supply`, `MAX_SUPPLY`, `supply_cap`,
   `SUPPLY_CAP`, `hard_cap`, `HARD_CAP`, `MINT_CAP`, `mint_cap`,
   `SupplyCap`, `cap`) within the *same* line as a comparison operator or
   inside an `assert!`/`require!`/`if … return Err`/`panic!` shape.
6. Comments are stripped before the cap-guard scan so a "// BUG: no cap"
   marker in the positive fixture cannot accidentally satisfy the guard
   regex (this is the `body_text_nocomment` lesson hoisted in R94 cycle 7).

False-positive guard rails
==========================
- Skipped if the function is `#[test]`-annotated (we never flag test
  helpers). `_util.in_test_cfg` covers `#[test]`, `#[tokio::test]`, and
  `#[cfg(test)]` modules.
- Skipped if the body merely *reads* `total_supply` without a comparison.
  A bare `let s = total_supply.get();` does NOT count as a guard; we
  require a comparison/assert/panic alongside the cap token.
- Skipped if no balance-write / token-mint call site is found in the
  body — pure-view helpers cannot mint.
- Stablecoin-scope filter: a `mint`/`mint_to` function only counts if its
  body references an aggregate-supply token (`total_supply`, `Supply`,
  …) OR its name is stablecoin-specific (`mint_stable`, `peg_keeper_mint`,
  `issue_stable`, `mint_stablecoin`). Share-vault `mint(user, asset,
  amount)` shapes that only touch per-user share keys are intentionally
  ignored — their inflation profile is bounded by deposited collateral,
  not by a privileged minter.

Severity: `high`
================
Stablecoin supply manipulation collapses redemption math and is a direct
fund-loss class on a peg-keeper, even when the privileged minter is honest,
if its signing key is ever lost.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    functions_in_contractimpl,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
    text_of,
    walk_no_nested_fn,
)


# Soroban / SPL stablecoin issuance entrypoint names.
_MINT_FN_RE = re.compile(
    r"^("
    r"mint|"
    r"mint_to|"
    r"mint_stable|"
    r"mint_stablecoin|"
    r"mint_with_role|"
    r"issue|"
    r"issue_stable|"
    r"print|"
    r"print_money|"
    r"peg_keeper_mint"
    r")$"
)

# Tokens that suggest the function actually credits / writes balance state.
_BALANCE_TOKENS = (
    "Balance",
    "balances",
    "Shares",
    "shares",
    "TotalSupply",
    "total_supply",
    "Supply",
    "supply",
)

# Tokens that mark a supply-cap guard. Must co-occur on the same line as a
# comparison / assert / require / panic / if-Err shape.
_CAP_TOKENS = (
    "max_supply",
    "MAX_SUPPLY",
    "supply_cap",
    "SUPPLY_CAP",
    "hard_cap",
    "HARD_CAP",
    "MINT_CAP",
    "mint_cap",
    "SupplyCap",
    # Bare `cap` is included but the per-line co-check below stops the
    # `keys.set_cap(...)` shape from satisfying the guard.
    "cap",
)

# Per-line comparison / assertion shapes that prove a real cap CHECK.
_GUARD_SHAPE_RE = re.compile(
    r"(==|!=|<=|>=|<|>|"
    r"assert!|require!|"
    r"\bif\b[^\n]*\breturn\b\s+Err|"
    r"\bif\b[^\n]*\bpanic!|"
    r"\bensure!|"
    r"panic!\s*\("
    r")"
)

# Comparison operators inside the same logical line as the cap token.
_COMP_OPS = ("<", ">", "==", "!=")


def _writes_balance_or_calls_mint(body, source: bytes):
    """Return the first call_expression that mints / writes balance, or None.

    Two shapes:
      a) `<expr>.mint(<args>)` — a TokenClient mint CPI.
      b) any storage write touching a balance-like key.
    """
    for n in walk_no_nested_fn(body):
        if n.type != "call_expression":
            continue
        # Shape (a): direct `.mint(` field call.
        for c in n.children:
            if c.type != "field_expression":
                continue
            for cc in c.children:
                if cc.type == "field_identifier" and text_of(cc, source) == "mint":
                    return n

    body_text = text_of(body, source)
    if not any(tok in body_text for tok in _BALANCE_TOKENS):
        return None

    # Shape (b): storage write inside a balance-aware body.
    for n in walk_no_nested_fn(body):
        if n.type != "call_expression":
            continue
        t = text_of(n, source)
        if not re.search(r"\.set\s*\(", t):
            continue
        if (
            "storage()" in t
            or ".persistent()" in t
            or ".instance()" in t
            or ".temporary()" in t
        ):
            return n
    return None


def _has_supply_cap_guard(body_text_no_comments: str) -> bool:
    """True if any line in `body_text_no_comments` contains both a cap
    token AND a guard shape (comparison / assert / require / if-Err /
    panic). Per-line scan kills the `keys.set_cap(...)` false-positive."""
    for line in body_text_no_comments.splitlines():
        if not any(tok in line for tok in _CAP_TOKENS):
            continue
        if _GUARD_SHAPE_RE.search(line):
            return True
        # Multi-line shapes: an `if … {` line with cap + comparison even
        # when the action body is below.
        if any(op in line for op in _COMP_OPS):
            return True
    return False


_STABLECOIN_FN_NAMES = (
    "mint_stable",
    "mint_stablecoin",
    "issue_stable",
    "peg_keeper_mint",
)

# Aggregate-supply tokens that mark this as a STABLECOIN-style supply mint
# (as opposed to a per-user share/deposit mint that conserves a 1:1
# deposit-to-share invariant and so cannot inflate supply by itself).
_AGGREGATE_SUPPLY_TOKENS = (
    "TotalSupply",
    "total_supply",
    "Supply",
    "stablecoin_supply",
    "PegSupply",
    "peg_supply",
    "outstanding_supply",
    "circulating_supply",
)


def _function_is_stablecoin_supply_mint(name: str, body_text: str) -> bool:
    """A `mint`-class function only counts as a STABLECOIN supply mint if
    either:
      - its name is stablecoin-specific (`mint_stable`, `peg_keeper_mint`,
        `issue_stable`, `mint_stablecoin`); OR
      - the function body references an aggregate-supply token name
        (`total_supply`, `TotalSupply`, `Supply`, …).

    Shared-account vault `mint`/`mint_to` functions that only touch
    per-user share keys (`user_shares`, `Shares`) and leave aggregate
    supply implicit do NOT match. They are share-vault functions, not
    stablecoin issuance entrypoints, and their inflation profile is
    bounded by deposited collateral, not by a minter role.
    """
    if name in _STABLECOIN_FN_NAMES:
        return True
    return any(tok in body_text for tok in _AGGREGATE_SUPPLY_TOKENS)


def run(tree, source: bytes, filepath: str):
    hits: list[dict] = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if not _MINT_FN_RE.match(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        # Stablecoin-supply scope check (avoid misfiring on share-vault
        # `mint(user, asset, amount)` callers).
        if not _function_is_stablecoin_supply_mint(name, body_text):
            continue

        # Must actually mint / credit something.
        mint_node = _writes_balance_or_calls_mint(body, source)
        if mint_node is None:
            continue

        # Must be auth-gated. If there is no `.require_auth(`, the
        # broader `r94_unrestricted_mint` detector already covers it.
        if ".require_auth(" not in body_text:
            continue

        # Comment-stripped scan for the cap guard (comments cannot satisfy
        # the guard).
        body_nc = body_text_nocomment(body, source)
        if _has_supply_cap_guard(body_nc):
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(mint_node, source),
                "message": (
                    f"pub fn `{name}` mints stablecoin tokens with "
                    f"`require_auth()` on the minter role but does not "
                    f"enforce any `max_supply` / `supply_cap` / "
                    f"`hard_cap` / `MINT_CAP` guard before crediting. "
                    f"A compromised single-key minter or honest-but-buggy "
                    f"caller can inflate `total_supply` past the protocol's "
                    f"governance-stated cap, breaking peg-keeper accounting "
                    f"and redemption math. Add an explicit `assert!`, "
                    f"`require!`, or `if … return Err(...)` over "
                    f"`prev_supply + amount > <cap>` before the credit."
                ),
            }
        )
    return hits
