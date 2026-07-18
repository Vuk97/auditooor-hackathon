"""
r94_loop_collateral_sweep_without_pre_post_delta_check.py

Flags adapter / collateral / wrapper / offramp fns that redeem /
convert / unwrap a fixed-amount position and then sweep the FULL
contract balance (`token.balance_of(this)`, `balance_of(program_id)`,
`token.balance(&env.current_contract_address())`) to the caller WITHOUT
measuring a pre/post delta. Any USDC/SPL collateral previously stranded
on the program is harvested by the next caller — a stranded-asset skim.

This is the Rust sibling of Solidity pattern
`collateral-sweep-without-pre-post-delta-check` (Polymarket Cantina
#173/#174 — CtfCollateralAdapter.redeemPositions /
NegRiskCtfCollateralAdapter.convertPositions). On Solana / Soroban the
same primitive appears in offramp adapters and wrappers that CPI-call
a redeem / burn / unwrap then `token::transfer(ctx, balance_of(self))`.

Source: Polymarket Cantina #173, #174 (phase 37d).
Class: collateral-sweep-without-pre-post-delta-check (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, line_col,
    snippet_of, is_pub, body_text_nocomment,
)

# Name heuristic: redeem/convert/offramp/unwrap/sweep/claimAll/withdrawAll
_FN_NAME_RE = re.compile(
    r"(?i)(redeem_positions|redeem_position|convert_positions|"
    r"split_position|merge_positions|offramp|unwrap_all|claim_all|"
    r"withdraw_all|sweep_to_caller|redeem_all|burn_and_sweep)"
)

# Full-balance sweep: transfer the contract's entire balance to caller.
# Matches several Rust idioms:
#   token.transfer(caller, token.balance_of(this))
#   token.transfer(&env, &caller, &balance_of(&contract))
#   transfer(ctx, token::balance_of(program_id))
#   self.token.transfer(msg.sender, self.token.balance_of(address_this))
_FULL_SWEEP_RE = re.compile(
    r"(?i)(transfer|safe_transfer)\s*\([^;]{0,200}?"
    r"balance_of\s*\([^;]{0,120}?"
    r"(this|self|address_this|program_id|current_contract_address"
    r"|current_contract|ctx\.\s*accounts|env\.current_contract)"
)

# Safe form: pre-call snapshot (balance_before / bal_before /
# snapshot_before / prev_balance) or explicit delta/received var.
_DELTA_MEASURED_RE = re.compile(
    r"(?i)(balance_before|bal_before|pre_balance|snapshot_before|"
    r"prev_balance|initial_bal)\s*=|"
    r"\bdelta\s*=|\breceived\s*=|actual_received\s*=|"
    r"balance_of\s*\([^)]+\)\s*-\s*(balance_before|bal_before|"
    r"pre_balance|snapshot_before|prev_balance)"
)

# Contract-name precondition: adapter / collateral / wrapper / offramp /
# bridge / vault — match on the impl item's target type text (fallback
# heuristic is filepath / source body).
_CONTRACT_CONTEXT_RE = re.compile(
    r"(?i)(Adapter|Collateral|Offramp|Wrapper|Converter|Bridge|Vault)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    src_head = source[:4096].decode("utf-8", errors="replace")
    # Coarse precondition: file must mention an adapter/collateral-like
    # struct or the filepath itself must hint at one.
    if not (_CONTRACT_CONTEXT_RE.search(src_head)
            or _CONTRACT_CONTEXT_RE.search(filepath)):
        return hits
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
        if not _FULL_SWEEP_RE.search(body_nc):
            continue
        if _DELTA_MEASURED_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` on an Adapter/Collateral/Wrapper/"
                f"Offramp-style struct redeems/converts a fixed-amount "
                f"position and then sweeps the FULL contract balance "
                f"(`token.transfer(..., balance_of(this))`) to the caller "
                f"without a pre/post-call delta — any stranded SPL/SPL-"
                f"like collateral is harvested by the next caller "
                f"(collateral-sweep-without-pre-post-delta-check). "
                f"See Polymarket Cantina #173 / #174."
            ),
        })
    return hits
