#!/usr/bin/env python3
"""
economic-hypotheses-ir.py — R63 IR-based economic attack-surface reporter.

Replaces the grep-based `tools/economic-hypotheses.sh` with a Slither IR
dataflow analysis. The core win over the grep version is *cross-function*
tracing: a deadline check performed inside an internal helper is recognised
as *enforced*, instead of being flagged as missing (the R62 PermissionedRamp
false-positive case).

Scope (see CATEGORIES below): oracle reads, flashloan callbacks, rate math,
rounding direction, LP share math, liquidation self-exit, slippage zero
check, deadline enforcement, fee-on-transfer awareness, cross-function state.

Usage:
    python3 tools/economic-hypotheses-ir.py <contract.sol | project-dir> \\
        [--out <path>] [--only cat1,cat2,...] [--verbose]

The tool REPORTS attack surface and, where possible, GUARD STATUS. It does
not declare findings — it narrows the operator's walk-through.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

try:
    from slither import Slither
    from slither.slithir.operations import (
        HighLevelCall,
        LibraryCall,
        InternalCall,
        SolidityCall,
        Binary,
        BinaryType,
        Assignment,
        TypeConversion,
    )
    from slither.slithir.variables import Constant
    from slither.core.declarations import Function, SolidityVariableComposed
except ImportError:
    print("Error: slither-analyzer not installed. Run: pip install slither-analyzer",
          file=sys.stderr)
    sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────────────

VENDORED = ("/lib/", "forge-std", "solady/src", "solmate/src",
            "openzeppelin", "/node_modules/", "/out/", "/cache/", "/test/",
            "/tests/", "/mocks/", "/dev/")
SKIP_CONTRACT_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

ORACLE_SIGS = frozenset({
    "latestAnswer()",
    "latestRoundData()",
    "getPrice()",
    "getPrice(address)",
    "getAnswer(uint256)",
    "observe(uint32[])",
    "getPoolPrice()",
    "priceOf(address)",
    "resolvedPrice(bytes32)",
    "settleAndGetPrice(bytes32,uint256,bytes)",
})
ORACLE_IFACES_NAMECONTAINS = (
    "aggregator", "oracle", "pricefeed", "pricer", "ipriceprovider",
    "optimisticoracle", "chainlink",
)

FLASH_CB_NAMES = frozenset({
    "onFlashLoan",
    "flashLoanCallback",
    "executeOperation",
    "uniswapV2Call",
    "uniswapV3SwapCallback",
    "flashCallback",
    "pancakeCall",
    "doSwap",
    "receiveFlashLoan",
})

RATE_FN_RE = re.compile(
    r"(getBorrowRate|getSupplyRate|rewardPerToken|exchangeRate|accrue|"
    r"rewardIndex|borrowIndex|supplyIndex|accumulate|previewIndex)",
    re.IGNORECASE,
)

DEPOSIT_RE = re.compile(r"(deposit|mint|supply|invest|stake)", re.IGNORECASE)
WITHDRAW_RE = re.compile(r"(withdraw|redeem|unstake|burn|claim|offramp|unwrap)",
                         re.IGNORECASE)

LIQUIDATE_RE = re.compile(r"^(liquidate|close|forceclose|seize|closePosition|closeLoan)",
                          re.IGNORECASE)

SLIPPAGE_PARAM_RE = re.compile(r"(minOut|minAmountOut|minShares|slippage|"
                               r"minReceived|minimumOut|minReturn|minOutput)",
                               re.IGNORECASE)

DEADLINE_PARAM_RE = re.compile(r"(deadline|expiry|expiration)", re.IGNORECASE)

MAX_INTERNAL_TRACE_HOPS = 3


# ──────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    category: str
    tag: str
    file: str
    line: int
    function: str
    contract: str
    message: str
    guard_status: str  # "enforced", "missing", "unknown"


@dataclass
class Report:
    target: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def by_category(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.category, []).append(f)
        return out


# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────

def _is_vendored_path(path: str) -> bool:
    low = path.lower()
    return any(v in low for v in VENDORED)


def _is_skippable_contract(contract) -> bool:
    if any(k in contract.name.lower() for k in SKIP_CONTRACT_KEYWORDS):
        return True
    src = getattr(contract, "source_mapping", None)
    fn = getattr(src, "filename", None)
    path = ""
    if fn is not None:
        path = getattr(fn, "absolute", None) or getattr(fn, "relative", None) or ""
    if _is_vendored_path(path):
        return True
    return False


def _fn_source_location(function) -> tuple[str, int]:
    src = getattr(function, "source_mapping", None)
    if src is None:
        return ("?", 0)
    fn = getattr(src, "filename", None)
    path = "?"
    if fn is not None:
        path = getattr(fn, "relative", None) or getattr(fn, "absolute", None) or "?"
    line = getattr(src, "lines", [0])
    first = line[0] if isinstance(line, (list, tuple)) and line else 0
    return (path, first)


def _node_source_location(node) -> tuple[str, int]:
    src = getattr(node, "source_mapping", None)
    if src is None:
        return ("?", 0)
    fn = getattr(src, "filename", None)
    path = "?"
    if fn is not None:
        path = getattr(fn, "relative", None) or getattr(fn, "absolute", None) or "?"
    lines = getattr(src, "lines", [0])
    first = lines[0] if isinstance(lines, (list, tuple)) and lines else 0
    return (path, first)


def _callee_solidity_signature(ir) -> str | None:
    fn = getattr(ir, "function", None)
    if fn is None:
        return None
    return getattr(fn, "solidity_signature", None)


def _callee_contract_name(ir) -> str:
    dest = getattr(ir, "destination", None)
    if dest is None:
        dest = getattr(ir, "contract", None)
    if dest is None:
        return ""
    name = getattr(dest, "name", None)
    if name:
        return str(name)
    t = getattr(dest, "type", None)
    return str(t) if t else ""


def _iter_function_irs(function) -> Iterable[tuple[object, object]]:
    """Yield (node, ir) pairs for every IR in the function."""
    for node in function.nodes:
        for ir in node.irs:
            yield node, ir


def _contains_timestamp_deadline_check(function, deadline_names: set[str]) -> tuple[bool, str]:
    """Return (True, human_desc) if function IR contains a Binary comparing
    block.timestamp with one of the deadline-like parameters, flowing into
    a require/revert. We accept either direction of inequality.
    """
    for node, ir in _iter_function_irs(function):
        if not isinstance(ir, Binary):
            continue
        if ir.type not in (
            BinaryType.LESS_EQUAL,
            BinaryType.GREATER_EQUAL,
            BinaryType.LESS,
            BinaryType.GREATER,
            BinaryType.EQUAL,
            BinaryType.NOT_EQUAL,
        ):
            continue
        left, right = ir.variable_left, ir.variable_right
        # SolidityVariableComposed handles `block.timestamp`
        names = {
            getattr(left, "name", ""),
            getattr(right, "name", ""),
        }
        has_ts = any(
            str(v) in ("block.timestamp", "now")
            or (isinstance(v, SolidityVariableComposed)
                and getattr(v, "name", "") == "block.timestamp")
            for v in (left, right)
        )
        has_deadline = any(
            getattr(v, "name", "") in deadline_names
            for v in (left, right)
        )
        if has_ts and has_deadline:
            _, ln = _node_source_location(node)
            return True, f"`block.timestamp` vs `{deadline_names}` compared at L{ln}"
    return False, ""


def _callee_is_internal(ir) -> bool:
    return isinstance(ir, InternalCall)


def _trace_deadline_into_callees(function, deadline_names: set[str],
                                 visited: set[int] | None = None,
                                 depth: int = 0) -> tuple[bool, str]:
    """Recursively look for a block.timestamp vs deadline check in callees.
    Returns (found, human_chain)."""
    if visited is None:
        visited = set()
    if id(function) in visited or depth > MAX_INTERNAL_TRACE_HOPS:
        return False, ""
    visited.add(id(function))

    ok, desc = _contains_timestamp_deadline_check(function, deadline_names)
    if ok:
        return True, f"{function.contract_declarer.name}.{function.name} ({desc})"

    for node, ir in _iter_function_irs(function):
        if isinstance(ir, InternalCall):
            callee = getattr(ir, "function", None)
            if callee is None or not isinstance(callee, Function):
                continue
            ok2, chain = _trace_deadline_into_callees(
                callee, deadline_names, visited, depth + 1
            )
            if ok2:
                return True, f"{function.name} → {chain}"
    return False, ""


def _param_names(function) -> list[str]:
    return [p.name for p in function.parameters if p.name]


def _function_writes_state(function) -> bool:
    return bool(function.state_variables_written)


def _function_calls_oracle(function) -> list[tuple[object, object]]:
    """Return list of (node, ir) HighLevelCall / LibraryCall matching oracle
    signature or interface name heuristics."""
    hits = []
    for node, ir in _iter_function_irs(function):
        if not isinstance(ir, (HighLevelCall, LibraryCall)):
            continue
        sig = _callee_solidity_signature(ir)
        if sig in ORACLE_SIGS:
            hits.append((node, ir))
            continue
        # Interface/contract name heuristic
        cname = _callee_contract_name(ir).lower()
        if cname and any(k in cname for k in ORACLE_IFACES_NAMECONTAINS):
            # Only count "price-getter-looking" calls, not random ones
            fnname = ""
            fn = getattr(ir, "function", None)
            if fn is not None:
                fnname = (getattr(fn, "name", "") or "").lower()
            if any(t in fnname for t in ("price", "answer", "observe", "feed", "round")):
                hits.append((node, ir))
    return hits


def _function_calls_balanceof_self(function) -> list[tuple[object, object]]:
    """Find every `balanceOf(address(this))` read. Handles:
      (a) HighLevelCall `t.balanceOf(this)` — ERC20 direct
      (b) LibraryCall `SafeTransferLib.balanceOf(token, this)` — Solady
    We identify `address(this)` by matching `TypeConversion src=this` and then
    tracing forward: if the converted temp appears in a balanceOf call args.
    """
    # Pre-pass: collect temporary-variable names that are CONVERT this to address
    this_tempnames: set[str] = set()
    for node, ir in _iter_function_irs(function):
        if isinstance(ir, TypeConversion):
            src = getattr(ir, "variable", None)
            if src is None:
                continue
            srcn = getattr(src, "name", "") or str(src)
            if srcn == "this":
                lv = getattr(ir, "lvalue", None)
                ln = getattr(lv, "name", "") if lv else ""
                if ln:
                    this_tempnames.add(ln)

    hits = []
    for node, ir in _iter_function_irs(function):
        if not isinstance(ir, (HighLevelCall, LibraryCall)):
            continue
        fn = getattr(ir, "function", None)
        fnname = getattr(fn, "name", "") if fn else ""
        if fnname != "balanceOf":
            continue
        args = getattr(ir, "arguments", [])
        for a in args:
            a_name = getattr(a, "name", "") or str(a)
            if a_name == "this" or "this" in a_name or a_name in this_tempnames:
                hits.append((node, ir))
                break
    return hits


def _function_safe_transfer_calls(function, erc20_only: bool = False
                                  ) -> list[tuple[object, object]]:
    """Return transfer-like IR calls. When erc20_only=True, skip ERC1155-style
    batch transfers (those are not a fee-on-transfer concern)."""
    hits = []
    for node, ir in _iter_function_irs(function):
        if not isinstance(ir, (HighLevelCall, LibraryCall)):
            continue
        fn = getattr(ir, "function", None)
        fnname = getattr(fn, "name", "") if fn else ""
        if fnname in ("safeTransfer", "safeTransferFrom", "transfer",
                      "transferFrom"):
            hits.append((node, ir))
        elif fnname in ("safeBatchTransferFrom", "safeTransferBatch"):
            if not erc20_only:
                hits.append((node, ir))
    return hits


def _function_has_balance_delta_pattern(function) -> bool:
    """Heuristic: find two balanceOf(this) reads bracketing a transfer call."""
    seen_balances_before = 0
    seen_transfer = False
    for node, ir in _iter_function_irs(function):
        if isinstance(ir, (HighLevelCall, LibraryCall)):
            fn = getattr(ir, "function", None)
            fnname = getattr(fn, "name", "") if fn else ""
            if fnname == "balanceOf":
                if not seen_transfer:
                    seen_balances_before += 1
                else:
                    if seen_balances_before >= 1:
                        return True
            elif fnname in ("safeTransferFrom", "transferFrom",
                            "safeTransfer", "transfer"):
                seen_transfer = True
    return False


def _function_checks_msg_sender_eq_state(function) -> bool:
    """Return True if function IR contains an equality between msg.sender and
    any state variable (e.g., `msg.sender == trustedLender`) routed through a
    require. Used for flashloan sender checks."""
    state_var_names = {
        v.name for v in function.contract.state_variables if v.name
    }
    for node, ir in _iter_function_irs(function):
        if not isinstance(ir, Binary):
            continue
        if ir.type not in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
            continue
        left_n = getattr(ir.variable_left, "name", "")
        right_n = getattr(ir.variable_right, "name", "")
        has_ms = ("msg.sender" in (str(ir.variable_left), str(ir.variable_right))
                  or left_n == "msg.sender" or right_n == "msg.sender")
        has_state = (left_n in state_var_names) or (right_n in state_var_names)
        if has_ms and has_state:
            return True
    return False


def _function_self_exclusion_check(function) -> bool:
    """Flag True if function contains a Binary comparing msg.sender with one
    of its address-typed parameters (likely `msg.sender != borrower`)."""
    param_names = {
        p.name for p in function.parameters
        if p.name and str(p.type) == "address"
    }
    if not param_names:
        return False
    for node, ir in _iter_function_irs(function):
        if not isinstance(ir, Binary):
            continue
        if ir.type not in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
            continue
        left_n = getattr(ir.variable_left, "name", "")
        right_n = getattr(ir.variable_right, "name", "")
        if ((left_n == "msg.sender" and right_n in param_names) or
                (right_n == "msg.sender" and left_n in param_names)):
            return True
    return False


def _zero_check_on_var(function, varname: str) -> bool:
    """Check if function IR contains a Binary comparing `varname` against 0
    via require (i.e. require(varname > 0) or require(varname != 0))."""
    for node, ir in _iter_function_irs(function):
        if not isinstance(ir, Binary):
            continue
        if ir.type not in (BinaryType.GREATER, BinaryType.NOT_EQUAL,
                           BinaryType.EQUAL, BinaryType.LESS):
            continue
        lv, rv = ir.variable_left, ir.variable_right
        left_n = getattr(lv, "name", "")
        right_n = getattr(rv, "name", "")
        is_target = (left_n == varname) or (right_n == varname)
        is_zero = (isinstance(rv, Constant) and _const_int(rv) == 0) or (
            isinstance(lv, Constant) and _const_int(lv) == 0
        )
        if is_target and is_zero:
            return True
    return False


def _const_int(c):
    try:
        return int(c.value)
    except Exception:
        return None


def _iter_division_ops(function) -> Iterable[tuple[object, object]]:
    for node, ir in _iter_function_irs(function):
        if isinstance(ir, Binary) and ir.type == BinaryType.DIVISION:
            yield node, ir


# ──────────────────────────────────────────────────────────────────────────
# Analysis categories
# ──────────────────────────────────────────────────────────────────────────

def analyze_oracle_reads(function, report: Report, fpath: str) -> None:
    hits = _function_calls_oracle(function)
    if not hits:
        return
    writes_state = _function_writes_state(function)
    for node, ir in hits:
        _, ln = _node_source_location(node)
        fn = getattr(ir, "function", None)
        sig = getattr(fn, "solidity_signature", None) or getattr(fn, "name", "?")
        # Staleness heuristic: is updatedAt / round answer used?
        if writes_state:
            msg = (f"oracle read `{sig}` on L{ln} in function that WRITES state — "
                   "potential same-tx manipulation path")
            tag = "oracle_read_feeds_state_write"
        else:
            msg = f"oracle read `{sig}` on L{ln} (view path — lower risk)"
            tag = "oracle_read_view_only"
        report.add(Finding(
            category="1_oracle_reads",
            tag=tag,
            file=fpath,
            line=ln,
            function=function.name,
            contract=function.contract.name,
            message=msg,
            guard_status="unknown",
        ))


def analyze_flashloan_cb(function, report: Report, fpath: str) -> None:
    if function.name not in FLASH_CB_NAMES:
        return
    fpath_, ln = _fn_source_location(function)
    has_check = _function_checks_msg_sender_eq_state(function)
    # Recurse one hop: check internal-called functions too
    if not has_check:
        for _, ir in _iter_function_irs(function):
            if isinstance(ir, InternalCall):
                cal = getattr(ir, "function", None)
                if isinstance(cal, Function) and _function_checks_msg_sender_eq_state(cal):
                    has_check = True
                    break
    tag = "flashloan_callback_sender_unchecked" if not has_check else "flashloan_callback_sender_checked"
    msg = ("NO `msg.sender == <trustedLender>` check found — callback may be invoked by anyone"
           if not has_check else
           "sender equality vs state variable found — guard present")
    report.add(Finding(
        category="2_flashloan_callbacks",
        tag=tag,
        file=fpath_,
        line=ln,
        function=function.name,
        contract=function.contract.name,
        message=msg,
        guard_status="missing" if not has_check else "enforced",
    ))


def analyze_rate_math(function, report: Report, fpath: str) -> None:
    if not RATE_FN_RE.search(function.name or ""):
        return
    # Heuristic: any external call appearing *between* two BinaryOps suggests
    # rate-value asymmetry.  For now just flag the BinaryOps present.
    bops = [(n, ir) for n, ir in _iter_function_irs(function) if isinstance(ir, Binary)]
    calls_between = any(
        isinstance(ir, (HighLevelCall, LibraryCall))
        for _, ir in _iter_function_irs(function)
    )
    fpath_, ln = _fn_source_location(function)
    tag = "rate_asymmetry_candidate" if calls_between else "rate_math_inline"
    msg = (f"rate-compute function with {len(bops)} BinaryOp(s); external call present "
           "— verify both operands share a snapshot"
           if calls_between else
           f"rate-compute function with {len(bops)} BinaryOp(s) (inline)")
    report.add(Finding(
        category="3_rate_reward_index",
        tag=tag,
        file=fpath_,
        line=ln,
        function=function.name,
        contract=function.contract.name,
        message=msg,
        guard_status="unknown",
    ))


def analyze_rounding_direction(function, report: Report, fpath: str) -> None:
    if function.visibility not in ("public", "external"):
        return
    divs = list(_iter_division_ops(function))
    if not divs:
        return
    is_deposit = bool(DEPOSIT_RE.search(function.name or ""))
    is_withdraw = bool(WITHDRAW_RE.search(function.name or ""))
    expected = None
    if is_deposit and not is_withdraw:
        expected = "round UP (protect protocol from free shares)"
    elif is_withdraw and not is_deposit:
        expected = "round DOWN (protect protocol from over-withdraw)"
    for node, ir in divs:
        _, ln = _node_source_location(node)
        if expected is None:
            tag = "rounding_direction_uncategorised"
            msg = f"DIVISION at L{ln} (function context not deposit/withdraw — manual check)"
        else:
            tag = "rounding_direction_suspect"
            msg = f"DIVISION at L{ln} — expected {expected}; Solidity default is truncation (DOWN). VERIFY."
        report.add(Finding(
            category="4_rounding_direction",
            tag=tag,
            file=fpath,
            line=ln,
            function=function.name,
            contract=function.contract.name,
            message=msg,
            guard_status="unknown",
        ))


def analyze_lp_share_math(function, report: Report, fpath: str) -> None:
    bhits = _function_calls_balanceof_self(function)
    if not bhits:
        return
    transfers = _function_safe_transfer_calls(function)
    divs = list(_iter_division_ops(function))
    fpath_, ln = _fn_source_location(function)

    if transfers:
        tag = "lp_share_math_balanceof_feeds_transfer"
        msg = (f"`balanceOf(this)` read and subsequent transfer(s) in same function — "
               "R53-01/02 class: credited amount may include pre-existing dust/donations")
        report.add(Finding(
            category="5_lp_share_math",
            tag=tag,
            file=fpath_,
            line=ln,
            function=function.name,
            contract=function.contract.name,
            message=msg,
            guard_status="missing",
        ))
    if divs:
        tag = "lp_share_math_balanceof_feeds_division"
        msg = (f"`balanceOf(this)` read and division in same function — "
               "share-price denominator may be donation-inflatable")
        report.add(Finding(
            category="5_lp_share_math",
            tag=tag,
            file=fpath_,
            line=ln,
            function=function.name,
            contract=function.contract.name,
            message=msg,
            guard_status="unknown",
        ))


def analyze_liquidation_self(function, report: Report, fpath: str) -> None:
    if not LIQUIDATE_RE.match(function.name or ""):
        return
    if function.visibility not in ("public", "external"):
        return
    has_self_exclusion = _function_self_exclusion_check(function)
    fpath_, ln = _fn_source_location(function)
    tag = "self_liquidation_possible" if not has_self_exclusion else "self_liquidation_guarded"
    msg = ("no `msg.sender != <addressParam>` check found — self-liquidation may be possible"
           if not has_self_exclusion else "address parameter compared with msg.sender — guarded")
    report.add(Finding(
        category="6_liquidation_self",
        tag=tag,
        file=fpath_,
        line=ln,
        function=function.name,
        contract=function.contract.name,
        message=msg,
        guard_status="missing" if not has_self_exclusion else "enforced",
    ))


def analyze_slippage(function, report: Report, fpath: str) -> None:
    if function.visibility not in ("public", "external"):
        return
    slip_params = [p for p in function.parameters
                   if p.name and SLIPPAGE_PARAM_RE.search(p.name)]
    if not slip_params:
        return
    fpath_, ln = _fn_source_location(function)
    for p in slip_params:
        has_zero_check = _zero_check_on_var(function, p.name)
        tag = "slippage_zero_check_missing" if not has_zero_check else "slippage_zero_check_present"
        msg = (f"slippage param `{p.name}` has no `>0`/`!=0` guard — callers can pass 0 to disable protection"
               if not has_zero_check else
               f"slippage param `{p.name}` has a zero-check guard")
        report.add(Finding(
            category="7_slippage_zero_check",
            tag=tag,
            file=fpath_,
            line=ln,
            function=function.name,
            contract=function.contract.name,
            message=msg,
            guard_status="missing" if not has_zero_check else "enforced",
        ))


def analyze_deadline(function, report: Report, fpath: str) -> None:
    if function.visibility not in ("public", "external"):
        return
    deadline_params = [p for p in function.parameters
                       if p.name and DEADLINE_PARAM_RE.search(p.name)]
    if not deadline_params:
        return
    deadline_names = {p.name for p in deadline_params}
    fpath_, ln = _fn_source_location(function)

    # 1. Direct check in this function
    direct, direct_desc = _contains_timestamp_deadline_check(function, deadline_names)
    if direct:
        report.add(Finding(
            category="8_deadline_enforcement",
            tag="deadline_enforced_direct",
            file=fpath_,
            line=ln,
            function=function.name,
            contract=function.contract.name,
            message=(f"deadline param(s) {sorted(deadline_names)}: direct check in "
                     f"this function — {direct_desc}"),
            guard_status="enforced",
        ))
        return

    # 2. Indirect via internal call trace
    indirect, chain = _trace_deadline_into_callees(function, deadline_names)
    if indirect:
        report.add(Finding(
            category="8_deadline_enforcement",
            tag="deadline_enforced_via_internal_call",
            file=fpath_,
            line=ln,
            function=function.name,
            contract=function.contract.name,
            message=(f"deadline param(s) {sorted(deadline_names)} enforced through "
                     f"internal call chain: {chain}"),
            guard_status="enforced",
        ))
        return

    # 3. Nothing found
    report.add(Finding(
        category="8_deadline_enforcement",
        tag="deadline_not_enforced",
        file=fpath_,
        line=ln,
        function=function.name,
        contract=function.contract.name,
        message=(f"deadline param(s) {sorted(deadline_names)} present but NO "
                 "`block.timestamp` comparison found up to 3 internal hops — "
                 "verify enforcement manually"),
        guard_status="missing",
    ))


def analyze_fot(function, report: Report, fpath: str) -> None:
    # FoT is an ERC20 concern; skip ERC1155 batch calls.
    transfers = _function_safe_transfer_calls(function, erc20_only=True)
    if not transfers:
        return
    has_delta = _function_has_balance_delta_pattern(function)
    fpath_, ln = _fn_source_location(function)
    # Only flag on the first transfer per function (noise reduction)
    node, ir = transfers[0]
    _, tln = _node_source_location(node)
    tag = "fot_unaware_transfer" if not has_delta else "fot_delta_pattern_present"
    fn = getattr(ir, "function", None)
    fnname = getattr(fn, "name", "?") if fn else "?"
    msg = (f"`{fnname}` at L{tln} — no balance-before/after delta pattern detected; "
           "fee-on-transfer tokens credit less than requested"
           if not has_delta else
           f"`{fnname}` at L{tln} — balance-delta pattern detected")
    report.add(Finding(
        category="9_fee_on_transfer",
        tag=tag,
        file=fpath_,
        line=ln,
        function=function.name,
        contract=function.contract.name,
        message=msg,
        guard_status="missing" if not has_delta else "enforced",
    ))


def analyze_cross_function_state(contract, report: Report, fpath: str) -> None:
    """Identify state variables written under strict access control but read
    from a less-restricted function — flag as atomic-read risk."""
    # Build {state_var: set((function, visibility, modifier_names))}
    access: dict[str, list[tuple[str, str, list[str]]]] = {}
    for fn in contract.functions_declared:
        if fn.is_constructor:
            continue
        mods = [m.name for m in fn.modifiers]
        vis = fn.visibility
        for sv in fn.state_variables_written:
            access.setdefault(sv.name, []).append((fn.name, vis, mods))
        for sv in fn.state_variables_read:
            key = f"read::{sv.name}"
            access.setdefault(key, []).append((fn.name, vis, mods))

    # Heuristic: state var with a restricted writer AND a non-restricted reader
    restricted_mods = {"onlyOwner", "onlyAdmin", "onlyOperator", "onlyRoles",
                       "onlyRole", "onlyGovernance"}
    for sv_name in list(access.keys()):
        if sv_name.startswith("read::"):
            continue
        writers = access.get(sv_name, [])
        readers = access.get(f"read::{sv_name}", [])
        if not writers or not readers:
            continue
        has_restricted_writer = any(
            any(m in restricted_mods or m.startswith("onlyR") for m in mods)
            for _, _, mods in writers
        )
        has_loose_reader = any(
            vis in ("public", "external") and not any(
                m in restricted_mods or m.startswith("onlyR") for m in mods
            )
            for _, vis, mods in readers
        )
        if has_restricted_writer and has_loose_reader:
            # pick first reader for citation
            rn = readers[0][0]
            report.add(Finding(
                category="10_cross_function_state",
                tag="cross_function_state_atomic_read_risk",
                file=fpath,
                line=0,
                function=rn,
                contract=contract.name,
                message=(f"state var `{sv_name}` written under restricted access "
                         f"({[w[0] for w in writers]}) but read from loose function(s) "
                         f"{[r[0] for r in readers if r[1] in ('public', 'external')]}"),
                guard_status="unknown",
            ))


# ──────────────────────────────────────────────────────────────────────────
# Driver
# ──────────────────────────────────────────────────────────────────────────

def run_analysis(target: str, report: Report, only: set[str] | None,
                 verbose: bool) -> None:
    print(f"[ir] compiling {target}", file=sys.stderr)
    try:
        slither = Slither(target)
    except Exception as e:
        print(f"[ir] Slither load failed: {e}", file=sys.stderr)
        raise

    n_contracts = 0
    for cu in slither.compilation_units:
        for contract in cu.contracts:
            if _is_skippable_contract(contract):
                continue
            n_contracts += 1
            src = getattr(contract, "source_mapping", None)
            fn_ = getattr(src, "filename", None) if src else None
            path_ = "?"
            if fn_ is not None:
                path_ = getattr(fn_, "relative", None) or getattr(fn_, "absolute", None) or "?"
            if verbose:
                print(f"  [ir] contract {contract.name} @ {path_}", file=sys.stderr)

            for function in contract.functions_declared:
                if function.is_constructor:
                    continue
                fpath_, _ = _fn_source_location(function)
                if only is None or "1" in only:
                    analyze_oracle_reads(function, report, fpath_)
                if only is None or "2" in only:
                    analyze_flashloan_cb(function, report, fpath_)
                if only is None or "3" in only:
                    analyze_rate_math(function, report, fpath_)
                if only is None or "4" in only:
                    analyze_rounding_direction(function, report, fpath_)
                if only is None or "5" in only:
                    analyze_lp_share_math(function, report, fpath_)
                if only is None or "6" in only:
                    analyze_liquidation_self(function, report, fpath_)
                if only is None or "7" in only:
                    analyze_slippage(function, report, fpath_)
                if only is None or "8" in only:
                    analyze_deadline(function, report, fpath_)
                if only is None or "9" in only:
                    analyze_fot(function, report, fpath_)

            if only is None or "10" in only:
                analyze_cross_function_state(contract, report, path_)

    print(f"[ir] scanned {n_contracts} in-scope contract(s), "
          f"{len(report.findings)} finding(s)", file=sys.stderr)


CATEGORY_TITLES = {
    "1_oracle_reads": "Oracle reads",
    "2_flashloan_callbacks": "Flashloan callbacks",
    "3_rate_reward_index": "Rate / reward / index math",
    "4_rounding_direction": "Rounding direction (DIVISION)",
    "5_lp_share_math": "LP / share math",
    "6_liquidation_self": "Liquidation self-exclusion",
    "7_slippage_zero_check": "Slippage zero check",
    "8_deadline_enforcement": "Deadline enforcement",
    "9_fee_on_transfer": "Fee-on-transfer awareness",
    "10_cross_function_state": "Cross-function state reuse",
}


def render_markdown(report: Report, target: str) -> str:
    import datetime
    out: list[str] = []
    out.append(f"# Economic attack surface (IR) — `{target}`")
    out.append("")
    out.append(f"Generated: {datetime.datetime.now().isoformat(timespec='seconds')}")
    out.append("")
    out.append("> IR-based reporter. Reports attack surface with dataflow-derived "
               "guard status. Cross-function deadline tracing is the key improvement "
               "over the grep-based `economic-hypotheses.sh`.")
    out.append("")

    by_cat = report.by_category()

    # Summary table
    out.append("## Summary")
    out.append("")
    out.append("| # | Category | Findings | Enforced | Missing | Unknown |")
    out.append("|---|---|---:|---:|---:|---:|")
    for key in sorted(CATEGORY_TITLES.keys()):
        fs = by_cat.get(key, [])
        total = len(fs)
        enforced = sum(1 for f in fs if f.guard_status == "enforced")
        missing = sum(1 for f in fs if f.guard_status == "missing")
        unknown = sum(1 for f in fs if f.guard_status == "unknown")
        out.append(f"| {key.split('_')[0]} | {CATEGORY_TITLES[key]} "
                   f"| {total} | {enforced} | {missing} | {unknown} |")
    out.append("")
    out.append(f"**Total**: {len(report.findings)}")
    out.append("")

    # Per-category sections
    for key in sorted(CATEGORY_TITLES.keys()):
        fs = by_cat.get(key, [])
        out.append(f"## {key}. {CATEGORY_TITLES[key]} ({len(fs)} finding(s))")
        out.append("")
        if not fs:
            out.append("_No findings._")
            out.append("")
            continue
        for f in fs:
            basename = os.path.basename(f.file) if f.file != "?" else "?"
            status_sym = {
                "enforced": "[ENFORCED]",
                "missing":  "[MISSING]",
                "unknown":  "[NOTE]",
            }.get(f.guard_status, "[?]")
            where = f"`{basename}:{f.line}`" if f.line else f"`{basename}`"
            out.append(
                f"- {status_sym} {where} — `{f.contract}.{f.function}` — "
                f"{f.tag}: {f.message}"
            )
        out.append("")

    # Verdict per category
    out.append("## Aggregate verdict")
    out.append("")
    for key in sorted(CATEGORY_TITLES.keys()):
        fs = by_cat.get(key, [])
        if not fs:
            continue
        enforced = sum(1 for f in fs if f.guard_status == "enforced")
        missing = sum(1 for f in fs if f.guard_status == "missing")
        out.append(f"- **{CATEGORY_TITLES[key]}**: {len(fs)} found, "
                   f"{enforced} enforced / {missing} potentially unsafe.")
    out.append("")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="Solidity file or project directory")
    ap.add_argument("--out", help="Output markdown path", default=None)
    ap.add_argument("--only", help="Comma-separated categories (1..10)",
                    default=None)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        print(f"Target not found: {target}", file=sys.stderr)
        return 2

    only = None
    if args.only:
        only = {s.strip() for s in args.only.split(",") if s.strip()}

    out_path = args.out
    if out_path is None:
        base = os.path.basename(target)
        base = re.sub(r"\.sol$", "", base)
        parent = os.path.dirname(target) or "."
        out_dir = os.path.join(parent, "economic_hypotheses_ir")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"{base}.md")

    report = Report(target=target)
    try:
        run_analysis(target, report, only, args.verbose)
    except Exception as e:
        print(f"[ir] fatal: {e}", file=sys.stderr)
        # Write a partial report so the operator still has something.
        md = render_markdown(report, target)
        md = f"# PARTIAL REPORT (Slither load failed)\n\n```\n{e}\n```\n\n" + md
        Path(out_path).write_text(md)
        print(out_path)
        return 3

    md = render_markdown(report, target)
    Path(out_path).write_text(md)
    print(f"[ir] wrote {out_path}", file=sys.stderr)
    print(out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
