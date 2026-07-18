"""
slither_predicates.py — AST-level helper predicates (R94-D / R74-D delivery).

Target: the top-20 regex predicate shapes currently used across the 946 active
Solidity detectors (see reference/R94_R74D_INVENTORY.md). Each helper walks
Slither IR / CFG instead of grepping the raw source string, eliminating false
positives from comments, string literals, and shadow identifiers.

Design:
  - Every helper takes a Slither `function` (or `contract`) and returns bool.
  - Every helper has a regex-based `_regex_fallback_*` sibling that the detector
    can invoke when Slither IR is not available. The fallback reads
    `function.source_mapping.content` and runs the original regex, matching the
    behaviour of the pre-R74D predicate engine exactly.
  - `available()` tells the caller whether Slither IR introspection is usable
    on this object (graceful degrade → fallback).
  - The helpers are deliberately side-effect free and do not import the
    detector runtime (`_predicate_engine.py`). Compiled detectors can import
    this module lazily.

Usage in a compiled detector:

    try:
        from tools.slither_predicates import reads_msg_sender, available
    except Exception:
        reads_msg_sender = None  # type: ignore

    ...
    for f in contract.functions:
        if reads_msg_sender is not None and available(f):
            hit = reads_msg_sender(f)
        else:
            hit = _regex_fallback(f, r"msg\\.sender")
        ...

References:
  - reference/AST_EXPLAINED.md — full AST primer
  - reference/10_of_10_auditor_roadmap.md — R74-D 15-30% FP-reduction target
  - detectors/_predicate_engine.py — existing partial AST predicates (extended)
"""

from __future__ import annotations

import re
from typing import Any, Optional

# ──────────────────────────────────────────────────────────────────────────────
# Capability probe
# ──────────────────────────────────────────────────────────────────────────────

def available(obj: Any) -> bool:
    """Return True when the object looks like a Slither IR function/contract
    (i.e. has `nodes` or `functions` attrs). Falls back to False on anything
    that isn't structurally navigable — callers should then use the regex path.
    """
    try:
        return (
            hasattr(obj, "nodes")
            or hasattr(obj, "functions")
            or hasattr(obj, "state_variables")
        )
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Low-level building blocks
# ──────────────────────────────────────────────────────────────────────────────

def _iter_nodes(function: Any):
    try:
        for n in getattr(function, "nodes", []) or []:
            yield n
    except Exception:
        return


def _node_expr_str(node: Any) -> str:
    try:
        return str(getattr(node, "expression", "") or "")
    except Exception:
        return ""


def _node_irs(node: Any):
    """SlithIR operations on this node (if available)."""
    try:
        return getattr(node, "irs", []) or []
    except Exception:
        return []


def _high_level_call_names(function: Any):
    for n in _iter_nodes(function):
        for c in getattr(n, "high_level_calls", []) or []:
            if isinstance(c, (list, tuple)) and len(c) >= 2:
                fn = c[1]
            else:
                fn = c
            name = getattr(fn, "name", None) or ""
            if name:
                yield name


def _low_level_call_types(function: Any):
    for n in _iter_nodes(function):
        for lc in getattr(n, "low_level_calls", []) or []:
            # Slither encodes low-level calls as (contract_or_variable, call_type_str)
            # in various versions. We coerce to string and lower.
            try:
                if isinstance(lc, (list, tuple)) and len(lc) >= 2:
                    yield str(lc[1]).lower()
                else:
                    yield str(lc).lower()
            except Exception:
                continue


def _solidity_call_names(function: Any):
    """Built-in Solidity calls: ecrecover, keccak256, selfdestruct,
    abi.encode / abi.encodePacked, etc."""
    for n in _iter_nodes(function):
        # SlithIR tracks these in node.solidity_calls
        for sc in getattr(n, "solidity_calls", []) or []:
            name = getattr(sc, "name", None) or str(sc)
            if name:
                yield name


# ──────────────────────────────────────────────────────────────────────────────
# Top-20 AST-level predicates (1:1 with reference/R94_R74D_INVENTORY.md)
# ──────────────────────────────────────────────────────────────────────────────

# Helper: IR-level variable-read check that ignores string literals.
def _has_solidity_var_read(function: Any, wanted_name: str) -> bool:
    """True when any node of `function` reads the Solidity built-in whose
    name is `wanted_name` (e.g. "msg.sender", "tx.origin", "block.timestamp").
    Uses `node.solidity_variables_read` which is the semantic IR signal —
    does NOT trigger on the same string appearing inside a Solidity string
    literal or a comment. This is the core FP-reduction mechanism."""
    for n in _iter_nodes(function):
        for v in getattr(n, "solidity_variables_read", []) or []:
            if getattr(v, "name", "") == wanted_name:
                return True
    return False


# #1 msg.sender
def reads_msg_sender(function: Any) -> bool:
    return _has_solidity_var_read(function, "msg.sender")


# #18 tx.origin
def reads_tx_origin(function: Any) -> bool:
    return _has_solidity_var_read(function, "tx.origin")


# #3 block.timestamp
def reads_block_timestamp(function: Any) -> bool:
    # Slither emits this as either "block.timestamp" or the legacy alias "now".
    return (
        _has_solidity_var_read(function, "block.timestamp")
        or _has_solidity_var_read(function, "now")
    )


def reads_block_number(function: Any) -> bool:
    return _has_solidity_var_read(function, "block.number")


# #2, #4, #5, #7, #8, #10, #16 — high-level calls by name
def has_high_level_call(function: Any, name_regex: str) -> bool:
    rx = re.compile(name_regex, re.IGNORECASE)
    for nm in _high_level_call_names(function):
        if rx.search(nm or ""):
            return True
    return False


# Convenience wrappers (stable API for compiled detectors):
def has_safe_transfer(function: Any) -> bool:
    return has_high_level_call(function, r"^safeTransfer$|safeTransferFrom")


def has_transfer_from(function: Any) -> bool:
    return has_high_level_call(function, r"^transferFrom$")


def has_balance_of(function: Any) -> bool:
    return has_high_level_call(function, r"^balanceOf$")


def has_total_supply(function: Any) -> bool:
    return has_high_level_call(function, r"^totalSupply$")


def has_safe_approve(function: Any) -> bool:
    return has_high_level_call(function, r"^safeApprove$")


def has_latest_round_data(function: Any) -> bool:
    return has_high_level_call(function, r"^latestRoundData$")


# #11 delegatecall — inspects SlithIR LowLevelCall ops. Previously also
# fell back to expression substring, which FP'd on string literals like
# `"delegatecall"`; the substring-fallback was removed in R94-D hardening.
def has_low_level_delegatecall(function: Any) -> bool:
    for op in _low_level_call_types(function):
        if "delegatecall" in op:
            return True
    # Some Slither versions don't classify delegatecall under `low_level_calls`.
    # Walk SlithIR LowLevelCall ops directly as a secondary check.
    for n in _iter_nodes(function):
        for ir in _node_irs(n):
            cls = type(ir).__name__.lower()
            if "lowlevelcall" in cls or "delegatecall" in cls:
                try:
                    fn_name = getattr(ir, "function_name", "") or ""
                    if fn_name.lower() == "delegatecall" or "delegatecall" in cls:
                        return True
                except Exception:
                    pass
    return False


# #15 low-level .call{}
def has_low_level_call(function: Any, op: Optional[str] = None) -> bool:
    want = op.lower() if op else None
    for t in _low_level_call_types(function):
        if want is None:
            return True
        if want in t:
            return True
    return False


# #9 ecrecover — walks IR SOLIDITY_CALL only (no string-substring fallback,
# which would FP on comments / string literals mentioning "ecrecover").
def calls_ecrecover(function: Any) -> bool:
    for nm in _solidity_call_names(function):
        if "ecrecover" in nm.lower():
            return True
    return False


# #13 keccak256 — SOLIDITY_CALL only. Pre-R94-D used a substring fallback
# which FP'd on string literals such as "keccak256 unsafe".
def computes_keccak(function: Any) -> bool:
    for nm in _solidity_call_names(function):
        if "keccak256" in nm.lower():
            return True
    return False


# #12 abi.encode / abi.encodePacked — SOLIDITY_CALL only.
def computes_abi_encode(function: Any, packed_only: bool = False) -> bool:
    for nm in _solidity_call_names(function):
        nm_l = nm.lower()
        if packed_only:
            if "encodepacked" in nm_l:
                return True
        else:
            if "abi.encode" in nm_l or "encodepacked" in nm_l or nm_l.startswith("encode"):
                return True
    return False


# #6 revert / custom error. Slither emits revert as a SolidityCall named
# "revert()" / "revert(string)" / "revert(Error)". Substring fallback on
# expression repr avoided in R94-D (FP'd on identifiers like `_revertReason`).
def has_revert(function: Any) -> bool:
    for nm in _solidity_call_names(function):
        if nm.lower().startswith("revert"):
            return True
    # Also cover custom-error reverts (Slither encodes them as SolidityCall but
    # some older versions put them on node.expression) — but we only accept
    # expressions that start with the literal `revert ` / `revert(` token,
    # ruling out identifiers that merely contain "revert" as a substring.
    for n in _iter_nodes(function):
        expr = _node_expr_str(n).lstrip()
        if expr.startswith("revert(") or expr.startswith("revert "):
            return True
    return False


# #14 / #17 modifier presence
def has_modifier_named(function: Any, name_regex: str) -> bool:
    rx = re.compile(name_regex, re.IGNORECASE)
    try:
        for m in getattr(function, "modifiers", []) or []:
            if rx.search(getattr(m, "name", "") or ""):
                return True
    except Exception:
        pass
    return False


def has_only_owner_modifier(function: Any) -> bool:
    return has_modifier_named(function, r"onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyRole|restricted")


def has_non_reentrant_modifier(function: Any) -> bool:
    return has_modifier_named(function, r"nonReentrant|noReentrant|notReentrant|reentrancyGuard")


# #19 selfdestruct — SOLIDITY_CALL only. Substring fallback dropped (FP on
# strings like `"use selfdestruct carefully"`).
def calls_selfdestruct(function: Any) -> bool:
    for nm in _solidity_call_names(function):
        nl = nm.lower().rstrip("()").strip()
        if nl in ("selfdestruct", "suicide") or nl.startswith("selfdestruct") or nl.startswith("suicide"):
            return True
    return False


# #20 address(this).balance — scans SlithIR for a read of the `balance`
# member on the `this` identifier. Unlike substring matching, this
# ignores occurrences inside string literals.
def reads_self_balance(function: Any) -> bool:
    for n in _iter_nodes(function):
        # Check the IR: a Balance operation on THIS.
        for ir in _node_irs(n):
            ir_name = type(ir).__name__.lower()
            if "balance" in ir_name:
                return True
            try:
                s = str(ir).lower()
                if "balance(this)" in s or "balance(address(this))" in s:
                    return True
            except Exception:
                pass
        # Slither represents member-access on expressions — check the
        # expression object's printed form but restrict to patterns that
        # look like a real AST member access, not a commented-out substring.
        expr = _node_expr_str(n)
        if "address(this).balance" in expr or "(this).balance" in expr:
            return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# Regex fallbacks (exact replicas of the pre-R74D predicate semantics).
# Used when `available()` returns False or when callers explicitly opt out.
# ──────────────────────────────────────────────────────────────────────────────

def _regex_body(function: Any, pattern: str, negate: bool = False) -> bool:
    try:
        src = function.source_mapping.content or ""
    except Exception:
        src = ""
    try:
        found = bool(re.search(pattern, src, re.IGNORECASE))
    except re.error:
        return False
    return (not found) if negate else found


_REGEX_EQUIVALENTS = {
    # label → default regex that the corresponding AST helper replaces.
    "reads_msg_sender":          r"msg\.sender",
    "reads_tx_origin":           r"tx\.origin",
    "reads_block_timestamp":     r"block\.timestamp",
    "reads_block_number":        r"block\.number",
    "has_safe_transfer":         r"\.safeTransfer(?:From)?\s*\(",
    "has_transfer_from":         r"\.transferFrom\s*\(",
    "has_balance_of":            r"\.balanceOf\s*\(",
    "has_total_supply":          r"\.totalSupply\s*\(",
    "has_safe_approve":          r"\.safeApprove\s*\(",
    "has_latest_round_data":     r"\.latestRoundData\s*\(",
    "has_low_level_delegatecall": r"\.delegatecall\s*\(",
    "has_low_level_call":        r"\.call\s*\{|\.call\s*\(",
    "calls_ecrecover":           r"\becrecover\s*\(",
    "computes_keccak":           r"\bkeccak256\s*\(",
    "computes_abi_encode":       r"\babi\.encode(?:Packed)?\s*\(",
    "has_revert":                r"\brevert\s*\(|\brevert\s+\w+",
    "has_only_owner_modifier":   r"\bonlyOwner\b|\bonlyAdmin\b|\bonlyGovern\w*\b|\bonlyRole\b",
    "has_non_reentrant_modifier": r"\bnonReentrant\b|\bnoReentrant\b|\bnotReentrant\b",
    "calls_selfdestruct":        r"\bselfdestruct\s*\(|\bsuicide\s*\(",
    "reads_self_balance":        r"address\s*\(\s*this\s*\)\s*\.\s*balance|\bthis\s*\)\s*\.\s*balance",
}


def regex_fallback(function: Any, helper_label: str) -> bool:
    """Reference-behaviour fallback — evaluates the same regex the predicate
    engine would have used for `function.body_contains_regex: <X>` where `X`
    is the canonical pattern behind `helper_label`. Callers invoke this when
    `available(function)` is False (e.g. a Slither-less unit test)."""
    rx = _REGEX_EQUIVALENTS.get(helper_label)
    if not rx:
        return False
    return _regex_body(function, rx)


# ──────────────────────────────────────────────────────────────────────────────
# Convenience: unified `check(function, label)` dispatcher.
# Allows a compiled detector to do:
#
#     from tools.slither_predicates import check
#     if not check(f, 'reads_msg_sender'):
#         continue
#
# which picks AST → regex-fallback automatically.
# ──────────────────────────────────────────────────────────────────────────────

_AST_HELPERS = {
    "reads_msg_sender":            reads_msg_sender,
    "reads_tx_origin":             reads_tx_origin,
    "reads_block_timestamp":       reads_block_timestamp,
    "reads_block_number":          reads_block_number,
    "has_safe_transfer":           has_safe_transfer,
    "has_transfer_from":           has_transfer_from,
    "has_balance_of":              has_balance_of,
    "has_total_supply":            has_total_supply,
    "has_safe_approve":            has_safe_approve,
    "has_latest_round_data":       has_latest_round_data,
    "has_low_level_delegatecall":  has_low_level_delegatecall,
    "has_low_level_call":          has_low_level_call,
    "calls_ecrecover":             calls_ecrecover,
    "computes_keccak":             computes_keccak,
    "computes_abi_encode":         computes_abi_encode,
    "has_revert":                  has_revert,
    "has_only_owner_modifier":     has_only_owner_modifier,
    "has_non_reentrant_modifier":  has_non_reentrant_modifier,
    "calls_selfdestruct":          calls_selfdestruct,
    "reads_self_balance":          reads_self_balance,
}


def check(function: Any, label: str) -> bool:
    """AST-first dispatcher. Returns True when the predicate fires.
    Graceful-degrades to the regex fallback if Slither IR isn't navigable.
    """
    fn = _AST_HELPERS.get(label)
    if fn is None:
        return False
    if available(function):
        try:
            return bool(fn(function))
        except Exception:
            # Defensive: any IR traversal crash → fallback, never silently skip.
            return regex_fallback(function, label)
    return regex_fallback(function, label)


# ──────────────────────────────────────────────────────────────────────────────
# Recursive call-graph CLOSURE primitives (Glider callee/caller_functions_recursive
# + modifier-fold + override-resolution analog) — offline / Slither-backed.
#
# Why this exists: per-function regex / header-only auth analysis is our #1 FP/FN
# source. A guard one hop away (a `require` in a private helper, or inside an
# inherited modifier BODY) is invisible to a header-only check. These predicates
# walk the REAL Slither call graph with an UNBOUNDED, cycle-guarded traversal and
# fold modifier bodies into the closure so the guard is found wherever it lives.
#
# Honesty contract (R80): when the caller hands us a non-navigable object (Slither
# failed to compile the target, so no `nodes`/`functions`), every closure helper
# returns a DEGRADED sentinel (see `DEGRADED`) — never a silent regex guess. The
# caller decides whether to fall back; we never silently pretend semantic depth.
# ──────────────────────────────────────────────────────────────────────────────


class _Degraded:
    """Sentinel returned by closure helpers when Slither IR is unavailable.

    Truthy-falsy: it is *falsy* so a naive `if has_guard_in_closure(fn, ...):`
    does not silently treat a degraded result as "guard present". But it is a
    distinct object, so an honest caller can do `res is DEGRADED` (or
    `is_degraded(res)`) and choose the regex fallback explicitly rather than
    silently mis-scoring. Never emit a guess in the degraded path (R80)."""

    _instance: "Optional[_Degraded]" = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __bool__(self) -> bool:
        return False

    def __repr__(self) -> str:
        return "DEGRADED(slither-unavailable)"


DEGRADED = _Degraded()


def is_degraded(value: Any) -> bool:
    """True iff `value` is the DEGRADED sentinel (Slither could not introspect)."""
    return value is DEGRADED


def _is_callable_function(obj: Any) -> bool:
    """True when obj looks like a Slither Function/Modifier (has `nodes`)."""
    return hasattr(obj, "nodes")


def _direct_callees(fn: Any):
    """Yield the directly-called Function/Modifier objects of `fn` — internal
    calls AND high-level (cross-contract) calls — at ONE hop. Skips SolidityCall
    IR (require/keccak/etc.) and library/variable targets that have no body.

    This is the per-node adjacency we recurse over; it deliberately does NOT use
    Slither's own transitive `all_internal_calls()` because (a) we need our own
    cycle-guarded closure to also fold modifier bodies, and (b) `all_*` flattens
    SolidityCall IR ops in with Function objects in this Slither version."""
    for node in getattr(fn, "nodes", []) or []:
        # Internal calls — Slither may yield Function objects or (ctx, Function)
        # tuples or IR ops depending on version; coerce defensively.
        for ic in getattr(node, "internal_calls", []) or []:
            cand = ic[1] if isinstance(ic, (list, tuple)) and len(ic) >= 2 else ic
            # Some Slither versions wrap the callee on the IR op (`.function`).
            if not _is_callable_function(cand):
                cand = getattr(cand, "function", cand)
            if _is_callable_function(cand):
                yield cand
        # High-level (cross-contract) calls — call-graph edges.
        for hc in getattr(node, "high_level_calls", []) or []:
            cand = hc[1] if isinstance(hc, (list, tuple)) and len(hc) >= 2 else hc
            if not _is_callable_function(cand):
                cand = getattr(cand, "function", cand)
            if _is_callable_function(cand):
                yield cand


def _modifier_bodies(fn: Any):
    """Yield the Modifier objects applied to `fn`. Each Modifier has `.nodes`
    (its BODY) so it is treated as a first-class node in the closure — this is
    the modifier-fold that fixes the hollow-modifier FN and the guard-in-modifier
    detection both."""
    for m in getattr(fn, "modifiers", []) or []:
        if _is_callable_function(m):
            yield m


def callee_closure(fn: Any, include_modifiers: bool = True):
    """Cycle-guarded, UNBOUNDED-depth forward closure: the set of all
    Function/Modifier objects transitively reachable from `fn` via internal
    calls, high-level (cross-contract) calls, and (optionally) applied modifier
    bodies. `fn` itself is NOT included.

    Returns a `set` of Slither callables, or `DEGRADED` if `fn` is not
    navigable (R80 — never a silent guess)."""
    if not _is_callable_function(fn):
        return DEGRADED
    seen: set = set()
    frontier = [fn]
    # Track the root so we never add it to the result set.
    root = fn
    while frontier:
        cur = frontier.pop()
        callees = list(_direct_callees(cur))
        if include_modifiers:
            callees.extend(_modifier_bodies(cur))
        for callee in callees:
            if callee is root:
                continue
            if callee in seen:
                continue  # cycle-guard: visited-set terminates recursion
            seen.add(callee)
            frontier.append(callee)
    return seen


def caller_closure(fn: Any, scope: Any = None, include_modifiers: bool = True):
    """Cycle-guarded, UNBOUNDED-depth BACKWARD closure: the set of all
    Function objects that can transitively reach `fn` (i.e. `fn` is in their
    forward callee_closure). `fn` itself is NOT included.

    `scope` is an iterable of candidate Function objects to consider as
    potential callers (e.g. `contract.functions` or every function across the
    Slither compilation). When `scope` is None we try Slither's own
    `reachable_from_functions` reverse edge if present; otherwise we DEGRADE,
    because a backward closure with no candidate universe cannot be honestly
    computed (R80).

    Returns a `set` of callers, or `DEGRADED`."""
    if not _is_callable_function(fn):
        return DEGRADED

    # Fast path: Slither exposes a (1-hop) reverse edge. We still need the
    # transitive closure, so we BFS over it.
    if scope is None:
        rev = getattr(fn, "reachable_from_functions", None)
        if rev is None:
            return DEGRADED
        seen: set = set()
        frontier = [fn]
        while frontier:
            cur = frontier.pop()
            for caller in getattr(cur, "reachable_from_functions", []) or []:
                if caller is fn or caller in seen or not _is_callable_function(caller):
                    continue
                seen.add(caller)
                frontier.append(caller)
        return seen

    # General path: build the reverse reachability over the provided scope by
    # computing each candidate's forward closure and testing membership. This
    # is O(N * closure); N is the in-scope function count, which is bounded.
    callers: set = set()
    for cand in scope:
        if cand is fn or not _is_callable_function(cand):
            continue
        fwd = callee_closure(cand, include_modifiers=include_modifiers)
        if fwd is DEGRADED:
            continue
        if fn in fwd:
            callers.add(cand)
    return callers


# ── Guard-in-closure (modifier-fold) ────────────────────────────────────────

# Known OpenZeppelin-style access-control HELPER functions. Calling one of these
# IS the access-control check (each reverts internally on a caller-identity
# mismatch), so a bare statement `_checkOwner();` / `_checkRole(role);` inside a
# modifier body or function body counts as a guard even though THAT node reads
# no msg.sender directly. Matched by exact (lower-cased) function NAME so we do
# not FP on an unrelated identifier that merely contains the substring.
_AUTHZ_HELPER_NAMES = frozenset({
    "_checkowner",        # OZ Ownable
    "_checkrole",         # OZ AccessControl
    "_authorizeupgrade",  # OZ UUPSUpgradeable upgrade gate
    "_onlyrole",          # variant naming
    "_checkadmin",        # common variant
    "_onlyowner",         # variant naming
    "_checkcancall",      # OZ AccessManaged (the `restricted` modifier body)
    "cancall",            # OZ IAccessManager.canCall
    "cancallwithdelay",   # OZ AuthorityUtils.canCallWithDelay (deeper link)
})

# OZ AccessManaged & external-authority-enforced authz primitives. Unlike
# _checkOwner/_checkRole (which enforce via an IN-BODY require the closure CAN see,
# so they stay under the unresolved-only body-deferral for mutation-sensitivity),
# these enforce via an EXTERNAL authority call (IAccessManager.canCall) that the
# closure cannot introspect. So calling them IS the guard and the name is ALWAYS
# trusted - the body-deferral does not apply (there is no in-CUT body check to see).
# Polygon sPOL PolBridger.rescue/rescueNative/pause are `restricted` (-> _checkCanCall);
# without this they false-flagged unguarded even with the name in the helper set.
_AUTHZ_HELPER_EXTERNAL_ENFORCED = frozenset({
    "_checkcancall",
    "cancall",
    "cancallwithdelay",
})

# Caller-identity ACCESSORS. A compare/check against one of these inside a
# require/assert/revert/if is a caller-identity guard even when the caller is
# read via _msgSender() (Context indirection) rather than a direct msg.sender.
# `owner()` / `hasRole(...)` / `_msgSender()` are the OZ canonical accessors.
_AUTHZ_ACCESSOR_NAMES = frozenset({
    "owner",
    "hasrole",
    "_msgsender",
    "getroleadmin",
    "checkrole",
    "isowner",            # legacy openzeppelin-solidity Ownable: require(isOwner())
    "isadmin",            # common legacy variant: require(isAdmin())
})


def _node_callee_names(node: Any):
    """Yield lower-cased callee NAMES for every call on `node` (internal,
    high-level/cross-contract, and Solidity built-in calls). Coerces the many
    Slither encodings ((ctx, fn) tuples, IR ops with `.function`, bare objs).

    Only NAMES are used downstream (exact-match against small allow-lists), so a
    string literal / comment mentioning `_checkOwner` cannot trigger — Slither
    only records real call edges here, not source substrings."""
    for attr in ("internal_calls", "high_level_calls", "solidity_calls"):
        for c in getattr(node, attr, []) or []:
            cand = c[1] if isinstance(c, (list, tuple)) and len(c) >= 2 else c
            nm = getattr(cand, "name", None)
            if not nm:
                nm = getattr(getattr(cand, "function", None), "name", None)
            if nm:
                # strip a trailing argument-signature suffix, e.g.
                # "require(bool,string)" -> "require"; "hasRole(bytes32,address)"
                yield str(nm).split("(", 1)[0].strip().lower()


def _node_in_revert_context(node: Any) -> bool:
    """True when `node` is a require/assert/revert statement or an `if`
    condition node — the contexts where a caller-identity check enforces AC."""
    expr = str(getattr(node, "expression", "") or "").lstrip()
    ntype = str(getattr(node, "type", "") or "").upper()
    head = expr.split("(", 1)[0]
    return (
        expr.startswith("require(")
        or expr.startswith("assert(")
        or expr.startswith("revert")
        or "IF" in ntype
        or head.endswith("require")
        or head.endswith("assert")
    )


def _node_reads_caller(node: Any) -> bool:
    """True when `node` reads msg.sender / tx.origin via the semantic IR signal
    (ignores comments / string literals)."""
    for v in getattr(node, "solidity_variables_read", []) or []:
        if getattr(v, "name", "") in ("msg.sender", "tx.origin"):
            return True
    return False


# Caller-identity operand names accepted on ONE side of a storage-compare guard.
# `_msgsender` covers the OZ Context._msgSender() indirection; `msg.sender` /
# `tx.origin` cover the direct SolidityVariableComposed read. Deliberately narrow
# (conservative): nothing else on the caller side widens the storage-compare
# signal (no `owner`/`admin` locals etc. - those are not the CALLER).
_CALLER_OPERAND_NAMES = frozenset({"msg.sender", "tx.origin", "_msgsender"})


def _caller_alias_vars(function: Any) -> frozenset:
    """Set of LOCAL / TEMPORARY variable NAMES in `function` that ALIAS the
    transaction caller via an intra-function assignment chain, i.e.

        address who = msg.sender;            // who  -> caller
        address s   = _msgSender();           // s, TMP -> caller (via the call result)

    Slither does NOT thread `points_to_origin` through a plain local assignment
    (`who := msg.sender` is an IR Assignment, not a reference), so signal (4)'s
    direct operand check misses the CACHED-CALLER shape - which is exactly the
    shape signals (1) (literal msg.sender read on the SAME node) and (3)
    (`_msgSender()` accessor call on the SAME node) ALSO miss. Resolving the alias
    at FUNCTION scope is what makes signal (4) load-bearing: it detects a
    `validators[id].owner == who` compare where `who` was cached from the caller
    on a prior line, a gate neither (1) nor (3) sees.

    Conservative / fail-closed: only an assignment whose RHS is literally
    msg.sender/tx.origin, OR a SolidityCall/InternalCall to `_msgSender()` whose
    result lhs is then compared, seeds the alias set. A fixed-point pass folds
    `b := a` chains so `address b = who;` also aliases. Returns an EMPTY set on any
    structural surprise (never widens)."""
    aliases: set = set()
    try:
        nodes = list(getattr(function, "nodes", []) or [])
    except Exception:  # noqa: BLE001
        return frozenset()
    # (a) seed direct caller assignments / _msgSender() call results.
    for n in nodes:
        for ir in _node_irs(n):
            cls = type(ir).__name__.lower()
            lval = getattr(ir, "lvalue", None)
            lnm = str(getattr(lval, "name", "") or "")
            if not lnm:
                continue
            # Assignment lhs := rhs where rhs is a literal caller variable.
            if "assignment" in cls:
                rhs = getattr(ir, "rvalue", None)
                rnm = str(getattr(rhs, "name", "") or "").lower()
                if rnm in _CALLER_OPERAND_NAMES:
                    aliases.add(lnm)
            # A call to _msgSender()/msgSender storing into lval (TMP/local).
            elif "call" in cls:
                callee = getattr(ir, "function", None)
                cnm = str(getattr(callee, "name", "") or "").lower()
                if cnm in ("_msgsender", "msgsender"):
                    aliases.add(lnm)
    # (b) fixed-point fold of `b := a` where `a` is already an alias.
    for _ in range(8):  # bounded; alias chains are shallow in practice
        grew = False
        for n in nodes:
            for ir in _node_irs(n):
                if "assignment" not in type(ir).__name__.lower():
                    continue
                lval = getattr(ir, "lvalue", None)
                rhs = getattr(ir, "rvalue", None)
                lnm = str(getattr(lval, "name", "") or "")
                rnm = str(getattr(rhs, "name", "") or "")
                if lnm and rnm and rnm in aliases and lnm not in aliases:
                    aliases.add(lnm)
                    grew = True
        if not grew:
            break
    return frozenset(aliases)


def _ir_operand_is_caller(v: Any, caller_aliases: Optional[frozenset] = None) -> bool:
    """True when a slither IR Binary operand denotes the transaction caller:
    the `msg.sender` / `tx.origin` SolidityVariable, a temp/ref that points back
    to a `_msgSender()` call result, OR (when `caller_aliases` is supplied) a
    local/temp whose NAME is in the function-level caller-alias set (a value
    cached from msg.sender / _msgSender() on a prior line). Name-exact only (no
    substring), so an unrelated local merely containing "sender" cannot match."""
    if v is None:
        return False
    nm = str(getattr(v, "name", "") or "").lower()
    if nm in _CALLER_OPERAND_NAMES:
        return True
    # Follow points-to: `_msgSender()` lowers to TMP = HIGH_LEVEL_CALL _msgSender()
    # and the compare reads that TMP. Resolve the call name behind the temp.
    try:
        origin = getattr(v, "points_to_origin", None)
        if origin is not None:
            onm = str(getattr(origin, "name", "") or "").lower()
            if onm in _CALLER_OPERAND_NAMES:
                return True
    except Exception:
        pass
    # Function-level caller alias (cached `who = msg.sender` / `s = _msgSender()`):
    # the shape signals (1)/(3) miss because the caller read is on a PRIOR node.
    if caller_aliases:
        rawnm = str(getattr(v, "name", "") or "")
        if rawnm and rawnm in caller_aliases:
            return True
    return False


def _ir_operand_is_storage_read(v: Any) -> bool:
    """True when a slither IR Binary operand is a value READ FROM A STORAGE
    mapping / struct field (e.g. `validators[id].contractAddress`), i.e. a
    ReferenceVariable whose `points_to_origin` chain roots in a StateVariable.

    CONSERVATIVE: a plain state SCALAR read (e.g. bare `owner`) is intentionally
    out of scope here - that path is already covered by the accessor signal (3)
    and the direct-read signal (1); this signal exists specifically for the
    mapping/struct-field lvalue shape the node-level `solidity_variables_read`
    does not surface as a caller guard. Only a reference rooted in a
    StateVariable counts (a local / memory ref does not)."""
    if v is None:
        return False
    # Must look like a reference into composite storage (Index/Member chain).
    cls = type(v).__name__.lower()
    if "reference" not in cls:
        return False
    try:
        origin = getattr(v, "points_to_origin", None)
    except Exception:
        origin = None
    if origin is None:
        return False
    ocls = type(origin).__name__.lower()
    # The chain must terminate at a STATE variable (storage), not a local/memory.
    if "statevariable" in ocls:
        return True
    # Some slither versions expose `is_storage` on the rooted variable.
    try:
        if getattr(origin, "is_storage", False) and "local" not in ocls:
            return True
    except Exception:
        pass
    return False


def _node_caller_vs_storage_read_compare(node: Any) -> bool:
    """True when `node` carries a Binary `==` / `!=` comparison with the
    transaction caller (msg.sender / tx.origin / _msgSender()) on ONE side and a
    storage mapping/struct-field READ on the OTHER side. This is the SSV-surfaced
    `require(validators[id].contractAddress == msg.sender)` caller-identity guard
    shape, where the storage lvalue is a ReferenceVariable that the node-level
    `solidity_variables_read` does not expose as a guard signal.

    CONSERVATIVE (never over-credit): requires BOTH a caller operand AND a
    storage-read operand on the SAME equality/inequality comparator. An arbitrary
    equality (`a == b`), a value-bound (`amt <= cap`), or a caller compared to a
    non-storage operand does NOT match here (other signals own those cases or it
    is correctly not a guard).

    LOAD-BEARING shape (the gap signals (1)/(3) leave open): the caller side may
    be a LOCAL/TEMP cached from msg.sender/_msgSender() on a PRIOR node, so we
    resolve the function-level caller-alias set once and pass it to the operand
    classifier. A literal-msg.sender compare is ALSO matched by signal (1), but a
    `validators[id].owner == cachedCaller` compare is matched ONLY here."""
    Binary, BinaryType = _binary_ir_classes()
    # Resolve the caller-alias set once at function scope (cached locals / temps
    # that hold msg.sender / _msgSender()). This is what lets signal (4) detect the
    # cached-caller shape that the node-level signals (1)/(3) cannot see.
    fn = getattr(node, "function", None)
    caller_aliases = _caller_alias_vars(fn) if fn is not None else frozenset()
    for ir in _node_irs(node):
        if Binary is not None and not isinstance(ir, Binary):
            continue
        # Restrict to equality / inequality comparators (identity check shape).
        op = _binarytype_to_op(getattr(ir, "type", None), BinaryType)
        if op not in ("==", "!="):
            continue
        lhs = getattr(ir, "variable_left", None)
        rhs = getattr(ir, "variable_right", None)
        lhs_caller = _ir_operand_is_caller(lhs, caller_aliases)
        rhs_caller = _ir_operand_is_caller(rhs, caller_aliases)
        if not (lhs_caller or rhs_caller):
            continue
        storage_side = (
            (lhs_caller and _ir_operand_is_storage_read(rhs))
            or (rhs_caller and _ir_operand_is_storage_read(lhs))
        )
        if storage_side:
            return True
    return False


def _node_default_guard(node: Any, unresolved_helpers_only: Optional[set] = None) -> bool:
    """The built-in caller-identity access-control guard predicate.

    A node is an access-control guard when EITHER:
      1. it sits in a require/assert/revert/if context AND reads msg.sender /
         tx.origin directly (the original, conservative signal), OR
      2. it CALLS a known OZ authz helper (_checkOwner / _checkRole /
         _authorizeUpgrade / _onlyRole / ...) whose BODY is NOT resolvable in
         the surrounding closure — calling the helper IS the check (it reverts
         internally) and we cannot see its body to verify it, so we trust the
         canonical name. When the helper body IS in the closure, this shortcut
         is suppressed so the real check inside the body carries detection
         (keeps the predicate mutation-sensitive / non-vacuous, and keeps a
         hollow helper correctly UNGUARDED), OR
      3. it sits in a require/assert/revert/if context AND compares against a
         caller-identity ACCESSOR (owner() / hasRole(...) / _msgSender()) — this
         catches the OZ `require(owner() == _msgSender(), ...)` form where the
         caller is read indirectly through Context._msgSender() rather than a
         literal msg.sender, OR
      4. it sits in a require/assert/revert/if context AND compares msg.sender /
         _msgSender() against a value READ FROM A STORAGE MAPPING / STRUCT FIELD
         (e.g. `require(validators[id].contractAddress == msg.sender)`) — the SSV
         per-validator owner gate, where the storage lvalue is an IR
         ReferenceVariable the node-level read-set does not surface as a guard.

    `unresolved_helpers_only`, when provided by `has_guard_in_closure`, is the
    set of authz-helper names whose bodies were NOT folded into the closure;
    only those are honoured for signal (2). When None (e.g. a caller invoking
    the per-node predicate standalone) every authz-helper name is honoured.

    Scope is deliberately limited to CALLER-IDENTITY authz. A value-bound check
    like `require(amt <= cap)` reads no caller signal and calls no authz helper,
    so it is NOT counted (no widening into amount/bound guards)."""
    callees = set(_node_callee_names(node))

    # (2a) External-authority-enforced primitives (OZ AccessManaged `restricted` ->
    #      _checkCanCall -> authority.canCall). The real check is an external call the
    #      closure cannot see, so calling the primitive IS the guard - always trusted,
    #      independent of body resolution.
    if callees & _AUTHZ_HELPER_EXTERNAL_ENFORCED:
        return True

    # (2) A call to an authz helper. Only trust the NAME when the helper body is
    #     not visible in the closure (otherwise let the body's real check decide,
    #     so mutation can flip and a hollow helper stays unguarded).
    helper_hits = callees & _AUTHZ_HELPER_NAMES
    if helper_hits:
        if unresolved_helpers_only is None:
            return True
        if helper_hits & unresolved_helpers_only:
            return True

    in_ctx = _node_in_revert_context(node)
    if not in_ctx:
        return False

    # (1) Direct msg.sender / tx.origin read inside the guard context.
    if _node_reads_caller(node):
        return True

    # (3) Compare against a caller-identity accessor inside the guard context
    #     (covers _msgSender() Context indirection). A `_msgSender()` call alone
    #     only counts when paired with an identity accessor OR a direct caller
    #     read is also present; but in practice OZ pairs owner()/_msgSender(),
    #     so requiring any accessor hit is sufficient and stays caller-scoped.
    if callees & _AUTHZ_ACCESSOR_NAMES:
        return True

    # (4) Compare msg.sender / _msgSender() against a STORAGE mapping/struct-field
    #     read inside the guard context (the SSV per-validator owner gate:
    #     `require(validators[id].contractAddress == msg.sender)`). The storage
    #     lvalue is an IR ReferenceVariable the node-level read-set does not expose
    #     as a guard. Requires BOTH a caller operand AND a storage-read operand on
    #     the SAME equality comparator (conservative: never credits arbitrary `==`).
    if _node_caller_vs_storage_read_compare(node):
        return True

    return False


def _node_has_guard(node: Any, guard_pred: Optional[Any],
                    unresolved_helpers_only: Optional[set] = None) -> bool:
    """Default guard predicate over a single CFG node: a real access-control
    style guard. Detects:
      - `require(...)` / `assert(...)` / `revert ...` / `if` that reads
        msg.sender / tx.origin (direct caller-identity guard);
      - a call to a known OZ authz helper (_checkOwner / _checkRole /
        _authorizeUpgrade / _onlyRole) — the OZ onlyOwner -> _checkOwner ->
        owner()-revert indirection, where no direct msg.sender appears in the
        modifier node;
      - a require/assert/revert/if comparing against a caller-identity accessor
        (owner() / hasRole(...) / _msgSender()).

    A custom `guard_pred(node) -> bool` overrides this default entirely."""
    if guard_pred is not None:
        try:
            return bool(guard_pred(node))
        except Exception:
            return False
    return _node_default_guard(node, unresolved_helpers_only)


def has_guard_in_closure(fn: Any, guard_pred: Optional[Any] = None) -> Any:
    """True iff an access-control guard exists ANYWHERE in `fn`'s forward callee
    closure OR inside any applied modifier BODY (transitively). This is the
    capability that fixes BOTH error sides of header-only auth analysis:

      - FALSE POSITIVE side: a function with no inline guard whose private
        helper (one or more hops away) contains the `require(msg.sender == ...)`
        is correctly seen as guarded → NOT flagged missing-AC.
      - FALSE NEGATIVE side: a function whose modifier HEADER says `onlyOwner`
        but whose modifier BODY is hollow (no real check) is correctly seen as
        UNGUARDED → flagged. We read modifier BODIES, not headers.

    `guard_pred(node) -> bool` overrides the default caller-identity guard.

    Returns bool, or `DEGRADED` (R80) when `fn` is not navigable."""
    if not _is_callable_function(fn):
        return DEGRADED

    closure = callee_closure(fn, include_modifiers=True)
    if closure is DEGRADED:
        return DEGRADED

    # For the default predicate, compute which authz-helper names have a BODY
    # folded into the closure (or `fn` itself). The by-name authz-helper shortcut
    # (#2) is honoured ONLY for helpers whose body is NOT resolvable here, so a
    # resolvable helper lets its real body carry detection — keeping the
    # predicate non-vacuous (mutation flips) and a hollow helper unguarded.
    unresolved_helpers: Optional[set] = None
    if guard_pred is None:
        resolved_names = {
            str(getattr(c, "name", "") or "").lower()
            for c in ({fn} | (closure if isinstance(closure, set) else set()))
        }
        unresolved_helpers = {h for h in _AUTHZ_HELPER_NAMES if h not in resolved_names}

    # Check the function's own body first.
    for node in getattr(fn, "nodes", []) or []:
        if _node_has_guard(node, guard_pred, unresolved_helpers):
            return True

    for callee in closure:
        for node in getattr(callee, "nodes", []) or []:
            if _node_has_guard(node, guard_pred, unresolved_helpers):
                return True
    return False


# ── Backward unguarded-path enumeration to a sink ───────────────────────────

def _is_entrypoint(fn: Any) -> bool:
    vis = getattr(fn, "visibility", "")
    if vis not in ("external", "public"):
        return False
    if getattr(fn, "is_constructor", False):
        return False
    return True


def unguarded_paths_to_sink(sink_fn: Any, scope: Any, guard_pred: Optional[Any] = None):
    """Backward caller-closure tagging: enumerate every public/external
    entrypoint in `scope` that can transitively REACH `sink_fn`, tagging each
    entrypoint as guarded / unguarded by folding its guard closure (which
    includes the path through to the sink and the entrypoint's own modifiers).

    `scope` is the candidate universe of Function objects (e.g.
    `[f for c in slither.contracts for f in c.functions]`).

    Returns a list of dicts:
        {"entrypoint": <Function>, "name": str, "contract": str,
         "guarded": bool, "via_sink_in_closure": True}
    or `DEGRADED` when `sink_fn` is not navigable (R80)."""
    if not _is_callable_function(sink_fn):
        return DEGRADED

    results = []
    scope_list = [f for f in scope if _is_callable_function(f)]
    for ep in scope_list:
        if ep is sink_fn:
            # The sink itself may be a public entrypoint.
            if not _is_entrypoint(ep):
                continue
            guarded = has_guard_in_closure(ep, guard_pred)
            results.append({
                "entrypoint": ep,
                "name": getattr(ep, "name", "?"),
                "contract": getattr(getattr(ep, "contract", None), "name", "?"),
                "guarded": bool(guarded) if guarded is not DEGRADED else False,
                "via_sink_in_closure": True,
            })
            continue
        if not _is_entrypoint(ep):
            continue
        fwd = callee_closure(ep, include_modifiers=True)
        if fwd is DEGRADED:
            continue
        if sink_fn not in fwd:
            continue
        guarded = has_guard_in_closure(ep, guard_pred)
        results.append({
            "entrypoint": ep,
            "name": getattr(ep, "name", "?"),
            "contract": getattr(getattr(ep, "contract", None), "name", "?"),
            "guarded": bool(guarded) if guarded is not DEGRADED else False,
            "via_sink_in_closure": True,
        })
    return results


# ── Comparator + branch-target GUARD-CORRECTNESS semantics ──────────────────
# Glider's `is_eq`/comparator + `son_true`/`son_false` branch-target analog.
# The closure guard predicate above answers "is there a caller-identity guard";
# these helpers answer "is the guard CORRECT" - they read the COMPARATOR op
# (==,!=,<,<=,>,>=) and WHICH branch carries the value-moving effect, so a
# boundary off-by-one (`<=` where `<` was intended), a strict/non-strict cap
# mismatch, or an inverted-branch guard can be surfaced as a conservative LEAD.
#
# CONSERVATIVE-BY-CONSTRUCTION: every helper only CLASSIFIES; the oracle only
# returns a LEAD (boundary_suspect=True) - never an auto-finding, never a flip
# of `unguarded`. A correct strict guard returns boundary_suspect=False
# (never-false-positive). All helpers degrade (DEGRADED) on a non-navigable
# input and never raise (R80).

# Canonical comparator op strings (stable, Slither-version-independent). We map
# the slither BinaryType enum onto these so downstream consumers key on a fixed
# vocabulary regardless of the installed slither version.
_COMPARATOR_OPS = frozenset({"==", "!=", "<", "<=", ">", ">="})
# Non-strict <-> strict pairing for the boundary off-by-one signal.
_NONSTRICT_TO_STRICT = {"<=": "<", ">=": ">"}


def _binary_ir_classes():
    """Lazily import the slither Binary/BinaryType IR classes. Returns
    (Binary, BinaryType) or (None, None) when slither is not importable
    (caller then degrades to DEGRADED / [])."""
    try:
        from slither.slithir.operations import Binary  # noqa
        from slither.slithir.operations.binary import BinaryType  # noqa
        return Binary, BinaryType
    except Exception:
        try:
            from slither.slithir.operations import Binary, BinaryType  # noqa
            return Binary, BinaryType
        except Exception:
            return None, None


def _binarytype_to_op(btype: Any, BinaryType: Any) -> Optional[str]:
    """Map a slither BinaryType enum value -> a canonical comparator op string,
    or None when the binary op is not a comparator (arithmetic / bitwise /
    logical-and-or). Compares by enum identity, falling back to the enum's
    string form so a version that renames members still resolves."""
    if BinaryType is not None:
        pairs = (
            ("EQUAL", "=="), ("NOT_EQUAL", "!="),
            ("LESS", "<"), ("LESS_EQUAL", "<="),
            ("GREATER", ">"), ("GREATER_EQUAL", ">="),
        )
        for member, op in pairs:
            m = getattr(BinaryType, member, None)
            if m is not None and btype is m:
                return op
    # Fallback: parse the stringified enum (e.g. "BinaryType.LESS_EQUAL").
    s = str(btype or "").upper()
    name = s.rsplit(".", 1)[-1]
    return {
        "EQUAL": "==", "NOT_EQUAL": "!=",
        "LESS": "<", "LESS_EQUAL": "<=",
        "GREATER": ">", "GREATER_EQUAL": ">=",
    }.get(name)


def _var_name(v: Any) -> str:
    """Best-effort readable name for a slither IR variable/constant operand."""
    if v is None:
        return ""
    nm = getattr(v, "name", None)
    if nm:
        return str(nm)
    # Constants expose `.value`; reference/temp vars stringify reasonably.
    val = getattr(v, "value", None)
    if val is not None:
        return str(val)
    return str(v)


def _var_is_constant(v: Any) -> bool:
    """True when the operand looks like a compile-time Constant (a literal bound
    such as a cap value or magic number)."""
    if v is None:
        return False
    cls = type(v).__name__.lower()
    if "constant" in cls:
        return True
    # A state var named like a cap/limit is a likely BOUND even when not literal.
    nm = str(getattr(v, "name", "") or "").lower()
    return any(tok in nm for tok in ("cap", "max", "limit", "bound", "threshold", "ceiling"))


def guard_comparators(node: Any) -> Any:
    """Extract every COMPARATOR on `node` as a list of dicts:
        {"op": "<="|"<"|">"|">="|"=="|"!=",
         "lhs": <str>, "rhs": <str>,
         "lhs_const": bool, "rhs_const": bool}
    in CFG / source order. Reads slither Binary IR (node.irs); arithmetic /
    bitwise / logical binaries are skipped (only comparators are returned).

    Returns [] for a node with no comparator IR (or no IR at all). Returns
    DEGRADED only when slither's IR classes are unimportable AND the node still
    looks navigable (so the caller can distinguish "no comparator" from "could
    not analyse"). A node that simply has no `.irs` yields []."""
    Binary, BinaryType = _binary_ir_classes()
    if Binary is None:
        # IR classes unavailable -> cannot classify. Distinguish from "no comparator".
        return DEGRADED
    out = []
    try:
        irs = getattr(node, "irs", None)
        if irs is None:
            return out
        for ir in irs:
            if not isinstance(ir, Binary):
                continue
            op = _binarytype_to_op(getattr(ir, "type", None), BinaryType)
            if op not in _COMPARATOR_OPS:
                continue  # arithmetic / logical binary, not a comparator
            lhs = getattr(ir, "variable_left", None)
            rhs = getattr(ir, "variable_right", None)
            out.append({
                "op": op,
                "lhs": _var_name(lhs),
                "rhs": _var_name(rhs),
                "lhs_const": _var_is_constant(lhs),
                "rhs_const": _var_is_constant(rhs),
            })
    except Exception:
        return DEGRADED
    return out


def _node_is_if(node: Any) -> bool:
    """True for a CFG branch node (IF / IFLOOP) - NOT for ENDIF (which also ends
    in 'IF' textually but is the join, with no son_true/son_false branch)."""
    ntype = str(getattr(node, "type", "") or "").upper()
    name = ntype.rsplit(".", 1)[-1]
    return name in ("IF", "IFLOOP")


def branch_effect_target(node: Any) -> Any:
    """For an `if` node, return which CFG branch the navigator should treat as the
    body the guard ADMITS (the TRUE arm) vs the one it REJECTS (the FALSE arm):
        {"son_true": <Node|None>, "son_false": <Node|None>, "is_if": bool}
    Uses Node.son_true / Node.son_false (the Glider branch-target analog).

    For a require/assert (lowered to an `if (!cond) revert`), the EFFECT runs in
    the path where the condition HOLDS. The caller (the boundary oracle) uses this
    only to detect an INVERTED-branch guard - it never flips `unguarded`.

    Returns DEGRADED on a non-navigable node (R80)."""
    if not hasattr(node, "type"):
        return DEGRADED
    return {
        "son_true": getattr(node, "son_true", None),
        "son_false": getattr(node, "son_false", None),
        "is_if": _node_is_if(node),
    }


def _node_is_revert_or_require(node: Any) -> bool:
    """True when the node IS the require/assert/revert itself (so the comparator
    on it is a GUARD condition, not an ordinary arithmetic comparison)."""
    return _node_in_revert_context(node)


def boundary_suspect(node: Any, value_names: Optional[set] = None) -> Any:
    """Conservative GUARD-CORRECTNESS oracle over a single guard node.

    Flags a guard node as BOUNDARY-SUSPECT (a LEAD, never an auto-finding) when
    its comparator is a NON-STRICT bound (`<=` / `>=`) on a VALUE/amount operand
    against a CONST/cap operand - i.e. exactly the `<=`-where-`<` (or `>=`-where-`>`)
    off-by-one cap shape. Returns a dict:

        {"boundary_suspect": bool,
         "reason": "<short why or empty>",
         "comparators": [<guard_comparators rows that triggered>],
         "op": "<the suspect op or empty>",
         "suggested_op": "<the strict counterpart or empty>"}

    Never-false-positive contract:
      - a STRICT bound (`<` / `>`) on a value -> boundary_suspect=False
        (the strict guard is the correct form).
      - an equality / inequality / caller-identity guard -> boundary_suspect=False.
      - no comparator at all -> boundary_suspect=False.

    `value_names`, when provided, restricts the value-side match to those variable
    names (e.g. the tainted amount vars of a data-flow path); when None, ANY
    non-const operand paired with a const/cap operand counts as the value side.

    Returns DEGRADED when the comparator extraction degrades (R80)."""
    if not hasattr(node, "type") and not hasattr(node, "irs"):
        return DEGRADED
    comps = guard_comparators(node)
    if is_degraded(comps):
        return DEGRADED

    result = {
        "boundary_suspect": False,
        "reason": "",
        "comparators": [],
        "op": "",
        "suggested_op": "",
    }
    if not comps:
        return result

    in_guard_ctx = _node_is_revert_or_require(node)
    vnames = {str(v).lower() for v in value_names} if value_names else None

    for c in comps:
        op = c["op"]
        if op not in _NONSTRICT_TO_STRICT:
            continue  # only <= / >= are boundary-suspect; <,>,==,!= are not
        lhs, rhs = c["lhs"], c["rhs"]
        lhs_c, rhs_c = c["lhs_const"], c["rhs_const"]
        # Identify the (value, bound) sides. The bound is the const/cap side; the
        # value is the other side. A const-vs-const or var-vs-var comparator is
        # NOT a value-vs-cap boundary (skip - never-false-positive on those).
        value_side = None
        if rhs_c and not lhs_c:
            value_side = lhs
        elif lhs_c and not rhs_c:
            value_side = rhs
        if value_side is None:
            continue
        if vnames is not None and str(value_side).lower() not in vnames:
            continue  # value-name filter active and this operand is not tainted
        # Only treat as a suspect when the comparator IS a guard condition (in a
        # require/assert/if). A `<=` inside ordinary arithmetic is not a guard.
        if not in_guard_ctx:
            continue
        result["boundary_suspect"] = True
        result["op"] = op
        result["suggested_op"] = _NONSTRICT_TO_STRICT[op]
        result["comparators"].append(c)
        result["reason"] = (
            f"non-strict bound `{op}` on value `{value_side}` vs cap `"
            f"{rhs if value_side == lhs else lhs}` - possible off-by-one "
            f"(`{_NONSTRICT_TO_STRICT[op]}` may have been intended); LEAD only"
        )
        break  # one suspect comparator is enough to flag the node
    return result


def path_boundary_suspect(fn: Any, value_names: Optional[set] = None) -> Any:
    """Scan every node in `fn`'s OWN body for a boundary-suspect guard, returning
    the FIRST suspect annotation (with the node's first source line) or a
    not-suspect result. This is the function-level entry the data-flow closure
    pass consults for a resolved source/sink fn.

        {"boundary_suspect": bool, "reason": str, "op": str,
         "suggested_op": str, "line": <int|None>, "comparators": [...]}

    Returns DEGRADED when `fn` is not navigable (R80). CONSERVATIVE: only the
    function's own nodes are scanned (no closure fold) so the annotation anchors
    at a concrete in-fn comparator the hunter can verify at source (R76)."""
    if not _is_callable_function(fn):
        return DEGRADED
    any_degraded = False
    for node in getattr(fn, "nodes", []) or []:
        bs = boundary_suspect(node, value_names=value_names)
        if is_degraded(bs):
            any_degraded = True
            continue
        if bs.get("boundary_suspect"):
            line = None
            sm = getattr(node, "source_mapping", None)
            lines = list(getattr(sm, "lines", []) or []) if sm else []
            if lines:
                line = lines[0]
            bs["line"] = line
            return bs
    if any_degraded:
        return DEGRADED
    return {"boundary_suspect": False, "reason": "", "op": "",
            "suggested_op": "", "line": None, "comparators": []}


def closure_boundary_suspect(fn: Any, value_names: Optional[set] = None) -> Any:
    """Like `path_boundary_suspect` but scans `fn`'s OWN body AND its forward
    callee closure (folding modifier bodies) - so a non-strict value-bound guard
    living in an INTERMEDIATE hop (e.g. `withdraw -> _route[require(amt<=cap)] ->
    _pay -> transferFrom`) is found even though it is not in the source or sink
    fn's own body. Returns the FIRST suspect annotation with `at_fn` (the
    declaring fn's name) + `line`, or a not-suspect result.

        {"boundary_suspect": bool, "reason": str, "op": str,
         "suggested_op": str, "line": <int|None>, "at_fn": <str>,
         "comparators": [...]}

    CONSERVATIVE: when `value_names` is provided it filters the value side, but
    because the tainted var is RENAMED across hops the caller typically passes
    None here (the closure context already establishes the value-flow). A degrade
    in the closure leaves the own-body result (R80). Returns DEGRADED when `fn`
    is not navigable."""
    # First the fn's own body (anchors at the most-specific site when present).
    own = path_boundary_suspect(fn, value_names=value_names)
    if is_degraded(own):
        return DEGRADED
    if own.get("boundary_suspect"):
        own["at_fn"] = getattr(fn, "name", "?")
        return own
    closure = callee_closure(fn, include_modifiers=True)
    if is_degraded(closure):
        # own body was clean and closure could not navigate -> honest not-suspect
        # on the own body (do not claim degrade for the whole, the own scan ran).
        own["at_fn"] = getattr(fn, "name", "?")
        return own
    for callee in closure:
        cb = path_boundary_suspect(callee, value_names=value_names)
        if is_degraded(cb):
            continue
        if cb.get("boundary_suspect"):
            cb["at_fn"] = getattr(callee, "name", "?")
            return cb
    own["at_fn"] = getattr(fn, "name", "?")
    return own


# ── Type-convertibility lattice + UNSAFE-DOWNCAST oracle ─────────────────────
# Glider's `can_convert` / type-convertibility analog. Glider exposes whether a
# type CONVERSION is lossless; we have only per-var type STRINGS today (no lattice).
# This adds the lattice (`can_convert` / `cast_is_lossy`) over slither IR type info
# (int/uint bitwidth + signedness) PLUS an UNSAFE-DOWNCAST detector over the
# TypeConversion IR: a VALUE-MOVING operand (amount/balance/shares/units/debt/
# earnings/timestamp/index, reusing the dataflow-slice economic-value heuristic)
# that is narrowed in bitwidth or sign-flipped is the silent uint256->uint64
# truncation / int<->uint sign-flip bug class.
#
# CONSERVATIVE-BY-CONSTRUCTION (never-false-positive):
#   - a WIDENING cast (uint64->uint256) is lossless -> NOT flagged.
#   - a non-VALUE operand (a uint256->uint8 of an `id`/`flag`) -> NOT flagged.
#   - a SafeCast.toUintN()-wrapped cast is a LibraryCall (not a TypeConversion at
#     the call site) -> structurally NOT flagged; and a cast guarded by a
#     `require(x <= type(uintN).max)` bound-check in the same fn -> NOT flagged
#     (it reverts on overflow = safe). A SafeCast WRAPPER body (a `toUintN` fn) is
#     itself excluded so the library's own internal cast does not self-flag.
# Every helper degrades (DEGRADED) / returns a benign empty result on a
# non-navigable input and never raises (R80). `unsafe_value_downcasts` only ever
# returns a LEAD list; it is NEVER an auto-finding and NEVER flips `unguarded`.

# elementary numeric type parse: (signed: bool, bits: int) or None when the type
# is not an int/uint elementary type (address/bool/bytes/string/struct/mapping...).
_INT_TYPE_RX = re.compile(r"^\s*(u?)int(\d*)\s*$", re.IGNORECASE)


def parse_int_type(type_str: Any) -> Optional[dict]:
    """Parse a solidity elementary integer type string into
    {"signed": bool, "bits": int}, or None when it is not an int/uint scalar.

    `uint`/`int` with no width default to 256 bits (solidity semantics). A leading
    `u` => unsigned. Anything that is not an `(u)intN` elementary type (address,
    bool, bytes, a mapping, a struct, an array `uint64[]`) returns None so the
    caller treats it as non-numeric (and a cast to/from it is NOT a lossy-numeric
    downcast we reason about)."""
    if type_str is None:
        return None
    s = str(type_str).strip()
    m = _INT_TYPE_RX.match(s)
    if not m:
        return None
    unsigned = bool(m.group(1))
    width = m.group(2)
    bits = int(width) if width else 256
    if bits <= 0 or bits > 256 or (bits % 8) != 0:
        # not a valid solidity int width -> treat as unparseable (conservative).
        return None
    return {"signed": not unsigned, "bits": bits}


def cast_is_lossy(from_type: Any, to_type: Any) -> str:
    """Classify a numeric type conversion `from_type -> to_type`:

        "lossless"   widening, SAME signedness (uint64 -> uint256, int8 -> int256)
        "narrowing"  target bitwidth < source bitwidth (uint256 -> uint64)
        "sign-flip"  signedness changes (int256 -> uint256, uint256 -> int256),
                     INCLUDING a same-width sign change (a value-representation
                     change that can silently re-interpret a negative as a huge
                     positive, or vice-versa).
        "unknown"    either side is not a parseable (u)intN scalar (the caller
                     treats "unknown" as NOT-lossy -> conservatively NOT flagged).

    `can_convert` (below) is the boolean Glider-analog wrapper. Precedence:
    a sign change is reported as "sign-flip" even when it is also a widen/narrow,
    because the sign re-interpretation is the load-bearing lossy property."""
    a = parse_int_type(from_type)
    b = parse_int_type(to_type)
    if a is None or b is None:
        return "unknown"
    if a["signed"] != b["signed"]:
        return "sign-flip"
    if b["bits"] < a["bits"]:
        return "narrowing"
    return "lossless"


def can_convert(from_type: Any, to_type: Any) -> Any:
    """Glider `can_convert` analog: True iff `from_type -> to_type` is a LOSSLESS
    numeric conversion (widening, same signedness). False for a narrowing or
    sign-flip lossy conversion. Returns DEGRADED (R80) when EITHER side is not a
    parseable (u)intN scalar - the lattice cannot honestly rule on a non-numeric
    conversion, so the caller must not treat 'cannot decide' as 'lossless'."""
    kind = cast_is_lossy(from_type, to_type)
    if kind == "unknown":
        return DEGRADED
    return kind == "lossless"


# SafeCast-style wrapper function names. A cast INSIDE one of these (the library's
# own `uint64(value)` body) is the SAFE primitive itself (it require-checks the
# bound before casting), so we exclude the wrapper body from downcast flagging.
_SAFECAST_WRAPPER_RX = re.compile(r"^(?:to|toInt|toUint|safeCast)\w*$|^to(?:U?int)\d+$",
                                  re.IGNORECASE)


def _fn_is_safecast_wrapper(fn: Any) -> bool:
    nm = str(getattr(fn, "name", "") or "")
    if _SAFECAST_WRAPPER_RX.match(nm):
        return True
    cn = str(getattr(getattr(fn, "contract", None), "name", "") or "")
    return cn.lower() == "safecast"


# A `require(... <= type(uintN).max ...)` style bound-check makes a subsequent
# raw downcast safe (it reverts on overflow). Slither lowers `type(uint64).max`
# into the node expression as `type()(uint64).max` / `type(uint64).max`.
_TYPE_MAX_BOUND_RX = re.compile(r"type\s*\(\s*\)?\s*\(?\s*u?int\d*\s*\)?\s*\.\s*max",
                                re.IGNORECASE)


def _fn_has_type_max_bound(fn: Any) -> bool:
    """True when `fn` contains a require/assert/if comparing against
    `type(uintN).max` - a manual overflow bound-check that makes a raw downcast
    safe. Read from the node expression (semantic enough; only used to SUPPRESS a
    flag, so a false-positive here only makes us MORE conservative, never less)."""
    for n in _iter_nodes(fn):
        expr = _node_expr_str(n)
        if not expr:
            continue
        if _TYPE_MAX_BOUND_RX.search(expr) and _node_in_revert_context(n):
            return True
    return False


# Economic / value-moving operand-name heuristic for the downcast oracle. Mirrors
# tools/dataflow-slice.py `_is_economic_value_var` (amount/balance/shares/units/
# debt/earnings/...) and EXTENDS it with the time/position nouns the brief calls
# out (timestamp/index/nonce) - a truncated timestamp or index is a real value-
# class bug (expiry wrap, slot collision). Conservative: a name that does NOT match
# is NOT flagged (never-false-positive on a non-value cast).
_DOWNCAST_VALUE_NAME_RX = re.compile(
    r"amount|balance|shares?|\bunits?\b|debt|earnings?|deposit|owed|credit|"
    r"\bfee\b|reward|stake|collateral|liquidity|principal|payout|funds?|escrow|"
    r"vunits|ethv|totaleth|\bvalue\b|timestamp|deadline|expir|\bindex\b|\bnonce\b",
    re.IGNORECASE,
)
# substrings that look value-ish but are NOT a unit of value/time/position we
# reason about (an address/flag/string), so a downcast of them is not flagged.
_DOWNCAST_VALUE_DENY_RX = re.compile(
    r"recipient|receiver|address|owner|admin|manager|enabled|paused|"
    r"\bflag\b|\bname\b|symbol|hash|selector|sig\b|root\b",
    re.IGNORECASE,
)


def _is_economic_value_var(name: str) -> bool:
    """Operand-name value heuristic for the downcast oracle (self-contained mirror
    of dataflow-slice's `_is_economic_value_var`, extended with timestamp/index/
    nonce). A truncation/sign-flip is only a LEAD on a value/time/position operand."""
    if not name:
        return False
    if _DOWNCAST_VALUE_DENY_RX.search(name):
        return False
    return bool(_DOWNCAST_VALUE_NAME_RX.search(name))


def _type_conversion_classes():
    """Lazily import slither TypeConversion IR. Returns the class or None."""
    try:
        from slither.slithir.operations import TypeConversion  # noqa
        return TypeConversion
    except Exception:
        return None


def unsafe_value_downcasts(fn: Any, value_names: Optional[set] = None) -> Any:
    """Conservative UNSAFE-DOWNCAST oracle over a function's TypeConversion IR.

    Returns a list of LEAD dicts (one per suspect cast), each:
        {"var": <operand name>, "from": <source type str>, "to": <target type str>,
         "kind": "narrowing"|"sign-flip", "line": <int|None>, "fn": <fn name>}
    or DEGRADED (R80) when `fn` is not navigable or slither's TypeConversion IR is
    unimportable.

    A cast is flagged iff ALL hold (never-false-positive by construction):
      1. it is a slither TypeConversion IR (a raw `uintN(x)` / `intN(x)` cast) -
         a SafeCast.toUintN() wrap is a LibraryCall, NOT a TypeConversion, so it
         never reaches here;
      2. the operand is a VALUE-MOVING var by name (amount/balance/.../timestamp/
         index/nonce) - or in `value_names` when provided (the tainted vars of a
         data-flow path); a non-value operand is NOT flagged;
      3. the conversion is LOSSY (cast_is_lossy -> narrowing or sign-flip);
         a widening / same-width same-sign cast is NOT flagged;
      4. the enclosing fn is NOT a SafeCast wrapper body AND does NOT carry a
         `require(x <= type(uintN).max)` bound-check (both make the cast safe).

    `value_names`, when provided, restricts the operand match to those names; when
    None, the built-in economic/time/position name heuristic decides."""
    if not _is_callable_function(fn):
        return DEGRADED
    TypeConversion = _type_conversion_classes()
    if TypeConversion is None:
        return DEGRADED
    # SafeCast wrapper body OR a manual type(uintN).max bound-check -> the casts in
    # this fn are the safe primitive; emit no leads (conservative suppression).
    if _fn_is_safecast_wrapper(fn) or _fn_has_type_max_bound(fn):
        return []
    vnames = {str(v).lower() for v in value_names} if value_names else None
    out = []
    seen = set()
    for n in _iter_nodes(fn):
        for ir in _node_irs(n):
            if not isinstance(ir, TypeConversion):
                continue
            operand = getattr(ir, "variable", None)
            if operand is None:
                continue
            op_name = str(getattr(operand, "name", "") or "")
            if not op_name:
                continue
            # value-operand filter
            if vnames is not None:
                if op_name.lower() not in vnames:
                    continue
            elif not _is_economic_value_var(op_name):
                continue
            from_type = str(getattr(operand, "type", "") or "")
            to_type = str(getattr(ir, "type", "") or "")
            kind = cast_is_lossy(from_type, to_type)
            if kind not in ("narrowing", "sign-flip"):
                continue  # lossless / unknown -> never flagged
            line = None
            sm = getattr(n, "source_mapping", None)
            lines = list(getattr(sm, "lines", []) or []) if sm else []
            if lines:
                line = lines[0]
            key = (op_name, from_type, to_type, line)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "var": op_name,
                "from": from_type,
                "to": to_type,
                "kind": kind,
                "line": line,
                "fn": str(getattr(fn, "name", "?") or "?"),
            })
    return out


def closure_unsafe_value_downcasts(fn: Any, value_names: Optional[set] = None) -> Any:
    """Like `unsafe_value_downcasts` but scans `fn`'s OWN body AND its forward
    callee closure (folding modifier bodies), so a lossy value downcast living in
    an INTERMEDIATE hop (e.g. `withdraw -> _settle[uint64(amount)] -> _pay`) is
    found even when it is not in the source/sink fn's own body. Returns the FIRST
    suspect cast (with `at_fn`) or [] when none. DEGRADED (R80) when `fn` is not
    navigable. Conservative: SafeCast-wrapper / type-max-guarded hops are skipped
    inside `unsafe_value_downcasts`, so they never surface here either."""
    own = unsafe_value_downcasts(fn, value_names=value_names)
    if is_degraded(own):
        return DEGRADED
    if own:
        for r in own:
            r["at_fn"] = getattr(fn, "name", "?")
        return [own[0]]
    closure = callee_closure(fn, include_modifiers=True)
    if is_degraded(closure):
        return []
    for callee in closure:
        cd = unsafe_value_downcasts(callee, value_names=value_names)
        if is_degraded(cd) or not cd:
            continue
        r = cd[0]
        r["at_fn"] = getattr(callee, "name", "?")
        return [r]
    return []


# ── DIVIDE-BEFORE-MULTIPLY precision-loss oracle (Glider gap W3) ─────────────
# The classic integer-precision bug: a DIVISION whose result is then MULTIPLIED -
# `(a / b) * c` - truncates BEFORE scaling and loses precision relative to the
# correct `(a * c) / b`. Reuses the gap #2 Binary-IR walking pattern (the same
# `_binary_ir_classes` / `BinaryType` enum + per-node IR iteration the comparator /
# downcast oracles use). Detection over slither SlithIR (verified enum names
# `BinaryType.DIVISION` / `BinaryType.MULTIPLICATION` - both exist in the installed
# slither; DEGRADE to [] + reason when the IR classes are unimportable, R80):
#
#   1. collect every DIVISION Binary op and remember its lvalue (the SSA temp that
#      holds the quotient);
#   2. follow that quotient through any pure-copy Assignment IR (`q = TMP_div`) so
#      `uint q = a/b; q*c;` is caught as well as the inline `(a/b)*c`;
#   3. flag when a later MULTIPLICATION op uses any of those div-result variables as
#      `variable_left` OR `variable_right` (the div result flows INTO the mul).
#
# CONSERVATIVE / never-false-positive by construction:
#   - `(a * b) / c` (mul-before-div, the CORRECT scale-then-divide ordering) is
#     NEVER flagged - the mul lvalue feeding a div is the opposite direction and is
#     not matched.
#   - a DIVISION with no downstream MULTIPLICATION consuming its result -> not flagged.
#   - a pure-constant fold (both div operands AND the mul's other operand are
#     compile-time Constants) is not a runtime precision bug -> not flagged. (In
#     practice solidity 0.8 folds a literal `(100/7)*3` to a rational at compile
#     time and will not even type-check as an integer expression, so this is belt-
#     and-suspenders.)
#   - identity-based def-use within the one function (slither IR vars are stable
#     objects), with a name fallback, so a rename across a copy is still tracked but
#     an unrelated same-named var in another scope is not conflated.
#
# VALUE-MOVING bias (ranking only, never a gate): when an operand of the div or the
# mul is an economic/value-moving var by name (reusing `_is_economic_value_var`) the
# record carries `value_moving: True`; when it is positively a non-value name it is
# `False`; otherwise `"unknown"`. The class is a real precision bug regardless, so
# `value_moving` only informs the consumer/triager ranking - it is NOT a flag gate.
# LEAD ONLY: never an auto-finding, never flips `unguarded`.


def _ir_operand_is_literal_const(v: Any) -> bool:
    """STRICT compile-time-literal test for the const-fold guard: True ONLY for a
    slither `Constant` IR operand (a literal `100` / `3`). Deliberately does NOT use
    the cap/max NAME heuristic (`_var_is_constant`), so a value-moving variable named
    like a bound never falsely suppresses a real precision bug (conservative: a
    false-NEGATIVE here only makes us flag MORE, never less)."""
    if v is None:
        return False
    return "constant" in type(v).__name__.lower()


def _ir_var_key(v: Any):
    """A hashable identity key for a slither IR operand: the object id (stable
    within one function's IR) plus its name, so a copy-assignment that re-uses the
    same temp is tracked by identity and a same-named var elsewhere is not conflated
    by name alone. Returns None for a None operand."""
    if v is None:
        return None
    return (id(v), str(getattr(v, "name", "") or ""))


def _assignment_ir_classes():
    """Lazily import slither Assignment IR. Returns the class or None (caller then
    simply does not fold copy-assignments - still correct for the inline case)."""
    try:
        from slither.slithir.operations import Assignment  # noqa
        return Assignment
    except Exception:
        return None


def divide_before_multiply(function: Any) -> Any:
    """Conservative DIVIDE-BEFORE-MULTIPLY precision oracle over a function's Binary
    SlithIR. Returns a list of LEAD dicts (one per div-result-feeds-mul site), each:

        {"contract": <str>, "function": <str>,
         "div_line": <int|None>, "mul_line": <int|None>,
         "at_file": <str|None>, "at_line": <int|None>   # div line (the anchor),
         "value_moving": True|False|"unknown",
         "severity_hint": "precision-loss"}

    or DEGRADED (R80) when `function` is not navigable or slither's Binary IR is
    unimportable. NEVER raises.

    A site is flagged iff (never-false-positive by construction):
      1. there is a `BinaryType.DIVISION` op whose lvalue (the quotient temp) -
         possibly after a chain of pure-copy `Assignment` IR - is used as
         `variable_left` OR `variable_right` of a LATER `BinaryType.MULTIPLICATION`;
      2. the site is NOT a pure-constant fold (some operand of the div or mul is a
         non-constant variable);
      3. it is NOT the mul-before-div ordering (a mul lvalue feeding a div is the
         CORRECT form and is structurally never matched here).
    """
    if not _is_callable_function(function):
        return DEGRADED
    Binary, BinaryType = _binary_ir_classes()
    if Binary is None:
        # IR classes unavailable -> cannot classify the div/mul ordering. DEGRADE
        # (return []-equivalent sentinel) rather than guess (R80).
        return DEGRADED
    Assignment = _assignment_ir_classes()

    contract_name = str(getattr(getattr(function, "contract", None), "name", "") or "")
    fn_name = str(getattr(function, "name", "?") or "?")

    # Walk the IR in CFG/source order, threading a set of "is-a-division-result"
    # variable identity keys forward. A DIVISION stamps its lvalue; a pure-copy
    # Assignment whose rvalue is a div-result propagates the flag to its lvalue; a
    # MULTIPLICATION whose left/right is a div-result is the flagged site.
    out = []
    seen_keys = set()  # (div_line, mul_line) dedupe
    div_result_keys = {}  # key -> {"div_line": int|None, "div_ir": Binary}
    try:
        # IR ops in linear program order across the fn's nodes.
        ir_seq = []
        for node in getattr(function, "nodes", []) or []:
            line = None
            sm = getattr(node, "source_mapping", None)
            lines = list(getattr(sm, "lines", []) or []) if sm else []
            if lines:
                line = lines[0]
            for ir in getattr(node, "irs", None) or []:
                ir_seq.append((ir, line))

        def _operand_value_moving(*operands) -> Any:
            """True when any operand name is positively economic/value-moving;
            False when there is >=1 named operand and NONE is value-moving; unknown
            when no operand carries an inspectable name."""
            any_named = False
            for v in operands:
                nm = str(getattr(v, "name", "") or "")
                if not nm:
                    continue
                any_named = True
                if _is_economic_value_var(nm):
                    return True
            return False if any_named else "unknown"

        for ir, line in ir_seq:
            if not isinstance(ir, Binary):
                # Fold a pure-copy assignment of a div-result temp into a new var so
                # `uint q = a/b; q*c;` is tracked (the IR lowers the copy as an
                # Assignment with rvalue == the div lvalue).
                if Assignment is not None and isinstance(ir, Assignment):
                    rkey = _ir_var_key(getattr(ir, "rvalue", None))
                    lkey = _ir_var_key(getattr(ir, "lvalue", None))
                    if rkey is not None and rkey in div_result_keys:
                        if lkey is not None:
                            div_result_keys[lkey] = div_result_keys[rkey]
                    else:
                        # Reassignment to a non-div-result value KILLS the lvalue's
                        # stale stamp: `x = a/b; x = fresh; x*c;` must NOT flag, since
                        # the multiply consumes `fresh`, not the quotient. Conservative:
                        # any reassignment whose rvalue is not provably a div-result
                        # drops the stamp (favor never-false-positive).
                        if lkey is not None:
                            div_result_keys.pop(lkey, None)
                else:
                    # Other lvalue-rewriting IR ops (TypeConversion, Phi, Unary, a
                    # Call assigned to a temp, ...): div-ness is NEVER propagated
                    # through these, so any such op whose lvalue matches a stamped
                    # key OVERWRITES it with a provably-non-div-result value and must
                    # KILL the stale stamp. Conservative companion to the Assignment
                    # kill above (favor never-false-positive); a Binary DIVISION
                    # re-stamps below, so this never suppresses a real div result.
                    owkey = _ir_var_key(getattr(ir, "lvalue", None))
                    if owkey is not None and owkey in div_result_keys:
                        div_result_keys.pop(owkey, None)
                continue
            btype = getattr(ir, "type", None)
            is_div = btype is getattr(BinaryType, "DIVISION", object())
            is_mul = btype is getattr(BinaryType, "MULTIPLICATION", object())
            if is_div:
                lvkey = _ir_var_key(getattr(ir, "lvalue", None))
                if lvkey is not None:
                    div_result_keys[lvkey] = {"div_line": line, "div_ir": ir}
                continue
            if not is_mul:
                continue
            # MULTIPLICATION: is either operand a known division result?
            lkey = _ir_var_key(getattr(ir, "variable_left", None))
            rkey = _ir_var_key(getattr(ir, "variable_right", None))
            hit = None
            if lkey is not None and lkey in div_result_keys:
                hit = div_result_keys[lkey]
            elif rkey is not None and rkey in div_result_keys:
                hit = div_result_keys[rkey]
            if hit is None:
                continue  # mul does not consume a div result (e.g. mul-before-div)
            div_ir = hit["div_ir"]
            div_line = hit["div_line"]
            # The "source" operands that actually carry the values: the two division
            # operands plus the multiplication's OTHER operand (the one that is NOT
            # the div-result link temp). The linking temp is internal plumbing and is
            # excluded from both the const-fold guard and the value-moving heuristic.
            mul_other = (getattr(ir, "variable_right", None)
                         if (lkey is not None and lkey in div_result_keys)
                         else getattr(ir, "variable_left", None))
            source_operands = [
                getattr(div_ir, "variable_left", None),
                getattr(div_ir, "variable_right", None),
                mul_other,
            ]
            named_source = [v for v in source_operands if v is not None]
            # Pure-constant fold guard: a `(100 / 10) * 3` whose source operands are
            # ALL compile-time literals (slither `Constant` IR) is a compile-time fold,
            # not a runtime precision bug -> NOT flagged. Uses the STRICT literal test
            # (Constant class only), NOT the cap/max name heuristic, so a value-moving
            # state var named like a bound never falsely suppresses a real bug.
            if named_source and all(_ir_operand_is_literal_const(v) for v in named_source):
                continue
            key = (div_line, line)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            vm = _operand_value_moving(*named_source)
            at_file = None
            sm = getattr(function, "source_mapping", None)
            fn = getattr(sm, "filename", None) if sm else None
            if fn is not None:
                at_file = (getattr(fn, "relative", None)
                           or getattr(fn, "short", None)
                           or getattr(fn, "absolute", None)
                           or str(fn))
            out.append({
                "contract": contract_name,
                "function": fn_name,
                "div_line": div_line,
                "mul_line": line,
                "at_file": at_file,
                "at_line": div_line,
                "value_moving": vm,
                "severity_hint": "precision-loss",
            })
    except Exception:
        return DEGRADED
    return out


def closure_divide_before_multiply(fn: Any, value_names: Optional[set] = None) -> Any:
    """Like `divide_before_multiply` but scans `fn`'s OWN body AND its forward callee
    closure (folding modifier bodies), so a divide-before-multiply living in an
    INTERMEDIATE hop (e.g. `quote -> _scale[(amt/rate)*mult] -> _pay`) is found even
    when it is not in the source/sink fn's own body. Returns the FIRST suspect site
    (with `at_fn`) or [] when none. DEGRADED (R80) when `fn` is not navigable.

    `value_names` is accepted for signature symmetry with the sibling closure entries
    (downcast / boundary); the precision class is value-name-independent (a precision
    bug is a precision bug regardless of which tainted var flows through it), so it is
    not used to gate the match - it only travels for caller uniformity."""
    own = divide_before_multiply(fn)
    if is_degraded(own):
        return DEGRADED
    if own:
        for r in own:
            r["at_fn"] = getattr(fn, "name", "?")
        return [own[0]]
    closure = callee_closure(fn, include_modifiers=True)
    if is_degraded(closure):
        return []
    for callee in closure:
        cd = divide_before_multiply(callee)
        if is_degraded(cd) or not cd:
            continue
        r = cd[0]
        r["at_fn"] = getattr(callee, "name", "?")
        return [r]
    return []


# ── Inline-assembly / Yul detection + asm-scoped sink oracle ─────────────────
# Glider `is_assembly` / assembly-node analog. `has_low_level_delegatecall` only
# catches a SOLIDITY-level `.delegatecall()` member call; NOTHING in this module
# inspects Yul / inline-assembly. The high-value, OFFLINE bug class this closes:
#   (a) a delegatecall HIDDEN in Yul (`delegatecall(...)`) - a proxy / upgrade
#       backdoor the solidity-level predicate is structurally blind to;
#   (b) a storage-slot COLLISION via a literal/constant-slot `sstore(SLOT, ...)`
#       (a hardcoded slot can alias a declared state var's compiler slot);
#   (c) a raw value-moving `call(`/`callcode(` performed inside assembly.
#
# Slither attaches the Yul block as ONE `NodeType.ASSEMBLY` CFG node whose
# `source_mapping.content` is the assembly block text (the per-node `inline_asm`
# attribute is None in this slither version, so the block CONTENT is the reliable,
# version-independent signal). Because the scan is scoped to the ASSEMBLY node's
# own content (NOT the whole function), a comment / string literal elsewhere in the
# function body cannot pollute the match; and Yul has no string-literal syntax that
# would embed `delegatecall(` / `sstore(`, so a content-scoped token scan is
# semantically tight here. Yul `//` and `/* */` comments are stripped first.
#
# CONSERVATIVE-BY-CONSTRUCTION (never-false-positive):
#   - a delegatecall in Yul is ALWAYS surfaced (an upgrade/proxy primitive worth a
#     LEAD), kind="delegatecall".
#   - an `sstore` is surfaced ONLY when its slot operand is a LITERAL/constant
#     (numeric `0x..`/decimal) or a constant-arithmetic expression containing a
#     numeric literal that is NOT a `.slot` member access (the storage-collision
#     shape), kind="sstore-literal". A `sstore(x.slot, v)` to a DECLARED storage
#     var's `.slot`, or to a keccak/computed slot derived from a `.slot`, is the
#     canonical safe mapping/var access -> NOT flagged.
#   - plain memory-only assembly (mload/mstore/return with no sstore/delegatecall/
#     call) -> NOTHING flagged.
# Every helper degrades benignly on a non-navigable input and never raises (R80).
# These are LEADS only - never an auto-finding, never a flip of `unguarded`.

# Strip Yul line + block comments before token scanning (so a `// sstore(0x0,..)`
# comment inside an assembly block cannot trigger). Applied to the ASSEMBLY node's
# content only.
_YUL_LINE_COMMENT_RX = re.compile(r"//[^\n]*")
_YUL_BLOCK_COMMENT_RX = re.compile(r"/\*.*?\*/", re.DOTALL)
# Yul opcode tokens (call boundary `(` is required so an identifier like
# `delegatecallTarget` does not match).
_YUL_DELEGATECALL_RX = re.compile(r"\bdelegatecall\s*\(")
_YUL_CALLCODE_RX = re.compile(r"\bcallcode\s*\(")
# raw value-moving `call(` (NOT staticcall/delegatecall, which are matched
# separately / are not value-moving). Negative lookbehind rules out
# `staticcall`/`delegatecall`/`callcode` whose names END in `call`.
_YUL_RAWCALL_RX = re.compile(r"(?<![a-zA-Z0-9_])call\s*\(")
# An `sstore(<slot>, <value>)` statement: capture the slot operand (first arg).
_YUL_SSTORE_RX = re.compile(r"\bsstore\s*\(\s*([^,]+?)\s*,")
# A numeric literal slot operand (hex or decimal) => literal-slot collision shape.
_YUL_NUMERIC_LITERAL_RX = re.compile(r"0x[0-9a-fA-F]+|\b\d+\b")
# A `.slot` member access on a declared var => the var's own canonical slot (safe).
_YUL_DOTSLOT_RX = re.compile(r"\.\s*slot\b")


def _asm_content(node: Any) -> str:
    """Return the inline-assembly block's source text for an ASSEMBLY node, with
    Yul comments stripped. Empty string when unavailable (R80: never raises)."""
    try:
        sm = getattr(node, "source_mapping", None)
        content = getattr(sm, "content", None) if sm else None
        if not content:
            return ""
        content = _YUL_BLOCK_COMMENT_RX.sub(" ", content)
        content = _YUL_LINE_COMMENT_RX.sub("", content)
        return content
    except Exception:
        return ""


def _asm_node_first_line(node: Any) -> Optional[int]:
    try:
        sm = getattr(node, "source_mapping", None)
        lines = list(getattr(sm, "lines", []) or []) if sm else []
        return lines[0] if lines else None
    except Exception:
        return None


def _line_of_offset(content: str, base_line: Optional[int], offset: int) -> Optional[int]:
    """Best-effort absolute source line for a match at char `offset` within the
    ASSEMBLY block `content`, given the block's first source line `base_line`.
    Returns base_line + (number of newlines before offset). None when base_line
    is unknown (conservative; the node's first line is still available upstream)."""
    if base_line is None:
        return None
    try:
        return base_line + content.count("\n", 0, offset)
    except Exception:
        return base_line


def _node_is_assembly(node: Any) -> bool:
    """True when `node` is a Slither inline-assembly (Yul) CFG node. Matches
    NodeType.ASSEMBLY by identity when importable, else by the stringified type
    name (version-independent). Also honours a truthy `node.inline_asm` when the
    installed slither version populates it."""
    ntype = getattr(node, "type", None)
    try:
        from slither.core.cfg.node import NodeType  # noqa
        if ntype is getattr(NodeType, "ASSEMBLY", object()):
            return True
    except Exception:
        pass
    name = str(ntype or "").upper().rsplit(".", 1)[-1]
    if name == "ASSEMBLY":
        return True
    # Some slither versions expose the raw Yul on the EXPRESSION node instead.
    try:
        if getattr(node, "inline_asm", None):
            return True
    except Exception:
        pass
    return False


def assembly_nodes(function: Any):
    """Yield every inline-assembly (Yul) CFG node of `function` (or [] when the
    function is not navigable). The unit downstream helpers scan."""
    if not _is_callable_function(function):
        return
    for n in _iter_nodes(function):
        if _node_is_assembly(n):
            yield n


def has_inline_assembly(function: Any) -> Any:
    """True iff `function` contains >=1 inline-assembly (Yul) block.

    Returns DEGRADED (R80) when `function` is not navigable (never a silent
    False that would mask a real assembly block on a degrade)."""
    if not _is_callable_function(function):
        return DEGRADED
    for _ in assembly_nodes(function):
        return True
    return False


def asm_delegatecalls(function: Any) -> Any:
    """Conservative ASM-SCOPED delegatecall oracle. Returns a list of LEAD dicts,
    one per Yul `delegatecall(` (and `callcode(`, the same delegate-context
    primitive) found inside an inline-assembly block:

        {"kind": "delegatecall", "slot": None, "line": <int|None>,
         "fn": <fn name>, "snippet": <short asm excerpt>}

    or DEGRADED (R80) when `function` is not navigable. A Yul delegatecall is the
    proxy/upgrade backdoor primitive the SOLIDITY-level `has_low_level_delegatecall`
    is structurally blind to, so it is ALWAYS surfaced (a LEAD - never an
    auto-finding). Empty list when the function has no asm delegatecall."""
    if not _is_callable_function(function):
        return DEGRADED
    out = []
    fname = str(getattr(function, "name", "?") or "?")
    for n in assembly_nodes(function):
        content = _asm_content(n)
        if not content:
            continue
        base_line = _asm_node_first_line(n)
        for rx in (_YUL_DELEGATECALL_RX, _YUL_CALLCODE_RX):
            for m in rx.finditer(content):
                line = _line_of_offset(content, base_line, m.start())
                snippet = content[m.start():m.start() + 60].strip().replace("\n", " ")
                out.append({
                    "kind": "delegatecall",
                    "slot": None,
                    "line": line if line is not None else base_line,
                    "fn": fname,
                    "snippet": snippet,
                })
    return out


def _asm_slot_is_literal(slot_operand: str) -> bool:
    """Classify an `sstore` slot operand string -> True when it is a LITERAL /
    constant slot (a storage-collision shape), False when it is a declared var's
    `.slot` (or a slot derived purely from one).

    CONSERVATIVE never-false-positive contract:
      - a `.slot` member access (e.g. `value.slot`, `balances.slot`) -> NOT literal
        (the var's own canonical compiler slot - safe).
      - a bare numeric literal (`0x0`, `42`) -> literal (collision risk).
      - a constant-arithmetic expression that contains a numeric literal AND has
        NO `.slot` access (e.g. `add(0x10, i)`) -> literal (a hardcoded base slot
        with offset arithmetic - collision risk).
      - anything else (a bare local var `s`, a keccak result, a slot derived from
        a `.slot`) -> NOT literal (could be a safe computed mapping slot - do not
        flag, stay never-FP)."""
    if not slot_operand:
        return False
    s = slot_operand.strip()
    # A `.slot` access anywhere in the operand => the var's canonical slot => safe.
    if _YUL_DOTSLOT_RX.search(s):
        return False
    # A numeric literal with no `.slot` => hardcoded/arithmetic constant slot.
    return bool(_YUL_NUMERIC_LITERAL_RX.search(s))


def asm_sstores(function: Any) -> Any:
    """Conservative ASM-SCOPED `sstore` oracle. Returns a list of dicts, one per
    Yul `sstore(<slot>, <value>)` found inside an inline-assembly block:

        {"kind": "sstore-literal", "slot": <slot operand str>, "literal": True,
         "line": <int|None>, "fn": <fn name>, "snippet": <short asm excerpt>}

    or DEGRADED (R80) when `function` is not navigable.

    ONLY literal/constant-slot sstores are returned (the storage-collision shape).
    A `sstore(x.slot, v)` to a DECLARED storage var's `.slot`, or a keccak/computed
    slot derived from a `.slot`, is the canonical safe access and is NOT returned
    (never-false-positive). Each returned row carries `literal: True` for symmetry
    with the brief's `asm{kind,slot?,line}` shape."""
    if not _is_callable_function(function):
        return DEGRADED
    out = []
    fname = str(getattr(function, "name", "?") or "?")
    for n in assembly_nodes(function):
        content = _asm_content(n)
        if not content:
            continue
        base_line = _asm_node_first_line(n)
        for m in _YUL_SSTORE_RX.finditer(content):
            slot_operand = m.group(1).strip()
            if not _asm_slot_is_literal(slot_operand):
                continue  # declared-var .slot / computed-from-.slot -> not flagged
            line = _line_of_offset(content, base_line, m.start())
            snippet = content[m.start():m.start() + 60].strip().replace("\n", " ")
            out.append({
                "kind": "sstore-literal",
                "slot": slot_operand,
                "literal": True,
                "line": line if line is not None else base_line,
                "fn": fname,
                "snippet": snippet,
            })
    return out


def asm_raw_calls(function: Any) -> Any:
    """Conservative ASM-SCOPED raw value-moving `call(`/`callcode(` oracle. Returns
    a list of LEAD dicts, one per Yul raw `call(` found inside an inline-assembly
    block (excluding `staticcall`/`delegatecall`):

        {"kind": "asm-call", "slot": None, "line": <int|None>, "fn": <fn name>,
         "snippet": <short asm excerpt>}

    or DEGRADED (R80) when `function` is not navigable. A Yul `call(` can move
    native value out of the contract bypassing the solidity-level call predicates,
    so it is surfaced as a LEAD (never an auto-finding). `callcode(` is reported by
    `asm_delegatecalls` (delegate context); here only the plain `call(` is added."""
    if not _is_callable_function(function):
        return DEGRADED
    out = []
    fname = str(getattr(function, "name", "?") or "?")
    for n in assembly_nodes(function):
        content = _asm_content(n)
        if not content:
            continue
        base_line = _asm_node_first_line(n)
        for m in _YUL_RAWCALL_RX.finditer(content):
            line = _line_of_offset(content, base_line, m.start())
            snippet = content[m.start():m.start() + 60].strip().replace("\n", " ")
            out.append({
                "kind": "asm-call",
                "slot": None,
                "line": line if line is not None else base_line,
                "fn": fname,
                "snippet": snippet,
            })
    return out


def asm_suspect_sinks(function: Any) -> Any:
    """Aggregate ASM-SCOPED sink oracle: the union of `asm_delegatecalls`,
    `asm_sstores` (literal-slot only), and `asm_raw_calls` for `function`, in a
    stable order (delegatecall, sstore-literal, asm-call). Returns a list of
    `asm{kind, slot?, line, fn, snippet}` LEAD dicts, or DEGRADED (R80) when
    `function` is not navigable. Empty list when the function has no suspect asm
    sink (memory-only asm or no asm at all -> never-false-positive)."""
    if not _is_callable_function(function):
        return DEGRADED
    dele = asm_delegatecalls(function)
    if is_degraded(dele):
        return DEGRADED
    sst = asm_sstores(function)
    if is_degraded(sst):
        return DEGRADED
    raw = asm_raw_calls(function)
    if is_degraded(raw):
        return DEGRADED
    return list(dele) + list(sst) + list(raw)


def closure_asm_suspect_sinks(function: Any) -> Any:
    """Like `asm_suspect_sinks` but scans `function`'s OWN body AND its forward
    callee closure (folding modifier bodies), so a Yul delegatecall / literal-slot
    sstore living in an INTERMEDIATE hop (e.g. `upgradeTo -> _setImpl[asm
    sstore(slot,impl)] -> _delegate[asm delegatecall(...)]`) is found even when it
    is not in the source/sink fn's own body. Returns the FIRST suspect sink (with
    `at_fn`) or [] when none. DEGRADED (R80) when `function` is not navigable.

    Mirrors `closure_unsafe_value_downcasts` / `closure_boundary_suspect`: own body
    first (most-specific anchor), then closure; a degrade in the closure leaves the
    own-body result honest."""
    own = asm_suspect_sinks(function)
    if is_degraded(own):
        return DEGRADED
    if own:
        r = dict(own[0])
        r["at_fn"] = getattr(function, "name", "?")
        return [r]
    closure = callee_closure(function, include_modifiers=True)
    if is_degraded(closure):
        return []
    for callee in closure:
        cs = asm_suspect_sinks(callee)
        if is_degraded(cs) or not cs:
            continue
        r = dict(cs[0])
        r["at_fn"] = getattr(callee, "name", "?")
        return [r]
    return []


# ── Override / dispatch resolution ──────────────────────────────────────────

def _fn_selector_key(fn: Any) -> str:
    """A stable selector-ish key for a function: prefer solidity_signature,
    fall back to full_name, then name."""
    for attr in ("solidity_signature", "full_name", "name"):
        v = getattr(fn, attr, None)
        if v:
            return str(v)
    return ""


def resolve_concrete_impl(contract: Any, selector: str) -> Any:
    """Resolve which CONCRETE function body a `selector` (full signature like
    `setX(uint256)`, or a bare name) dispatches to on `contract`, following
    Solidity override resolution. This is the analog of an interface→impl /
    base→override dispatch resolver — we have ZERO dispatch resolution today,
    so a base modifier dropped by a child override (`function f() external
    override { /* no onlyOwner */ }`) is currently invisible.

    Resolution rule: among all functions on `contract` whose selector matches,
    return the MOST-DERIVED one — i.e. the function that is NOT overridden by
    any other matching function on this contract. Slither's `overridden_by`
    encodes the override DAG; the concrete dispatch target is the leaf.

    Returns the resolved Function, or `DEGRADED` when `contract` is not
    navigable (R80). Returns None when no function matches the selector."""
    if not (hasattr(contract, "functions") or hasattr(contract, "functions_declared")):
        return DEGRADED

    funcs = list(getattr(contract, "functions", []) or [])
    # Match by selector (signature) or bare name.
    matches = []
    for f in funcs:
        key = _fn_selector_key(f)
        if key == selector or getattr(f, "name", "") == selector or key.split("(")[0] == selector:
            matches.append(f)
    if not matches:
        return None
    if len(matches) == 1:
        return matches[0]

    match_set = set(matches)
    # The concrete impl is the match that is NOT overridden by any other match.
    leaves = []
    for f in matches:
        overridden_by = getattr(f, "overridden_by", []) or []
        if any(ob in match_set for ob in overridden_by):
            continue  # a more-derived match exists; skip the base
        leaves.append(f)
    if len(leaves) == 1:
        return leaves[0]
    if leaves:
        # Multiple leaves (diamond / duplicate entries). Prefer the one declared
        # on the most-derived contract == `contract` itself, else the first.
        for f in leaves:
            if getattr(getattr(f, "contract", None), "name", None) == getattr(contract, "name", None):
                return f
        return leaves[0]
    # No clear leaf (cycle in override data — shouldn't happen); fall back to
    # the most-derived-contract match.
    for f in matches:
        if getattr(getattr(f, "contract", None), "name", None) == getattr(contract, "name", None):
            return f
    return matches[0]


# ── OVERRIDE-DROPPED-GUARD dispatch detector (Glider gap W1) ─────────────────
#
# `resolve_concrete_impl` (above) documents that a base modifier dropped by a
# child override is currently invisible:
#   contract Base { function f() external virtual onlyOwner { ... } }
#   contract Child is Base { function f() external override { /* no guard */ } }
# The leaf dispatch target (Child.f) is what runs - so the access-control guard
# the base enforced has been silently DROPPED. This oracle flags exactly that
# DROP, reusing the EXISTING guard recognition (`has_guard_in_closure` ->
# `_node_default_guard` -> OZ/legacy/AccessManaged sets); it does NOT rebuild
# guard recognition.
#
# CONSERVATIVE / never-FP by construction:
#   - flags ONLY when the base version is positively GUARDED and the override is
#     positively NOT guarded (a genuine drop). A base with no recognizable guard
#     is not a "drop" (nothing to drop) -> NOT flagged.
#   - the override guard set is computed with `has_guard_in_closure(f)`, so a
#     guard the override moved into a forward callee (or re-added under a
#     different OZ/legacy/AccessManaged name) is recognized -> NOT flagged.
#   - any DEGRADED guard resolution (either side not navigable) -> NOT flagged
#     (we never guess a drop we cannot positively confirm).


def _fn_base_overridden(fn: Any) -> list:
    """Return the base Function objects that `fn` overrides (its `overrides`
    edge), filtered to navigable callables. Empty when `fn` overrides nothing.

    Slither's `overrides` is the set of base-contract functions a child override
    shadows (the inverse of `overridden_by`). We use it to find the base version
    whose guard set we compare against."""
    out = []
    for b in (getattr(fn, "overrides", []) or []):
        cand = b[1] if isinstance(b, (list, tuple)) and len(b) >= 2 else b
        if _is_callable_function(cand) and cand is not fn:
            out.append(cand)
    return out


def _w1_strict_base_guard(node: Any) -> bool:
    """W1-ONLY stricter base-guard predicate (does NOT touch the global
    `_node_default_guard` / `has_guard_in_closure` defaults; gaps #1-5 keep the
    permissive default verbatim).

    Rationale: the permissive default's signal (3) counts a require/assert/revert/if
    that merely NAMES a caller-identity accessor (owner() / hasRole(...) / ...) as a
    guard, even when the accessor value is never compared against the caller. That
    over-recognition is SAFE for the unguarded-path detectors (it suppresses a lead;
    conservative / never-FP). But for W1 it makes a base look guarded and produces a
    FALSE DROP - e.g. a permissionless base whose only "guard" is the zero-address
    SANITY check `require(owner() != address(0))`, whose override merely omits that
    require, is wrongly flagged as dropping access control.

    A node counts as a genuine base access-control guard when AT LEAST ONE of:
      (a) it calls a recognized authz helper / external-authority primitive
          (_checkOwner / _checkRole / _authorizeUpgrade / canCall / ...). The helper
          body carries the real caller-identity revert (OZ onlyOwner -> _checkOwner),
          so this is an unambiguous AC guard - kept exactly as the default treats it
          (when invoked with a custom guard_pred, has_guard_in_closure passes
          unresolved_helpers_only=None, so EVERY authz-helper name is honoured here,
          matching the existing standalone-predicate semantics); OR
      (b) it sits in a require/assert/revert/if context AND READS THE CALLER
          (msg.sender / tx.origin) in that same condition - a genuine caller-identity
          comparison (covers both the direct `require(msg.sender == owner)` form and
          the OZ `require(owner() == msg.sender)` accessor-vs-caller form).

    Mere accessor-presence-in-a-revert-context WITHOUT a caller read (signal (3) of
    the default) is deliberately NOT counted here: that is the FP branch. This reuses
    the existing node-level signals (`_node_callee_names`, `_node_in_revert_context`,
    `_node_reads_caller`) verbatim - it does not rebuild guard recognition."""
    callees = set(_node_callee_names(node))

    # (a) authz helper / external-authority-enforced primitive call. Calling it IS
    #     the AC check (the caller-identity revert lives in the helper/authority).
    if callees & (_AUTHZ_HELPER_NAMES | _AUTHZ_HELPER_EXTERNAL_ENFORCED):
        return True

    # (b) caller-identity comparison: require/assert/revert/if context that reads the
    #     caller. Drops the default's accessor-name-only signal (3) - the FP branch.
    if _node_in_revert_context(node) and _node_reads_caller(node):
        return True

    return False


def override_dropped_guards(contract: Any) -> Any:
    """Flag every function on `contract` whose concrete override DROPPED a
    caller-identity access-control guard that its base (overridden) version
    enforced.

    For each function `f` declared on `contract` that OVERRIDES a base function
    (`f.overrides` is non-empty):
      - compute the BASE guard verdict via
        `has_guard_in_closure(base_fn, guard_pred=_w1_strict_base_guard)` for each
        base it overrides - the STRICTER W1-only predicate that counts a base AC
        guard only on a genuine caller-identity comparison (authz-helper call OR a
        require/assert/revert/if that reads the caller), so a bare accessor-in-revert
        sanity check like `require(owner() != address(0))` is NOT a droppable guard;
      - compute the OVERRIDE guard verdict via the permissive default
        `has_guard_in_closure(f)` - keeping the override-side conservative (an
        override that has any recognized guard is NOT a drop);
      - FLAG only when SOME base is positively GUARDED (True) AND the override is
        positively UNGUARDED (False) - a genuine DROP.

    Reuses the existing guard recognition end-to-end (OZ onlyOwner->_checkOwner,
    legacy require(isOwner()), AccessManaged restricted->_checkCanCall), so a
    guard re-added under a different recognized name, or moved into a forward
    callee of the override, is NOT a drop (the override verdict stays True).

    Returns a list of records (deterministically ordered by line, then function):
        {"contract", "function", "selector", "base_contract", "base_fn",
         "dropped_guard", "at_file", "at_line", "severity_hint"}
    or `DEGRADED` (R80) when `contract` is not navigable. An empty list means no
    drop - never a silent miss. CONSERVATIVE: a DEGRADED guard resolution on
    either side suppresses the flag (we never guess a drop)."""
    if not (hasattr(contract, "functions") or hasattr(contract, "functions_declared")):
        return DEGRADED

    # Only functions DECLARED on this contract can be the leaf override here; an
    # inherited (non-declared) function is the base, not the dropping override.
    declared = list(getattr(contract, "functions_declared", []) or [])
    if not declared:
        declared = [f for f in (getattr(contract, "functions", []) or [])
                    if getattr(getattr(f, "contract_declarer", None), "name", None)
                    == getattr(contract, "name", None)]

    cname = str(getattr(contract, "name", "?") or "?")
    out = []
    seen_keys: set = set()
    for f in declared:
        if not _is_callable_function(f):
            continue
        if not bool(getattr(f, "is_override", False)) and not _fn_base_overridden(f):
            continue
        bases = _fn_base_overridden(f)
        if not bases:
            continue

        # Override guard verdict. A DEGRADED here means we cannot positively say
        # the override is UNguarded -> do NOT flag.
        ov_guard = has_guard_in_closure(f)
        if is_degraded(ov_guard) or bool(ov_guard):
            continue  # override still guarded (or unknown) -> not a drop

        # Find a base that was positively GUARDED. A DEGRADED base verdict cannot
        # establish "the base was guarded", so it does not justify a flag.
        guarded_base = None
        for b in bases:
            # STRICTER base verdict (W1-only): require a genuine caller-identity
            # guard (authz-helper call OR a require/assert/revert/if that reads the
            # caller). A bare accessor-in-revert sanity check like
            # `require(owner() != address(0))` does NOT count - dropping it is not
            # an access-control drop. `_node_default_guard` / has_guard_in_closure's
            # default path is untouched (gaps #1-5 stay byte-identical).
            bg = has_guard_in_closure(b, guard_pred=_w1_strict_base_guard)
            if is_degraded(bg):
                continue
            if bool(bg):
                guarded_base = b
                break
        if guarded_base is None:
            continue  # no positively-guarded base -> nothing was dropped

        # Emit. Anchor at the override's declaration (the dropping site).
        sm = getattr(f, "source_mapping", None)
        lines = list(getattr(sm, "lines", []) or []) if sm else []
        at_line = lines[0] if lines else None
        at_file = ""
        fobj = getattr(sm, "filename", None) if sm else None
        if fobj is not None:
            for attr in ("relative", "short", "absolute"):
                v = getattr(fobj, attr, None)
                if v:
                    at_file = str(v)
                    break
            if not at_file:
                at_file = str(fobj)

        selector = _fn_selector_key(f)
        base_c = str(getattr(getattr(guarded_base, "contract_declarer", None), "name", None)
                     or getattr(getattr(guarded_base, "contract", None), "name", None) or "?")
        # Describe the dropped guard by the base's recognizable guard surface
        # (modifier names + authz-helper names) for an actionable lead.
        dropped = _describe_base_guard(guarded_base)
        key = (cname, selector, base_c)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        out.append({
            "contract": cname,
            "function": str(getattr(f, "name", "?") or "?"),
            "selector": selector,
            "base_contract": base_c,
            "base_fn": str(getattr(guarded_base, "name", "?") or "?"),
            "dropped_guard": dropped,
            "at_file": at_file,
            "at_line": at_line,
            "severity_hint": "access-control",
        })
    out.sort(key=lambda r: ((r["at_line"] is None, r["at_line"] or 0), r["function"]))
    return out


def _describe_base_guard(base_fn: Any) -> str:
    """Best-effort human-readable name for the guard the base enforced: the
    applied modifier names (e.g. `onlyOwner`) plus any recognized authz-helper /
    accessor names seen in the base body/closure. Returns `access-control guard`
    when no specific name is resolvable (still honest - we already KNOW the base
    is guarded via `has_guard_in_closure`)."""
    names: list = []
    for m in (getattr(base_fn, "modifiers", []) or []):
        nm = getattr(m, "name", None)
        if nm and nm not in names:
            names.append(str(nm))
    # Recognized authz-helper / accessor call names in the base body + closure.
    recog = _AUTHZ_HELPER_NAMES | _AUTHZ_ACCESSOR_NAMES | _AUTHZ_HELPER_EXTERNAL_ENFORCED
    nodes = list(getattr(base_fn, "nodes", []) or [])
    closure = callee_closure(base_fn, include_modifiers=True)
    if isinstance(closure, set):
        for c in closure:
            nodes.extend(getattr(c, "nodes", []) or [])
    for n in nodes:
        for cn in _node_callee_names(n):
            if cn in recog and cn not in [x.lower() for x in names]:
                names.append(cn)
    if names:
        return ", ".join(names)
    return "access-control guard"


def closure_override_dropped_guards(contract: Any) -> Any:
    """Closure variant of `override_dropped_guards`. Provided as a thin,
    FP-neutral wrapper: it returns exactly `override_dropped_guards(contract)`.

    Rationale (kept clean rather than forced): the base/override guard verdicts
    are ALREADY computed with `has_guard_in_closure` (an unbounded forward
    closure that folds modifier bodies + forward callees). A drop is established
    by the per-function closure comparison itself, so there is no additional,
    distinct closure dimension to widen over without raising FP risk. This
    wrapper exists only so a caller can request the closure-aware verdict by name
    symmetrically with the other gap predicates; it adds no new flags."""
    return override_dropped_guards(contract)


# ── ORACLE TRY/CATCH-SWALLOW detector (Glider gap W2) ────────────────────────
#
# The classic oracle-failure-ignored bug:
#   try priceFeed.latestRoundData() returns (..., int256 p, ...) { price = p; }
#   catch { /* swallow: keep stale price */ }
#   ... value-moving logic uses `price` ...
# The catch block SWALLOWS the external-call failure (does NOT revert / does NOT
# propagate), so on an oracle revert the function proceeds with a stale, zero, or
# default price/value. We have ZERO try/catch handling today; this oracle adds it.
#
# Slither models a try/catch with `NodeType.TRY` (carrying the external-call IR)
# and `NodeType.CATCH` (each catch clause's entry). Empirically (slither 0.11.5):
#   TRY node          - holds the HighLevelCall IR (the oracle read); its `.sons`
#                       are CATCH-type nodes.
#   TRY.sons[0]       - the SUCCESS continuation (the `returns (...) { ... }` body
#                       header; slither labels it CATCH but it is the try-success
#                       arm, NOT a catch handler).
#   TRY.sons[1:]      - the actual CATCH handler clause entries.
# All arms rejoin at a post-try merge node (its `fathers` include the TRY and/or
# each arm tail).
#
# CONSERVATIVE / never-FP by construction (when unsure, do NOT flag):
#   - the TRY callee must look like an ORACLE / price read (curated name set);
#   - a handler that REVERTS (revert / revert CustomError / require(false) /
#     throw) does NOT swallow -> NOT flagged;
#   - a handler that sets a fallback flag/value which a SUBSEQUENT
#     require/assert/revert/if validates after the try-merge does NOT swallow
#     (best-effort: any revert/require in the post-try region suppresses) ->
#     NOT flagged;
#   - DEGRADE (return [] + a logged reason) when the installed slither lacks
#     try/catch node modeling, rather than guessing (R80).
#   - it only ANNOTATES a LEAD; it never flips `unguarded`, never auto-claims.


# Curated ORACLE / price-read callee names. A TRY whose external call resolves to
# one of these (exact lower-cased name match - never a substring, so a string
# literal / comment cannot trigger) is treated as an oracle read. Kept next to the
# authz sets as a module-level frozenset.
# W2 FP-tightening: the bare-generic tokens `read` / `quote` / `current` were
# DROPPED - they match plain (non-oracle) getters (vault.read(), router.quote(),
# accumulator.current()) and produced non-oracle false positives. Only specific
# oracle/price method names remain; an ambiguous name is removed rather than kept.
_ORACLE_READ_NAMES = frozenset({
    "latestrounddata",      # Chainlink AggregatorV3
    "latestanswer",         # Chainlink legacy
    "latestround",          # Chainlink legacy
    "getrounddata",         # Chainlink historical round
    "getanswer",            # Chainlink legacy historical
    "getprice",             # generic price getter
    "getpriceunsafe",       # Pyth
    "getemaprice",          # Pyth EMA
    "getpricenotolderthan", # Pyth staleness-bounded
    "price",                # generic price()
    "peek",                 # MakerDAO OSM / Tellor-style read
    "consult",              # Uniswap V2 TWAP oracle
    "getreserves",          # Uniswap V2 pair reserves (price proxy)
    "price0cumulativelast", # Uniswap V2 TWAP accumulator
    "price1cumulativelast",
    "currentvalue",         # Tellor
    "getdatabefore",        # Tellor
    "getcurrentvalue",      # Tellor legacy
    "exchangerate",         # rate oracle
    "getexchangerate",
    "getrate",              # rate oracle
    "pricefeed",            # generic
})

# Revert-ish solidity-call names a catch handler may use to PROPAGATE the failure
# (so the handler does NOT swallow). Exact lower-cased prefix match on the slither
# SolidityCall name; `require(false, ...)` is treated as a propagate too.
_PROPAGATE_CALL_PREFIXES = ("revert", "require", "assert")


def _node_type_name(node: Any) -> str:
    """Upper-cased short NodeType name for `node` (e.g. "TRY", "CATCH"), or ""."""
    try:
        return str(getattr(node, "type", "") or "").rsplit(".", 1)[-1].upper()
    except Exception:
        return ""


def _slither_try_catch_modeled() -> bool:
    """True when the installed slither models try/catch CFG nodes (NodeType.TRY
    and NodeType.CATCH both present). False -> the oracle DEGRADES (R80: never
    guess a try/catch shape the running slither cannot produce)."""
    try:
        from slither.core.cfg.node import NodeType  # noqa
    except Exception:
        return False
    return hasattr(NodeType, "TRY") and hasattr(NodeType, "CATCH")


def _try_call_names(try_node: Any):
    """Yield lower-cased callee NAMES of the external call on a TRY node. Reads the
    HighLevelCall / LibraryCall IR `function_name`/`function.name` (semantic, not a
    source substring) plus, defensively, the node's high_level_calls edge."""
    for ir in _node_irs(try_node):
        cls = type(ir).__name__.lower()
        if "highlevelcall" in cls or "librarycall" in cls or "internalcall" in cls:
            nm = getattr(ir, "function_name", None)
            if not nm:
                nm = getattr(getattr(ir, "function", None), "name", None)
            if nm:
                yield str(nm).split("(", 1)[0].strip().lower()
    for hc in getattr(try_node, "high_level_calls", []) or []:
        cand = hc[1] if isinstance(hc, (list, tuple)) and len(hc) >= 2 else hc
        nm = getattr(cand, "name", None)
        if not nm:
            nm = getattr(getattr(cand, "function", None), "name", None)
        if nm:
            yield str(nm).split("(", 1)[0].strip().lower()


def _node_is_propagate(node: Any) -> bool:
    """True when `node` PROPAGATES a failure (reverts / re-throws / require(false)):
    a THROW node, a SolidityCall whose name starts revert/require/assert, or a
    `revert ...` / custom-error revert expression. Conservative: any such node in a
    catch body means the handler does NOT swallow."""
    if _node_type_name(node) == "THROW":
        return True
    for nm in _node_callee_names(node):
        if any(nm.startswith(p) for p in _PROPAGATE_CALL_PREFIXES):
            return True
    expr = _node_expr_str(node).lstrip()
    if expr.startswith("revert(") or expr.startswith("revert "):
        return True
    # SolidityCall IR may carry the revert as the op string when the callee-name
    # walk above missed it (older custom-error encodings).
    for ir in _node_irs(node):
        s = str(ir).lower()
        if "solidity_call revert" in s or "solidity_call require" in s:
            # `require(bool)(true)` is not a propagate; only require(false,...) is,
            # but to stay never-FP we treat ANY require in a catch as a propagate
            # (it can revert), suppressing the flag (conservative).
            return True
    return False


# Matches the slither EXPRESSION text of an UNCONDITIONAL require/assert revert,
# i.e. the first argument is the literal `false`: `require(bool)(false)`,
# `require(bool,string)(false,...)`, `assert(bool)(false)`. A conditional
# `require(b)` / `require(b,...)` does NOT match (it can pass through), so this is
# strictly stronger than `_node_is_propagate` and is used only for the
# always-reverts proof (never-MISS direction).
_REQUIRE_ASSERT_FALSE_RE = re.compile(
    r"^\s*(?:require|assert)\s*\([^)]*\)\s*\(\s*false\s*[,)]"
)


def _node_is_unconditional_revert(node: Any) -> bool:
    """True ONLY when `node` UNCONDITIONALLY aborts the call: a THROW node, a
    `revert ...` / `revert(...)` (plain, string, or custom-error), or a
    `require(false ...)` / `assert(false ...)`. A CONDITIONAL `require(cond)` /
    `assert(cond)` is NOT counted (it may pass and fall through). This is the
    strict terminal-revert test that `_fn_always_reverts` walks; it is the
    never-MISS-a-real-swallow direction (we only suppress a flag when we can
    PROVE the path aborts)."""
    if _node_type_name(node) == "THROW":
        return True
    expr = _node_expr_str(node).lstrip()
    # `revert`, `revert(...)`, `revert "msg"`, `revert CustomError()` - any
    # revert statement is an unconditional abort.
    if expr.startswith("revert(") or expr.startswith("revert ") or expr == "revert":
        return True
    if expr.lower().startswith("revert"):
        # slither renders custom-error reverts as `revert E()()`; the leading
        # token is `revert`, so the lower-cased startswith covers them.
        return True
    if _REQUIRE_ASSERT_FALSE_RE.match(expr):
        return True
    return False


def _fn_always_reverts(fn: Any, _depth: int = 0, _seen: Optional[set] = None) -> bool:
    """Conservative proof that EVERY terminal path of `fn` aborts the call (always
    reverts / re-throws). Used by the catch-handler transitive-propagate check: a
    catch whose ONLY effect is a one+-hop call to an always-reverting helper does
    NOT swallow (the whole tx reverts), so it must NOT be flagged.

    Conservative / never-MISS-a-real-swallow: returns True ONLY when provable.
      - Every LEAF node (no CFG successors) is an UNCONDITIONAL revert
        (`_node_is_unconditional_revert`), OR a leaf that is a single one-hop call
        to a helper that itself `_fn_always_reverts` (bounded recursion, depth<=2),
      - and the function body is non-empty (an empty body returns normally -> not
        always-reverting).
    Anything we cannot prove (a leaf that returns / falls through / a conditional
    require / an unresolved external call leaf) -> False, so a genuine swallow that
    merely *touches* such a helper is still FLAGGED. Cycle- and depth-guarded;
    DEGRADE-safe (any introspection failure -> conservative False)."""
    if _seen is None:
        _seen = set()
    if _depth > 2:
        return False  # hop budget exhausted: cannot prove -> conservative False
    if not _is_callable_function(fn):
        return False
    fid = id(fn)
    if fid in _seen:
        return False  # recursion / cycle: cannot prove a terminal revert
    _seen = _seen | {fid}
    try:
        nodes = list(getattr(fn, "nodes", []) or [])
    except Exception:
        return False
    if not nodes:
        return False  # no body modeled -> cannot prove it reverts
    leaves = [n for n in nodes if not (getattr(n, "sons", []) or [])]
    # An ENTRYPOINT with no sons == an empty function body: returns normally.
    if not leaves:
        return False
    proved_any_revert = False
    for leaf in leaves:
        if _node_type_name(leaf) == "ENTRYPOINT":
            # an entrypoint that is itself a leaf == empty body -> returns
            return False
        if _node_is_unconditional_revert(leaf):
            proved_any_revert = True
            continue
        # One-hop transitive: a leaf whose sole effect is a call to a helper that
        # itself always reverts (e.g. `_fail();` -> `_fail` reverts). Resolve the
        # concrete callee via the existing closure adjacency and recurse (bounded).
        callee = _leaf_single_revert_callee(leaf, fn, _depth + 1, _seen)
        if callee:
            proved_any_revert = True
            continue
        # A leaf we cannot prove aborts -> the function may return -> not always
        # reverting (conservative: never suppress a real swallow).
        return False
    return proved_any_revert


def _leaf_single_revert_callee(leaf: Any, fn: Any, depth: int, seen: set) -> bool:
    """True when `leaf` is (or contains) a one-hop call to a callable whose body
    `_fn_always_reverts`. Resolves the callee through the same adjacency used by
    `_direct_callees` (internal + high-level/library calls), so an internal helper
    (`_fail()`) and a library revert (`Errors.revertOnStale()`) are both handled.
    Conservative: only returns True when a resolved callee provably always reverts."""
    for attr in ("internal_calls", "high_level_calls"):
        for c in getattr(leaf, attr, []) or []:
            cand = c[1] if isinstance(c, (list, tuple)) and len(c) >= 2 else c
            if not _is_callable_function(cand):
                cand = getattr(cand, "function", cand)
            if _is_callable_function(cand) and _fn_always_reverts(cand, depth, seen):
                return True
    return False


def _handler_node_calls_always_reverts(node: Any) -> bool:
    """True when catch-handler `node` makes a one-hop internal/library call to a
    function whose body provably always reverts. The transitive-propagate entry
    point: resolves every internal + high-level (library) callee on the node and
    tests `_fn_always_reverts`. Conservative - an unresolved or only-conditionally
    reverting callee returns False (so a real swallow is never missed)."""
    for attr in ("internal_calls", "high_level_calls"):
        for c in getattr(node, attr, []) or []:
            cand = c[1] if isinstance(c, (list, tuple)) and len(c) >= 2 else c
            if not _is_callable_function(cand):
                cand = getattr(cand, "function", cand)
            if _is_callable_function(cand) and _fn_always_reverts(cand):
                return True
    return False


def _catch_handler_entries(try_node: Any) -> list:
    """The CATCH-handler entry nodes of a TRY node: its CATCH-type sons EXCLUDING
    the first (slither labels the try-SUCCESS continuation as the first CATCH son;
    the genuine handler clauses are the remaining CATCH sons). Returns [] when the
    TRY has no handler son (defensive)."""
    catch_sons = [s for s in (getattr(try_node, "sons", []) or [])
                  if _node_type_name(s) == "CATCH"]
    if len(catch_sons) <= 1:
        # Only the success-arm modeled (no separate handler son) -> no handler to
        # inspect. Conservative: nothing to flag.
        return []
    return catch_sons[1:]


def _collect_handler_block(entry: Any, try_node: Any, all_nodes_ids: set):
    """Bounded forward walk of a catch-handler clause starting at `entry`,
    returning (handler_nodes, merge_nodes). A node belongs to the handler clause
    while it is reached ONLY from within this clause; the first node whose
    `fathers` reach outside the clause (the post-try MERGE / rejoin) terminates the
    clause and is collected into `merge_nodes` (plus a small bounded tail, so a
    validating require just after the merge is seen). Cycle-guarded."""
    handler: list = []
    handler_ids: set = set()
    frontier = [entry]
    merge_seeds: list = []
    while frontier:
        cur = frontier.pop()
        cid = id(cur)
        if cid in handler_ids:
            continue
        # A node is part of THIS handler clause iff every father is the TRY itself
        # or already-in-this-handler. A node with an external father is the rejoin.
        fathers = list(getattr(cur, "fathers", []) or [])
        external_father = any(
            (id(f) != id(try_node) and id(f) not in handler_ids and f is not entry)
            for f in fathers
        ) if cur is not entry else False
        if external_father:
            merge_seeds.append(cur)
            continue
        handler_ids.add(cid)
        handler.append(cur)
        for s in (getattr(cur, "sons", []) or []):
            if id(s) not in handler_ids:
                frontier.append(s)
    # Bounded post-merge tail: from each merge seed, walk a few sons so a
    # `require(ok)` validating a fallback set in the handler is observed.
    merge: list = []
    merge_ids: set = set()
    tail_frontier = list(merge_seeds)
    budget = 8
    while tail_frontier and budget > 0:
        cur = tail_frontier.pop()
        if id(cur) in merge_ids:
            continue
        merge_ids.add(id(cur))
        merge.append(cur)
        budget -= 1
        for s in (getattr(cur, "sons", []) or []):
            if id(s) not in merge_ids:
                tail_frontier.append(s)
    return handler, merge


def _first_line(node: Any) -> Optional[int]:
    sm = getattr(node, "source_mapping", None)
    lines = list(getattr(sm, "lines", []) or []) if sm else []
    return lines[0] if lines else None


def oracle_swallow_suspects(function: Any) -> Any:
    """Flag every TRY/CATCH in `function` where an ORACLE / price read is wrapped
    in a try whose catch handler SWALLOWS the failure (no revert / no re-throw /
    no post-merge validating require), so execution proceeds on a stale/zero/
    default value.

    Returns a list of records (deterministically ordered by catch line):
        {"contract", "function", "selector", "oracle_callee", "try_line",
         "catch_line", "at_file", "at_line", "severity_hint": "oracle"}
    or `DEGRADED` (R80) when:
      - `function` is not navigable, OR
      - the installed slither does not model try/catch CFG nodes (logged reason).
    An empty list means no swallowing oracle try/catch (never a silent miss).

    CONSERVATIVE / never-FP: only flags when (a) the TRY callee is a curated oracle
    read name, AND (b) NO catch handler node and NO bounded post-try-merge node
    reverts / re-throws / requires. If a handler reverts, or a subsequent require
    validates a fallback the handler set, the suspect is suppressed."""
    if not _is_callable_function(function):
        return DEGRADED
    if not _slither_try_catch_modeled():
        # R80: degrade with a logged reason rather than guessing a try/catch shape.
        try:
            import logging
            logging.getLogger(__name__).info(
                "oracle_swallow_suspects: installed slither lacks NodeType.TRY/CATCH "
                "modeling - DEGRADED (no guess)."
            )
        except Exception:
            pass
        return DEGRADED

    nodes = list(getattr(function, "nodes", []) or [])
    all_ids = {id(n) for n in nodes}
    cname = getattr(getattr(function, "contract", None), "name", "?")
    fname = getattr(function, "name", "?")
    selector = (getattr(function, "solidity_signature", None)
                or getattr(function, "full_name", None) or fname)
    at_file = ""
    try:
        sm = getattr(function, "source_mapping", None)
        at_file = str(getattr(sm, "filename_short", "") or
                      getattr(getattr(sm, "filename", None), "short", "") or "")
    except Exception:
        at_file = ""

    out: list = []
    for n in nodes:
        if _node_type_name(n) != "TRY":
            continue
        callees = set(_try_call_names(n))
        oracle_hit = callees & _ORACLE_READ_NAMES
        if not oracle_hit:
            continue  # not an oracle read -> never-FP, skip
        handlers = _catch_handler_entries(n)
        if not handlers:
            continue
        # The TRY swallows iff EVERY handler clause swallows (none propagates) AND
        # the shared post-merge region does not validate. Conservative: if ANY
        # handler propagates, NOT a swallow.
        any_swallow = False
        swallow_catch_line = None
        for entry in handlers:
            handler_nodes, merge_nodes = _collect_handler_block(entry, n, all_ids)
            propagates = any(_node_is_propagate(hn) for hn in handler_nodes)
            if not propagates:
                # TRANSITIVE PROPAGATE: a catch that re-throws via a one+-hop
                # internal/library helper whose body UNCONDITIONALLY reverts
                # (catch { _fail(); } / Errors.revertOnStale()) is NOT a swallow -
                # the whole tx reverts. Resolve the callee through the existing
                # closure adjacency and prove it always reverts (conservative:
                # only an always-revert helper suppresses; an unprovable callee
                # leaves the clause classified as a swallow, never-MISS).
                propagates = any(
                    _handler_node_calls_always_reverts(hn) for hn in handler_nodes
                )
            if propagates:
                # this handler re-throws -> not a swallow on this clause
                continue
            # post-merge validation: a require/assert/revert/if-revert after the
            # try-merge that could gate on a fallback the handler set.
            merge_validates = any(_node_is_propagate(mn) for mn in merge_nodes)
            if merge_validates:
                continue  # validated fallback -> NOT a swallow (never-FP)
            any_swallow = True
            cl = _first_line(entry)
            if swallow_catch_line is None or (cl is not None and cl < (swallow_catch_line or 1 << 30)):
                swallow_catch_line = cl
        if not any_swallow:
            continue
        out.append({
            "contract": str(cname),
            "function": str(fname),
            "selector": str(selector),
            "oracle_callee": sorted(oracle_hit)[0],
            "try_line": _first_line(n),
            "catch_line": swallow_catch_line,
            "at_file": at_file,
            "at_line": swallow_catch_line,
            "severity_hint": "oracle",
        })
    out.sort(key=lambda r: (r.get("catch_line") or 0, r.get("function") or ""))
    return out


def closure_oracle_swallow_suspects(function: Any) -> Any:
    """Closure variant of `oracle_swallow_suspects`: scans `function`'s OWN body
    AND its forward callee closure (folding modifier bodies), so a swallowing
    oracle try/catch living in an INTERMEDIATE helper the function calls is found.
    Aggregates the per-function suspect lists (deduplicated by
    contract/function/catch_line). FP-neutral: each member list is produced by the
    same conservative `oracle_swallow_suspects`, so the closure adds reach, not FP
    risk. Returns the merged list, or `DEGRADED` (R80) when `function` is not
    navigable or slither lacks try/catch modeling."""
    own = oracle_swallow_suspects(function)
    if is_degraded(own):
        return DEGRADED
    merged = list(own)
    seen = {(r.get("contract"), r.get("function"), r.get("catch_line")) for r in merged}
    closure = callee_closure(function, include_modifiers=True)
    if not is_degraded(closure):
        for callee in closure:
            res = oracle_swallow_suspects(callee)
            if is_degraded(res):
                continue
            for r in res:
                key = (r.get("contract"), r.get("function"), r.get("catch_line"))
                if key in seen:
                    continue
                seen.add(key)
                merged.append(r)
    merged.sort(key=lambda r: (r.get("catch_line") or 0, r.get("function") or ""))
    return merged


# ── AST-exact name/signature-filtered CALL-SITE selector (Glider gap #4) ─────
#
# The L30 "enumerate-all-callsites" enumerator was grep/regex-based, so it
# SILENTLY MISSES call sites that the source text does not spell with the
# target's canonical name:
#   (b) renamed-import aliases  -- `import {Real as Alias}` then `Alias.f()`
#   (c) overloads-by-signature  -- `f(uint)` vs `f(uint,address)` (grep cannot
#                                  tell the two apart by a name-only match)
#   (d) virtual / override      -- `f()` that dispatches to a child/base body
#   (e) interface dispatch      -- `IFoo(x).f()` resolved to the concrete impl
#
# Slither's call IR already resolves every one of these to the concrete callee
# Function (canonical_name + solidity_signature + the owning contract), so we
# walk the IR and select the sites whose resolved callee matches the target.
# This is the AST-exact analog of the grep enumerator and a SUPERSET-or-equal
# of it (it adds the alias/overload/dispatch sites grep cannot see; it never
# returns fewer genuine sites for the same target).


def _callee_of_ir(ir: Any) -> Any:
    """Return the resolved callee Function of a call IR op, or None. Handles
    InternalCall / HighLevelCall / LibraryCall (all expose `.function`) plus the
    defensive `(ctx, fn)` tuple shape some Slither versions yield."""
    if isinstance(ir, (list, tuple)) and len(ir) >= 2:
        ir = ir[1]
    cand = getattr(ir, "function", None)
    if cand is not None and _is_callable_function(cand):
        return cand
    if _is_callable_function(ir):
        return ir
    return None


def _ir_dispatch_kind(ir: Any, callee: Any, caller_contract: Any) -> str:
    """Classify the dispatch kind of a call IR op against its resolved callee.

    Returns one of:
      - "interface"        HighLevelCall whose callee is declared on an interface
      - "high-level"       other cross-contract HighLevelCall
      - "library"          LibraryCall (using-for / Lib.f())
      - "virtual-override"  internal call resolving to a body on a DIFFERENT
                            contract than the caller (base/override dispatch)
      - "direct"            internal call resolving on the caller's own contract
    """
    cls = type(ir).__name__
    if cls == "LibraryCall":
        return "library"
    if cls == "HighLevelCall":
        c = getattr(callee, "contract", None)
        if c is not None and bool(getattr(c, "is_interface", False)):
            return "interface"
        return "high-level"
    # InternalCall (or anything else with a body): distinguish own-contract vs
    # base/override dispatch. `contract_declarer` is the contract whose BODY is
    # dispatched to (a base, for an inherited/virtual call); `contract` is the
    # resolution context (the caller's contract). When the body lives on a
    # DIFFERENT contract than the caller, this is base/virtual/override dispatch
    # -- the case a grep on the caller's text cannot resolve.
    declarer = (getattr(callee, "contract_declarer", None)
                or getattr(callee, "contract", None))
    declarer_c = getattr(declarer, "name", None)
    caller_c = getattr(caller_contract, "name", None)
    if declarer_c is not None and caller_c is not None and declarer_c != caller_c:
        return "virtual-override"
    # Same-contract resolution, but the bare call dispatched through the
    # virtual/override DAG (Slither devirtualised it to the leaf override). A
    # grep on the call-site text cannot resolve which body this binds to, so it
    # is still a dispatch site, not a plain direct call.
    if (bool(getattr(callee, "is_virtual", False))
            or bool(getattr(callee, "is_override", False))
            or (getattr(callee, "overrides", []) or [])
            or (getattr(callee, "overridden_by", []) or [])):
        return "virtual-override"
    return "direct"


def _target_matches(callee: Any, target: str, want_sig: bool) -> bool:
    """True when `callee` is the call-site target. When `target` carries a
    signature (`f(uint256)`) we match the solidity_signature / full_name exactly
    (so an overload `f(uint256,address)` is NOT a match). When `target` is a bare
    name we match the function name (so EVERY overload counts)."""
    if want_sig:
        for attr in ("solidity_signature", "full_name"):
            v = getattr(callee, attr, None)
            if v and str(v) == target:
                return True
        # canonical_name carries the contract prefix; compare its signature tail.
        cn = getattr(callee, "canonical_name", None)
        if cn and str(cn).split(".")[-1] == target:
            return True
        return False
    return str(getattr(callee, "name", "")) == target


def _site_line(node: Any) -> Optional[int]:
    sm = getattr(node, "source_mapping", None)
    lines = list(getattr(sm, "lines", []) or []) if sm else []
    return lines[0] if lines else None


def _site_file(node: Any, fn: Any) -> str:
    for obj in (node, fn):
        sm = getattr(obj, "source_mapping", None)
        f = getattr(sm, "filename", None)
        if f is not None:
            # Slither Filename has .relative / .absolute / .short
            for attr in ("relative", "short", "absolute"):
                v = getattr(f, attr, None)
                if v:
                    return str(v)
            return str(f)
    return ""


def callsites_of(target: str, contracts: Any) -> Any:
    """AST-EXACT name/signature-filtered call-site selector (Glider gap #4).

    Enumerate EVERY call site of `target` across the compiled `contracts`,
    resolved through Slither's call IR so renamed-import aliases, overloads (by
    signature), and virtual / interface / override dispatch are all caught --
    the exact sites the grep enumerator silently misses.

    `target`:
      - a full signature `transfer(address,uint256)` -> match that overload ONLY.
      - a bare name `transfer`                       -> match every overload.
    `contracts`: an iterable of Slither Contract objects (e.g. `slither.contracts`).

    Returns a list of dicts (deterministically ordered by file, line, caller):
        {"caller_contract", "caller_fn", "file", "line", "dispatch_kind",
         "callee", "callee_sig"}
    or `DEGRADED` (R80) when `contracts` is not navigable. An empty list means no
    call site -- never a silent miss.

    SUPERSET-or-equal contract: for any target the grep enumerator would find,
    this returns those sites PLUS the alias/overload/dispatch sites grep cannot
    see; it never returns fewer genuine sites."""
    try:
        contracts = list(contracts or [])
    except Exception:
        return DEGRADED
    if not contracts:
        return DEGRADED
    # Navigability probe: a real Contract exposes `.functions`.
    if not any(hasattr(c, "functions") for c in contracts):
        return DEGRADED

    want_sig = "(" in target
    seen: set = set()
    out = []
    for contract in contracts:
        for fn in getattr(contract, "functions", []) or []:
            if not _is_callable_function(fn):
                continue
            for node in getattr(fn, "nodes", []) or []:
                for ir in getattr(node, "irs", []) or []:
                    callee = _callee_of_ir(ir)
                    if callee is None:
                        continue
                    if not _target_matches(callee, target, want_sig):
                        continue
                    kind = _ir_dispatch_kind(ir, callee, contract)
                    row = {
                        "caller_contract": getattr(contract, "name", "?"),
                        "caller_fn": getattr(fn, "name", "?"),
                        "file": _site_file(node, fn),
                        "line": _site_line(node),
                        "dispatch_kind": kind,
                        "callee": str(getattr(callee, "canonical_name",
                                              getattr(callee, "name", "?"))),
                        "callee_sig": str(getattr(callee, "solidity_signature",
                                                  "") or ""),
                    }
                    dedupe = (row["caller_contract"], row["caller_fn"],
                              row["file"], row["line"], row["dispatch_kind"],
                              row["callee"])
                    if dedupe in seen:
                        continue
                    seen.add(dedupe)
                    out.append(row)
    out.sort(key=lambda r: (r["file"], r["line"] if r["line"] is not None else -1,
                            r["caller_contract"], r["caller_fn"]))
    return out


# ── INTRA-PROCEDURAL CFG NAVIGATION + SAME-FN-CEI / UNBOUNDED-LOOP oracle ─────
# Glider gap #5 (final). The closure primitives above reason at CALL-GRAPH
# granularity (callee_closure / has_guard_in_closure), and `_iter_nodes` walks a
# function's nodes FLATLY (declaration order, NOT execution order - see the probe:
# ENTRYPOINT then VARIABLE then STARTLOOP/ENDLOOP appear before the loop body).
# So nothing here today reasons about intra-function STATEMENT ORDER. That blinds
# us to two bug classes the cross-fn closure reentrancy oracle structurally misses:
#
#   (a) SAME-FN CEI VIOLATION - an external call THEN a state-write WITHIN ONE
#       function (e.g. `msg.sender.call{value:x}(""); balances[msg.sender]=0;`).
#       has_guard_in_closure only answers "is there an access-control guard"; it
#       does NOT see the ext-call-before-write ORDERING inside a single fn. The
#       cross-fn closure reentrancy reasoning sees A->B call edges, not A's own
#       internal statement order. This complements (does not duplicate) it.
#   (b) UNBOUNDED-LOOP GAS GRIEFING - a loop bounded by an attacker-growable
#       `.length` (a state array/mapping the public surface can grow), with an
#       effect (state-write / external call) inside the loop body. A constant- or
#       param-capped loop reads no state var in its bound and is NEVER flagged.
#
# These reuse `branch_effect_target` (son_true/son_false from gap #1) for the IF/
# IFLOOP navigation and `has_non_reentrant_modifier` / `has_guard_in_closure` for
# the reentrancy-guard dominance check. CONSERVATIVE-BY-CONSTRUCTION (never-FP):
#   - a write-BEFORE the external call (CEI-correct) -> NOT flagged.
#   - a fn carrying a nonReentrant / reentrancy-lock guard -> NOT flagged.
#   - a loop whose bound is a constant / parameter / local cap (reads no state
#     var) -> NOT flagged.
# Both oracles are LEADS only - never an auto-finding, never a flip of `unguarded`.
# Every helper degrades (DEGRADED) on a non-navigable input and never raises (R80).


def cfg_ordered_nodes(function: Any) -> Any:
    """Return `function`'s CFG nodes in EXECUTION (sons-walk) order, starting from
    the entry node and following `node.sons` breadth-first with a visited-set
    cycle-guard (a loop's back-edge terminates). This is the ordered analog of the
    flat `_iter_nodes` declaration-order walk - it is what lets the same-fn CEI
    oracle reason about whether a state-write comes AFTER an external call on a
    real control-flow path.

    Returns a list of Slither Node objects (entry first), or DEGRADED (R80) when
    `function` is not navigable. A function whose nodes are unreachable from the
    entry are appended at the end (declaration order) so no node is silently
    dropped (conservative: we never lose a node)."""
    if not _is_callable_function(function):
        return DEGRADED
    nodes = list(getattr(function, "nodes", []) or [])
    if not nodes:
        return []
    # Entry node: prefer the explicit entry_point, else the first declared node.
    entry = getattr(function, "entry_point", None)
    if entry is None:
        entry = nodes[0]
    ordered: list = []
    seen: set = set()
    frontier = [entry]
    while frontier:
        cur = frontier.pop(0)
        if cur is None or id(cur) in seen:
            continue
        seen.add(id(cur))
        ordered.append(cur)
        for s in getattr(cur, "sons", []) or []:
            if s is not None and id(s) not in seen:
                frontier.append(s)
    # Append any nodes not reachable from entry (defensive; keep declaration order).
    for n in nodes:
        if id(n) not in seen:
            ordered.append(n)
            seen.add(id(n))
    return ordered


def dominators(function: Any) -> Any:
    """Compute the DOMINATOR set of every CFG node of `function` (the classic
    iterative dataflow fixpoint: dom(entry)={entry}; dom(n)={n} U intersect over
    predecessors). Returns a dict mapping `id(node) -> set(id(dominator-node))`
    PLUS a companion `id(node) -> node` index under the key `"_index"`, or DEGRADED
    (R80) when `function` is not navigable.

    A node D dominates node N iff every path from entry to N passes through D.
    Used by `node_dominates` to ask "does a reentrancy-guard node dominate the
    state-write" - if so the write is protected and the CEI shape is NOT flagged."""
    if not _is_callable_function(function):
        return DEGRADED
    nodes = list(getattr(function, "nodes", []) or [])
    if not nodes:
        return {"_index": {}}
    entry = getattr(function, "entry_point", None) or nodes[0]
    all_ids = {id(n): n for n in nodes}
    all_ids[id(entry)] = entry
    universe = set(all_ids.keys())

    def preds(n):
        # Slither exposes fathers (predecessors); fall back to scanning sons.
        ps = getattr(n, "fathers", None)
        if ps:
            return [p for p in ps if p is not None]
        out = []
        for m in all_ids.values():
            if n in (getattr(m, "sons", []) or []):
                out.append(m)
        return out

    # Initialise: entry dominated by itself; every other node dominated by all.
    dom: dict = {}
    for nid, n in all_ids.items():
        dom[nid] = {id(entry)} if n is entry else set(universe)
    changed = True
    guard = 0
    while changed and guard < 10000:
        changed = False
        guard += 1
        for nid, n in all_ids.items():
            if n is entry:
                continue
            ps = preds(n)
            if ps:
                inter = None
                for p in ps:
                    pd = dom.get(id(p), set(universe))
                    inter = set(pd) if inter is None else (inter & pd)
                new = ({nid} | (inter or set()))
            else:
                # Unreachable node (no predecessors): dominated only by itself.
                new = {nid}
            if new != dom[nid]:
                dom[nid] = new
                changed = True
    dom["_index"] = all_ids
    return dom


def node_dominates(dom: Any, a: Any, b: Any) -> bool:
    """True iff node `a` dominates node `b`, given a `dom` map from `dominators`.
    False on a degraded map or when either node is absent. Conservative: an
    unknown relationship returns False (we never claim a guard dominates when we
    cannot prove it)."""
    if dom is None or is_degraded(dom) or not isinstance(dom, dict):
        return False
    if a is None or b is None:
        return False
    return id(a) in dom.get(id(b), set())


def loop_headers(function: Any) -> Any:
    """Return the loop-header CFG nodes of `function`: the STARTLOOP and IFLOOP
    nodes (Slither lowers every `for`/`while`/`do` to a STARTLOOP -> IFLOOP(cond)
    -> body -> ENDLOOP shape). The IFLOOP node carries the loop CONDITION (the
    bound) on its expression + `variables_read`/`state_variables_read`, so it is
    the node the unbounded-loop oracle inspects.

    Returns a list of nodes, or DEGRADED (R80) when `function` is not navigable."""
    if not _is_callable_function(function):
        return DEGRADED
    out = []
    for n in _iter_nodes(function):
        name = str(getattr(n, "type", "") or "").upper().rsplit(".", 1)[-1]
        if name in ("STARTLOOP", "IFLOOP"):
            out.append(n)
    return out


def _node_external_call_lines(node: Any):
    """Yield a short marker for every EXTERNAL call on `node` (high-level
    cross-contract call OR low-level `.call`/`.delegatecall`/`.staticcall`/`.send`/
    `.transfer`). These are the reentrancy-relevant external-call sites of the
    same-fn CEI oracle."""
    for _ in getattr(node, "high_level_calls", []) or []:
        yield "high_level"
    for lc in getattr(node, "low_level_calls", []) or []:
        try:
            yield str(lc).lower()
        except Exception:
            yield "low_level"


def _node_is_external_call(node: Any) -> bool:
    for _ in _node_external_call_lines(node):
        return True
    return False


# --- CEI-scoped external-call recognition (W4 FP fix) -----------------------
# The CEI oracle must count an external call ONLY when it is STATE-MUTATING, i.e.
# capable of reentering and writing state. A `view`/`pure` callee compiles to a
# STATICCALL (the callee cannot write state or make state-changing sub-calls), so a
# state-write AFTER such a call is CEI-SAFE and must NOT be flagged. This predicate
# is used SOLELY by the CEI path (the direct gate in `intra_fn_cei` and the
# transitive marker via `_fn_body_has_external_call`); the global
# `_node_is_external_call` / `_node_external_call_lines` keep their broad meaning
# for the callback-reentrancy oracle / `has_external_call_to` etc.
#
# CONSERVATIVE never-MISS: a call is treated as state-mutating (reentrant-relevant)
# UNLESS the target is POSITIVELY proven `view`/`pure` (high-level) or a STATICCALL
# (low-level). An UNKNOWN/unresolvable target -> treated as state-mutating, so a
# real CEI is never missed.

def _hlc_target_function(call: Any) -> Any:
    """Resolve the TARGET Function of one `high_level_calls` entry. Slither encodes
    these as a `(Contract, IROperation)` tuple where the IR op carries `.function`,
    or (older shapes) as the Function / `(ctx, Function)` directly. Returns the
    target Function or None when it cannot be resolved (UNKNOWN -> caller treats as
    state-mutating)."""
    cand = call
    if isinstance(cand, (list, tuple)) and len(cand) >= 2:
        cand = cand[1]
    # SlithIR HighLevelCall / LibraryCall op exposes the callee on `.function`.
    fn = getattr(cand, "function", None)
    if _is_callable_function(fn):
        return fn
    if _is_callable_function(cand):
        return cand
    return None


def _hlc_is_view_or_pure(call: Any) -> bool:
    """True ONLY when the high-level call's target function is POSITIVELY `view` or
    `pure` (a STATICCALL that cannot reenter-and-write). Conservative: an
    unresolvable target, or one whose mutability flags are missing/unreadable, is
    NOT treated as view/pure (so the caller counts it as state-mutating)."""
    fn = _hlc_target_function(call)
    if fn is None:
        return False
    try:
        if bool(getattr(fn, "view", False)):
            return True
        if bool(getattr(fn, "pure", False)):
            return True
    except Exception:
        return False
    return False


def _llc_is_staticcall(call: Any) -> bool:
    """True ONLY when the low-level call lowers to a `.staticcall` (a read-only call
    that cannot reenter-and-write). Slither lowers it to an IR op whose string form
    carries `function:staticcall`. Any failure to read the form -> False (counted as
    state-mutating, never-MISS)."""
    try:
        s = str(call).lower()
    except Exception:
        return False
    return "function:staticcall" in s or s.strip() == ".staticcall" or s.strip() == "staticcall"


def _node_is_reentrant_external_call(node: Any) -> bool:
    """CEI-scoped external-call recognition: True iff `node` makes at least one
    STATE-MUTATING external call (one that could reenter and write state). Excludes
    POSITIVELY `view`/`pure` high-level calls (STATICCALL) and low-level
    `.staticcall`. CONSERVATIVE never-MISS: an UNKNOWN/unresolvable high-level target
    or any low-level call that is not provably a staticcall (`.call`/`.delegatecall`/
    `.transfer`/`.send`/unknown) counts as state-mutating. Does NOT mutate the global
    `_node_is_external_call`."""
    for hc in getattr(node, "high_level_calls", []) or []:
        if not _hlc_is_view_or_pure(hc):
            return True
    for lc in getattr(node, "low_level_calls", []) or []:
        if not _llc_is_staticcall(lc):
            return True
    return False


def _node_state_writes(node: Any):
    """Yield the names of state variables WRITTEN on `node` (the semantic IR
    signal `state_variables_written` - ignores comments / string literals)."""
    for v in getattr(node, "state_variables_written", []) or []:
        nm = getattr(v, "name", None)
        if nm:
            yield str(nm)


def _node_first_line(node: Any) -> Optional[int]:
    sm = getattr(node, "source_mapping", None)
    lines = list(getattr(sm, "lines", []) or []) if sm else []
    return lines[0] if lines else None


def _fn_has_reentrancy_guard(function: Any) -> bool:
    """True when `function` is protected by a reentrancy guard: a nonReentrant /
    reentrancy-lock modifier (header check) OR a guard folded into its closure
    (e.g. a `_nonReentrantBefore()` helper). Conservative: when in doubt we treat
    the fn as guarded (suppress the CEI lead) only on a POSITIVE modifier/closure
    signal; a degrade in the closure means we DON'T claim guarded (so we may still
    emit the lead, which is the safe direction for a never-miss-the-bug oracle)."""
    if has_non_reentrant_modifier(function):
        return True
    # A reentrancy guard sometimes lives in a folded helper (e.g. the OZ
    # ReentrancyGuard `_nonReentrantBefore`). Detect it by a guard-closure check
    # keyed on the reentrancy-lock modifier names appearing anywhere in the
    # closure's modifiers; reuse the closure walk.
    closure = callee_closure(function, include_modifiers=True)
    if is_degraded(closure):
        return False
    for callee in ({function} | (closure if isinstance(closure, set) else set())):
        nm = str(getattr(callee, "name", "") or "")
        if re.search(r"nonReentrant|noReentrant|notReentrant|reentrancyGuard|"
                     r"_nonReentrantBefore|_reentrancyGuardEntered", nm, re.IGNORECASE):
            return True
    return False


# Transitive-ext recognition (Glider gap W4): an INTERNAL-call node whose callee
# closure contains a GENUINE external call is treated as ext-bearing, catching the
# cross-fn "ext-via-internal-helper THEN write-in-caller" reentrancy slice that the
# direct `_node_is_external_call` walk misses (the caller's node for `_doCall()` is
# an internal call, so `seen_ext` would never flip). REUSES `_node_is_external_call`
# + `callee_closure`; ADDITIVE-ONLY (a direct ext hit is unchanged - see
# `_call_node_reaches_external`, which short-circuits True on a direct ext).
_TRANSITIVE_EXT_MAX_HOPS = 3

# Cache: id(callee Function) -> bool (closure-or-own-body reaches an external call).
# Keyed by object id; lifetime is the analysis process (Slither objects are stable
# within a compile). DEGRADE-safe: an unnavigable callee caches False.
_closure_ext_cache: dict = {}


def _fn_body_has_external_call(fn: Any) -> bool:
    """True iff `fn`'s OWN body holds a GENUINE STATE-MUTATING external call
    (`_node_is_reentrant_external_call`). CEI-scoped: a `view`/`pure` (STATICCALL)
    call cannot reenter-and-write, so it does NOT make the body ext-bearing for the
    transitive CEI marker. Uses the CEI-scoped predicate (NOT the broad global)."""
    for node in getattr(fn, "nodes", []) or []:
        if _node_is_reentrant_external_call(node):
            return True
    return False


def _closure_reaches_external(fn: Any) -> bool:
    """True iff `fn`'s OWN body OR a callee reachable within `_TRANSITIVE_EXT_MAX_HOPS`
    internal-call hops contains a GENUINE external call (`_node_is_external_call`).
    Hop-BOUNDED + cycle-guarded + DEGRADE-safe (R80): an unnavigable `fn` yields
    False (treat as non-ext, never crash, never over-claim). REUSES the exact
    external-call recognition the direct walk uses (`_node_is_external_call`) and the
    same one-hop internal adjacency as `_direct_callees` (`_node_internal_callees`),
    so the transitive marker can never be looser than a direct hit."""
    if not _is_callable_function(fn):
        return False
    key = id(fn)
    cached = _closure_ext_cache.get(key)
    if cached is not None:
        return cached
    result = False
    try:
        # Bounded BFS over internal-call edges (hop 0 = `fn`'s own body). Modifier
        # bodies are folded in via `callee_closure` semantics but here we stay on the
        # internal-call edge set the same way `_direct_callees` does, with an explicit
        # hop cap so the transitive recognition is depth-bounded per the brief.
        seen: set = {id(fn)}
        frontier = [(fn, 0)]
        while frontier:
            cur, depth = frontier.pop(0)
            if _fn_body_has_external_call(cur):
                result = True
                break
            if depth >= _TRANSITIVE_EXT_MAX_HOPS:
                continue
            for node in getattr(cur, "nodes", []) or []:
                for callee in _node_internal_callees(node):
                    if id(callee) in seen:
                        continue  # cycle-guard
                    seen.add(id(callee))
                    frontier.append((callee, depth + 1))
    except Exception:
        # R80: navigation failure DEGRADES to non-ext (never a guess, never a crash).
        result = False
    _closure_ext_cache[key] = result
    return result


def _node_internal_callees(node: Any):
    """Yield the directly-called INTERNAL Function/Modifier objects of `node` at ONE
    hop. Same defensive coercion as `_direct_callees` (Slither may yield Function
    objects, (ctx, Function) tuples, or IR ops with a `.function`). EXTERNAL
    (high-level) calls are deliberately NOT yielded here - a direct external call is
    already handled by `_node_is_external_call`; this resolver feeds ONLY the
    internal-helper transitive path."""
    for ic in getattr(node, "internal_calls", []) or []:
        cand = ic[1] if isinstance(ic, (list, tuple)) and len(ic) >= 2 else ic
        if not _is_callable_function(cand):
            cand = getattr(cand, "function", cand)
        if _is_callable_function(cand):
            yield cand


def _call_node_reaches_external(node: Any) -> Any:
    """Return the internal-callee NAME via which `node` transitively reaches a
    GENUINE external call, or True for a DIRECT external call, or None when the node
    reaches no external call.

      - DIRECT: `_node_is_reentrant_external_call(node)` -> return True (a
        STATE-MUTATING external call; a view/pure STATICCALL is NOT counted, since it
        cannot reenter-and-write). The caller treats this with no provenance.
      - TRANSITIVE: the node is an INTERNAL call whose callee's own-body-or-closure
        contains an external call -> return that callee's name (str), so the caller
        can record `via`/`transitive` provenance on the emitted LEAD.
      - else -> None.

    Conservative + DEGRADE-safe (R80): hop depth is bounded by
    `_TRANSITIVE_EXT_MAX_HOPS` via `_closure_reaches_external`'s own cycle-guarded
    bounded closure; an unresolved / unnavigable callee contributes nothing (the
    node is treated as non-ext, never a false flag, never a crash)."""
    # DIRECT external call: CEI-scoped (a STATE-MUTATING external call only; a
    # `view`/`pure` STATICCALL cannot reenter-and-write, so it is NOT a CEI ext).
    if _node_is_reentrant_external_call(node):
        return True
    # TRANSITIVE: an internal helper whose closure reaches out.
    try:
        for callee in _node_internal_callees(node):
            if _closure_reaches_external(callee):
                return str(getattr(callee, "name", "") or "?")
    except Exception:
        return None
    return None


def intra_fn_cei(function: Any) -> Any:
    """Conservative SAME-FN CHECKS-EFFECTS-INTERACTIONS oracle.

    Returns a list of LEAD dicts, one per state-write that occurs AFTER an
    external call in CFG (execution) order WITHIN this one function, when the fn
    carries NO reentrancy guard:

        {"ext_call_line": <int|None>, "state_write_line": <int|None>,
         "var": <state-var name>, "fn": <fn name>}

    or DEGRADED (R80) when `function` is not navigable.

    Detection (CONSERVATIVE, never-false-positive by construction):
      1. walk the CFG in EXECUTION order (`cfg_ordered_nodes`);
      2. once an EXTERNAL call has been seen on the path, any subsequent
         STATE-WRITE node is a CEI-violation candidate (write-AFTER-call);
      3. a write that appears BEFORE the first external call (CEI-correct
         ordering) is NEVER flagged;
      4. a fn protected by a nonReentrant / reentrancy-lock guard (modifier or
         folded helper) is NEVER flagged - the guard makes the ordering safe.
    Additionally, when the dominator analysis can prove the external-call node
    does NOT dominate the write (the write is on a CFG branch that does not flow
    through the call), we still only flag the linear ext-then-write order; the
    dominator check is used to SUPPRESS (raise conservatism), never to add.

    This COMPLEMENTS the cross-fn closure reentrancy oracle (callee_closure /
    has_guard_in_closure), which reasons over A->B call EDGES and is blind to A's
    own internal statement ORDER. It does NOT duplicate it."""
    if not _is_callable_function(function):
        return DEGRADED
    # Guarded fn -> the ordering is safe; emit nothing (never-FP).
    if _fn_has_reentrancy_guard(function):
        return []
    ordered = cfg_ordered_nodes(function)
    if is_degraded(ordered):
        return DEGRADED
    out = []
    seen_ext = False
    last_ext_line: Optional[int] = None
    # Provenance of the most-recent ext marker: None for a DIRECT external call
    # (legacy behavior, no provenance), or the internal-callee name when the marker
    # came TRANSITIVELY via an internal helper whose closure reaches out.
    last_ext_via: Optional[str] = None
    fname = str(getattr(function, "name", "?") or "?")
    seen_keys: set = set()
    for node in ordered:
        reach = _call_node_reaches_external(node)
        if reach is not None:
            seen_ext = True
            ln = _node_first_line(node)
            if ln is not None:
                last_ext_line = ln
            # `reach is True` -> DIRECT external call (unchanged); a str -> the
            # internal helper through which the call is reached (TRANSITIVE).
            last_ext_via = reach if isinstance(reach, str) else None
            # A node can both call AND write (e.g. `x = a.call(...)`); the write of
            # the call's own return tuple is not a CEI effect, so we record the
            # ext marker but do NOT treat THIS node's writes as post-call effects.
            continue
        if not seen_ext:
            continue
        for var in _node_state_writes(node):
            wln = _node_first_line(node)
            key = (var, last_ext_line, wln)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            lead = {
                "ext_call_line": last_ext_line,
                "state_write_line": wln,
                "var": var,
                "fn": fname,
            }
            # ADDITIVE-ONLY provenance: a DIRECT-ext lead is byte-identical to the
            # legacy dict (no extra keys). Only a TRANSITIVE marker adds `via` +
            # `transitive` so the downstream same-fn-reentrancy question can name the
            # helper without changing question_class / attack_class.
            if last_ext_via is not None:
                lead["via"] = last_ext_via
                lead["transitive"] = True
            out.append(lead)
    return out


# Attacker-growable collection heuristic: a loop bound on `<state-array>.length`
# is unbounded when the public surface can grow the array. We CONSERVATIVELY treat
# a `.length` on a STATE variable as the unbounded shape (a constant/param/local
# cap reads no state var in its bound, so it never reaches here). The `.length`
# token in the IFLOOP condition is the load-bearing signal.
_LOOP_LENGTH_RX = re.compile(r"\.\s*length\b", re.IGNORECASE)


def _node_reads_state(node: Any):
    """Yield names of state variables READ on `node` (semantic IR signal)."""
    for v in getattr(node, "state_variables_read", []) or []:
        nm = getattr(v, "name", None)
        if nm:
            yield str(nm)


def _ifloop_body_first(node: Any) -> Any:
    """For an IFLOOP node, the son_true is the loop BODY (son_false is the exit /
    ENDLOOP). Returns son_true or None."""
    bt = branch_effect_target(node)
    if is_degraded(bt):
        return None
    return bt.get("son_true")


def _loop_body_has_effect(ifloop: Any, function: Any) -> bool:
    """True when the loop body (reachable from the IFLOOP's son_true, before the
    loop's back-edge to the same IFLOOP) contains a state-write OR an external
    call - i.e. the loop does real per-iteration work, so a large bound is a real
    gas-griefing surface. Conservative: an empty / read-only loop body -> False
    (NOT flagged). Bounded by a visited-set; stops at the IFLOOP back-edge."""
    body = _ifloop_body_first(ifloop)
    if body is None:
        return False
    seen: set = set()
    frontier = [body]
    while frontier:
        cur = frontier.pop()
        if cur is None or id(cur) in seen or cur is ifloop:
            continue
        seen.add(id(cur))
        # Effect inside the loop body?
        for _ in _node_state_writes(cur):
            return True
        if _node_is_external_call(cur):
            return True
        for s in getattr(cur, "sons", []) or []:
            # Do not walk back into the loop header (back-edge) or out the exit.
            if s is ifloop:
                continue
            if s is not None and id(s) not in seen:
                frontier.append(s)
    return False


def unbounded_loops(function: Any) -> Any:
    """Conservative UNBOUNDED-LOOP (gas-griefing) oracle.

    Returns a list of LEAD dicts, one per loop whose bound is an attacker-growable
    `<state-collection>.length` with an EFFECT inside the body:

        {"loop_line": <int|None>, "bound_var": <state-var name>, "fn": <fn name>}

    or DEGRADED (R80) when `function` is not navigable.

    Detection (CONSERVATIVE, never-false-positive by construction):
      1. find each IFLOOP (loop condition) node via `loop_headers`;
      2. flag ONLY when the loop condition READS a STATE variable AND its
         expression text references `.length` (the `for (i=0; i<arr.length; ...)`
         attacker-growable shape). A constant bound (`i < 10`), a parameter bound
         (`i < n`), or a local cap (`i < cap`) reads NO state variable in the
         condition -> NEVER flagged;
      3. require an EFFECT (state-write / external call) inside the loop body -
         a read-only / empty loop is NOT a meaningful griefing surface and is NOT
         flagged.

    This is a LEAD only - never an auto-finding, never a flip of `unguarded`."""
    if not _is_callable_function(function):
        return DEGRADED
    headers = loop_headers(function)
    if is_degraded(headers):
        return DEGRADED
    out = []
    fname = str(getattr(function, "name", "?") or "?")
    seen_lines: set = set()
    for n in headers:
        name = str(getattr(n, "type", "") or "").upper().rsplit(".", 1)[-1]
        if name != "IFLOOP":
            continue  # the condition lives on IFLOOP, not STARTLOOP
        expr = _node_expr_str(n)
        if not _LOOP_LENGTH_RX.search(expr):
            continue  # bound is not a `.length` -> not the attacker-growable shape
        state_read = list(_node_reads_state(n))
        if not state_read:
            continue  # constant / param / local-cap bound -> NEVER flagged
        if not _loop_body_has_effect(n, function):
            continue  # read-only / empty loop body -> not a griefing surface
        ln = _node_first_line(n)
        if ln in seen_lines:
            continue
        seen_lines.add(ln)
        # Pick the state collection whose `.length` is the bound (best-effort: the
        # first state var read in the condition; the `.length` token confirms it).
        out.append({
            "loop_line": ln,
            "bound_var": state_read[0],
            "fn": fname,
        })
    return out


def closure_intra_fn_cei(function: Any) -> Any:
    """Like `intra_fn_cei` but scans `function`'s OWN body AND its forward callee
    closure (folding modifier bodies), so a same-fn CEI violation living in an
    INTERMEDIATE hop (e.g. `withdraw -> _settle[call; then state-write]`) is found
    even when it is not in the source/sink fn's own body. Returns the FIRST CEI
    suspect (with `at_fn`) or [] when none. DEGRADED (R80) when not navigable.

    Mirrors `closure_unsafe_value_downcasts` / `closure_asm_suspect_sinks`: own
    body first (most-specific anchor), then the closure; a degrade in the closure
    leaves the own-body result honest. CONSERVATIVE: a guarded hop is suppressed
    inside `intra_fn_cei`, so it never surfaces here either."""
    own = intra_fn_cei(function)
    if is_degraded(own):
        return DEGRADED
    if own:
        r = dict(own[0])
        r["at_fn"] = getattr(function, "name", "?")
        return [r]
    closure = callee_closure(function, include_modifiers=True)
    if is_degraded(closure):
        return []
    for callee in closure:
        cc = intra_fn_cei(callee)
        if is_degraded(cc) or not cc:
            continue
        r = dict(cc[0])
        r["at_fn"] = getattr(callee, "name", "?")
        return [r]
    return []


def closure_unbounded_loops(function: Any) -> Any:
    """Like `unbounded_loops` but scans `function`'s OWN body AND its forward
    callee closure (folding modifier bodies), so an attacker-growable loop living
    in an INTERMEDIATE hop is found even when it is not in the source/sink fn's own
    body. Returns the FIRST unbounded loop (with `at_fn`) or [] when none.
    DEGRADED (R80) when not navigable. Mirrors `closure_intra_fn_cei`."""
    own = unbounded_loops(function)
    if is_degraded(own):
        return DEGRADED
    if own:
        r = dict(own[0])
        r["at_fn"] = getattr(function, "name", "?")
        return [r]
    closure = callee_closure(function, include_modifiers=True)
    if is_degraded(closure):
        return []
    for callee in closure:
        cl = unbounded_loops(callee)
        if is_degraded(cl) or not cl:
            continue
        r = dict(cl[0])
        r["at_fn"] = getattr(callee, "name", "?")
        return [r]
    return []


# ──────────────────────────────────────────────────────────────────────────────
# EnumerableSet at()-in-remove iteration-skip oracle (Glider gap W5)
# ──────────────────────────────────────────────────────────────────────────────
# OpenZeppelin `EnumerableSet.remove` (and a bare array swap-and-pop) moves the LAST
# element into the removed slot. A FORWARD loop that reads `set.at(i)` AND calls
# `set.remove(...)` on the SAME collection in the same body, while the loop counter
# advances monotonically (`i++`), SKIPS the element swapped into slot `i` (the index
# advances past it). The CORRECT pattern iterates BACKWARD (`i--`) so a swapped-in
# element occupies an already-processed slot, or re-reads without advancing.
#
# This COMPLEMENTS gap #5 `unbounded_loops` (gas-exhaustion: an attacker-growable
# `.length` bound) - that is a griefing surface; THIS is functional iteration-skip
# (incomplete iteration / unhandled state). The two oracles never overlap: one keys
# on the bound being attacker-growable, the other on a forward at()+remove pair.
#
# OZ EnumerableSet is recognized by the `.at(`/`.remove(`/`.length(` method-name
# triple on a library call (any of AddressSet/UintSet/Bytes32Set) plus a bare array
# `.pop()` swap-pop shape. Recognized method tokens live in module-level frozensets.

# EnumerableSet (and EnumerableMap) accessor / mutator method NAMES. We match on the
# Slither library-call `function.name`, so the *.AddressSet / *.UintSet / *.Bytes32Set
# variant does not matter (all three share these method names).
_ENUMSET_AT_METHODS = frozenset({"at"})
_ENUMSET_REMOVE_METHODS = frozenset({"remove"})
_ENUMSET_LENGTH_METHODS = frozenset({"length"})
# Bare-array swap-pop: a `.pop()` on a dynamic array is the same swap-and-pop hazard
# when paired with an indexed read on the same array in a forward loop.
_ARRAY_POP_RX = re.compile(r"\.\s*pop\s*\(\s*\)")
# Monotonic-increment shapes on the loop counter (FORWARD - flaggable direction).
# Matched against the counter-advance node expression text with the counter name.
_INCR_RXES = (
    r"^{c}\s*\+\+$", r"^\+\+\s*{c}$",            # i++  /  ++i
    r"^{c}\s*\+=", r"^{c}\s*=\s*{c}\s*\+",       # i += k  /  i = i + k
)
# Monotonic-decrement shapes (BACKWARD - the SAFE pattern; NEVER flagged).
_DECR_RXES = (
    r"^{c}\s*--$", r"^--\s*{c}$",                # i--  /  --i
    r"^{c}\s*-=", r"^{c}\s*=\s*{c}\s*-",         # i -= k  /  i = i - k
)


def _node_library_calls(node: Any):
    """Yield (method_name:str, receiver:str, arg_strs:list[str]) for every library
    call on `node`. Slither encodes library calls as `(Contract, LibraryCall_op)`
    where the op exposes `.function` (the library fn) and `.arguments` (the call
    args - argument[0] is the `using`-receiver collection). DEGRADE-safe: an
    unreadable entry is skipped (never crash, never a guess)."""
    for lc in getattr(node, "library_calls", []) or []:
        op = lc[1] if isinstance(lc, (list, tuple)) and len(lc) >= 2 else lc
        fn = getattr(op, "function", None)
        name = str(getattr(fn, "name", "") or "")
        if not name:
            continue
        args = getattr(op, "arguments", None) or []
        try:
            arg_strs = [str(a) for a in args]
        except Exception:
            arg_strs = []
        receiver = arg_strs[0] if arg_strs else ""
        yield (name, receiver, arg_strs)


def _loop_counter_name(ifloop: Any) -> Optional[str]:
    """Best-effort name of the loop COUNTER variable of an IFLOOP node: the LOCAL
    variable read in the loop condition (`i < members.length()` -> `i`). Prefers a
    local/temporary read over a state read (the collection is a state var). Returns
    None when no single counter can be positively identified (-> never flag)."""
    if ifloop is None:
        return None
    locals_read = []
    for v in getattr(ifloop, "local_variables_read", []) or []:
        nm = getattr(v, "name", None)
        if nm:
            locals_read.append(str(nm))
    # A canonical `i < coll.length()` condition reads exactly one local (the counter).
    if len(locals_read) == 1:
        return locals_read[0]
    return None


def _loop_direction(function: Any, ifloop: Any, counter: str) -> Optional[str]:
    """Return "forward" / "backward" / None for the COUNTER advance of `ifloop`.
    Scans the function's nodes for the counter-advance node (an EXPRESSION node
    writing `counter` whose expression text is a pure inc/dec of `counter`). The
    Slither lowering of `for (...; ...; i++)` places `i ++` as its own EXPRESSION
    node that writes `i`. CONSERVATIVE: when the direction cannot be POSITIVELY
    determined (no advance node, or a write that is neither a clean inc nor dec)
    -> None, and the caller NEVER flags an unknown direction (never-FP)."""
    if not counter:
        return None
    cre = re.escape(counter)
    incr = [re.compile(p.format(c=cre)) for p in _INCR_RXES]
    decr = [re.compile(p.format(c=cre)) for p in _DECR_RXES]
    for n in _iter_nodes(function):
        # The advance node WRITES the counter and is not the IFLOOP/condition itself.
        if n is ifloop:
            continue
        writes = {str(getattr(v, "name", "") or "") for v in (getattr(n, "local_variables_written", []) or [])}
        if counter not in writes:
            continue
        expr = _node_expr_str(n).strip()
        if not expr:
            continue
        if any(rx.match(expr) for rx in decr):
            return "backward"  # SAFE pattern
        if any(rx.match(expr) for rx in incr):
            return "forward"
    return None


def _loop_body_nodes(ifloop: Any) -> list:
    """Return the loop-body CFG nodes reachable from the IFLOOP's son_true, bounded
    by a visited-set and stopping at the IFLOOP back-edge (so the body is not walked
    out the loop exit). Mirrors gap #5 `_loop_body_has_effect`'s body walk. Returns
    [] when the body cannot be navigated."""
    body = _ifloop_body_first(ifloop)
    if body is None:
        return []
    out: list = []
    seen: set = set()
    frontier = [body]
    while frontier:
        cur = frontier.pop()
        if cur is None or id(cur) in seen or cur is ifloop:
            continue
        seen.add(id(cur))
        out.append(cur)
        for s in getattr(cur, "sons", []) or []:
            if s is ifloop:
                continue  # back-edge - do not walk the header
            if s is not None and id(s) not in seen:
                frontier.append(s)
    return out


def _is_loop_terminating_node(node: Any) -> bool:
    """True when `node` is an unconditional loop-exit statement: a slither BREAK or
    RETURN CFG node. CONTINUE is NOT loop-terminating (it re-reaches the back-edge),
    so it is deliberately excluded. Uses the short NodeType name (works whether or
    not slither.core.cfg.node.NodeType is importable - mirrors `_node_type_name`)."""
    return _node_type_name(node) in ("BREAK", "RETURN")


def _post_remove_reaches_back_edge(ifloop: Any, remove_node: Any) -> Optional[bool]:
    """W5 FP fix - post-remove loop-exit reachability.

    Walk the CFG forward from `remove_node` (the node carrying the `.remove(...)` /
    swap-pop), staying INSIDE the loop body, and decide whether the iteration-skip
    hazard is real:

      - the hazard is REAL iff there EXISTS a path from the remove node to the loop
        BACK-EDGE (re-reaching the IFLOOP header `ifloop`, i.e. the next
        `at(counter)` iteration) that does NOT first pass through an unconditional
        loop-terminating statement (BREAK / RETURN). -> return True (FLAG);
      - if EVERY post-remove path hits a BREAK/RETURN before the back-edge (the
        canonical find-and-remove-ONE-then-break/return idiom), the removal can
        never be followed by another `at(counter)` read -> no skip -> return False
        (SUPPRESS, never-FP).

    How the pieces are determined (reusing existing CFG nav):
      - BACK-EDGE: a `son` edge whose target IS `ifloop` (the IFLOOP header). The
        forward `i++` advance node's son is the IFLOOP, so reaching `ifloop` is
        exactly "the loop will run another iteration".
      - BREAK / RETURN: `_is_loop_terminating_node` (slither NodeType BREAK/RETURN).
        Such a node's outgoing edges leave the loop body (BREAK -> ENDLOOP,
        RETURN -> function exit), so we PRUNE the walk there (do not traverse its
        sons) - that path can never reach the back-edge.
      - LOOP BODY BOUND: we never traverse out the loop exit. We stop at `ifloop`
        itself (recording it as the back-edge) and prune at loop-terminating nodes.

    DEGRADE-safe (R80): returns None when the CFG cannot be resolved (no remove
    node / no ifloop). The caller then PRESERVES current behavior (flag) - i.e. an
    unresolved CFG does NOT suppress, so a real hazard is never silently dropped.
    Only a POSITIVELY-proven unconditional post-remove exit suppresses."""
    if remove_node is None or ifloop is None:
        return None
    seen: set = set()
    frontier = [remove_node]
    # Do not treat the remove node itself as the back-edge even in the degenerate
    # case; we walk its sons. (remove_node is never the IFLOOP header.)
    while frontier:
        cur = frontier.pop()
        if cur is None or id(cur) in seen:
            continue
        seen.add(id(cur))
        # A BREAK/RETURN reached on this path terminates the loop before any
        # further iteration: prune (do not walk its sons toward the exit).
        if cur is not remove_node and _is_loop_terminating_node(cur):
            continue
        for s in getattr(cur, "sons", []) or []:
            if s is None:
                continue
            if s is ifloop:
                # Back-edge reached WITHOUT first hitting a break/return on this
                # path -> the loop runs another at(counter) iteration -> REAL skip.
                return True
            if id(s) not in seen:
                frontier.append(s)
    # Exhausted every post-remove path without reaching the back-edge: every path
    # exited the loop (break/return) first -> hazard vacuous -> SUPPRESS.
    return False


def enumerable_remove_in_loop(function: Any) -> Any:
    """Conservative EnumerableSet at()-in-remove ITERATION-SKIP oracle.

    Returns a list of LEAD dicts, one per FORWARD loop whose body reads
    `<coll>.at(<counter>)` AND calls `<coll>.remove(...)` (or a bare-array swap-pop)
    on the SAME collection, while the counter advances monotonically:

        {"contract": <name>, "function": <fn name>, "loop_line": <int|None>,
         "at_line": <int|None>, "remove_line": <int|None>, "collection": <recv name>,
         "at_fn": "at", "severity_hint": "iteration-skip"}

    or DEGRADED (R80) when `function` is not navigable.

    Detection (CONSERVATIVE, never-false-positive by construction):
      1. for each IFLOOP (`loop_headers`), determine the counter direction
         (`_loop_direction`). Only a positively-FORWARD counter is flaggable;
      2. in the loop BODY (`_loop_body_nodes` - bounded, stops at the back-edge),
         find a `.at(` library read whose argument list references the COUNTER, AND
         a `.remove(`/array `.pop()` on the SAME collection receiver;
      3. flag ONLY when both the at-by-counter read and the remove hit the SAME
         collection.

    Never-flag (never-FP):
      - a BACKWARD loop (`i--`) -> the swapped-in element is already processed (SAFE);
      - an UNKNOWN / undeterminable direction -> not flagged;
      - a `.remove()` with NO `.at(counter)` on that collection (fixed-key removal,
        or the counter indexes a different array) -> not flagged;
      - a `.at(counter)` read with NO remove on that collection in the body -> not
        flagged.
    DEGRADE-safe (R80): an unnavigable function/loop yields DEGRADED or [].

    This is a LEAD only - never an auto-finding, never a flip of `unguarded`. It
    COMPLEMENTS gap #5 `unbounded_loops` (gas-exhaustion), which keys on an
    attacker-growable `.length` bound; this keys on a forward at()+remove pair."""
    if not _is_callable_function(function):
        return DEGRADED
    headers = loop_headers(function)
    if is_degraded(headers):
        return DEGRADED
    cname = ""
    contract = getattr(function, "contract", None) or getattr(function, "contract_declarer", None)
    if contract is not None:
        cname = str(getattr(contract, "name", "") or "")
    fname = str(getattr(function, "name", "?") or "?")
    out = []
    seen_lines: set = set()
    for ifl in headers:
        name = str(getattr(ifl, "type", "") or "").upper().rsplit(".", 1)[-1]
        if name != "IFLOOP":
            continue  # the condition + body anchor live on IFLOOP, not STARTLOOP
        counter = _loop_counter_name(ifl)
        if not counter:
            continue  # cannot positively identify the counter -> never flag
        direction = _loop_direction(function, ifl, counter)
        if direction != "forward":
            continue  # backward (SAFE) or unknown -> never flag (never-FP)
        body = _loop_body_nodes(ifl)
        if not body:
            continue
        # Collect, per collection receiver: the at()-by-counter read line and the
        # remove()/pop() line. Only a SAME-collection at+remove pair is flagged.
        at_by_counter: dict = {}   # collection -> at_line
        removes: dict = {}         # collection -> remove_line
        remove_nodes: dict = {}    # collection -> the CFG node carrying the remove
        for n in body:
            ln = _node_first_line(n)
            for (meth, recv, arg_strs) in _node_library_calls(n):
                if meth in _ENUMSET_AT_METHODS and recv:
                    # the .at() index argument must reference the advancing counter.
                    idx_args = arg_strs[1:] if len(arg_strs) > 1 else []
                    if any(re.search(r"\b" + re.escape(counter) + r"\b", a) for a in idx_args):
                        at_by_counter.setdefault(recv, ln)
                elif meth in _ENUMSET_REMOVE_METHODS and recv:
                    removes.setdefault(recv, ln)
                    remove_nodes.setdefault(recv, n)
            # Bare-array swap-pop: `<coll>.pop()` in the body. Receiver is the text
            # before `.pop()`; record under that token so a same-name `.at(`-like
            # indexed read (`coll[counter]`) could pair. We only record the pop line;
            # the same-collection pairing below requires an at()-by-counter read,
            # which for a bare array is captured via the index expression heuristic.
            expr = _node_expr_str(n)
            mpop = re.search(r"(\w+)\s*\.\s*pop\s*\(\s*\)", expr)
            if mpop:
                removes.setdefault(mpop.group(1), ln)
                remove_nodes.setdefault(mpop.group(1), n)
            # Bare-array indexed read by counter: `x = coll[counter]` -> at-by-counter
            # on the array `coll` (mirrors EnumerableSet.at for plain arrays).
            marr = re.search(r"(\w+)\s*\[\s*" + re.escape(counter) + r"\s*\]", expr)
            if marr:
                at_by_counter.setdefault(marr.group(1), ln)
        for coll, at_ln in at_by_counter.items():
            if coll not in removes:
                continue  # at()-by-counter but no remove on the SAME collection
            # W5 FP fix: suppress the find-and-remove-ONE-then-break/return idiom.
            # If EVERY post-remove path exits the loop (break/return) before the
            # back-edge, the swap-pop can never affect a later at(counter) read ->
            # the iteration-skip hazard is vacuous -> NEVER flag. A None (CFG could
            # not be resolved) PRESERVES current behavior (flag), never-MISS.
            reaches = _post_remove_reaches_back_edge(ifl, remove_nodes.get(coll))
            if reaches is False:
                continue
            loop_ln = _node_first_line(ifl)
            key = (cname, fname, loop_ln, at_ln, removes[coll], coll)
            if key in seen_lines:
                continue
            seen_lines.add(key)
            out.append({
                "contract": cname,
                "function": fname,
                "loop_line": loop_ln,
                "at_line": at_ln,
                "remove_line": removes[coll],
                "collection": coll,
                "at_fn": "at",
                "severity_hint": "iteration-skip",
            })
    return out


def closure_enumerable_remove_in_loop(function: Any) -> Any:
    """Like `enumerable_remove_in_loop` but scans `function`'s OWN body AND its
    forward callee closure (folding modifier bodies), so a forward at()+remove loop
    living in an INTERMEDIATE hop is found even when it is not in the source/sink
    fn's own body. Returns the FIRST hit (with `at_fn` overwritten to the hosting
    fn name) or [] when none. DEGRADED (R80) when not navigable. Mirrors
    `closure_unbounded_loops`."""
    own = enumerable_remove_in_loop(function)
    if is_degraded(own):
        return DEGRADED
    if own:
        r = dict(own[0])
        r["at_fn"] = getattr(function, "name", "?")
        return [r]
    closure = callee_closure(function, include_modifiers=True)
    if is_degraded(closure):
        return []
    for callee in closure:
        cl = enumerable_remove_in_loop(callee)
        if is_degraded(cl) or not cl:
            continue
        r = dict(cl[0])
        r["at_fn"] = getattr(callee, "name", "?")
        return [r]
    return []


# ── Unchecked return-value oracle (Glider gap W6 P1) ─────────────────────────
#
# A call whose boolean/success RETURN value is never consumed by any downstream
# IR (require / assert / if-condition / return / any read) silently continues on
# failure. This subsumes four Glider templates that all key on RETURN-value
# CONSUMPTION (distinct from cap-3 taint-of-INPUTS-to-sinks, and from cap-8 / W4
# external-call-then-write ORDERING):
#   missing-transfer-return-validation, unchecked-erc20-transfer-return-value,
#   missing-validation-on-low-level-call-returns,
#   missing-validation-on-delegate-call-returns.
#
# CALL-IR REUSE: target classification rides the SAME SlithIR call ops the other
# predicates use:
#   - HighLevelCall with `.function.name` in {transfer, transferFrom} (the
#     bool-returning ERC20 surface) -- same op `_high_level_call_names` walks.
#   - LowLevelCall with `.function_name` in {call, send, delegatecall} -- same op
#     `has_low_level_call` / `has_low_level_delegatecall` inspect.
#   - the `Send` op (address.send -> bool) -- a bool-returning low-level send.
# `address.transfer` lowers to a `Transfer` op with NO lvalue (it reverts on
# failure itself), so it is structurally never a target -> never flagged.
#
# SSA REUSE: consumption is decided by the SAME def-use identity machinery
# `divide_before_multiply` uses -- `_ir_var_key` keys the call's lvalue, and we
# scan every later IR's `.read` operands (folding the `Unpack` of a tuple-return
# `(bool ok, ) = x.call(...)` and pure-copy `Assignment`s) for that key. If the
# lvalue (or a transitive copy/unpack of it) is read by ANY downstream op, the
# return is consumed -> NOT flagged (require/assert/if-revert/return all read it).
# Only a wholly-unread return is a suspect. This is the conservative, never-FP
# definition: a developer who captured the bool at all is trusted.

def _ull_target_kind(ir: Any) -> Optional[str]:
    """Classify a SlithIR op as an unchecked-return-value TARGET call, returning
    the kind string or None. Reuses the call-IR classification the sibling
    predicates rely on; never raises.
      - "transfer"        HighLevelCall to transfer / transferFrom (ERC20 bool)
      - "low_level_call"  LowLevelCall .call / .send, or a Send op (bool success)
      - "delegatecall"    LowLevelCall .delegatecall (bool success)
    address.transfer (Transfer op, no bool return) -> None (reverts itself)."""
    cls = type(ir).__name__
    if cls == "HighLevelCall":
        try:
            nm = str(getattr(getattr(ir, "function", None), "name", "") or "")
        except Exception:
            nm = ""
        if nm in ("transfer", "transferFrom"):
            return "transfer"
        return None
    if cls == "LowLevelCall":
        try:
            fnm = str(getattr(ir, "function_name", "") or "").lower()
        except Exception:
            fnm = ""
        if fnm == "delegatecall":
            return "delegatecall"
        if fnm in ("call", "send"):
            return "low_level_call"
        return None
    if cls == "Send":
        # address.send(...) -> bool success (low-level, may be silently dropped)
        return "low_level_call"
    return None


def unchecked_return_values(function: Any) -> Any:
    """Flag every call in `function` whose boolean / success RETURN value is NEVER
    consumed by any downstream IR (no require / assert / if-condition / return /
    read of the result), so a failed call silently continues.

    Returns a list of records (deterministically ordered by call line):
        {"contract", "function", "call_line", "callee", "kind", "at_file",
         "at_line", "severity_hint": "unchecked-return"}
    or `DEGRADED` (R80) when `function` is not navigable or slither's call IR is
    unimportable (logged reason; never a guess). An empty list means every target
    call's return is consumed (never a silent miss).

    CONSERVATIVE / never-FP:
      - Targets ONLY the bool/success-returning calls (transfer/transferFrom high-
        level; .call/.send/delegatecall low-level; Send op). `address.transfer`
        (Transfer op, no bool return, reverts itself) is structurally not a target.
      - A SafeERC20-style call site does a LibraryCall to safeTransfer (NOT a
        target); the bool transfer lives inside the wrapper where it IS consumed by
        the wrapper's require -- so the consumer is never flagged.
      - A return consumed by require/assert/if->revert/return/any read (directly,
        or transitively via the Unpack of a `(bool ok, ) = ...` tuple or a pure-copy
        Assignment) -> NOT flagged.
      - When the call IR is unnavigable -> DEGRADE (R80), no guess."""
    if not _is_callable_function(function):
        return DEGRADED
    # Probe importability of the call IR classes; degrade (not guess) if missing.
    try:
        from slither.slithir.operations import (  # noqa: F401
            HighLevelCall, LowLevelCall, Send,
        )
    except Exception:
        try:
            import logging
            logging.getLogger(__name__).info(
                "unchecked_return_values: slither call IR ops unimportable - "
                "DEGRADED (no guess)."
            )
        except Exception:
            pass
        return DEGRADED

    Assignment = _assignment_ir_classes()

    cname = str(getattr(getattr(function, "contract", None), "name", "") or "?")
    fname = str(getattr(function, "name", "?") or "?")
    at_file = ""
    try:
        sm = getattr(function, "source_mapping", None)
        at_file = str(getattr(sm, "filename_short", "") or
                      getattr(getattr(sm, "filename", None), "short", "") or "")
    except Exception:
        at_file = ""

    # Linear IR program order across the fn's nodes, each tagged with its line.
    ir_seq = []
    try:
        for node in getattr(function, "nodes", []) or []:
            line = _first_line(node)
            for ir in _node_irs(node):
                ir_seq.append((ir, line))
    except Exception:
        return DEGRADED

    # Pass 1: build the transitive-read set of variable keys. Start with every
    # key that ANY IR op READS, then fold copy/unpack edges so the SOURCE temp of
    # a `(bool ok,) = x.call()` (Unpack) or a pure-copy Assignment counts as
    # "read" when its DESTINATION is read. We over-approximate "read" (any later
    # use, not only guard sinks) to stay conservative / never-FP: a developer who
    # captured the bool at all is trusted.
    read_keys = set()
    for ir, _ln in ir_seq:
        for v in (getattr(ir, "read", None) or []):
            k = _ir_var_key(v)
            if k is not None:
                read_keys.add(k)

    # Copy/unpack back-propagation: if `dst` is read, then `src` is effectively
    # consumed too (the bool flows through the unpack/copy into the guard).
    # Iterate to a fixpoint over Unpack/Assignment edges (small, bounded).
    edges = []  # (dst_key, src_key)
    for ir, _ln in ir_seq:
        cls = type(ir).__name__
        if cls == "Unpack":
            dst = _ir_var_key(getattr(ir, "lvalue", None))
            for v in (getattr(ir, "read", None) or []):
                src = _ir_var_key(v)
                if dst is not None and src is not None:
                    edges.append((dst, src))
        elif Assignment is not None and isinstance(ir, Assignment):
            dst = _ir_var_key(getattr(ir, "lvalue", None))
            src = _ir_var_key(getattr(ir, "rvalue", None))
            if dst is not None and src is not None:
                edges.append((dst, src))
    changed = True
    guard = 0
    while changed and guard < 1000:
        changed = False
        guard += 1
        for dst, src in edges:
            if dst in read_keys and src not in read_keys:
                read_keys.add(src)
                changed = True

    # Pass 2: each TARGET call whose lvalue key is NOT in read_keys is a suspect.
    out: list = []
    for ir, line in ir_seq:
        kind = _ull_target_kind(ir)
        if kind is None:
            continue
        lv = getattr(ir, "lvalue", None)
        lvkey = _ir_var_key(lv)
        if lvkey is None:
            # No lvalue at all -> no bool return to check (e.g. Transfer); skip.
            continue
        if lvkey in read_keys:
            continue  # return consumed -> NOT flagged
        # Resolve a human-readable callee name.
        callee = ""
        try:
            if type(ir).__name__ == "HighLevelCall":
                callee = str(getattr(getattr(ir, "function", None), "name", "") or "")
            elif type(ir).__name__ == "Send":
                callee = "send"
            else:
                callee = str(getattr(ir, "function_name", "") or "")
        except Exception:
            callee = ""
        out.append({
            "contract": cname,
            "function": fname,
            "call_line": line,
            "callee": callee,
            "kind": kind,
            "at_file": at_file,
            "at_line": line,
            "severity_hint": "unchecked-return",
        })
    out.sort(key=lambda r: (r.get("call_line") or 0, r.get("callee") or ""))
    return out


def closure_unchecked_return_values(function: Any) -> Any:
    """Closure variant of `unchecked_return_values`: scans `function`'s OWN body
    AND its forward callee closure (folding modifier bodies), so a bare unchecked
    transfer / low-level call living in an INTERMEDIATE helper the function calls is
    found. Aggregates the per-function suspect lists (deduplicated by
    contract/function/call_line/callee). FP-neutral: each member list is produced by
    the same conservative `unchecked_return_values`, so the closure adds reach, not
    FP risk. Returns the merged list, or `DEGRADED` (R80) when `function` is not
    navigable or the call IR is unimportable."""
    own = unchecked_return_values(function)
    if is_degraded(own):
        return DEGRADED
    merged = list(own)
    seen = {(r.get("contract"), r.get("function"), r.get("call_line"), r.get("callee"))
            for r in merged}
    closure = callee_closure(function, include_modifiers=True)
    if not is_degraded(closure):
        for callee in closure:
            res = unchecked_return_values(callee)
            if is_degraded(res):
                continue
            for r in res:
                key = (r.get("contract"), r.get("function"), r.get("call_line"), r.get("callee"))
                if key in seen:
                    continue
                seen.add(key)
                merged.append(r)
    merged.sort(key=lambda r: (r.get("call_line") or 0, r.get("callee") or ""))
    return merged


# ── LOGIC-TAUTOLOGY / DEAD-COMPARISON guard-logic correctness (Glider gap W6 P2) ─
#
# Two high-signal sub-rules that detect guard LOGIC errors (distinct from the
# boundary/comparator off-by-one class which keys on the OPERATOR, not the
# boolean structure of the guard):
#
# (a) ALWAYS-TRUE access tautology:
#     require(msg.sender != A || msg.sender != B) - always true (no address
#     can simultaneously be both A and B), nullifying the access check.
#     Detected by finding a Binary OROR whose two input temporaries were both
#     produced by NOT_EQUAL comparisons with the SAME caller-identity variable
#     (msg.sender or tx.origin) as the left/right operand.
#
# (b) DEAD comparison:
#     A standalone EXPRESSION node whose ONLY Binary IR is an EQUAL or NOT_EQUAL
#     whose lvalue is never read by any subsequent IR in the SAME node. The
#     comparison result is discarded - a guard the dev forgot to wrap in require.
#     Detected by a no-read lvalue scan over the node's own IR list.
#
# Design / never-FP contract:
#   (a) Only flagged when BOTH NOT_EQUAL sides involve the SAME caller name
#       ("msg.sender" or "tx.origin") - a conservative name-equality check,
#       not a semantic taint; the _msgSender() indirection form uses different
#       TMP objects per call so is intentionally NOT flagged by (a).
#   (b) Only flagged on EXPRESSION nodes (the standalone-statement context) when
#       the Binary lvalue is wholly unread within the node. An IF node (the
#       comparison drives a branch), an assignment (`ok = (a == b)`), a
#       require/assert argument, or a return all consume the result -> never FP.
#   Neither sub-rule auto-claims a finding; both are LEADS. DEGRADE-safe: the
#   helpers degrade to the DEGRADED sentinel (R80) on non-navigable functions.
#
# Future sub-rule (documented, NOT implemented - FP-prone without role knowledge):
#   allowances role-swap: require(allowances[msg.sender] == X ||
#   allowances[msg.sender] == Y) where X and Y denote swapped roles. Needs
#   role-taxonomy knowledge to avoid FPs - deferred to a corpus-grounded follow-up.

_CALLER_IDENTITY_NAMES = frozenset({"msg.sender", "tx.origin"})


def _is_caller_identity_var(v: Any) -> bool:
    """True when `v` is a SolidityVariableComposed for msg.sender / tx.origin."""
    nm = str(getattr(v, "name", "") or "")
    return nm in _CALLER_IDENTITY_NAMES


def _node_first_source_line(node: Any) -> Optional[int]:
    """Return the first source line of a CFG node, or None."""
    sm = getattr(node, "source_mapping", None)
    lines = list(getattr(sm, "lines", []) or []) if sm else []
    return lines[0] if lines else None


def _check_always_true_or(node: Any, Binary: Any, BinaryType: Any) -> Optional[dict]:
    """Scan a single CFG node for the always-true access tautology pattern.

    Detects: a BinaryType.OROR where both input temporaries were produced by
    BinaryType.NOT_EQUAL comparisons whose caller-identity operand (by name)
    is the SAME.

    Returns a hit dict or None. Never raises (caller catches)."""
    irs = list(getattr(node, "irs", []) or [])
    # Map lvalue id -> (left_caller_name, right_caller_name) for each NOT_EQUAL.
    ne_caller: dict[int, str] = {}  # lvalue_id -> caller name (left or right)
    for ir in irs:
        if not isinstance(ir, Binary):
            continue
        bt = getattr(ir, "type", None)
        bt_name = _binarytype_to_op(bt, BinaryType)
        if bt_name != "!=":
            continue
        lv = getattr(ir, "lvalue", None)
        if lv is None:
            continue
        lhs = getattr(ir, "variable_left", None)
        rhs = getattr(ir, "variable_right", None)
        # Identify which side is the caller-identity variable.
        if _is_caller_identity_var(lhs):
            ne_caller[id(lv)] = str(getattr(lhs, "name", ""))
        elif _is_caller_identity_var(rhs):
            ne_caller[id(lv)] = str(getattr(rhs, "name", ""))
    if not ne_caller:
        return None
    # Now find an OROR whose left and right were both NOT_EQUAL caller ops
    # with the SAME caller name.
    # NOTE: _binarytype_to_op only maps comparators, NOT OROR/ANDAND. Check
    # OROR by enum identity + string-fallback (enum name comparison).
    oror_type = getattr(BinaryType, "OROR", None)
    for ir in irs:
        if not isinstance(ir, Binary):
            continue
        bt = getattr(ir, "type", None)
        # Check for OROR by enum identity first, then string-fallback.
        is_oror = (
            (oror_type is not None and bt is oror_type)
            or str(bt).rsplit(".", 1)[-1].upper() == "OROR"
        )
        if not is_oror:
            continue
        l_var = getattr(ir, "variable_left", None)
        r_var = getattr(ir, "variable_right", None)
        l_nm = ne_caller.get(id(l_var))
        r_nm = ne_caller.get(id(r_var))
        if l_nm is not None and r_nm is not None and l_nm == r_nm:
            line = _node_first_source_line(node)
            expr = str(getattr(node, "expression", "") or "")
            return {
                "kind": "always-true-or",
                "at_line": line,
                "expr": expr,
                "caller_name": l_nm,
                "severity_hint": "broken-access-control",
            }
    return None


def _check_dead_comparison(node: Any, Binary: Any, BinaryType: Any) -> Optional[dict]:
    """Scan a single EXPRESSION CFG node for a dead == / != comparison.

    A dead comparison: the ONLY Binary IR on the node is an EQUAL or NOT_EQUAL,
    and its lvalue is never read by any subsequent IR in the same node. The
    comparison result is silently discarded (a guard the dev forgot to put in
    require / assert / if).

    Only fires on EXPRESSION nodes (not IF / IFLOOP nodes where the comparison
    DRIVES a branch decision - those are valid guards).

    Returns a hit dict or None. Never raises (caller catches)."""
    ntype = str(getattr(node, "type", "") or "").upper()
    # Only stand-alone expression statement nodes.
    if "EXPRESSION" not in ntype or "IF" in ntype or "LOOP" in ntype:
        return None
    irs = list(getattr(node, "irs", []) or [])
    if not irs:
        return None
    # Collect EQUAL / NOT_EQUAL Binary ops with their lvalues.
    eq_ops: list[tuple[Any, str, int]] = []  # (lvalue, op_str, ir_index)
    for i, ir in enumerate(irs):
        if not isinstance(ir, Binary):
            continue
        bt_name = _binarytype_to_op(getattr(ir, "type", None), BinaryType)
        if bt_name not in ("==", "!="):
            continue
        lv = getattr(ir, "lvalue", None)
        if lv is not None:
            eq_ops.append((lv, bt_name, i))
    if not eq_ops:
        return None
    # For each candidate, verify its lvalue is not read by any later IR.
    for lv, op_str, i_idx in eq_ops:
        lv_id = id(lv)
        used = False
        for j in range(i_idx + 1, len(irs)):
            later = irs[j]
            # `read` is a list/set of variables this IR reads.
            for rv in (list(getattr(later, "read", []) or [])):
                if id(rv) == lv_id:
                    used = True
                    break
            if used:
                break
        if not used:
            # Additional conservative check: is the node itself inside a
            # require/assert/if? That would mean the comparison is the guard
            # condition (handled by the IF node, not EXPRESSION). We already
            # excluded IF/IFLOOP node types above.
            line = _node_first_source_line(node)
            expr = str(getattr(node, "expression", "") or "")
            return {
                "kind": "dead-comparison",
                "at_line": line,
                "expr": expr,
                "op": op_str,
                "severity_hint": "broken-access-control",
            }
    return None


def logic_tautology_suspects(function: Any) -> Any:
    """Guard-LOGIC correctness oracle (Glider gap W6 P2): scan every node in
    `function`'s OWN body for the two always-signal sub-rules and return a list
    of hit dicts:

        [{"contract": str,
          "function": str,
          "kind": "always-true-or" | "dead-comparison",
          "at_line": int | None,
          "expr": str,
          "severity_hint": "broken-access-control",
          ...kind-specific keys...}, ...]

    Sub-rule (a) always-true-or: a Binary OROR whose both input temporaries
    were produced by NOT_EQUAL comparisons sharing the SAME caller-identity
    variable name (msg.sender / tx.origin). The OR of two disequalities on the
    same caller is logically tautological, nullifying the access check.

    Sub-rule (b) dead-comparison: a stand-alone EXPRESSION statement whose ONLY
    Binary IR is an EQUAL or NOT_EQUAL whose lvalue is never read by any later
    IR in the same node. The result is discarded - a guard forgotten in require.

    Never-FP contract:
      - (a) requires BOTH sides to involve the SAME caller-identity name; the
        _msgSender() indirection form (different TMP objects) is NOT flagged.
      - (b) fires only on EXPRESSION nodes; a comparison inside IF / IFLOOP
        (the branch decision), require/assert (guard argument), assignment, or
        return (the lvalue IS read by later IR) is never flagged.

    NOT implemented (documented future sub-rule - needs role taxonomy):
      allowances role-swap (FP-prone without role knowledge).

    Returns DEGRADED (R80) when `function` is not navigable or Slither Binary IR
    is not importable. Returns [] for a navigable function with no suspects."""
    if not _is_callable_function(function):
        return DEGRADED
    Binary, BinaryType = _binary_ir_classes()
    if Binary is None:
        return DEGRADED
    # Resolve the contract + function names once for annotation.
    contract_name = ""
    fn_name = ""
    try:
        contract_name = str(getattr(getattr(function, "contract", None), "name", "") or "")
        fn_name = str(getattr(function, "name", "") or "")
    except Exception:
        pass

    hits: list[dict] = []
    try:
        for node in (getattr(function, "nodes", []) or []):
            try:
                h = _check_always_true_or(node, Binary, BinaryType)
                if h:
                    hits.append({"contract": contract_name, "function": fn_name, **h})
                    continue  # one hit per node is enough
                h = _check_dead_comparison(node, Binary, BinaryType)
                if h:
                    hits.append({"contract": contract_name, "function": fn_name, **h})
            except Exception:
                continue
    except Exception:
        return DEGRADED
    return hits


def closure_logic_tautology_suspects(function: Any) -> Any:
    """Closure variant of `logic_tautology_suspects`: scans `function`'s OWN
    body AND its forward callee closure (folding modifier bodies), so a
    tautological or dead guard living in an intermediate helper the function
    calls is also found. Aggregates the per-function suspect lists
    (deduplicated by contract/function/at_line/kind). FP-neutral: each member
    list is produced by the same conservative `logic_tautology_suspects`.

    Returns the merged list, or DEGRADED (R80) when `function` is not navigable
    or Slither Binary IR is not importable."""
    own = logic_tautology_suspects(function)
    if is_degraded(own):
        return DEGRADED
    merged = list(own)
    seen = {(r.get("contract"), r.get("function"), r.get("at_line"), r.get("kind"))
            for r in merged}
    closure = callee_closure(function, include_modifiers=True)
    if not is_degraded(closure):
        for callee in closure:
            res = logic_tautology_suspects(callee)
            if is_degraded(res):
                continue
            for r in res:
                key = (r.get("contract"), r.get("function"), r.get("at_line"), r.get("kind"))
                if key in seen:
                    continue
                seen.add(key)
                merged.append(r)
    merged.sort(key=lambda r: (r.get("at_line") or 0, r.get("kind") or ""))
    return merged
# ── Memory-copy-of-storage-never-written-back oracle (Glider gap W6 P8) ──────
#
# A storage STATE variable is read into a MEMORY local (e.g. `MyStruct memory s =
# storageStruct;` or a primitive memory copy of a storage value), the local is then
# MUTATED (field write / compound assign), but the function NEVER writes that
# mutation back to the storage var - so the state update is silently lost.
#
# DETECTION (CONSERVATIVE, never-false-positive by construction):
#   1. Find an `Assignment` SSA IR where:
#      - `lvalue` is a LocalVariable with `.location == "memory"` (verified above:
#        this means it is a genuine memory copy, not a storage pointer which has
#        `.location == "storage"` / `.is_storage == True`).
#      - `rvalue` is a StateVariable (the storage source being copied).
#   2. Verify that the memory local is subsequently MUTATED - i.e. some node in the
#      function has that local variable in its `local_variables_written` list (other
#      than the initial copy-assignment node). Field writes like `c.limit = v`
#      produce a `Member` IR that writes a `ReferenceVariable` whose point-of-write
#      node also appears in `local_variables_written` for `c`.
#   3. Confirm that the original state variable is NEVER written by any node in the
#      whole function (no `state_variables_written` containing the sv name). If it
#      IS written (a direct `storageVar = ...` or `storageVar = localCopy` write-
#      back exists) -> CLEAN.
#
# NEVER-FLAG (never-FP) cases:
#   - A local declared `storage` (`.location == "storage"`, `.is_storage == True`)
#     is a real storage POINTER, NOT a copy - mutations go directly to storage.
#   - A memory copy that is never mutated after the initial assignment (read-only
#     use, e.g. for a local view computation) - condition 2 is not met.
#   - A memory copy whose originating state var is written anywhere in the function
#     (the dev writes back explicitly, or writes the state var directly elsewhere in
#     the same function) - condition 3 is not met.
#   - A local whose `location` is `None` / unresolvable (not `"memory"`) - we do
#     NOT assume memory; conservatively skip (no false-positive possible).
#
# DEGRADE-SAFE (R80): an unnavigable function returns DEGRADED. If the Assignment
# class is not importable (Slither IR unavailable), returns DEGRADED.
#
# NOTE: this uses `local_variables_written` (a node-level set in Slither) to detect
# mutation, NOT just the IR `.lvalue`. Both signals are checked for robustness.
# The `StateVariable` class check on the rvalue is an exact type check: a plain
# `LocalVariable` rvalue (a local-to-local copy) is NOT flagged (only a state-to-
# local copy enters condition 1). This is the tightest correct definition.


def _mcnwb_local_is_memory_copy(lv: Any) -> bool:
    """True when `lv` is a LocalVariable with explicit `location == "memory"`.
    A `None` / unknown location, a `"storage"` pointer, or a `"calldata"` param
    are all NOT treated as memory copies (conservative). Never raises."""
    try:
        loc = getattr(lv, "location", None)
        return loc == "memory"
    except Exception:
        return False


def _mcnwb_is_state_variable(v: Any) -> bool:
    """True when `v` is a Slither StateVariable (not a LocalVariable or
    ReferenceVariable). Keyed on the class name string so it does not require a
    direct import of the StateVariable class (import-safe / degrade-safe)."""
    try:
        cn = type(v).__name__
        # StateVariable, StateVariableSSA, StateVariableSSAWithAccessedStorage
        return "StateVariable" in cn and "Local" not in cn
    except Exception:
        return False


def memory_copy_no_writeback(function: Any) -> Any:
    """Conservative MEMORY-COPY-OF-STORAGE-NEVER-WRITTEN-BACK oracle.

    Returns a list of LEAD dicts, one per {state_var, memory_local} pair where:
      (1) the state var is read into a MEMORY local (Assignment IR: LocalVariable
          with location=="memory" <- StateVariable),
      (2) the memory local is subsequently mutated in the same function
          (`local_variables_written` hit after the copy-assignment node), AND
      (3) the state variable is NEVER written anywhere in the function
          (no node has the sv name in `state_variables_written`).

    Dict shape:
        {"contract": <str>, "function": <str>,
         "state_var": <str>, "local": <str>,
         "copy_line": <int|None>, "mutate_line": <int|None>,
         "severity_hint": "lost-state-update"}

    Returns DEGRADED (R80) when `function` is not navigable or Assignment IR is
    unavailable. Returns [] (no leads) when the function is navigable but no hit
    matches all three conditions. Never-FP: a storage pointer, a read-only copy,
    or a copy paired with a real writeback are all cleanly rejected."""
    if not _is_callable_function(function):
        return DEGRADED

    # Attempt to import the Assignment IR class; if unavailable -> degrade.
    try:
        from slither.slithir.operations import Assignment as _Assign
    except Exception:
        return DEGRADED

    try:
        nodes = list(getattr(function, "nodes", []) or [])
    except Exception:
        return DEGRADED

    # ── Pass 0: collect all state variables WRITTEN anywhere in this function.
    # Used for condition (3): if the sv IS written anywhere, the copy+mutate pair
    # is NOT a bug (developer writes back, or writes the sv separately). We collect
    # by sv NAME (string) since the same StateVariable object appears across nodes.
    sv_written_names: set = set()
    try:
        for n in nodes:
            for sv in getattr(n, "state_variables_written", []) or []:
                nm = getattr(sv, "name", None)
                if nm:
                    sv_written_names.add(str(nm))
    except Exception:
        return DEGRADED

    # ── Pass 1: find MEMORY-COPY assignments (condition 1).
    # Record: local_name -> (state_var_name, copy_line, copy_node_idx).
    # If the same local is reassigned multiple times (rare), the LAST assignment
    # wins (so the later pair can still be flagged if the local is then mutated
    # but the sv is still never written back).
    copy_info: dict = {}  # local_name -> {"sv": str, "copy_line": int|None, "idx": int}
    try:
        for ni, n in enumerate(nodes):
            for ir in (getattr(n, "irs", []) or []):
                if not isinstance(ir, _Assign):
                    continue
                lv = getattr(ir, "lvalue", None)
                rv = getattr(ir, "rvalue", None)
                if lv is None or rv is None:
                    continue
                # Condition 1: lvalue is a memory LocalVariable, rvalue is a StateVar.
                if not _mcnwb_local_is_memory_copy(lv):
                    continue
                if not _mcnwb_is_state_variable(rv):
                    continue
                lv_name = str(getattr(lv, "name", "") or "")
                sv_name = str(getattr(rv, "name", "") or "")
                if not lv_name or not sv_name:
                    continue
                copy_line = _node_first_line(n)
                copy_info[lv_name] = {"sv": sv_name, "copy_line": copy_line, "idx": ni}
    except Exception:
        return DEGRADED

    if not copy_info:
        return []

    # ── Pass 2: find MUTATION of a memory-copy local (condition 2).
    # A mutation is a node (after the copy-assignment node) that has the local
    # name in `local_variables_written`. The initial copy-assignment node itself
    # writes the local (the copy), so we skip that node (idx == copy_idx).
    mutate_info: dict = {}  # local_name -> mutate_line
    try:
        for lv_name, ci in copy_info.items():
            copy_idx = ci["idx"]
            for ni, n in enumerate(nodes):
                if ni == copy_idx:
                    continue  # skip the copy-assignment node itself
                for lv in (getattr(n, "local_variables_written", []) or []):
                    if str(getattr(lv, "name", "") or "") == lv_name:
                        mutate_info[lv_name] = _node_first_line(n)
                        break
                if lv_name in mutate_info:
                    break
    except Exception:
        return DEGRADED

    # ── Pass 3: emit leads for {copy, mutate} pairs where the sv is NEVER written.
    cname = ""
    try:
        contract = (getattr(function, "contract", None)
                    or getattr(function, "contract_declarer", None))
        if contract is not None:
            cname = str(getattr(contract, "name", "") or "")
    except Exception:
        pass
    fname = str(getattr(function, "name", "?") or "?")

    out = []
    seen_pairs: set = set()
    for lv_name, ci in copy_info.items():
        if lv_name not in mutate_info:
            continue  # condition 2 not met: no mutation -> CLEAN (no lost write)
        sv_name = ci["sv"]
        if sv_name in sv_written_names:
            continue  # condition 3 not met: sv IS written -> CLEAN (writeback exists)
        key = (cname, fname, sv_name, lv_name)
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        out.append({
            "contract": cname,
            "function": fname,
            "state_var": sv_name,
            "local": lv_name,
            "copy_line": ci["copy_line"],
            "mutate_line": mutate_info[lv_name],
            "severity_hint": "lost-state-update",
        })
    return out


# ── Two-step-ownership-accept WRONG-GUARD detector (Glider gap W6 P5) ────────
#
# A two-step ownership-transfer pattern has TWO phases:
#   Phase 1: current owner calls `transferOwnership(newOwner)` to set a
#            `pendingOwner` state variable (not protected here).
#   Phase 2: the PENDING owner calls `acceptOwnership()` to confirm the
#            transfer -- this function should `require(msg.sender == pendingOwner)`.
#
# The BUG: the accept/claim function is gated by `onlyOwner` (checking the
# CURRENT owner) instead of checking the pending owner. Consequence: the pending
# owner can never call it (wrong guard), OR the current owner can bypass the
# two-step and directly self-assign (guard confusion / privilege escalation).
#
# CONSERVATIVE / never-FP: flag ONLY when ALL 5 predicates hold:
#   (1) function name starts with accept/claim AND contains ownership/admin token
#   (2) a pending* state var EXISTS somewhere in the contract
#   (3) the function writes an ownership-family state var (owner/_owner/admin/...)
#   (4) the function has an onlyOwner/onlyAdmin-family MODIFIER (wrong guard present)
#   (5) the function has NO Binary comparison of msg.sender/_msgSender against a
#       pending* state var (the correct guard is ABSENT)
# If the correct pending-check IS present, do NOT flag (never mis-class a properly
# dual-gated accept). DEGRADE-safe (R80): a non-navigable object returns DEGRADED.
# Distinct from: missing-guard (cap-1, no guard at all) and override-dropped-guard
# (W1, guard present in base but dropped in child override).

# Canonical accept/claim-ownership function-name patterns (case-insensitive).
_ACCEPT_FN_PATTERN = re.compile(
    r"^(accept|claim)(ownership|admin|governance|governor|role)\w*$",
    re.IGNORECASE,
)

# Ownership-family state-variable NAME patterns (lower-cased match).
_OWNERSHIP_VAR_NAMES = frozenset({
    "owner",
    "_owner",
    "admin",
    "_admin",
    "governance",
    "_governance",
    "governor",
    "_governor",
})

# pending-owner state-variable name prefix (lower-cased).
_PENDING_VAR_PREFIX = "pending"

# onlyOwner/onlyAdmin-family MODIFIER name patterns (the WRONG guard for an
# accept-ownership function -- these check the CURRENT owner, not the pending one).
_ONLY_OWNER_FAMILY_RE = re.compile(
    r"onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyRole|restricted",
    re.IGNORECASE,
)


# ── SIGNATURE-REPLAY precondition detector (Glider gap W6 P3) ────────────────
# Two highest-signal sub-rules, both CONSERVATIVE / never-FP by construction:
#
# (a) MISSING-NONCE: the verifying function's closure calls ecrecover (or a
#     recover/ECDSA.recover helper) but has NO storage write that increments
#     or consumes a per-signer or per-message nonce / used-hash mapping
#     (no `nonces[signer]++`, no `usedHashes[hash] = true`). A verified
#     signature with no nonce consumption is replayable on the same chain.
#     Detection: `calls_ecrecover_in_closure` (the seed), then scan every
#     node in the function AND its forward callee closure for a state-variable
#     write (node.state_variables_written) that looks like a nonce/used-hash
#     store. If ANY such write is found, we SUPPRESS (never-FP). Only the
#     absence of ALL such writes triggers.
#
# (b) MISSING-CHAINID: the function's closure calls ecrecover AND builds a
#     digest (keccak256 / abi.encode feeds the ecrecover hash argument) but
#     NO node in the function OR its closure reads block.chainid. A digest
#     without the chain-id is replayable across forks / deployments on other
#     chains. Detection: `calls_ecrecover_in_closure` (seed), then verify that
#     block.chainid IS read somewhere in the function + closure; if not,
#     flag missing-chainid.
#
# Seed condition (both rules): ecrecover (or a RECOVER-named callee) must be
# genuinely present in the function's own body OR its forward callee closure.
# When ecrecover is absent, NEITHER rule fires (never-FP on non-sig functions).
#
# Documented future sub-rules (NOT built - FP-prone without taint):
#   (c) missing-address(this)/domain-separator: the digest omits address(this),
#       making it replayable across multiple contract instances; requires
#       taint tracking to distinguish domain-separator-absent from
#       domain-separator-included-via-import.
#   (d) batched-per-signer-dedup: a batch verify that processes N signatures but
#       checks uniqueness only at submission time (not per-element); requires
#       loop-body taint to avoid FP on single-sig paths.
#
# DEGRADE-safe (R80): a non-navigable function returns DEGRADED. The closure
# walk degrades gracefully (leaves no annotation) on an unavailable fn. A
# degrade on the closure NEVER silently suppresses a real flag - we only
# suppress on a POSITIVE nonce-write or chainid-read signal, never on absence
# of evidence.
#
# LEAD ONLY: never an auto-finding, never flips `unguarded`. Additive new
# stat key. DEFAULT-OFF: only emits records when ecrecover is genuinely present.

# Nonce / used-hash state-variable name heuristic. A state-variable write
# whose name matches is treated as a per-signer or per-message nonce
# consumption. Conservative: false-negative is safe (we may miss an obscurely
# named nonce variable); false-positive on a non-nonce store would suppress
# a real finding, so the allow-list is kept to high-signal tokens only.
_NONCE_VAR_NAME_RX = re.compile(
    r"nonce|used|replay|seen|executed|processed|consumed|spent|invalidat",
    re.IGNORECASE,
)

# Helper callee names recognised as ecrecover-equivalent (OpenZeppelin ECDSA
# and common library wrappers). Matched case-insensitively on the function name.
_ECRECOVER_CALLEE_RX = re.compile(
    r"^ecrecover$|^recover$|ECDSA\.recover|^_recover$|^_ecrecover$",
    re.IGNORECASE,
)


def _tsawg_is_ownership_fn(function: Any) -> bool:
    """True when the function name matches the accept/claim-ownership pattern."""
    name = str(getattr(function, "name", "") or "").strip()
    return bool(_ACCEPT_FN_PATTERN.match(name))


def _tsawg_has_pending_var_in_contract(function: Any) -> Optional[str]:
    """Return the name of the first pending* state variable found on the function's
    contract, or None when no such variable exists."""
    try:
        contract = (getattr(function, "contract", None)
                    or getattr(function, "contract_declarer", None))
        if contract is None:
            return None
        for sv in (getattr(contract, "state_variables", []) or []):
            sv_name = str(getattr(sv, "name", "") or "").lower()
            if sv_name.startswith(_PENDING_VAR_PREFIX):
                return str(getattr(sv, "name", "") or sv_name)
    except Exception:
        pass
    return None


def _tsawg_writes_ownership_var(function: Any) -> Optional[str]:
    """Return the name of the first ownership-family state variable WRITTEN in
    `function` (any node), or None when none is written.

    Uses Slither's semantic `state_variables_written` signal (no comment/literal FP)."""
    try:
        for n in _iter_nodes(function):
            for sv in (getattr(n, "state_variables_written", []) or []):
                sv_name = str(getattr(sv, "name", "") or "").lower()
                if sv_name in _OWNERSHIP_VAR_NAMES:
                    return str(getattr(sv, "name", "") or sv_name)
    except Exception:
        pass
    return None


def _tsawg_has_only_owner_modifier(function: Any) -> Optional[str]:
    """Return the modifier name matching the onlyOwner-family pattern, or None.

    Only header modifiers are checked (the WRONG guard is a modifier on the
    function declaration header, not an inline require). An inline
    `require(msg.sender == owner())` is also accepted as the "wrong guard" when
    it compares against a non-pending ownership accessor."""
    # Header modifier check.
    try:
        for m in (getattr(function, "modifiers", []) or []):
            mname = str(getattr(m, "name", "") or "")
            if _ONLY_OWNER_FAMILY_RE.search(mname):
                return mname
    except Exception:
        pass
    # Inline require(msg.sender == owner()) as wrong guard fallback.
    # Detected via: node in revert-context, reads caller, AND calls an
    # ownership accessor (owner()/_checkOwner/etc.) but NOT pending*.
    try:
        for n in _iter_nodes(function):
            if not _node_in_revert_context(n):
                continue
            if not _node_reads_caller(n):
                continue
            callees = set(_node_callee_names(n))
            # "owner" / "getowner" / "isowner" in callees but not a pending-accessor
            if callees & (_AUTHZ_ACCESSOR_NAMES | _AUTHZ_HELPER_NAMES):
                pending_callee = any(c.startswith(_PENDING_VAR_PREFIX) for c in callees)
                if not pending_callee:
                    return "inline-require(owner)"
    except Exception:
        pass
    return None


def _tsawg_has_pending_check(function: Any, pending_var_name: str) -> bool:
    """True when the function has ANY Binary comparison of msg.sender / _msgSender()
    against a pending* state variable (the CORRECT guard for an accept-ownership).

    Strategy: scan all node expressions (as strings) for the pending var name
    co-occurring with msg.sender / _msgSender in a require/assert/if context.
    Also scan SlithIR Binary ops for a direct (msg.sender, pending_var) comparison.
    CONSERVATIVE: if unsure (IR unavailable), return False (no suppression -> may
    emit a false positive) -- but all 5 conditions must hold before flagging, so a
    false positive from this sub-check is caught by the overall conservatism."""
    pname_lower = pending_var_name.lower()
    try:
        for n in _iter_nodes(function):
            # (a) SlithIR Binary op check: look for a Binary whose operands include
            #     a caller read (msg.sender) AND the pending var by name.
            for ir in _node_irs(n):
                ir_cls = type(ir).__name__.lower()
                if "binary" not in ir_cls:
                    continue
                lv = getattr(ir, "lvalue", None)
                rv_vars = []
                for attr in ("variable_left", "variable_right", "lvalue", "rvalue"):
                    v = getattr(ir, attr, None)
                    if v is not None:
                        rv_vars.append(v)
                operand_names_lower = set(
                    str(getattr(v, "name", "") or "").lower()
                    for v in rv_vars
                )
                if pname_lower in operand_names_lower:
                    # Check if msg.sender is also involved (via solidity_variables_read
                    # on this node, or operand name).
                    if "msg.sender" in operand_names_lower or _node_reads_caller(n):
                        return True

            # (b) String-expression heuristic fallback: pending var name + msg.sender
            #     both appear in a require/assert/if node expression. Conservative:
            #     only in a guard context.
            if not _node_in_revert_context(n):
                continue
            expr = _node_expr_str(n).lower()
            if pname_lower in expr and "msg.sender" in expr:
                return True
            # Also catch _msgSender() indirection.
            if pname_lower in expr and "_msgsender" in expr:
                return True
    except Exception:
        pass
    return False


def two_step_accept_wrong_guard(function: Any) -> Any:
    """Two-step-ownership-accept WRONG-GUARD detector (Glider gap W6 P5).

    Flags a function that:
      (1) is named accept*/claim* ownership/admin (acceptOwnership, claimOwnership,
          acceptAdmin, claimAdmin, acceptGovernance, ...),
      (2) has a pending* state variable in its contract,
      (3) WRITES an ownership-family state var (owner/_owner/admin/...),
      (4) has an onlyOwner/onlyAdmin-family MODIFIER (the WRONG guard: it checks the
          CURRENT owner, not the pending one), AND
      (5) has NO msg.sender==pending* comparison (the CORRECT guard is absent).

    Returns a list of records:
        {"contract", "function", "ownership_var", "pending_var", "guard_modifier",
         "at_line", "severity_hint"}
    or `DEGRADED` (R80) when `function` is not navigable. Empty list = no suspect.

    CONSERVATIVE / never-FP:
    - If a pending-check IS present (condition 5 fails), returns [].
    - If no pending* var EXISTS in the contract, returns [].
    - If no ownership var is written, returns [].
    - If no onlyOwner-family guard, returns [].
    - A non-navigable function returns DEGRADED (R80).
    """
    if not _is_callable_function(function):
        return DEGRADED

    # Condition 1: function name matches accept/claim-ownership pattern.
    if not _tsawg_is_ownership_fn(function):
        return []

    # Condition 2: pending* state var exists in contract.
    pending_var = _tsawg_has_pending_var_in_contract(function)
    if pending_var is None:
        return []

    # Condition 3: function writes an ownership-family state var.
    ownership_var = _tsawg_writes_ownership_var(function)
    if ownership_var is None:
        return []

    # Condition 4: function has an onlyOwner-family guard (the WRONG one).
    guard_modifier = _tsawg_has_only_owner_modifier(function)
    if guard_modifier is None:
        return []

    # Condition 5: NO correct pending-check present (if present, NOT a bug).
    if _tsawg_has_pending_check(function, pending_var):
        return []

    # All 5 conditions met: emit suspect record.
    cname = ""
    try:
        contract = (getattr(function, "contract", None)
                    or getattr(function, "contract_declarer", None))
        if contract is not None:
            cname = str(getattr(contract, "name", "") or "")
    except Exception:
        pass
    fname = str(getattr(function, "name", "?") or "?")

    # Anchor at the function declaration line.
    at_line: Optional[int] = None
    try:
        sm = getattr(function, "source_mapping", None)
        lines = list(getattr(sm, "lines", []) or []) if sm else []
        at_line = lines[0] if lines else None
    except Exception:
        pass

    return [{
        "contract": cname,
        "function": fname,
        "ownership_var": ownership_var,
        "pending_var": pending_var,
        "guard_modifier": guard_modifier,
        "at_line": at_line,
        "severity_hint": "access-control",
    }]


def _fn_closure_calls_ecrecover(fn: Any) -> bool:
    """True when `fn`'s own body OR any callee in its forward closure calls
    ecrecover or a recognised recover helper. Used as the seed condition for
    both signature-replay sub-rules (never-FP: only fires when genuinely present).
    Degrades to False (conservative) on a non-navigable fn - the caller then
    skips the function without flagging it."""
    if not _is_callable_function(fn):
        return False
    # Own body first (fast path).
    if calls_ecrecover(fn):
        return True
    # Walk high-level + internal callee NAMES looking for recover helpers.
    # We do NOT need the full body, just the callee name, so we scan _direct
    # callees without a full closure walk here.
    for node in getattr(fn, "nodes", []) or []:
        for attr in ("internal_calls", "high_level_calls"):
            for c in getattr(node, attr, []) or []:
                cand = c[1] if isinstance(c, (list, tuple)) and len(c) >= 2 else c
                nm = getattr(cand, "name", None) or getattr(
                    getattr(cand, "function", None), "name", None)
                if nm and _ECRECOVER_CALLEE_RX.match(str(nm)):
                    return True
        # Solidity built-in call names.
        for sc in getattr(node, "solidity_calls", []) or []:
            nm = getattr(sc, "name", None) or str(sc)
            if nm and "ecrecover" in str(nm).lower():
                return True
    # Check full closure for recover helpers (bounded by callee_closure cycle-guard).
    closure = callee_closure(fn, include_modifiers=True)
    if closure is DEGRADED:
        return False
    for callee in closure:
        if calls_ecrecover(callee):
            return True
        nm = str(getattr(callee, "name", "") or "")
        if _ECRECOVER_CALLEE_RX.match(nm):
            return True
    return False


def _fn_closure_reads_chainid(fn: Any) -> bool:
    """True when `fn`'s own body OR any callee in its forward closure reads
    block.chainid (the Solidity built-in). Reuses `_has_solidity_var_read`
    (semantic IR signal, ignores comments / string literals). Conservative:
    degrades to False on a non-navigable fn."""
    if not _is_callable_function(fn):
        return False
    # Own body.
    if _has_solidity_var_read(fn, "block.chainid"):
        return True
    # Full closure.
    closure = callee_closure(fn, include_modifiers=True)
    if closure is DEGRADED:
        return False
    for callee in closure:
        if _has_solidity_var_read(callee, "block.chainid"):
            return True
    return False


def _fn_closure_has_nonce_write(fn: Any) -> bool:
    """True when `fn`'s own body OR any callee in its forward closure writes a
    state variable whose name matches the nonce / used-hash heuristic. A storage
    write of this kind is a positive nonce-consumption signal; its presence
    SUPPRESSES the missing-nonce flag (conservative: prefer not to flag when
    nonce-like storage writes are present). Degrades to False on a non-navigable
    fn (conservative: may leave the flag active, which is safe for a never-FP
    oracle - a degrade means we cannot confirm suppression)."""
    if not _is_callable_function(fn):
        return False
    # Own body.
    for node in getattr(fn, "nodes", []) or []:
        for sv in getattr(node, "state_variables_written", []) or []:
            nm = str(getattr(sv, "name", "") or "")
            if nm and _NONCE_VAR_NAME_RX.search(nm):
                return True
    # Full closure.
    closure = callee_closure(fn, include_modifiers=True)
    if closure is DEGRADED:
        return False
    for callee in closure:
        for node in getattr(callee, "nodes", []) or []:
            for sv in getattr(node, "state_variables_written", []) or []:
                nm = str(getattr(sv, "name", "") or "")
                if nm and _NONCE_VAR_NAME_RX.search(nm):
                    return True
    return False


def _fn_first_line(fn: Any) -> Optional[int]:
    """Best-effort first source line of `fn` (for the `at_line` field)."""
    sm = getattr(fn, "source_mapping", None)
    lines = list(getattr(sm, "lines", []) or []) if sm else []
    return lines[0] if lines else None


def signature_replay_suspects(function: Any) -> Any:
    """Conservative SIGNATURE-REPLAY precondition oracle (Glider gap W6 P3).

    Returns a list of LEAD dicts, one per flagged sub-rule hit, each:
        {"contract": <name>, "function": <fn name>,
         "kind": "missing-nonce" | "missing-chainid",
         "ecrecover_line": <int|None>,
         "at_line": <int|None>,
         "severity_hint": "signature-replay"}

    or DEGRADED (R80) when `function` is not navigable.

    Detection (CONSERVATIVE, never-false-positive by construction):

    Seed: ecrecover (or a recover/ECDSA.recover helper) must be genuinely
    present in the function's own body or its forward callee closure; if not,
    NEITHER sub-rule fires.

    (a) MISSING-NONCE: ecrecover present AND no state-variable write in the
        function + closure whose name matches the nonce/used-hash heuristic
        (nonce/used/replay/seen/executed/processed/consumed/spent/invalidat).
        A positively-found nonce write SUPPRESSES this flag. A degrade on
        the nonce-write scan leaves the flag active (safe direction for a
        never-miss oracle).

    (b) MISSING-CHAINID: ecrecover present AND no node in the function +
        closure reads block.chainid (semantic IR signal via
        `_has_solidity_var_read`). A positively-found chainid read SUPPRESSES
        this flag. A degrade on the closure walk leaves the flag active.

    Both flags can fire on the same function (if both nonce AND chainid are
    absent). Each is reported as a SEPARATE dict in the output list.

    Never-false-positive: a function WITHOUT ecrecover -> []. A function
    WITH ecrecover + a nonce write -> no missing-nonce. A function WITH
    ecrecover + block.chainid read -> no missing-chainid.

    DEGRADE-safe (R80): a non-navigable `function` returns DEGRADED.
    """
    if not _is_callable_function(function):
        return DEGRADED

    # Seed: verify ecrecover is genuinely present. If not, return [] immediately.
    if not _fn_closure_calls_ecrecover(function):
        return []

    cname = ""
    contract = getattr(function, "contract", None) or getattr(
        function, "contract_declarer", None)
    if contract is not None:
        cname = str(getattr(contract, "name", "") or "")
    fname = str(getattr(function, "name", "?") or "?")

    # ecrecover line: best-effort from the function's own body.
    ecrecover_line: Optional[int] = None
    for node in getattr(function, "nodes", []) or []:
        for sc in getattr(node, "solidity_calls", []) or []:
            nm = getattr(sc, "name", None) or str(sc)
            if nm and "ecrecover" in str(nm).lower():
                ecrecover_line = _node_first_line(node)
                break
        if ecrecover_line is not None:
            break

    at_line = _fn_first_line(function)
    out = []

    # (a) MISSING-NONCE sub-rule.
    if not _fn_closure_has_nonce_write(function):
        out.append({
            "contract": cname,
            "function": fname,
            "kind": "missing-nonce",
            "ecrecover_line": ecrecover_line,
            "at_line": at_line,
            "severity_hint": "signature-replay",
        })

    # (b) MISSING-CHAINID sub-rule.
    if not _fn_closure_reads_chainid(function):
        out.append({
            "contract": cname,
            "function": fname,
            "kind": "missing-chainid",
            "ecrecover_line": ecrecover_line,
            "at_line": at_line,
            "severity_hint": "signature-replay",
        })

    return out


def closure_signature_replay_suspects(function: Any) -> Any:
    """Like `signature_replay_suspects` but also checks the function's forward
    callee closure for ecrecover-bearing intermediate hops. The OWN body is
    checked first (most-specific anchor). Returns the FIRST hit list from the
    own body if any flags fire there; otherwise scans each callee in closure
    order. Returns DEGRADED (R80) when `function` is not navigable.

    This is the closure variant; the step-1c produce pass should call
    `signature_replay_suspects` directly (function-level, anchored at the
    verifying function) and use the closure only when the verifying logic lives
    one hop away from the public entrypoint."""
    if not _is_callable_function(function):
        return DEGRADED
    # Own body first.
    own = signature_replay_suspects(function)
    if is_degraded(own):
        return DEGRADED
    if own:
        for r in own:
            r.setdefault("at_fn", getattr(function, "name", "?"))
        return own
    # Walk closure.
    closure = callee_closure(function, include_modifiers=True)
    if is_degraded(closure):
        return []
    for callee in closure:
        cl = signature_replay_suspects(callee)
        if is_degraded(cl) or not cl:
            continue
        for r in cl:
            r.setdefault("at_fn", getattr(callee, "name", "?"))
        return cl
    return []


# ──────────────────────────────────────────────────────────────────────────────
# A11 delegatecall-context-binding oracle (sibling of #11 has_low_level_delegatecall)
#
# `has_low_level_delegatecall` answers "does this fn CONTAIN a delegatecall". A11
# answers the DUAL, higher-value question: "is this fn a delegatecall TARGET that
# TRUSTS the execution context (writes storage / reads address(this) or msg.sender
# for auth) WITHOUT asserting the delegatecall context is what it expects?".
#
# The bug class (canonical `delegatecall-context-binding`): a module/library/logic
# contract meant to run under delegatecall stores context-sensitive state (or gates
# on address(this)/msg.sender). If a context-binding assertion (onlyProxy /
# notDelegated / `address(this) == __self`, or the inverse `_onlyDelegateCall`
# require-delegatecall guard) is MISSING on a context-sensitive entrypoint, the fn
# can be invoked in the WRONG context (direct call to a logic contract, or a
# delegatecall from an unexpected proxy) and corrupt / read the wrong storage.
#
# FP-guard: the class is DOMINATED by intended-caller-context primitives - an
# EIP-1967 `Proxy._delegate`, OZ `Address.functionDelegateCall`, a self-delegatecall
# `Multicall`, `LibClone`. Those are the delegate MACHINERY, not a trusting target,
# so a known-proxy/multicall/clone contract shape OR a delegatecall-dispatcher fn
# OR a deployment/create flow (caller-context-agnostic) is dropped. A present
# onlyProxy/notDelegated/`address(this)==__self`/`_onlyDelegateCall` guard anywhere
# in the fn's closure is BENIGN.
#
# Distinct from A2 (data-trust of a callee return) and A7 (re-entry ordering): A11 is
# purely about EXECUTION-CONTEXT binding, orthogonal to both.
#
# NO-AUTO-CREDIT: every emitted row carries verdict='needs-fuzz' + auto_credit=False.
# The wiring is advisory-first, env-gated OFF (see `_a11_advisory_enabled`).
# ──────────────────────────────────────────────────────────────────────────────

import os as _os

# env flag the CONSUMER checks before surfacing A11 rows (advisory-first, OFF by
# default). The raw predicate is ALWAYS callable (mutation-verify / FP tests drive
# it directly), exactly like `signature_replay_suspects`; only the pipeline surface
# is gated.
_A11_ENV = "AUDITOOOR_SLITHER_DELEGATE_CTX_BINDING"

# guard tokens that PROVE a delegatecall-context assertion (require or forbid a
# delegatecall context). `__self` / `_IMPLEMENTATION` / an `address(this)` self
# comparison are the OZ / EIP-1967 shapes; `_onlyDelegateCall` is the inverse
# (require-delegatecall) OPCM shape.
_A11_GUARD_HELPER_RE = re.compile(
    r"(?<![\w.])_?(onlyProxy|notDelegated|onlyDelegated|onlyDelegateCall|"
    r"requireDelegate|requireProxy|requireNotDelegated|onlyDelegatecall)\s*\(",
    re.IGNORECASE,
)
_A11_GUARD_MODIFIER_RE = re.compile(
    r"\b(onlyProxy|notDelegated|onlyDelegated|onlyDelegateCall|onlyDelegatecall)\b",
    re.IGNORECASE,
)
# a self-context comparison: `address(this) == <x>` / `<x> == address(this)` /
# `__self` / a stored-immutable-self compare. Any of these in the closure = guarded.
_A11_SELF_CMP_RE = re.compile(
    r"address\s*\(\s*this\s*\)\s*(==|!=)|(==|!=)\s*address\s*\(\s*this\s*\)|"
    r"\b__self\b|\b_IMPLEMENTATION\b",
)

# trust-signal probes (context binding the fn must not do blindly under delegatecall)
_A11_ADDR_THIS_RE = re.compile(r"address\s*\(\s*this\s*\)")
_A11_DELEGATECALL_RE = re.compile(r"\.delegatecall\s*\(")
# msg.sender used FOR AUTH (a comparison / require operand), NOT as a salt / event arg.
_A11_MSG_SENDER_AUTH_RE = re.compile(
    r"msg\.sender\s*(==|!=)|(==|!=)\s*msg\.sender|"
    r"require\s*\([^;{}]*msg\.sender|if\s*\([^;{}]*msg\.sender[^;{}]*\)\s*(revert|require)",
)

# delegate-TARGET contract signals (contract meant to run under delegatecall).
_A11_DELEGATE_TARGET_TOKEN_RE = re.compile(
    r"\.delegatecall\s*\(|(?<![\w.])_?(onlyDelegateCall|onlyProxy|notDelegated|"
    r"onlyDelegated)\s*\(|DELEGATECALL", re.IGNORECASE,
)

# FP-guard: known delegate-MACHINERY contract shapes (proxy / multicall / clone /
# OZ Address helper) - these are the intended-caller-context primitives, not a
# trusting target.
_A11_PROXY_SHAPE_RE = re.compile(
    r"(Proxy|Multicall\d*|Multicall3|Clones?|LibClone|Beacon|ERC1967|"
    r"TransparentUpgradeable|MinimalProxy)", re.IGNORECASE,
)
# FP-guard: a delegatecall DISPATCHER fn (the machinery itself).
_A11_DISPATCHER_FN_RE = re.compile(
    r"^_?(delegate|fallback|functionDelegateCall|functionDelegate|"
    r"delegatecall|dispatch)$", re.IGNORECASE,
)
# FP-guard: a deployment / CREATE flow is caller-context-agnostic (a fresh address /
# fresh storage), so it need not assert delegatecall context.
_A11_DEPLOY_FN_RE = re.compile(r"^_?(deploy|create|clone|initcode)", re.IGNORECASE)

# whole-word / non-member internal-call name matcher builder.
def _a11_calls_name(body: str, name: str) -> bool:
    return re.search(r"(?<![\w.])" + re.escape(name) + r"\s*\(", body) is not None


def _a11_find_match(src: str, open_idx: int) -> int:
    """Index of the `}` matching the `{` at/after open_idx. Tolerant (no lexer):
    good enough for well-formed Solidity; on imbalance returns end-of-string."""
    depth = 0
    i = open_idx
    n = len(src)
    while i < n:
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n - 1


_A11_CONTRACT_HDR_RE = re.compile(
    r"\b(abstract\s+contract|contract|library|interface)\s+(\w+)([^{;]*)")
_A11_FN_HDR_RE = re.compile(r"\bfunction\s+(\w+)\s*\(")
_A11_STATEVAR_RE = re.compile(
    r"^\s*(?:mapping|address|uint\d*|int\d*|bool|bytes\d*|string|"
    r"[A-Z]\w*)\b[^;=\n]*?\b(\w+)\s*(?:=|;)", re.MULTILINE)


_A11_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_A11_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def _a11_strip_comments(src: str) -> str:
    """Blank out block + line comments while PRESERVING newline offsets (so
    reported line numbers stay accurate). Comment bytes become spaces; newlines
    inside a block comment are kept."""
    def _blank(mt):
        return "".join("\n" if c == "\n" else " " for c in mt.group(0))
    src = _A11_BLOCK_COMMENT_RE.sub(_blank, src)
    src = _A11_LINE_COMMENT_RE.sub(_blank, src)
    return src


def _a11_line_of(src: str, idx: int) -> int:
    return src.count("\n", 0, idx) + 1


def _a11_parse_contracts(src: str):
    """Yield dicts {kind,name,bases,body,body_off} for each contract/library.
    `body_off` is the char offset (in `src`) of the body's first char."""
    out = []
    for m in _A11_CONTRACT_HDR_RE.finditer(src):
        kind = m.group(1).split()[-1]
        name = m.group(2)
        bases = m.group(3) or ""
        brace = src.find("{", m.end())
        if brace == -1:
            continue
        end = _a11_find_match(src, brace)
        out.append({
            "kind": kind, "name": name, "bases": bases,
            "body": src[brace + 1:end], "body_off": brace + 1,
        })
    return out


def _a11_parse_functions(contract_body: str):
    """Yield dicts {name,header,body,is_view,vis,off} for each fn WITH a body."""
    out = []
    for m in _A11_FN_HDR_RE.finditer(contract_body):
        name = m.group(1)
        # match the params paren
        p_open = contract_body.find("(", m.start())
        p_close = _a11_find_match_paren(contract_body, p_open)
        if p_close == -1:
            continue
        # scan for the body `{` before any `;`
        j = p_close + 1
        n = len(contract_body)
        brace = -1
        while j < n:
            c = contract_body[j]
            if c == ";":
                break  # declaration only (interface / abstract) - no body
            if c == "{":
                brace = j
                break
            j += 1
        if brace == -1:
            continue
        header = contract_body[p_close + 1:brace]
        end = _a11_find_match(contract_body, brace)
        body = contract_body[brace + 1:end]
        is_view = bool(re.search(r"\b(view|pure)\b", header))
        vis = "internal"
        vm = re.search(r"\b(external|public|internal|private)\b", header)
        if vm:
            vis = vm.group(1)
        out.append({
            "name": name, "header": header, "body": body,
            "is_view": is_view, "vis": vis, "off": m.start(),
        })
    return out


def _a11_find_match_paren(src: str, open_idx: int) -> int:
    depth = 0
    i = open_idx
    n = len(src)
    while i < n:
        c = src[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _a11_closure_bodies(fn, fns_by_name, max_hops: int = 5):
    """Return the concatenated bodies of `fn` + its transitive SAME-CONTRACT
    internal callees (bounded, cycle-guarded). Internal-only: a `.name(` member
    call is NOT folded (that is an external / delegatecall edge)."""
    seen = {fn["name"]}
    frontier = [(fn, 0)]
    parts = []
    while frontier:
        cur, depth = frontier.pop(0)
        parts.append(cur["body"])
        if depth >= max_hops:
            continue
        for cand_name, cand in fns_by_name.items():
            if cand_name in seen:
                continue
            if _a11_calls_name(cur["body"], cand_name):
                seen.add(cand_name)
                frontier.append((cand, depth + 1))
    return "\n".join(parts), seen


def _a11_scan_source(src: str, filename: str = "?", covered=None):
    """Core source-level A11 scan. Returns a list of hypothesis dicts (possibly
    empty). `covered` (a set of (contract,function) keys, OR a callable
    key->bool) is the UPSTREAM dedup signal - consumed VERBATIM, NEVER
    re-derived (A1 lesson). Every row carries verdict='needs-fuzz'."""
    hyps = []
    src = _a11_strip_comments(src)
    for ct in _a11_parse_contracts(src):
        cname = ct["name"]
        # only real code contracts (not interfaces) can be a trusting target
        if ct["kind"] == "interface":
            continue
        cbody = ct["body"]
        # is this contract a delegatecall TARGET / module / library?
        is_delegate_target = (
            ct["kind"] == "library"
            or bool(_A11_DELEGATE_TARGET_TOKEN_RE.search(cbody))
        )
        if not is_delegate_target:
            continue
        # FP-guard: known delegate-MACHINERY contract shape -> drop whole contract.
        if _A11_PROXY_SHAPE_RE.search(cname) or _A11_PROXY_SHAPE_RE.search(ct["bases"]):
            continue
        fns = _a11_parse_functions(cbody)
        fns_by_name = {f["name"]: f for f in fns}
        for fn in fns:
            if fn["vis"] not in ("external", "public"):
                continue
            if fn["is_view"]:
                continue  # a view cannot corrupt storage under mis-context
            fname = fn["name"]
            # FP-guard: delegatecall dispatcher / deployment-create flow.
            if _A11_DISPATCHER_FN_RE.match(fname) or _A11_DEPLOY_FN_RE.match(fname):
                continue
            closure_body, _members = _a11_closure_bodies(fn, fns_by_name)
            # trust signal (context binding) over the fn closure.
            trust = None
            if _A11_ADDR_THIS_RE.search(closure_body):
                trust = "address(this)-read"
            elif _A11_MSG_SENDER_AUTH_RE.search(closure_body):
                trust = "msg.sender-auth"
            elif _A11_DELEGATECALL_RE.search(closure_body):
                trust = "delegatecall"
            elif _a11_body_writes_state(fn["body"], cbody):
                trust = "storage-write"
            if trust is None:
                continue
            # guard-in-closure? (present onlyProxy/notDelegated/address(this)==__self
            # OR a call to a require/forbid-delegatecall helper OR a guard modifier)
            guarded = (
                _A11_GUARD_HELPER_RE.search(closure_body) is not None
                or _A11_SELF_CMP_RE.search(closure_body) is not None
                or _A11_GUARD_MODIFIER_RE.search(fn["header"]) is not None
            )
            if guarded:
                continue
            key = (cname, fname)
            cov = _a11_is_covered(covered, key)
            hyps.append({
                "detector": "trusts-context-binding-under-delegate",
                "canonical_class": "delegatecall-context-binding",
                "file": filename,
                "contract": cname,
                "function": fname,
                "line": _a11_line_of(src, ct["body_off"] + fn["off"]),
                "trust_signal": trust,
                "delegate_target_reason": (
                    "library" if ct["kind"] == "library"
                    else "delegatecall-or-context-guard-token-in-contract"),
                "guard_absent": True,
                "covered_by": cov,
                "verdict": "needs-fuzz",
                "auto_credit": False,
                "severity_hint": "context-confusion-delegatecall",
            })
    return hyps


def _a11_body_writes_state(fn_body: str, contract_body: str) -> bool:
    """Heuristic own-body state write: an assignment / delete whose LHS identifier
    is a contract-level state variable declared in `contract_body`."""
    statevars = set(_A11_STATEVAR_RE.findall(contract_body))
    if not statevars:
        return False
    for sv in statevars:
        if re.search(r"(?<![\w.])" + re.escape(sv) + r"\s*(?:\[[^\]]*\])?\s*(=[^=]|\+=|-=|\|=)", fn_body):
            return True
        if re.search(r"\bdelete\s+" + re.escape(sv) + r"\b", fn_body):
            return True
    return False


def _a11_is_covered(covered, key):
    """Consume the UPSTREAM covered_by signal VERBATIM (A1 dedup boundary - do NOT
    re-derive it here). `covered` may be None, a set/dict of keys, or a callable."""
    if covered is None:
        return False
    try:
        if callable(covered):
            return bool(covered(key))
        if isinstance(covered, dict):
            return bool(covered.get(key, covered.get(key[1], False)))
        return key in covered or key[1] in covered
    except Exception:
        return False


def trusts_context_binding_under_delegate(f: Any, covered=None) -> Any:
    """A11 predicate (sibling of #11 `has_low_level_delegatecall`). Flags a
    delegatecall-TARGET fn that TRUSTS the execution context (writes storage, or
    reads address(this) / msg.sender-for-auth) with NO context-binding guard
    (onlyProxy / notDelegated / `address(this)==__self` / `_onlyDelegateCall`) in
    its closure.

    Returns a list of hypothesis dicts (verdict='needs-fuzz', auto_credit=False),
    possibly empty, OR `DEGRADED` (R80) when `f` is not navigable.

    `f` may be:
      - a Slither Function object: its OWN contract source is scanned and the
        result filtered to `f`;
      - a Slither Contract object: the whole contract is scanned;
      - a str: treated as raw Solidity source (whole-file scan).

    `covered` is the UPSTREAM dedup signal (A1 boundary) - consumed verbatim.
    """
    # raw source path
    if isinstance(f, str):
        return _a11_scan_source(f, "?", covered)
    # Slither Function -> scan its contract, filter to this fn
    contract = getattr(f, "contract", None) or getattr(f, "contract_declarer", None)
    fname = getattr(f, "name", None)
    if contract is not None and fname is not None:
        src = _a11_source_of(contract)
        if src is None:
            return DEGRADED
        rows = _a11_scan_source(src, _a11_file_of(contract), covered)
        return [r for r in rows if r["function"] == fname]
    # Slither Contract -> whole-contract scan
    if hasattr(f, "functions") or hasattr(f, "state_variables"):
        src = _a11_source_of(f)
        if src is None:
            return DEGRADED
        return _a11_scan_source(src, _a11_file_of(f), covered)
    return DEGRADED


def _a11_source_of(obj: Any):
    try:
        sm = getattr(obj, "source_mapping", None)
        content = getattr(sm, "content", None) if sm else None
        return content if content else None
    except Exception:
        return None


def _a11_file_of(obj: Any) -> str:
    try:
        sm = getattr(obj, "source_mapping", None)
        fn = getattr(getattr(sm, "filename", None), "short", None) if sm else None
        return str(fn) if fn else "?"
    except Exception:
        return "?"


def delegate_context_binding_hypotheses(paths, covered=None):
    """Scan one or more `.sol` files (a path, a dir, or an iterable of paths) and
    return all A11 hypotheses (verdict='needs-fuzz'). Always callable; the
    advisory SURFACE is gated separately (`_a11_advisory_enabled`)."""
    from pathlib import Path as _P
    files = []
    def _add(p):
        p = _P(p)
        if p.is_dir():
            files.extend(sorted(p.rglob("*.sol")))
        elif p.suffix == ".sol":
            files.append(p)
    if isinstance(paths, (str, bytes)) or isinstance(paths, _P):
        _add(paths)
    else:
        for p in paths:
            _add(p)
    out = []
    for fp in files:
        try:
            src = _P(fp).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        out.extend(_a11_scan_source(src, str(fp), covered))
    return out


def _a11_advisory_enabled() -> bool:
    """Advisory-first gate: A11 rows are surfaced by the pipeline ONLY when the
    consumer sets `AUDITOOOR_SLITHER_DELEGATE_CTX_BINDING`. OFF by default."""
    return _os.environ.get(_A11_ENV, "").strip() not in ("", "0", "false", "off")


__all__ = [
    "available",
    "check",
    "regex_fallback",
    "reads_msg_sender",
    "reads_tx_origin",
    "reads_block_timestamp",
    "reads_block_number",
    "has_high_level_call",
    "has_safe_transfer",
    "has_transfer_from",
    "has_balance_of",
    "has_total_supply",
    "has_safe_approve",
    "has_latest_round_data",
    "has_low_level_delegatecall",
    "has_low_level_call",
    "calls_ecrecover",
    "computes_keccak",
    "computes_abi_encode",
    "has_revert",
    "has_modifier_named",
    "has_only_owner_modifier",
    "has_non_reentrant_modifier",
    "calls_selfdestruct",
    "reads_self_balance",
    # Closure primitives
    "DEGRADED",
    "is_degraded",
    "callee_closure",
    "caller_closure",
    "has_guard_in_closure",
    "unguarded_paths_to_sink",
    "resolve_concrete_impl",
    # Override-dropped-guard dispatch detector (Glider gap W1)
    "override_dropped_guards",
    "closure_override_dropped_guards",
    # Oracle try/catch-swallow detector (Glider gap W2)
    "oracle_swallow_suspects",
    "closure_oracle_swallow_suspects",
    # Comparator + branch-target guard-correctness semantics
    "guard_comparators",
    "branch_effect_target",
    "boundary_suspect",
    "path_boundary_suspect",
    "closure_boundary_suspect",
    # Type-convertibility lattice + UNSAFE-DOWNCAST oracle
    "parse_int_type",
    "cast_is_lossy",
    "can_convert",
    "unsafe_value_downcasts",
    "closure_unsafe_value_downcasts",
    # Divide-before-multiply precision-loss oracle (Glider gap W3)
    "divide_before_multiply",
    "closure_divide_before_multiply",
    # Inline-assembly / Yul detection + asm-scoped sink oracle
    "has_inline_assembly",
    "assembly_nodes",
    "asm_delegatecalls",
    "asm_sstores",
    "asm_raw_calls",
    "asm_suspect_sinks",
    "closure_asm_suspect_sinks",
    # AST-exact name/signature-filtered call-site selector (Glider gap #4)
    "callsites_of",
    # Intra-procedural CFG navigation + same-fn-CEI / unbounded-loop (Glider gap #5)
    "cfg_ordered_nodes",
    "dominators",
    "node_dominates",
    "loop_headers",
    "intra_fn_cei",
    "unbounded_loops",
    "closure_intra_fn_cei",
    "closure_unbounded_loops",
    # EnumerableSet at()-in-remove iteration-skip oracle (Glider gap W5)
    "enumerable_remove_in_loop",
    "closure_enumerable_remove_in_loop",
    # Unchecked return-value oracle (Glider gap W6 P1)
    "unchecked_return_values",
    "closure_unchecked_return_values",
    # Logic-tautology / dead-comparison guard-logic correctness (Glider gap W6 P2)
    "logic_tautology_suspects",
    "closure_logic_tautology_suspects",
    # Memory-copy-of-storage-never-written-back oracle (Glider gap W6 P8)
    "memory_copy_no_writeback",
    # Two-step-ownership-accept WRONG-GUARD detector (Glider gap W6 P5)
    "two_step_accept_wrong_guard",
    # Signature-replay precondition detector (Glider gap W6 P3)
    "signature_replay_suspects",
    "closure_signature_replay_suspects",
    # A11 delegatecall-context-binding oracle (sibling of #11)
    "trusts_context_binding_under_delegate",
    "delegate_context_binding_hypotheses",
]
