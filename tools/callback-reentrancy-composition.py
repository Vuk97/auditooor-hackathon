#!/usr/bin/env python3
"""callback-reentrancy-composition.py  (CRC) - Callback-before-Settlement /
Reentrancy-into-Settlement Composition Lane.

WHAT THIS TOOL DOES
===================
For every value-moving function in <ws>/.auditooor/value_moving_functions.json,
CRC detects the structural shape behind the flashLoan->take class of attack:

  1. CALLBACK WINDOW: the function invokes an external / attacker-reachable
     callback - INDEPENDENT of whether the window fn itself has any state
     writes. The window fn does NOT need a CEI violation in its OWN body;
     it only needs to hand control to an external/attacker-controlled address
     without a reentrancy guard. flashLoan (Midnight.sol:737-760) has zero
     ledger writes of its own - it still qualifies because it calls
     IFlashLoanCallback.onFlashLoan without a guard.

  2. REENTRANCY GUARD ABSENT: NO nonReentrant modifier, lock-variable guard,
     or equivalent re-entrance barrier protects the function.

  3. REENTRY TARGETS: the OTHER value-moving fns (from VMF) whose body
     contains a state write BEFORE a transfer/settlement (classic CEI
     violation). Those are the fns an attacker would re-enter FROM the
     callback window. CRC emits one hypothesis per (window, target) pair.

Shape reference (morpho Midnight.sol):
  - flashLoan: transfers tokens OUT, calls IFlashLoanCallback.onFlashLoan,
    then expects the tokens pulled back - the callback window is unguarded.
    flashLoan has ZERO ledger writes of its own and still qualifies as a
    CALLBACK WINDOW because it invokes an external attacker-controlled
    callback without a guard.
  - An attacker inside onFlashLoan re-enters take(), which writes credit/debt
    before settling the transfer - breaking conservation.
  - CRC emits: "during flashLoan's callback window, re-enter take".

NO FALSE-GREEN RULE
===================
CRC NEVER auto-credits a gate.  Every emitted hypothesis carries
verdict="needs-fuzz", attack_class="reentrancy-into-settlement".
The caller (VCIS + medusa/echidna actor pool) must independently verify.

COMPOSE WITH VCIS + SADL
========================
- VCIS supplies the conservation oracle (solvency floor invariant).
- SADL identifies self-dealing identity-collapse within the reentry target.
- CRC identifies WHICH function to call during the callback window and WHICH
  window-function opens that window.

LANGUAGE COVERAGE
=================
Solidity (.sol / .vy):
  - Callback patterns: external .call{...}(...), .call(...), interface-method
    invocations whose name starts with "on" or contains "Callback"/"Hook",
    safeTransfer / transfer calls (transfer-out is also a callback opportunity
    for ERC-777 / ERC-1363 / ERC-4626 hooks).
  - Guard patterns: nonReentrant modifier on the function signature, a
    _locked / _status storage bool set to true/ENTERED before the body,
    REENTRANCY_LOCK, ReentrancyGuard base contract usage.

Go/Cosmos (.go):
  - Callback patterns (ATTACKER-REACHABLE ONLY): CosmWasm WasmMsg Execute
    into an attacker-controlled contract (wasmKeeper.Execute/ExecuteContract,
    WasmMsg patterns), bank Send to a contract account that may have hooks
    (bank.SendCoins to a non-module address is the real vector), IBC
    OnRecvPacket/OnAcknowledgementPacket/OnTimeoutPacket callbacks, EVM
    precompile Execute calls, staking/slashing hooks routed THROUGH an
    attacker-deployed contract via gov/params.
    EXCLUDED: internal module hooks k.Before*/k.After*/hooks.Run* that are
    pure in-process synchronous SDK calls between trusted keeper instances -
    those are NOT attacker-reachable reentrancy vectors.
  - Guard patterns: a _locked bool or lockName variable set true before the
    call, LIQUIDATION_LOCK sentinel, sync.Mutex.Lock() before the hook.

Rust/CosmWasm (.rs):
  - Callback patterns: SubMsg with reply_on_success, CosmosMsg::Wasm calls,
    invoke / invoke_signed (Solana CPI), Promise::new (NEAR), any external
    call pattern where control leaves the current module before state is final.
  - Guard patterns: a reentrancy_guard bool / AtomicBool set, REENTRANCY
    static, Mutex guard, or #[access_control(reentrancy_guard)] attribute.

READ-ONLY-REENTRANCY-VIEW (Curve-style)
========================================
A second sub-class is emitted for views that an external integrator may call
DURING an active flashLoan/callback window, reading a stale state.

ALL four conditions must hold (tight discriminator - avoids the "every getter"
false-positive flood from the reverted broad version):

  (a) The view is external or public, and is view or pure.
  (b) Its return expression derives from a PRICE/RATE/SHARE/RESERVE/
      totalSupply-class field.  Field name must match (case-insensitive):
        price|rate|share|reserve|totalSupply|totalAssets|exchangeRate|
        getVirtualPrice|convertTo
      (NOT arbitrary fields like fee/owner/admin/config/paused.)
  (c) That exact field (same identifier token) is WRITTEN by a CRC window fn
      (an external-callback opener) DURING its callback window - i.e. the
      same field token appears in the window fn's body before settlement.
  (d) The view function has external visibility (public or external keyword).

Sub-class emitted: sub_class="read-only-reentrancy-view",
                   attack_class="read-only-reentrancy",
                   verdict="needs-fuzz".
Classic-reentrancy behavior is UNCHANGED.

OUTPUT SCHEMA
=============
<ws>/.auditooor/callback_reentrancy_hypotheses.jsonl - one JSON object per line:
{
  "workspace":     "<abs-path>",
  "file":          "<rel-path>",
  "function":      "<fn-name>",
  "language":      "sol|go|rs|move|cairo",
  "window_line":   <int>,            // 1-based line of the first callback/transfer-out
  "callback_evidence": "<snippet>",  // short excerpt triggering window detection
  "guard_detected": false,           // always false in emitted records
  "reentry_target_file":   "<rel-path>",   // classic only
  "reentry_target":        "<fn-name>",    // classic only; empty string for RO-view
  "sub_class":     "classic-reentrancy | read-only-reentrancy-view",
  "note":          "<human-readable description>",
  "attack_class":  "reentrancy-into-settlement | read-only-reentrancy",
  "source":        "CRC",
  "verdict":       "needs-fuzz"
}

CLI
===
  python3 tools/callback-reentrancy-composition.py <workspace> [--out <path>]
  --vmf-json   : override value_moving_functions.json path
  --regen-vmf  : re-run value-moving-functions.py even if JSON already exists

Returns rc=0 on success (even if 0 hypotheses emitted), rc=1 on error.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Reuse value-moving-functions.py for VMF enumeration (single source of truth).
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
_VMF_PATH = _HERE / "value-moving-functions.py"


def _load_vmf():
    spec = importlib.util.spec_from_file_location("value_moving_functions", _VMF_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["value_moving_functions"] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# OOS helper (same fallback chain as value-moving-functions.py).
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_exclusion import is_oos  # type: ignore
except Exception:
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + rel.replace("\\", "/")).lower()
            for marker in (
                "/test/", "/tests/", "_test.", ".t.sol", "/vendor/", "/lib/",
                "/node_modules/", "/out/", "/build/", "/target/",
            ):
                if marker in n:
                    return True
            return False


# ---------------------------------------------------------------------------
# Per-language CALLBACK / TRANSFER-OUT patterns.
#
# A "callback window" opens when the function body contains one of these
# BEFORE all its own state writes (CEI violation: Interactions before Effects).
# For the window detection we scan the FULL body; ordering is checked by
# position (callback snippet line < last ledger-write line within body).
# ---------------------------------------------------------------------------

# Solidity callback / transfer-out patterns - split into two tiers.
#
# TIER-1 (NAMED_CALLBACK): Named interface callbacks that explicitly hand
# control to an external/attacker-controlled address via a known protocol.
# These justify cross-file reentry hypotheses because the target contract
# is explicitly invoked during the callback.
#   flashLoan.onMorphoFlashLoan -> attacker can call back INTO Morpho.sol.
#
# TIER-2 (GENERIC_CALL): Low-level .call / delegatecall that are unguarded
# external calls but have no known target; cross-file reentry is speculative.
# Only emit same-file hypotheses for TIER-2 windows.
#
# WEAK (TRANSFER_ONLY): safeTransfer / transfer alone. These enable ERC-777
# hooks on compliant tokens but are very noisy on Diamond / DeFi codebases
# with many transfer-heavy fns. Do NOT emit classic-reentrancy hypotheses
# for WEAK-only windows (they still contribute to read-only-reentrancy-view
# detection which has its own tight discriminator).
#
# Detection strategy:
#   1. Scan the FULL function body for the STRONGEST tier found.
#   2. Emit if TIER-1 (any cross-file/same-file target), or TIER-2 (same-file
#      target only).  WEAK-only => no classic-reentrancy hypothesis emitted.
#   3. callback_evidence reports the STRONGEST match found (not just first).

_SOL_CALLBACK_TIER1_RES: list[re.Pattern] = [
    # Named flash-loan / flash-swap callbacks (morpho, balancer, uniswap, etc.)
    re.compile(r"\bIFlashLoan(?:Callback|Receiver)\b", re.I),
    re.compile(r"\bIMorpho(?:Callback|FlashLoan)\b", re.I),
    re.compile(r"\bIUniswap\w*Callee\b", re.I),
    re.compile(r"\bISwap(?:Callback|Router)\b", re.I),
    re.compile(r"\.onFlashLoan\s*\(", re.I),
    re.compile(r"\.onMorpho\w*\s*\(", re.I),
    re.compile(r"\.onSwap\s*\(", re.I),
    # Any method named on<Capital>* / *Callback / *Hook via interface dispatch
    re.compile(r"\.\s*on[A-Z]\w*\s*\("),
    re.compile(r"\.\s*\w+Callback\s*\(", re.I),
    re.compile(r"\.\s*\w+Hook\s*\(", re.I),
    # ERC-1155 / ERC-721 safeTransfer acceptance hooks
    re.compile(r"\bonERC1155Received\s*\(", re.I),
    re.compile(r"\bonERC1155BatchReceived\s*\(", re.I),
    re.compile(r"\bonERC721Received\s*\(", re.I),
]

_SOL_CALLBACK_TIER2_RES: list[re.Pattern] = [
    # Low-level state-mutating calls (NOT staticcall which is read-only).
    re.compile(r"\.\s*call\s*[\{(]"),
    re.compile(r"\.\s*delegatecall\s*\("),
]

_SOL_CALLBACK_WEAK_RES: list[re.Pattern] = [
    # token transfers that may enable ERC-777/ERC-1363 hooks - WEAK window.
    re.compile(r"\bsafeTransfer\s*\(", re.I),
    re.compile(r"\bsafeTransferFrom\s*\(", re.I),
    re.compile(r"\btransfer\s*\("),
    re.compile(r"\btransferFrom\s*\("),
]

# Flat list for backward-compat uses that don't need tier info.
_SOL_CALLBACK_RES: list[re.Pattern] = (
    _SOL_CALLBACK_TIER1_RES
    + _SOL_CALLBACK_TIER2_RES
    + _SOL_CALLBACK_WEAK_RES
)

# Go/Cosmos callback patterns - ATTACKER-REACHABLE ONLY.
#
# EXCLUDED (internal, in-process, synchronous, trusted keeper calls):
#   k.Before*/k.After*, hooks.Run*/RunHooks, BeforeSend/AfterSend,
#   SendCoinsFromModuleTo* (module-to-module or module-to-account are
#   trusted bank operations, not attacker-controlled callbacks).
#
# INCLUDED (genuinely external / can invoke attacker-controlled code):
#   - wasmKeeper.Execute / ExecuteContract (calls into a CosmWasm contract
#     that the attacker deployed/controls)
#   - WasmMsg::Execute routing through wasmkeeper
#   - IBC packet callbacks: OnRecvPacket, OnAcknowledgementPacket,
#     OnTimeoutPacket (route through the channel's ICS-4 port dispatch,
#     which can reach an attacker-registered IBC app)
#   - evm.Call / evmKeeper.Call (EVM precompile / cross-VM call boundary)
#   - bank.SendCoins to a non-module (externally-owned) address when the
#     chain has a BeforeSend hook routed to a CosmWasm contract
#     (cosmwasm_std token_factory / osmosis tokenfactory pattern)
_GO_CALLBACK_RES: list[re.Pattern] = [
    # CosmWasm contract execution (primary Cosmos attacker-control vector)
    re.compile(r"\bwasm[Kk]eeper\.\w*[Ee]xecute\w*\s*\("),
    re.compile(r"\bExecuteContract\s*\(", re.I),
    re.compile(r"\bWasmMsg\s*::\s*Execute\b"),
    re.compile(r"\bk\.wasm\.\w*[Ee]xecute\w*\s*\("),
    # IBC packet callbacks (port dispatch reaches attacker-registered IBC app)
    re.compile(r"\bOnRecvPacket\s*\("),
    re.compile(r"\bOnAcknowledgementPacket\s*\("),
    re.compile(r"\bOnTimeoutPacket\s*\("),
    re.compile(r"\bchannel[Kk]eeper\.\w*[Ss]end\w*\s*\("),
    # EVM cross-VM state-mutating call boundary (NOT EthCall which is a read-only sim).
    # ApplyMessage / CallEVM / CallEVMWithData / RunTx can mutate EVM state
    # and trigger re-entrance via EVM hooks or precompiles.
    re.compile(r"\bevm[Kk]eeper\.(?:ApplyMessage|CallEVM|CallEVMWithData|RunTx|Call)\s*\("),
    re.compile(r"\bApplyEVMMessage\s*\("),
    # Token-factory BeforeSend routed to a CosmWasm contract
    # (only flag when the pattern explicitly routes to a contract address)
    re.compile(r"\bsudoMsg\s*\.\s*BeforeSend\b"),
    re.compile(r"\bcontractKeeper\.\w*Sudo\w*\s*\("),
]

# Rust/CosmWasm callback patterns.
_RS_CALLBACK_RES: list[re.Pattern] = [
    re.compile(r"\bSubMsg\s*::\s*reply_on_success\b"),
    re.compile(r"\bReplyOn\s*::\s*Success\b"),
    re.compile(r"\bCosmosMsg\s*::\s*Wasm\b"),
    re.compile(r"\bWasmMsg\s*::\s*Execute\b"),
    re.compile(r"\binvoke\s*\(", re.I),
    re.compile(r"\binvoke_signed\s*\(", re.I),
    re.compile(r"\bPromise\s*::\s*new\b"),
    re.compile(r"\benv::promise_batch_action_transfer\b"),
    re.compile(r"\bsystem_instruction\s*::\s*transfer\b"),
    # Any method call ending in _callback / _hook
    re.compile(r"\.\w+_callback\s*\(", re.I),
    re.compile(r"\.\w+_hook\s*\(", re.I),
    # SubMsg construction
    re.compile(r"\bSubMsg\s*\{"),
]

_CALLBACK_RES_BY_LANG: dict[str, list[re.Pattern]] = {
    "sol": _SOL_CALLBACK_RES,
    "go": _GO_CALLBACK_RES,
    "rs": _RS_CALLBACK_RES,
    # Move / Cairo: treat external dispatch as callback opportunity
    "move": [
        re.compile(r"\bcall\s*\(", re.I),
        re.compile(r"\bdispatch\s*\(", re.I),
    ],
    "cairo": [
        re.compile(r"\bIContract\w*\.dispatch\b", re.I),
        re.compile(r"\bsystem_call\s*\(", re.I),
    ],
}


# ---------------------------------------------------------------------------
# Per-language REENTRANCY-GUARD patterns.
#
# A function is considered GUARDED if ANY of these patterns appear within a
# short prefix of the function signature (modifier line) OR the function body.
# We check BOTH the modifier annotation AND the body opening for set-lock ops.
# ---------------------------------------------------------------------------

# Pattern tuples: (pattern, description)
_SOL_GUARD_RES: list[re.Pattern] = [
    re.compile(r"\bnonReentrant\b"),
    re.compile(r"\bReentrancyGuard\b"),
    re.compile(r"\b_status\s*=\s*_ENTERED\b"),
    re.compile(r"\b_locked\s*=\s*true\b"),
    re.compile(r"\bREENTRANCY_LOCK\b"),
    re.compile(r"\b_entered\s*=\s*true\b"),
    re.compile(r"\bENTERED\b"),
    re.compile(r"\b_notEntered\b"),
]

_GO_GUARD_RES: list[re.Pattern] = [
    re.compile(r"\bLIQUIDATION_LOCK\b"),
    re.compile(r"\b_locked\s*(?:bool\b|=\s*true)"),
    re.compile(r"\bkeeper\.\w*[Ll]ock\b"),
    re.compile(r"\bctx\.KVStore.*[Ll]ock\b"),
    re.compile(r"\.Lock\s*\(\s*\)"),
    re.compile(r"\bmu\.Lock\s*\(\s*\)"),
    re.compile(r"\bsync\.Mutex\b"),
    re.compile(r"\breentrancyLock\b", re.I),
]

_RS_GUARD_RES: list[re.Pattern] = [
    re.compile(r"\breentrancy_guard\b", re.I),
    re.compile(r"\bREENTRANCY\b"),
    re.compile(r"\bATOMIC_BOOL\b"),
    re.compile(r"\bAtomicBool\b"),
    re.compile(r"#\[access_control\(reentrancy"),
    re.compile(r"\bMutex\s*::\s*lock\b"),
    re.compile(r"\b_is_locked\s*=\s*true\b"),
    re.compile(r"\bLOCKED\b"),
]

_GUARD_RES_BY_LANG: dict[str, list[re.Pattern]] = {
    "sol": _SOL_GUARD_RES,
    "go": _GO_GUARD_RES,
    "rs": _RS_GUARD_RES,
    "move": [re.compile(r"\bacquire\s*\(", re.I)],
    "cairo": [re.compile(r"\breentrancy_guard\b", re.I)],
}


# ---------------------------------------------------------------------------
# Per-language LEDGER-WRITE patterns (mirror of value-moving-functions.py).
# Used to check whether ANY state write exists AFTER the callback site in the
# body (confirming CEI violation: callback before final state write).
# ---------------------------------------------------------------------------
_SOL_WRITE_RE = re.compile(
    r"(?<![.\w])([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?<![=!<>])[-+*/|&^%]?=(?!=)"
)
_GO_WRITE_RE = re.compile(
    r"(?<![.\w])(?:k\.|s\.|app\.)?([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?<![=!<>:])[-+*/|&^%]?=(?!=)"
)
_RS_WRITE_RE = re.compile(
    r"\bself\.([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?<![=!<>])[-+*/|&^%]?=(?!=)"
)

# For Go: also match short variable declarations (:=) on value-named identifiers,
# since Go initializes ledger locals via `creditBalance := amount` style.
_GO_DECL_WRITE_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*:="
)

_LEDGER_WRITE_BY_LANG: dict[str, list[re.Pattern] | None] = {
    "sol": [_SOL_WRITE_RE],
    "go": [_GO_WRITE_RE, _GO_DECL_WRITE_RE],
    "rs": [_RS_WRITE_RE],
    "move": None,
    "cairo": None,
}

# ---------------------------------------------------------------------------
# READ-ONLY-REENTRANCY-VIEW discriminator constants.
#
# Only field NAMES in this narrow set are considered "price/rate/share/reserve-
# class" for the Curve-style read-only-reentrancy check.  The match is
# case-insensitive and uses a word-boundary regex so partial tokens do not fire.
#
# Deliberately does NOT include: fee, owner, admin, config, paused, version,
# nonce, operator, controller, manager, balanceOf, allowance, etc.
# ---------------------------------------------------------------------------
_RO_REENTRANT_FIELD_RE = re.compile(
    r"\b(price|rate|share|reserve|totalSupply|totalAssets|exchangeRate"
    r"|getVirtualPrice|convertTo)\b",
    re.IGNORECASE,
)

# Solidity external/public view/pure function signature pattern.
# Captures: visibility (public|external), view|pure keywords.
# We allow them in any order in the modifier list.
_SOL_VIEW_FN_RE = re.compile(
    r"\bfunction\s+([A-Za-z_]\w*)\s*\([^)]*\)\s*((?:[A-Za-z_]\w*\s*)*)"
    r"(?=.*?\breturns\b)",
    re.DOTALL,
)
# Simpler tokenizer: check that modifier text contains view|pure AND
# public|external, to classify a function as a Solidity external view.
_SOL_VISIBILITY_RE = re.compile(r"\b(public|external)\b")
_SOL_VIEW_MUTABILITY_RE = re.compile(r"\b(view|pure)\b")

_VALUE_ROOTS_RE = re.compile(
    r"balance|credit|debt|share|unit|amount|asset|vault|escrow"
    r"|collateral|reserve|stake|supply|borrow|lend|deposit|withdraw"
    r"|liquidity|fund|pool|holding|position|fee|reward|token|coin"
    r"|mint|burn",
    re.IGNORECASE,
)

_FIELD_STOPWORDS: frozenset[str] = frozenset({
    "return", "let", "var", "const", "if", "for", "while", "uint", "int",
    "bool", "address", "bytes", "string", "memory", "storage", "mut", "self",
    "this", "result", "ok", "err", "true", "false", "i", "j", "k", "n", "x",
    "y", "z", "tmp", "temp", "_", "out", "data", "value", "amount", "msg",
    "require", "assert", "emit", "new", "type",
    "nonce", "timestamp", "owner", "admin", "paused", "initialized",
    "version", "slot", "idx", "index", "count", "num", "flag", "lock",
})


def _is_value_field(tok: str) -> bool:
    if tok.lower() in _FIELD_STOPWORDS or len(tok) <= 1:
        return False
    return bool(_VALUE_ROOTS_RE.search(tok))


# ---------------------------------------------------------------------------
# Body extraction (identical to value-moving-functions.py - single logic).
# ---------------------------------------------------------------------------
def _extract_body(source: str, sig_end: int) -> str:
    i = source.find("{", sig_end)
    if i < 0:
        return ""
    # Bodiless-declaration guard: a function whose signature is terminated by
    # ';' BEFORE the next '{' is an interface method / abstract or external
    # declaration with no implementation body. Without this, the search above
    # latches onto the NEXT construct's body (e.g. an IWETH.withdraw interface
    # decl picking up a sibling fn's `call{value:...}`), creating false
    # value-mover / reentrancy hits. Treat as no body so callers skip it.
    # (Generic: Solidity interface methods + Rust trait-method declarations.)
    semi = source.find(";", sig_end)
    if semi != -1 and semi < i:
        return ""
    depth = 0
    for j in range(i, len(source)):
        c = source[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return source[i + 1: j]
    return source[i + 1:]


# ---------------------------------------------------------------------------
# Modifier prefix extraction: text BEFORE the opening brace of the fn body.
# Used to detect modifier-level guards (e.g. `nonReentrant` keyword between
# the parameter list and the opening brace).
# ---------------------------------------------------------------------------
def _extract_modifier_prefix(source: str, sig_end: int) -> str:
    """Return text from sig_end up to (but not including) the first '{' body brace."""
    i = source.find("{", sig_end)
    if i < 0:
        return source[sig_end: sig_end + 400]
    return source[sig_end:i]


# ---------------------------------------------------------------------------
# Guard detection: check modifier prefix AND first N chars of body.
# Returns True if any guard pattern fires.
# ---------------------------------------------------------------------------
_GUARD_CHECK_BODY_PREFIX = 300  # bytes


def _has_guard(lang: str, modifier_prefix: str, body: str) -> bool:
    """Return True if a reentrancy guard is detected for this function."""
    guard_res = _GUARD_RES_BY_LANG.get(lang, [])
    combined = modifier_prefix + body[:_GUARD_CHECK_BODY_PREFIX]
    for rx in guard_res:
        if rx.search(combined):
            return True
    return False


# ---------------------------------------------------------------------------
# Callback window detection: find the first external/attacker-reachable
# callback match in the body.
#
# WINDOW MODEL (v2 - fixed):
#   A fn is a CALLBACK WINDOW iff:
#     (a) it invokes an external / attacker-reachable callback (narrowed
#         lexicon; see _CALLBACK_RES_BY_LANG), AND
#     (b) no reentrancy guard is present (checked separately by _has_guard).
#   The window fn does NOT need to have any state writes of its own.
#   flashLoan (Midnight.sol) has zero ledger writes and still qualifies
#   because it calls IFlashLoanCallback.onFlashLoan without a guard.
#
# The CEI-violation ordering (state write BEFORE transfer/settlement) is
# the property of the REENTRY TARGET, not the window fn.  CRC's job is:
#   window fn = "opens an unguarded external callback"
#   target fn  = "has state-write-before-settlement" (from VMF)
#
# Returns (has_window, callback_line, callback_snippet) where callback_line is
# the 1-based line number within the SOURCE FILE of the callback hit.
# ---------------------------------------------------------------------------

def _find_callback_window(
    lang: str,
    source: str,
    body: str,
    body_offset: int,       # character offset of body start within source
) -> tuple[bool, int, str, str]:
    """Detect a fn that invokes an external/attacker-reachable callback.

    Returns (window_found, source_line_1based, snippet, tier) where tier is
    one of "tier1" (named callback), "tier2" (generic .call/delegatecall), or
    "weak" (transfer-only).

    For Solidity, scans the FULL body to find the STRONGEST tier present, then
    reports the position and snippet of the FIRST match at that tier level.
    This ensures that a fn containing both safeTransfer AND onFlashLoan (like
    morpho flashLoan) is correctly classified as "tier1" even though safeTransfer
    appears earlier in the body.

    The window fn does NOT need its own state writes (Defect 1 fix).
    """
    callback_res = _CALLBACK_RES_BY_LANG.get(lang, [])

    if lang == "sol":
        # Tiered scan: find the strongest tier present in the body, then pick
        # the first occurrence at that tier level.
        tier_order = [
            ("tier1", _SOL_CALLBACK_TIER1_RES),
            ("tier2", _SOL_CALLBACK_TIER2_RES),
            ("weak",  _SOL_CALLBACK_WEAK_RES),
        ]
        for tier_name, tier_res in tier_order:
            best_pos: int | None = None
            best_snippet: str = ""
            for rx in tier_res:
                m = rx.search(body)
                if m and (best_pos is None or m.start() < best_pos):
                    best_pos = m.start()
                    start = max(0, m.start() - 10)
                    best_snippet = body[start: m.end() + 30].strip().replace("\n", " ")[:80]
            if best_pos is not None:
                cb_line = source[: body_offset + best_pos].count("\n") + 1
                return True, cb_line, best_snippet, tier_name
        return False, 0, "", "weak"
    else:
        # Non-Solidity: single pass, all treated as "tier1" (attacker-reachable).
        first_cb_pos: int | None = None
        first_cb_snippet: str = ""
        for rx in callback_res:
            m = rx.search(body)
            if m and (first_cb_pos is None or m.start() < first_cb_pos):
                first_cb_pos = m.start()
                start = max(0, m.start() - 10)
                first_cb_snippet = body[start: m.end() + 30].strip().replace("\n", " ")[:80]

        if first_cb_pos is None:
            return False, 0, "", "weak"

        cb_line = source[: body_offset + first_cb_pos].count("\n") + 1
        return True, cb_line, first_cb_snippet, "tier1"


# ---------------------------------------------------------------------------
# Per-file analysis: returns list of unguarded window records.
# Each record: {file, function, language, window_line, callback_evidence}
# ---------------------------------------------------------------------------

# Per-language function-start detectors (copy from VMF, single source of truth).
_FN_RES: dict[str, re.Pattern] = {
    "sol": re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\("),
    "rs": re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*[<(]"),
    "go": re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*[<(]"),
    "move": re.compile(r"\bfun\s+([A-Za-z_]\w*)\s*[<(]"),
    "cairo": re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*[<(]"),
}

_EXT_TO_LANG: dict[str, str] = {
    ".sol": "sol", ".vy": "sol",
    ".go": "go",
    ".rs": "rs",
    ".move": "move",
    ".cairo": "cairo", ".nr": "cairo",
}

_RUST_TEST_ATTR_RE = re.compile(r"#\[\s*(?:tokio\s*::\s*)?test\b")


def _rust_fn_is_test(source: str, sig_start: int) -> bool:
    prefix = source[max(0, sig_start - 300): sig_start]
    for line in reversed(prefix.splitlines()[-6:]):
        stripped = line.strip()
        if not stripped:
            continue
        if _RUST_TEST_ATTR_RE.search(stripped):
            return True
        if stripped.startswith("}") or stripped.startswith("pub ") or stripped.startswith("fn "):
            break
        if stripped.startswith("#[") or stripped.startswith("///") or stripped.startswith("//"):
            continue
        break
    return False


def _scan_file_for_windows(
    path: Path, rel: str, lang: str
) -> list[dict[str, Any]]:
    """Scan one source file; return unguarded callback-window records."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    fn_re = _FN_RES.get(lang)
    if fn_re is None:
        return []

    results: list[dict[str, Any]] = []
    for m in fn_re.finditer(text):
        fn_name = m.group(1)
        sig_end = m.end()
        if lang == "rs" and _rust_fn_is_test(text, m.start()):
            continue

        mod_prefix = _extract_modifier_prefix(text, sig_end)
        body_start = text.find("{", sig_end)
        if body_start < 0:
            continue
        body = _extract_body(text, sig_end)
        if not body:
            continue

        # Guard check (modifier line + body prefix).
        if _has_guard(lang, mod_prefix, body):
            continue  # guarded - skip

        # Callback window check.
        has_window, cb_line, cb_snippet, cb_tier = _find_callback_window(
            lang, text, body, body_start + 1
        )
        if not has_window:
            continue

        # For Solidity: weak-only windows (transfer-only, no named callback or
        # generic .call) do NOT qualify as classic-reentrancy windows.
        # They are retained solely for the read-only-reentrancy-view sub-class
        # (which has its own tight discriminator).
        if lang == "sol" and cb_tier == "weak":
            continue

        results.append({
            "file": rel,
            "function": fn_name,
            "language": lang,
            "window_line": cb_line,
            "callback_evidence": cb_snippet,
            "callback_tier": cb_tier,  # "tier1" | "tier2" | "weak"
        })

    return results


# ---------------------------------------------------------------------------
# Read-only-reentrancy-view helpers (Curve-style, tight discriminator).
# ---------------------------------------------------------------------------

def _sol_fn_is_external_view(modifier_text: str) -> bool:
    """Return True if a Solidity fn's modifier text shows external/public + view/pure."""
    return (
        bool(_SOL_VISIBILITY_RE.search(modifier_text))
        and bool(_SOL_VIEW_MUTABILITY_RE.search(modifier_text))
    )


def _extract_return_field_tokens(body: str) -> set[str]:
    """Extract identifier tokens that appear in return statements.

    Returns the set of bare identifiers that follow 'return' (shallow scan).
    We want to know WHAT field names appear in the returned expression so we
    can check whether they are price/rate/share/reserve-class.
    """
    tokens: set[str] = set()
    # Match 'return <expr>;' lines - grab identifier tokens from the expression.
    for m in re.finditer(r"\breturn\b([^;{}\n]+)", body):
        expr = m.group(1)
        for tok_m in re.finditer(r"\b([A-Za-z_]\w*)\b", expr):
            tok = tok_m.group(1)
            # Skip keywords and short noise tokens.
            if tok.lower() not in {"return", "true", "false", "new", "this",
                                   "memory", "storage", "calldata", "uint",
                                   "int", "bool", "address", "bytes"}:
                tokens.add(tok)
    return tokens


def _window_body_writes_field(window_body: str, field_name: str) -> bool:
    """Return True if field_name appears as an assignment target in window_body.

    We check for patterns like:
      fieldName = ...
      fieldName += ...
      fieldName[...] = ...
      self.fieldName = ...  (Rust/Python style)
    We use word-boundary matching so partial names don't fire.
    """
    # Check for assignment patterns - field as LHS
    pattern = re.compile(
        r"\b" + re.escape(field_name) + r"\b"
        r"(?:\s*\[[^\]]*\])*\s*(?<![=!<>])[-+*/|&^%]?=(?!=)",
        re.IGNORECASE,
    )
    return bool(pattern.search(window_body))


def _scan_file_for_ro_view_candidates(
    path: Path,
    rel: str,
    lang: str,
) -> list[dict[str, Any]]:
    """Scan one Solidity file for external/public view fns returning a
    price/rate/share/reserve-class field.

    Returns list of dicts:
      {file, function, field_name, language, fn_start_line, body}
    Only Solidity is currently supported (the Curve/ERC-4626 pattern is
    Solidity-first; other languages have different idioms and are added
    incrementally as needed).
    """
    if lang != "sol":
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    fn_re = _FN_RES.get("sol")
    if fn_re is None:
        return []

    results: list[dict[str, Any]] = []
    for m in fn_re.finditer(text):
        fn_name = m.group(1)
        sig_end = m.end()

        # Extract the modifier text (between the parameter list end and the body '{').
        mod_prefix = _extract_modifier_prefix(text, sig_end)
        body_start = text.find("{", sig_end)
        if body_start < 0:
            continue
        body = _extract_body(text, sig_end)
        if not body:
            continue

        # Condition (a): must be external/public AND view/pure.
        if not _sol_fn_is_external_view(mod_prefix):
            continue

        # Condition (b): return expression must contain a price/rate/share/reserve field.
        ret_tokens = _extract_return_field_tokens(body)
        matched_fields: list[str] = []
        for tok in ret_tokens:
            if _RO_REENTRANT_FIELD_RE.search(tok):
                matched_fields.append(tok)

        # Also check if the body contains the RO_REENTRANT pattern in a return stmt
        # directly (e.g. "return _reserve;" or "return totalSupply;").
        if not matched_fields:
            for m2 in re.finditer(r"\breturn\b([^;{}\n]+)", body):
                expr = m2.group(1)
                if _RO_REENTRANT_FIELD_RE.search(expr):
                    # Extract the matching token(s).
                    for tok_m in _RO_REENTRANT_FIELD_RE.finditer(expr):
                        matched_fields.append(tok_m.group(0))
                    break

        if not matched_fields:
            continue

        fn_line = text[: m.start()].count("\n") + 1
        results.append({
            "file": rel,
            "function": fn_name,
            "language": "sol",
            "fn_start_line": fn_line,
            "body": body,
            "matched_fields": matched_fields,
        })

    return results


def _produce_ro_view_hypotheses(
    ws: Path,
    windows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Emit read-only-reentrancy-view hypotheses.

    For each unguarded callback window fn (already computed), check whether
    any external view fn in the workspace:
      (b) returns a price/rate/share/reserve-class field, AND
      (c) that exact field token is written in the window fn's body.

    Only Solidity is checked (see _scan_file_for_ro_view_candidates).
    """
    if not windows:
        return []

    # Build map: window fn -> its body text (for field-write checking).
    # We re-read each file once (cache by path).
    _file_text_cache: dict[str, str] = {}

    def _get_text(file_rel: str) -> str:
        if file_rel not in _file_text_cache:
            try:
                _file_text_cache[file_rel] = (ws / file_rel).read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                _file_text_cache[file_rel] = ""
        return _file_text_cache[file_rel]

    def _get_window_body(win: dict[str, Any]) -> str:
        text = _get_text(win["file"])
        fn_re = _FN_RES.get(win["language"])
        if fn_re is None:
            return ""
        for m in fn_re.finditer(text):
            if m.group(1) == win["function"]:
                return _extract_body(text, m.end())
        return ""

    # Collect all RO-view candidates across all source files.
    view_candidates: list[dict[str, Any]] = []
    for path in sorted(ws.rglob("*")):
        if not path.is_file():
            continue
        lang = _EXT_TO_LANG.get(path.suffix.lower())
        if lang is None:
            continue
        try:
            rel = str(path.relative_to(ws))
        except ValueError:
            rel = str(path)
        if is_oos(rel):
            continue
        view_candidates.extend(_scan_file_for_ro_view_candidates(path, rel, lang))

    if not view_candidates:
        return []

    hypotheses: list[dict[str, Any]] = []
    for win in windows:
        win_body = _get_window_body(win)
        if not win_body:
            continue

        for vc in view_candidates:
            # Skip if the view IS the window fn itself (trivial self-reference).
            if vc["file"] == win["file"] and vc["function"] == win["function"]:
                continue

            # Condition (c): at least one matched field must be WRITTEN in the window body.
            written_fields = [
                f for f in vc["matched_fields"]
                if _window_body_writes_field(win_body, f)
            ]
            if not written_fields:
                continue

            # All conditions met - emit a read-only-reentrancy-view hypothesis.
            field_list = ", ".join(written_fields)
            note = (
                f"during {win['function']}'s callback window "
                f"({win['file']}:{win['window_line']}, no reentrancy guard), "
                f"an external integrator calling {vc['function']} reads "
                f"price/reserve field(s) [{field_list}] that the window fn "
                f"writes mid-window - stale value returned (Curve-style read-only reentrancy)"
            )
            hypotheses.append({
                "workspace": str(ws),
                "file": vc["file"],
                "function": vc["function"],
                "language": vc["language"],
                "window_line": win["window_line"],
                "callback_evidence": win["callback_evidence"],
                "guard_detected": False,
                "reentry_target_file": win["file"],
                "reentry_target": win["function"],
                "sub_class": "read-only-reentrancy-view",
                "note": note,
                "attack_class": "read-only-reentrancy",
                "source": "CRC",
                "verdict": "needs-fuzz",
            })

    return hypotheses


# ---------------------------------------------------------------------------
# Load or generate VMF JSON.
# ---------------------------------------------------------------------------

def _ensure_vmf(ws: Path, vmf_json_path: Path | None, regen: bool) -> list[dict]:
    """Load value_moving_functions.json, regenerating if needed."""
    default = ws / ".auditooor" / "value_moving_functions.json"
    target = vmf_json_path or default

    if regen or not target.exists():
        vmf_mod = _load_vmf()
        vmf_mod.run(ws, target)

    if not target.exists():
        return []
    payload = json.loads(target.read_text(encoding="utf-8"))
    return payload.get("functions", [])


# ---------------------------------------------------------------------------
# Core pipeline: produce hypotheses.
# ---------------------------------------------------------------------------

def produce_hypotheses(
    ws: Path,
    vmf_json_path: Path | None = None,
    regen_vmf: bool = False,
) -> list[dict[str, Any]]:
    """Run CRC over workspace; return list of hypothesis dicts."""
    vmf_records = _ensure_vmf(ws, vmf_json_path, regen_vmf)

    # REENTRY TARGETS: value-moving fns that have BOTH a ledger write AND a
    # transfer/settlement (i.e. ledger_write_hit=True AND transfer_hit=True).
    # These are the fns whose state-write-before-settlement shape makes them
    # dangerous when re-entered from an external callback window.
    # Fns with only a ledger write but no transfer are not useful targets
    # (no settlement to exploit). Fns with only a transfer but no write are
    # view-like pass-through (not a re-entry gain).
    target_set: dict[tuple[str, str], dict] = {}
    for r in vmf_records:
        if r.get("ledger_write_hit") and r.get("transfer_hit"):
            target_set[(r["file"], r["function"])] = r

    # Also build the full VMF set (all fns) for window-self exclusion.
    vmf_set: set[tuple[str, str]] = {(r["file"], r["function"]) for r in vmf_records}

    # Walk all source files to find unguarded callback windows.
    windows: list[dict[str, Any]] = []
    for path in sorted(ws.rglob("*")):
        if not path.is_file():
            continue
        lang = _EXT_TO_LANG.get(path.suffix.lower())
        if lang is None:
            continue
        try:
            rel = str(path.relative_to(ws))
        except ValueError:
            rel = str(path)
        if is_oos(rel):
            continue
        windows.extend(_scan_file_for_windows(path, rel, lang))

    if not windows:
        return []

    # For each window, enumerate OTHER value-moving fns as reentry targets.
    # TARGET = VMF record with both ledger_write_hit AND transfer_hit,
    # excluding self-reentry (the window fn itself).
    #
    # CROSS-FILE FILTER (beanstalk Diamond explosion fix):
    #   A pure N*M cross-join over all window fns x all target fns floods the
    #   output on large Diamond-pattern codebases with many facets.
    #   We apply a tier-based filter:
    #
    #   tier1 (named callback): emit for ANY target (same-file or cross-file).
    #     Rationale: the window fn explicitly calls a named interface method
    #     (onFlashLoan, onMorphoFlashLoan, onERC1155Received, etc.) that hands
    #     control to an attacker-controlled address which can call back any
    #     entry-point in the same or a different contract.
    #
    #   tier2 (generic .call / delegatecall): emit for SAME-FILE targets only.
    #     Rationale: a generic .call{} opens an unguarded external call, but
    #     the target contract is anonymous; cross-contract reentry hypotheses
    #     are speculative without a known target address.
    #
    #   weak (safeTransfer / transfer only, Solidity): NOT emitted as
    #     classic-reentrancy. Weak-only windows were already filtered in
    #     _scan_file_for_windows (lang==sol guard). Non-Solidity windows are
    #     always treated as tier1 (the patterns are already attacker-reachable).
    hypotheses: list[dict[str, Any]] = []
    for win in windows:
        win_key = (win["file"], win["function"])
        win_tier = win.get("callback_tier", "tier1")  # non-sol defaults to tier1

        for (target_file, target_fn) in sorted(target_set.keys()):
            if (target_file, target_fn) == win_key:
                continue  # skip self-reentry (covered by SADL)

            same_file = (win["file"] == target_file)

            # Apply cross-file filter.
            if win_tier == "tier2" and not same_file:
                continue  # tier2 generic call -> same-file only

            # (weak is excluded at scan time for Solidity; non-Solidity is tier1)

            note = (
                f"during {win['function']}'s callback window "
                f"({win['file']}:{win['window_line']}, no reentrancy guard), "
                f"re-enter {target_fn} and re-check the value-conservation invariant"
            )
            hypotheses.append({
                "workspace": str(ws),
                "file": win["file"],
                "function": win["function"],
                "language": win["language"],
                "window_line": win["window_line"],
                "callback_evidence": win["callback_evidence"],
                "guard_detected": False,
                "reentry_target_file": target_file,
                "reentry_target": target_fn,
                "sub_class": "classic-reentrancy",
                "note": note,
                "attack_class": "reentrancy-into-settlement",
                "source": "CRC",
                "verdict": "needs-fuzz",
            })

    # Add read-only-reentrancy-view hypotheses (Curve-style, tight discriminator).
    ro_view_hyps = _produce_ro_view_hypotheses(ws, windows)
    hypotheses.extend(ro_view_hyps)

    return hypotheses


# ---------------------------------------------------------------------------
# run() - write JSONL output.
# ---------------------------------------------------------------------------

def run(
    ws: Path | str,
    out_path: Path | str | None = None,
    vmf_json_path: Path | str | None = None,
    regen_vmf: bool = False,
) -> Path:
    ws = Path(ws).resolve()
    hypotheses = produce_hypotheses(
        ws,
        vmf_json_path=Path(vmf_json_path) if vmf_json_path else None,
        regen_vmf=regen_vmf,
    )

    out = (
        Path(out_path)
        if out_path is not None
        else ws / ".auditooor" / "callback_reentrancy_hypotheses.jsonl"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for hyp in hypotheses:
            fh.write(json.dumps(hyp) + "\n")

    return out


# ---------------------------------------------------------------------------
# CLI entry-point.
# ---------------------------------------------------------------------------

def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Callback-Reentrancy-Composition (CRC): detect unguarded "
                    "callback windows in value-moving fns and emit reentry hypotheses."
    )
    parser.add_argument("workspace", help="Workspace root path")
    parser.add_argument("--out", default=None, help="Override output .jsonl path")
    parser.add_argument(
        "--vmf-json", default=None,
        help="Override value_moving_functions.json path",
    )
    parser.add_argument(
        "--regen-vmf", action="store_true",
        help="Re-run value-moving-functions.py even if JSON already exists",
    )
    args = parser.parse_args(argv)

    ws = Path(args.workspace)
    if not ws.is_dir():
        print(f"ERROR: workspace not found: {ws}", file=sys.stderr)
        return 1

    vmf_path = Path(args.vmf_json) if args.vmf_json else None
    out = run(ws, args.out, vmf_path, args.regen_vmf)

    lines = out.read_text(encoding="utf-8").strip().splitlines()
    count = len(lines) if lines and lines[0] else 0
    print(f"CRC: {count} hypotheses -> {out}")

    # Tally by sub_class.
    sub_counts: dict[str, int] = {}
    parsed_hyps: list[dict] = []
    for line in lines:
        try:
            h = json.loads(line)
            parsed_hyps.append(h)
            sc = h.get("sub_class", "classic-reentrancy")
            sub_counts[sc] = sub_counts.get(sc, 0) + 1
        except Exception:
            pass
    for sc, n in sorted(sub_counts.items()):
        print(f"  sub_class={sc}: {n}")

    for h in parsed_hyps[:20]:
        sc = h.get("sub_class", "?")
        print(f"  [{h['language']}][{sc}] {h['file']}::{h['function']} "
              f"(line {h['window_line']}) -> reenter {h.get('reentry_target', '-')}")
    if count > 20:
        print(f"  ... ({count - 20} more)")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
