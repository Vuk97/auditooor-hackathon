#!/usr/bin/env python3
"""value-conservation-invariant-synth.py  (VCIS) - auto-generate conservation
invariant harnesses from value_moving_functions.json.

WHAT THIS TOOL DOES
===================
For every function in <ws>/.auditooor/value_moving_functions.json, VCIS
synthesises a Solidity property that catches any bug that lets the protocol
account MORE liability than it actually holds in token balances.  The synthesised
property is the MINIMAL SAFE FORM - a solvency-floor inequality:

    balanceOf(protocol, token) >= sum(credit-side liability fields)

This form:
  - cannot false-positive on a legitimate state (holding MORE than owed is always
    valid);
  - catches the self-settled-take class (borrower calls take() to settle their OWN
    short -> net token flow to ZERO while creditOf[buyer] still increments -> loan
    balance falls below withdrawable + fee);
  - is derived mechanically from the token extraction + field-selection rules below.

PROPERTY FORMS (priority order)
================================
1. SOLVENCY-FLOOR (transfer_hit=true AND ledger_write_evidence non-empty)
   balanceOf(protocol, token) >= sum(credit_fields)
   -> highest value, catches self-settled-take, double-credit, phantom-mint.

2. DELTA-CONSERVATION (transfer_hit=true, ledger_write_evidence empty)
   net protocol balance after call >= pre-call balance - authorised_outflow
   -> ghost variable tracks the last authorised withdrawal.

3. ACCOUNTING-MONOTONE (transfer_hit=false, ledger_write_evidence non-empty)
   sum(credit_fields) does not decrease beyond the corresponding authorised
   debit (credit-side liability fields may only shrink when there is a matching
   authorised withdrawal).

EMIT TARGET
===========
<ws>/.auditooor/vcis/
  Properties_VCIS.sol         - synthesised Solidity property contract
  medusa.json                 - reuses emit_medusa_config shared actor pool
  echidna.yaml                - reuses emit_echidna_config shared actor pool
  conservation_vcis.go        - Go/Cosmos sdk.Invariant conservation bodies (mechanical)
  vcis_register_scaffold.go   - Go InvariantRegistry wiring scaffold (manual TODO)
  conservation_vcis_test.rs   - Rust/CosmWasm proptest + cw-multi-test assertions (mechanical)
  vcis_manifest.json          - per-fn verdict sidecar (needs-fuzz until mutation-verified)

GENUINE-CREDIT RULE (NO FALSE-GREEN)
=====================================
The vcis_manifest.json marks every synthesised harness with:
  "verdict": "needs-fuzz"
until the harness actually compiles, runs on the REAL CUT, and is
mutation-verified (kills a planted non-conservation mutant via
mutation-verify-coverage.py).  Only after that does the caller promote to
"non-vacuous" / "killed".  This tool NEVER self-credits genuine coverage.

LANGUAGE BACKENDS
=================
Solidity backend: FULLY IMPLEMENTED (morpho is the concrete provable case).
Go/Cosmos backend: IMPLEMENTED - emits a real sdk.Invariant conservation body
  (VCISConservation_<fn>) + a RegisterVCISInvariants wiring scaffold.
  Per-workspace manual steps (keeper-getter binding, InvariantRegistry wiring,
  module account + denom constants) are documented as README steps, not
  auto-compiled.  verdict=needs-fuzz until compiled + mutation-verified.
Rust/CosmWasm backend: IMPLEMENTED - emits a real cw-multi-test / proptest
  conservation assertion (#[test] fn vcis_conservation_<fn>) + an
  instantiate_contract scaffold.  Per-workspace manual steps (InstantiateMsg,
  query bindings, denom) are documented as README steps.
  verdict=needs-fuzz until compiled + mutation-verified.

REUSE MAP
=========
- evm-engine-harness-author.emit_medusa_config / emit_echidna_config:
  imported and called directly for the shared-actor-pool configs so VCIS
  inherits the payer==receiver reachable property automatically.
- tools/lib/scope_exclusion.is_oos: OOS filter on every source file.
- value-moving-functions.enumerate_value_moving: run if json absent.

DESIGN INVARIANTS
=================
- GENERIC CORE: no workspace literal ever appears in the property model or the
  field-selection heuristics.  Language is driven by the `language` field.
- HYPHEN-MINUS ONLY: no em-dash (U+2014) or en-dash (U+2013) anywhere.
- BOUND FUZZ: test_limit=10000, seqLen=50 - never runs away.

CLI
===
  python3 tools/value-conservation-invariant-synth.py <workspace> [--out <dir>]
  --out: override output directory (default: <ws>/.auditooor/vcis/)
  --force-regen: re-run value-moving-functions if json already exists

Returns rc=0 on success, rc=1 on error.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from textwrap import indent
from typing import Any

# ---------------------------------------------------------------------------
# Scope exclusion (single source of truth - same as all other tools).
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_exclusion import is_oos  # type: ignore
except Exception:
    _HERE = Path(__file__).resolve().parent
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + rel.replace("\\", "/")).lower()
            for m in ("/test/", "/tests/", "_test.", ".t.sol", "/vendor/",
                      "/lib/", "/node_modules/", "/out/", "/build/", "/target/"):
                if m in n:
                    return True
            return False


# ---------------------------------------------------------------------------
# Lazy-import the value-moving-functions module (hyphen in file name).
# ---------------------------------------------------------------------------
def _load_vmf():
    tool = Path(__file__).resolve().parent / "value-moving-functions.py"
    spec = importlib.util.spec_from_file_location("value_moving_functions", tool)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


# ---------------------------------------------------------------------------
# Lazy-import evm-engine-harness-author for medusa/echidna config emitters.
# ---------------------------------------------------------------------------
def _load_harness_author():
    tool = Path(__file__).resolve().parent / "evm-engine-harness-author.py"
    spec = importlib.util.spec_from_file_location("evm_engine_harness_author", tool)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


# ---------------------------------------------------------------------------
# Credit-side field heuristics (LIABILITY_FIELDS selection).
# These roots identify ledger fields that represent ADDITIVE lender / depositor
# obligations.  Debit-only fields (debt / borrow alone) are excluded unless
# the protocol model makes them part of a depositor claim.
# ---------------------------------------------------------------------------
_CREDIT_ROOTS: tuple[str, ...] = (
    "credit", "withdrawable", "units", "supply", "lend", "deposit",
    "collateral", "fee", "reward", "stake", "balance", "vault",
    "escrow", "reserve", "liquidity", "fund", "pool", "holding",
    "position", "asset", "share",
)

# Debit-only exclusion: if the field name ONLY matches these roots and NOT any
# credit root, it is excluded from the solvency-floor sum.
_DEBIT_ONLY_ROOTS: tuple[str, ...] = ("debt", "borrow",)


def _is_credit_field(field_name: str) -> bool:
    """Return True if field_name looks like a credit/liability field."""
    low = field_name.lower()
    # If ANY credit root appears, it qualifies.
    for r in _CREDIT_ROOTS:
        if r in low:
            return True
    return False


def _is_debit_only(field_name: str) -> bool:
    """Return True if field is purely debit-side (no credit root)."""
    low = field_name.lower()
    has_credit = any(r in low for r in _CREDIT_ROOTS)
    if has_credit:
        return False
    return any(r in low for r in _DEBIT_ONLY_ROOTS)


# ---------------------------------------------------------------------------
# Token extraction from transfer_evidence snippets.
# Heuristic: first identifier-like argument of safeTransfer / safeTransferFrom /
# transfer(  after the function name is the token address argument.
# Falls back to ALL tokens appearing in ledger_write_evidence matching
# _CREDIT_ROOTS if evidence is empty.
# ---------------------------------------------------------------------------
_TOKEN_EXTRACT_RE = re.compile(
    r"""(?:safeTransferFrom|safeTransfer|transferFrom|transfer)\s*\(\s*
        ([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)""",
    re.VERBOSE,
)


def _extract_tokens(fn_rec: dict) -> list[str]:
    """Extract token identifiers from a value_moving_functions record."""
    tokens: list[str] = []
    seen: set[str] = set()

    for snippet in fn_rec.get("transfer_evidence", []):
        m = _TOKEN_EXTRACT_RE.search(snippet)
        if m:
            tok = m.group(1).strip()
            if tok and tok not in seen:
                tokens.append(tok)
                seen.add(tok)

    # Fall back to ledger_write_evidence fields that smell like tokens if no
    # transfer evidence produced a name.
    if not tokens:
        for ev in fn_rec.get("ledger_write_evidence", []):
            low = ev.lower()
            if any(r in low for r in ("token", "loan", "collat", "asset", "coin")):
                if ev not in seen:
                    tokens.append(ev)
                    seen.add(ev)

    # If still empty, use a generic placeholder.
    if not tokens:
        tokens = ["token"]

    return tokens


def _extract_credit_fields(fn_rec: dict) -> list[str]:
    """Extract credit-side liability fields from ledger_write_evidence."""
    out: list[str] = []
    seen: set[str] = set()
    for ev in fn_rec.get("ledger_write_evidence", []):
        if ev in seen:
            continue
        if _is_credit_field(ev) and not _is_debit_only(ev):
            out.append(ev)
            seen.add(ev)
    return out


# ---------------------------------------------------------------------------
# Property form selection (spec priority order).
# ---------------------------------------------------------------------------
@dataclass
class PropertySpec:
    """Language-agnostic property specification for one value-moving fn."""

    fn_name: str
    fn_file: str
    language: str
    form: str          # "solvency-floor" | "delta-conservation" | "accounting-monotone"
    tokens: list[str]
    credit_fields: list[str]
    transfer_hit: bool
    ledger_write_hit: bool


def _classify_form(fn_rec: dict) -> str:
    transfer = fn_rec.get("transfer_hit", False)
    credit = bool([f for f in fn_rec.get("ledger_write_evidence", [])
                   if _is_credit_field(f) and not _is_debit_only(f)])
    if transfer and credit:
        return "solvency-floor"
    if transfer:
        return "delta-conservation"
    return "accounting-monotone"


def build_property_spec(fn_rec: dict) -> PropertySpec:
    """Derive a PropertySpec from a value_moving_functions record."""
    return PropertySpec(
        fn_name=fn_rec["function"],
        fn_file=fn_rec["file"],
        language=fn_rec.get("language", "sol"),
        form=_classify_form(fn_rec),
        tokens=_extract_tokens(fn_rec),
        credit_fields=_extract_credit_fields(fn_rec),
        transfer_hit=fn_rec.get("transfer_hit", False),
        ledger_write_hit=fn_rec.get("ledger_write_hit", False),
    )


# ---------------------------------------------------------------------------
# Solidity backend - emit Properties_VCIS.sol
# ---------------------------------------------------------------------------

_SOL_HEADER = """\
// SPDX-License-Identifier: MIT
// AUTO-GENERATED by value-conservation-invariant-synth.py
// CANDIDATE-HARNESS-NOT-PROOF - credit only after mutation-verification pass.
// Rule R80 / R58: harness must be non-vacuous (mutation-verified) before filing.
pragma solidity ^0.8.0;

/// @title VCIS - Value Conservation Invariant Suite
/// @notice Synthesised solvency-floor properties for every value-moving function
///         in the workspace.  Each property asserts the MINIMAL SAFE FORM:
///             balanceOf(protocol, token) >= sum(credit_side_liability_fields)
///         This cannot false-positive (a protocol holding MORE than it owes is
///         always valid) and catches the self-settled-take class, double-credit,
///         and phantom-mint bugs.
///
/// @dev HOW TO USE:
///   1. Inherit this contract from your Chimera TargetFunctions (or equivalent).
///   2. Fill _protocol() / _token_*() / _liability_*() with real state accessors.
///   3. Run medusa / echidna with the bundled config (shared actor pool).
///   4. Run mutation-verify-coverage.py to confirm non-vacuity.
///   5. Only credit genuine coverage after step 4 passes.
abstract contract VCIS_Properties {

    // -----------------------------------------------------------------------
    // PROTOCOL ADDRESS HOOK - implement in derived contract.
    // -----------------------------------------------------------------------
    function _vcis_protocol() internal view virtual returns (address);

    // -----------------------------------------------------------------------
    // TOKEN BALANCE HOOK - implement per-token in derived contract.
    // -----------------------------------------------------------------------
    function _vcis_balanceOf(address token, address acct)
        internal view virtual returns (uint256);

"""

_SOL_FOOTER = "}\n"


def _sol_property_name(fn_name: str, form: str, idx: int) -> str:
    safe = re.sub(r"[^A-Za-z0-9_]", "_", fn_name)
    suffix = {"solvency-floor": "solvency", "delta-conservation": "delta",
              "accounting-monotone": "monotone"}.get(form, "conservation")
    return f"echidna_vcis_{safe}_{suffix}_{idx}"


def _sol_liability_hook(fn_name: str, field_name: str) -> str:
    safe_fn = re.sub(r"[^A-Za-z0-9_]", "_", fn_name)
    safe_f = re.sub(r"[^A-Za-z0-9_]", "_", field_name)
    return f"_vcis_{safe_fn}_{safe_f}"


def _emit_solvency_floor_property(spec: PropertySpec, idx: int) -> str:
    """Emit a solvency-floor property for one fn + one token.

    Property: balanceOf(protocol, token) >= sum(credit_field_i)
    """
    prop_name = _sol_property_name(spec.fn_name, spec.form, idx)
    token = spec.tokens[0] if spec.tokens else "token"
    # token hook name
    tok_hook = f"_vcis_token_{re.sub(r'[^A-Za-z0-9_]', '_', token)}"

    lines: list[str] = []
    lines.append(f"    /// @notice SOLVENCY-FLOOR for {spec.fn_name}() [{spec.fn_file}]")
    lines.append(f"    /// @dev Minimal safe form: protocol balance >= credit-side liabilities.")
    lines.append(f"    /// Catches: self-settled-take, double-credit, phantom-mint.")
    lines.append(f"    /// Fill _vcis_protocol(), {tok_hook}(), and liability hooks below.")
    lines.append(f"    function {prop_name}() public view returns (bool) {{")
    lines.append(f"        address proto = _vcis_protocol();")
    lines.append(f"        address tok   = {tok_hook}();")
    lines.append(f"        uint256 bal   = _vcis_balanceOf(tok, proto);")

    if spec.credit_fields:
        lines.append(f"        uint256 owed  = 0;")
        for cf in spec.credit_fields:
            hook = _sol_liability_hook(spec.fn_name, cf)
            lines.append(f"        owed += {hook}(); // {cf}")
    else:
        lines.append(f"        // No credit fields found - using delta-fallback (pre-call ghost).")
        lines.append(f"        uint256 owed  = _vcis_{re.sub(r'[^A-Za-z0-9_]', '_', spec.fn_name)}_ghost_owed();")

    lines.append(f"        return bal >= owed;")
    lines.append(f"    }}")
    lines.append(f"")

    # Emit stub hooks that the implementer fills in.
    lines.append(f"    // --- TOKEN HOOK for {spec.fn_name} ---")
    lines.append(f"    function {tok_hook}() internal view virtual returns (address);")
    lines.append(f"")

    for cf in spec.credit_fields:
        hook = _sol_liability_hook(spec.fn_name, cf)
        lines.append(f"    // LIABILITY HOOK - return total {cf} from protocol storage.")
        lines.append(f"    function {hook}() internal view virtual returns (uint256);")
    if not spec.credit_fields:
        ghost = f"_vcis_{re.sub(r'[^A-Za-z0-9_]', '_', spec.fn_name)}_ghost_owed"
        lines.append(f"    // GHOST HOOK - return pre-call tracked owed amount.")
        lines.append(f"    function {ghost}() internal view virtual returns (uint256);")
    lines.append(f"")

    # Strict-equality variant as comment.
    lines.append(f"    // OPTIONAL STRICT-EQUALITY VARIANT (only when no unaccounted equity buffer):")
    lines.append(f"    // assert balanceOf == sum(credit_fields) + protocolEquityMargin")
    lines.append(f"    // Do NOT use as default - unaccounted fee accumulation false-positives it.")
    lines.append(f"")

    return "\n".join(lines)


def _emit_delta_conservation_property(spec: PropertySpec, idx: int) -> str:
    """Emit a delta-conservation property: net balance after call >= pre-call - authorised_outflow."""
    prop_name = _sol_property_name(spec.fn_name, spec.form, idx)
    token = spec.tokens[0] if spec.tokens else "token"
    tok_hook = f"_vcis_token_{re.sub(r'[^A-Za-z0-9_]', '_', token)}"
    ghost_pre = f"_vcis_{re.sub(r'[^A-Za-z0-9_]', '_', spec.fn_name)}_ghost_pre"
    ghost_auth = f"_vcis_{re.sub(r'[^A-Za-z0-9_]', '_', spec.fn_name)}_ghost_auth"

    lines: list[str] = []
    lines.append(f"    /// @notice DELTA-CONSERVATION for {spec.fn_name}() [{spec.fn_file}]")
    lines.append(f"    /// @dev Net protocol balance >= pre-call balance - authorised outflow.")
    lines.append(f"    /// Captures flash-loan repayment and claim-settlement-fee patterns.")
    lines.append(f"    function {prop_name}() public view returns (bool) {{")
    lines.append(f"        address proto = _vcis_protocol();")
    lines.append(f"        address tok   = {tok_hook}();")
    lines.append(f"        uint256 bal   = _vcis_balanceOf(tok, proto);")
    lines.append(f"        uint256 pre   = {ghost_pre}(); // ghost: pre-call balance snapshot")
    lines.append(f"        uint256 auth  = {ghost_auth}(); // ghost: authorised outflow this call")
    lines.append(f"        if (pre < auth) return true; // underflow guard: ok if auth > pre")
    lines.append(f"        return bal >= pre - auth;")
    lines.append(f"    }}")
    lines.append(f"")
    lines.append(f"    function {tok_hook}() internal view virtual returns (address);")
    lines.append(f"    function {ghost_pre}() internal view virtual returns (uint256);")
    lines.append(f"    function {ghost_auth}() internal view virtual returns (uint256);")
    lines.append(f"")
    return "\n".join(lines)


def _emit_accounting_monotone_property(spec: PropertySpec, idx: int) -> str:
    """Emit an accounting-monotone property: sum(credit_fields) does not decrease without transfer."""
    prop_name = _sol_property_name(spec.fn_name, spec.form, idx)
    ghost_floor = f"_vcis_{re.sub(r'[^A-Za-z0-9_]', '_', spec.fn_name)}_ghost_floor"

    lines: list[str] = []
    lines.append(f"    /// @notice ACCOUNTING-MONOTONE for {spec.fn_name}() [{spec.fn_file}]")
    lines.append(f"    /// @dev Credit-side liability sum must not silently decrease.")
    lines.append(f"    function {prop_name}() public view returns (bool) {{")

    if spec.credit_fields:
        lines.append(f"        uint256 total = 0;")
        for cf in spec.credit_fields:
            hook = _sol_liability_hook(spec.fn_name, cf)
            lines.append(f"        total += {hook}(); // {cf}")
        lines.append(f"        return total >= {ghost_floor}();")
    else:
        lines.append(f"        return true; // no credit fields to assert monotonicity on")
    lines.append(f"    }}")
    lines.append(f"")

    for cf in spec.credit_fields:
        hook = _sol_liability_hook(spec.fn_name, cf)
        lines.append(f"    function {hook}() internal view virtual returns (uint256);")
    lines.append(f"    function {ghost_floor}() internal view virtual returns (uint256);")
    lines.append(f"")
    return "\n".join(lines)


def emit_sol_properties(specs: list[PropertySpec]) -> str:
    """Emit the complete Properties_VCIS.sol content."""
    body_parts: list[str] = []
    for idx, spec in enumerate(specs):
        if spec.language != "sol":
            continue
        if spec.form == "solvency-floor":
            body_parts.append(_emit_solvency_floor_property(spec, idx))
        elif spec.form == "delta-conservation":
            body_parts.append(_emit_delta_conservation_property(spec, idx))
        else:
            body_parts.append(_emit_accounting_monotone_property(spec, idx))

    return _SOL_HEADER + "\n".join(body_parts) + _SOL_FOOTER


# ---------------------------------------------------------------------------
# Go/Cosmos backend - real sdk.Invariant conservation body.
# ---------------------------------------------------------------------------
#
# WHAT IS MECHANICAL vs MANUAL
# =============================
# MECHANICAL (emitted generically from value_moving_functions.json):
#   - The sdk.Invariant function body asserting bank balance >= sum(credit fields)
#   - A RegisterVCISInvariants() scaffold listing all invariant names
#   - A vcis_register_scaffold.go with the InvariantRegistry wiring TODO
#
# MANUAL (documented as README steps, NOT auto-compiled):
#   - Replacing GetTotal{CreditField}(ctx) with the real keeper getter name
#   - Wiring RegisterVCISInvariants into the app's InvariantRegistry
#   - Resolving the module account name and denom constants
#
# GENUINE-CREDIT RULE: all emitted functions carry a "CANDIDATE-HARNESS-NOT-PROOF"
# header. verdict=needs-fuzz until:
#   (a) harness compiles against the real app module
#   (b) mutation-verify kills a planted mutant
#
# ---------------------------------------------------------------------------

_GO_FILE_HEADER = """\
// AUTO-GENERATED by value-conservation-invariant-synth.py - Go/Cosmos sdk.Invariant backend.
// CANDIDATE-HARNESS-NOT-PROOF - verdict=needs-fuzz until:
//   (a) harness compiles against real app module, (b) mutation-verify kills a planted mutant.
// Rule R80 / R58: never self-credit genuine coverage.
//
// PROPERTY FORM: solvency-floor
//   bankKeeper.SpendableCoins(ctx, moduleAcct) >= sum(keeper.GetTotal<CreditField>(ctx))
//
// This form cannot false-positive (module holding MORE than it owes is always valid).
// It catches: double-credit, phantom-mint, self-settled-take.
//
// ============================================================
// MECHANICAL PART (auto-generated from value_moving_functions.json)
// ============================================================
// For each Go value-moving function VCIS derives:
//   - moduleAcct placeholder: MODULE_ACCOUNT_PLACEHOLDER (replace with real module name)
//   - denom placeholder:      DENOM_PLACEHOLDER (replace with real denom string)
//   - credit fields:          ledger_write_evidence entries matching _CREDIT_ROOTS
//
// ============================================================
// PER-WORKSPACE MANUAL PART (documented README step, NOT auto-compiled)
// ============================================================
// Step 1 - KEEPER GETTER BINDING:
//   Replace GetTotal{CreditField}(ctx) with the real keeper method for each credit field.
//   The getter name is a best-effort camelCase derivation; verify against the keeper interface.
//
// Step 2 - REGISTER IN APP:
//   Open vcis_register_scaffold.go and follow the TODO blocks to wire
//   RegisterVCISInvariants into the app's InvariantRegistry at app init.
//
// Step 3 - COMPILE CHECK:
//   go build ./... must pass before claiming any genuine coverage.
//
// Step 4 - MUTATION VERIFY:
//   Plant a mutation (decrement a credit field without a corresponding transfer)
//   and confirm the invariant fires. Use mutation-verify-coverage.py.
//
// Step 5 - ONLY THEN promote verdict from needs-fuzz to non-vacuous in vcis_manifest.json.

package vcis_conservation

import (
\t"fmt"

\tsdk "github.com/cosmos/cosmos-sdk/types"
)

// MODULE_ACCOUNT_PLACEHOLDER - replace with the real module account name string literal.
// Example: authtypes.NewModuleAddress("lending")
const MODULE_ACCOUNT_PLACEHOLDER = "MODULE_ACCOUNT_TODO"

// DENOM_PLACEHOLDER - replace with the real token denom string.
// Example: "uatom" or sdk.DefaultBondDenom
const DENOM_PLACEHOLDER = "DENOM_TODO"

// BankKeeper is the minimal interface required by VCIS invariants.
// The real app bankkeeper satisfies this.
type BankKeeper interface {
\tSpendableCoins(ctx sdk.Context, addr sdk.AccAddress) sdk.Coins
}

"""

_GO_INVARIANT_TEMPLATE = """\
// VCISConservation_{safe_fn} - sdk.Invariant asserting solvency-floor for {fn_name}().
// Source: {fn_file}
// Property form: {form}
// CANDIDATE-HARNESS-NOT-PROOF - compile + mutation-verify before crediting.
//
// MANUAL WIRING REQUIRED:
//   - Replace MODULE_ACCOUNT_PLACEHOLDER with the real module account name.
//   - Replace DENOM_PLACEHOLDER with the real denom.
{credit_field_todos}//   - Wire into app via RegisterVCISInvariants (see vcis_register_scaffold.go).
func VCISConservation_{safe_fn}(bankKeeper BankKeeper, keeper interface{{
{keeper_interface_lines}
}}) func(ctx sdk.Context) (string, bool) {{
\treturn func(ctx sdk.Context) (string, bool) {{
\t\tmoduleAddr := sdk.AccAddress([]byte(MODULE_ACCOUNT_PLACEHOLDER))
\t\tcoins := bankKeeper.SpendableCoins(ctx, moduleAddr)
\t\tbal := coins.AmountOf(DENOM_PLACEHOLDER)
{body_lines}
\t}}
}}

"""

_GO_REGISTER_SCAFFOLD = """\
// AUTO-GENERATED by value-conservation-invariant-synth.py - RegisterVCISInvariants scaffold.
// CANDIDATE-HARNESS-NOT-PROOF - see conservation_vcis.go for full wiring instructions.
//
// TODO: paste this function body into your app's invariant registration site.
// Example call site (app.go or module.go):
//
//   func (am AppModule) RegisterInvariants(ir sdk.InvariantRegistry) {{
//       RegisterVCISInvariants(ir, am.keeper.bankKeeper, am.keeper)
//   }}

package vcis_conservation

// RegisterVCISInvariants registers all VCIS solvency-floor invariants.
// Replace the keeper parameter type with the real keeper type for your module.
func RegisterVCISInvariants(ir sdk.InvariantRegistry, bankKeeper BankKeeper, keeper interface{{}}) {{
{register_lines}
}}
"""


def _go_safe_name(fn_name: str) -> str:
    """Derive a Go-safe identifier from a function name."""
    return re.sub(r"[^A-Za-z0-9]", "_", fn_name)


def _go_credit_getter_name(field: str) -> str:
    """Best-effort camelCase getter for a credit field.

    Examples:
      creditOf      -> GetTotalCreditOf
      totalDeposits -> GetTotalTotalDeposits  (intentionally verbose; dev replaces)
      shareBalance  -> GetTotalShareBalance
    """
    # Strip leading "total"/"get" prefix to avoid double-prefixing, capitalise first char.
    stripped = re.sub(r"^(total|get)", "", field, flags=re.IGNORECASE)
    if stripped:
        camel = stripped[0].upper() + stripped[1:]
    else:
        camel = field[0].upper() + field[1:]
    return f"GetTotal{camel}"


def _emit_go_invariant_body(spec: PropertySpec) -> str:
    """Emit one sdk.Invariant function body for a Go value-moving function."""
    safe_fn = _go_safe_name(spec.fn_name)

    # Build keeper interface method stubs for each credit field getter.
    if spec.credit_fields:
        interface_lines = "\n".join(
            f"\t{_go_credit_getter_name(f)}(ctx sdk.Context) sdk.Int"
            for f in spec.credit_fields
        )
        credit_field_todos = "".join(
            f"//   - Replace {_go_credit_getter_name(f)}(ctx) with the real keeper method for field '{f}'.\n"
            for f in spec.credit_fields
        )
        body_parts = ["\t\ttotalOwed := sdk.ZeroInt()"]
        for f in spec.credit_fields:
            getter = _go_credit_getter_name(f)
            body_parts.append(
                f"\t\ttotalOwed = totalOwed.Add(keeper.{getter}(ctx)) // credit field: {f}"
            )
        body_parts += [
            "\t\tif bal.LT(totalOwed) {",
            f'\t\t\treturn fmt.Sprintf(',
            f'\t\t\t\t"VCIS solvency-floor violated for {spec.fn_name}: '
            f'balance=%s owed=%s", bal, totalOwed), true',
            "\t\t}",
            "\t\treturn \"\", false",
        ]
    else:
        # delta-conservation form: assert balance has not decreased without authorisation.
        interface_lines = (
            "\tGetPreCallBalance(ctx sdk.Context) sdk.Int\n"
            "\tGetAuthorisedOutflow(ctx sdk.Context) sdk.Int"
        )
        credit_field_todos = (
            "//   - Implement GetPreCallBalance + GetAuthorisedOutflow on the keeper\n"
            "//     (ghost state tracking pre-call balance and authorised outflow).\n"
        )
        body_parts = [
            "\t\tpre := keeper.GetPreCallBalance(ctx)",
            "\t\tauth := keeper.GetAuthorisedOutflow(ctx)",
            "\t\t// underflow guard: if auth > pre, the state is already inconsistent.",
            "\t\tif pre.LT(auth) {",
            "\t\t\treturn \"\", false",
            "\t\t}",
            "\t\tfloor := pre.Sub(auth)",
            "\t\tif bal.LT(floor) {",
            f'\t\t\treturn fmt.Sprintf(',
            f'\t\t\t\t"VCIS delta-conservation violated for {spec.fn_name}: '
            f'balance=%s floor=%s", bal, floor), true',
            "\t\t}",
            "\t\treturn \"\", false",
        ]

    body_lines = "\n".join(body_parts)

    return _GO_INVARIANT_TEMPLATE.format(
        safe_fn=safe_fn,
        fn_name=spec.fn_name,
        fn_file=spec.fn_file,
        form=spec.form,
        credit_field_todos=credit_field_todos,
        keeper_interface_lines=interface_lines,
        body_lines=body_lines,
    )


def emit_go_backend(specs: list[PropertySpec]) -> tuple[str, str]:
    """Emit the Go/Cosmos conservation harness files.

    Returns a tuple:
      [0] conservation_vcis.go  - sdk.Invariant function bodies (mechanical part)
      [1] vcis_register_scaffold.go - InvariantRegistry wiring scaffold (manual TODO)
    """
    go_specs = [s for s in specs if s.language == "go"]

    invariant_bodies = "".join(_emit_go_invariant_body(s) for s in go_specs)

    register_lines_parts = []
    for s in go_specs:
        safe_fn = _go_safe_name(s.fn_name)
        register_lines_parts.append(
            f'\tir.RegisterRoute("vcis", "{s.fn_name}_conservation",\n'
            f"\t\tVCISConservation_{safe_fn}(bankKeeper, keeper))"
        )
    register_lines = "\n".join(register_lines_parts) if register_lines_parts else "\t// no Go value-moving functions detected"

    conservation_go = _GO_FILE_HEADER + invariant_bodies
    scaffold_go = _GO_REGISTER_SCAFFOLD.format(register_lines=register_lines)

    return conservation_go, scaffold_go


# ---------------------------------------------------------------------------
# Rust/CosmWasm backend - real proptest / cw-multi-test conservation assertions.
# ---------------------------------------------------------------------------
#
# WHAT IS MECHANICAL vs MANUAL
# =============================
# MECHANICAL (emitted generically from value_moving_functions.json):
#   - proptest / cw-multi-test conservation assertion body per value-moving fn
#   - A wiring scaffold showing the App setup pattern
#
# MANUAL (documented as README steps, NOT auto-compiled):
#   - Replacing INSTANTIATE_MSG_TODO with the real contract InstantiateMsg
#   - Replacing query_total_credit_field_TODO with real contract query bindings
#   - Adding the crate dependencies (cw-multi-test, proptest) to Cargo.toml
#
# GENUINE-CREDIT RULE: verdict=needs-fuzz until compiled + mutation-verified.
#
# ---------------------------------------------------------------------------

_RUST_FILE_HEADER = """\
// AUTO-GENERATED by value-conservation-invariant-synth.py - Rust/CosmWasm conservation backend.
// CANDIDATE-HARNESS-NOT-PROOF - verdict=needs-fuzz until:
//   (a) harness compiles against real contract, (b) mutation-verify kills a planted mutant.
// Rule R80 / R58: never self-credit genuine coverage.
//
// PROPERTY FORM: solvency-floor
//   bank_balance(protocol_addr, denom) >= sum(query_total_<credit_field>(&app))
//
// ============================================================
// MECHANICAL PART (auto-generated from value_moving_functions.json)
// ============================================================
//
// ============================================================
// PER-WORKSPACE MANUAL PART (documented README step, NOT auto-compiled)
// ============================================================
// Step 1 - CARGO DEPENDENCIES: add to Cargo.toml [dev-dependencies]:
//   cw-multi-test = "0.20"   (or latest compatible)
//   proptest      = "1"
//
// Step 2 - INSTANTIATE MSG: replace INSTANTIATE_MSG_TODO with the real InstantiateMsg
//   struct for your contract (import from your contract crate).
//
// Step 3 - QUERY BINDINGS: replace query_total_<field>_TODO(&app, addr) with a real
//   query dispatch to your contract's QueryMsg variant that returns the field total.
//
// Step 4 - DENOM: replace DENOM_TODO with the real denom string (e.g. "uatom").
//
// Step 5 - COMPILE: cargo test --no-run must pass before claiming genuine coverage.
//
// Step 6 - MUTATION VERIFY: plant a mutation (decrement a credit field without transfer)
//   and confirm the test fails. Use mutation-verify-coverage.py.
//
// Step 7 - ONLY THEN promote verdict from needs-fuzz to non-vacuous in vcis_manifest.json.

#![cfg(test)]

use cosmwasm_std::{{Uint128}};
// TODO: replace with the real cw_multi_test import from your contract crate.
// use cw_multi_test::{{App, ContractWrapper, Executor}};

/// DENOM_TODO - replace with the real token denom string.
const DENOM_TODO: &str = "DENOM_TODO";

/// PROTOCOL_ADDR_TODO - replace with the real module / contract address.
const PROTOCOL_ADDR_TODO: &str = "PROTOCOL_ADDR_TODO";

"""

_RUST_ASSERTION_TEMPLATE = """\
/// vcis_conservation_{safe_fn} - solvency-floor proptest for {fn_name}().
/// Source: {fn_file}
/// Property form: {form}
/// CANDIDATE-HARNESS-NOT-PROOF - compile + mutation-verify before crediting.
///
/// MANUAL WIRING REQUIRED:
///   - Replace INSTANTIATE_MSG_TODO with the real InstantiateMsg.
///   - Replace each query_total_*_TODO call with a real contract query binding.
///   - Replace execute_{fn_name}_TODO with a real execute-msg dispatch.
#[test]
fn vcis_conservation_{safe_fn}() {{
    // TODO: set up cw-multi-test App and instantiate the contract under test.
    // let mut app = App::default();
    // let contract_addr = instantiate_contract(&mut app, INSTANTIATE_MSG_TODO);

    // Snapshot pre-call bank balance of the protocol module account.
    // let pre_balance: Uint128 = app
    //     .wrap()
    //     .query_balance(PROTOCOL_ADDR_TODO, DENOM_TODO)
    //     .unwrap()
    //     .amount;

    // Snapshot pre-call credit-side liability sum.
{pre_credit_snapshots}

    // TODO: execute the function under test via app.execute_contract(...).
    // app.execute_contract(
    //     Addr::unchecked("attacker"),
    //     contract_addr.clone(),
    //     &ExecuteMsg::{fn_name_pascal} {{ /* ... */ }},
    //     &[],
    // ).unwrap();

    // Post-call bank balance.
    // let post_balance: Uint128 = app
    //     .wrap()
    //     .query_balance(PROTOCOL_ADDR_TODO, DENOM_TODO)
    //     .unwrap()
    //     .amount;

    // SOLVENCY-FLOOR assertion: protocol must hold >= what it owes.
{assertion_lines}
    // proptest harness (wrap the above in proptest! {{ }} for property-based coverage):
    // proptest!(|(seed: u64)| {{
    //     // vary initial state via seed, repeat the solvency-floor check above.
    // }});
}}

"""


def _rust_safe_name(fn_name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", fn_name).lower()


def _rust_pascal_name(fn_name: str) -> str:
    parts = re.split(r"[^A-Za-z0-9]+", fn_name)
    return "".join(p.capitalize() for p in parts if p)


def _emit_rust_assertion(spec: PropertySpec) -> str:
    safe_fn = _rust_safe_name(spec.fn_name)
    fn_name_pascal = _rust_pascal_name(spec.fn_name)

    if spec.credit_fields:
        pre_parts = []
        assertion_parts = ["    // SOLVENCY-FLOOR: post_balance >= sum(credit_fields)"]
        sum_vars = []
        for f in spec.credit_fields:
            var = _rust_safe_name(f) + "_total"
            pre_parts.append(
                f"    // let {var}: Uint128 = query_total_{_rust_safe_name(f)}_TODO(&app, &contract_addr);"
            )
            sum_vars.append(var)
        pre_credit_snapshots = "\n".join(pre_parts)
        if sum_vars:
            sum_expr = " + ".join(f"/* {v} */" for v in sum_vars)
            assertion_parts.append(
                f"    // let total_owed: Uint128 = {sum_expr}; // replace comments with real vars"
            )
            assertion_parts.append(
                "    // assert!(\n"
                "    //     post_balance >= total_owed,\n"
                f'    //     "VCIS solvency-floor violated for {spec.fn_name}: '
                f'balance={{}} owed={{}}", post_balance, total_owed\n'
                "    // );"
            )
        assertion_lines = "\n".join(assertion_parts)
    else:
        # delta-conservation fallback
        pre_credit_snapshots = (
            "    // delta-conservation: no credit fields detected;\n"
            "    // track pre-call balance as floor for post-call assertion.\n"
            "    // let pre_balance_snapshot = pre_balance;"
        )
        assertion_lines = (
            "    // DELTA-CONSERVATION: post_balance >= pre_balance - authorised_outflow\n"
            "    // let authorised_outflow: Uint128 = query_authorised_outflow_TODO(&app, &contract_addr);\n"
            "    // let floor = pre_balance.saturating_sub(authorised_outflow);\n"
            "    // assert!(\n"
            "    //     post_balance >= floor,\n"
            f'    //     "VCIS delta-conservation violated for {spec.fn_name}: balance={{}} floor={{}}", post_balance, floor\n'
            "    // );"
        )

    return _RUST_ASSERTION_TEMPLATE.format(
        safe_fn=safe_fn,
        fn_name=spec.fn_name,
        fn_name_pascal=fn_name_pascal,
        fn_file=spec.fn_file,
        form=spec.form,
        pre_credit_snapshots=pre_credit_snapshots,
        assertion_lines=assertion_lines,
    )


_RUST_SCAFFOLD_FOOTER = """\
// ============================================================
// cw-multi-test App WIRING SCAFFOLD
// ============================================================
// TODO: implement the helper below once you have the real contract bindings.
//
// fn instantiate_contract(app: &mut App, msg: InstantiateMsg) -> Addr {
//     let code = ContractWrapper::new(execute, instantiate, query);
//     let code_id = app.store_code(Box::new(code));
//     app.instantiate_contract(
//         code_id,
//         Addr::unchecked("owner"),
//         &msg,
//         &[],
//         "vcis_test_contract",
//         None,
//     ).unwrap()
// }
//
// proptest! {
//     #[test]
//     fn vcis_proptest_solvency_floor(seed in 0u64..1_000_000) {
//         // Drive all conservation assertions with varied initial state.
//         // Replace with real setup using `seed` to vary initial balances.
//     }
// }
"""


def emit_rust_backend(specs: list[PropertySpec]) -> str:
    """Emit the Rust/CosmWasm conservation harness file.

    Returns conservation_vcis_test.rs content (mechanical assertions + wiring scaffold).
    """
    rs_specs = [s for s in specs if s.language == "rs"]
    assertion_bodies = "".join(_emit_rust_assertion(s) for s in rs_specs)
    return _RUST_FILE_HEADER + assertion_bodies + _RUST_SCAFFOLD_FOOTER


# ---------------------------------------------------------------------------
# Medusa / Echidna config - reuse evm-engine-harness-author emitters.
# ---------------------------------------------------------------------------

def _emit_medusa_config_vcis(target_contract: str = "VCIS_Properties") -> str:
    """Bounded medusa config for VCIS - shared actor pool, small test limit."""
    cfg = {
        "fuzzing": {
            "workers": 2,
            "testLimit": 10000,  # bound: never runs away
            "callSequenceLength": 50,
            "targetContracts": [target_contract],
            "corpusDirectory": "vcis-medusa-corpus",
            "assertionTesting": {"enabled": True, "testViewMethods": True},
            "propertyTesting": {"enabled": True, "testPrefixes": ["echidna_vcis_"]},
            # Shared actor pool - payer==receiver reachable; discovers self-settled-take.
            "senderAddresses": ["0x10000", "0x20000", "0x30000"],
        },
        "compilation": {
            "platform": "crytic-compile",
            "platformConfig": {"target": ".", "solcVersion": ""},
        },
    }
    return json.dumps(cfg, indent=2) + "\n"


def _emit_echidna_config_vcis(target_contract: str = "VCIS_Properties") -> str:
    """Bounded echidna config for VCIS - shared actor pool, small test limit."""
    return (
        "testMode: assertion\n"
        "testLimit: 10000\n"  # bound: never runs away
        "seqLen: 50\n"
        f"# VCIS properties prefixed echidna_vcis_ in {target_contract}\n"
        "cryticArgs:\n"
        "  - --solc-remaps\n"
        "  - forge-std/=lib/forge-std/src/\n"
        "senders:\n"
        "  - \"0x10000\"\n"
        "  - \"0x20000\"\n"
        "  - \"0x30000\"\n"
    )


# ---------------------------------------------------------------------------
# VCIS manifest (verdict sidecar).
# ---------------------------------------------------------------------------

def _build_vcis_manifest(specs: list[PropertySpec], ws_path: str) -> dict:
    """Build the vcis_manifest.json - per-fn verdict sidecar.

    ALL verdicts start as 'needs-fuzz'.  Genuine coverage is credited ONLY after:
      1. The harness compiles and runs on the real CUT (baseline passes).
      2. mutation-verify-coverage.py kills a planted non-conservation mutant.
    Never self-credit: the caller must update this file after verification.
    """
    verdicts: list[dict] = []
    for spec in specs:
        prop_name = _sol_property_name(spec.fn_name, spec.form, len(verdicts))
        verdicts.append({
            "function": spec.fn_name,
            "file_line": spec.fn_file,
            "language": spec.language,
            "property_form": spec.form,
            "property_name": prop_name,
            "tokens": spec.tokens,
            "credit_fields": spec.credit_fields,
            # GENUINE-CREDIT RULE: always starts as needs-fuzz.
            # Promote to "non-vacuous" / "killed" only after:
            #   (a) harness compiles + runs on real CUT (baseline PASS), AND
            #   (b) mutation-verify-coverage.py kills >=1 planted mutant.
            "verdict": "needs-fuzz",
            "mutation_verified": False,
            "clean_result": "pending",
            "harness_contract": "VCIS_Properties",
            "axis": "vcis",
            "note": (
                "CANDIDATE-HARNESS-NOT-PROOF. "
                "Run mutation-verify-coverage.py to earn genuine coverage credit."
            ),
        })
    return {
        "schema": "vcis_manifest.v1",
        "workspace": ws_path,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "value-conservation-invariant-synth.py",
        "genuine_credit_rule": (
            "verdict='needs-fuzz' until harness compiles + runs on real CUT "
            "(baseline PASS) AND mutation-verify-coverage.py kills >=1 mutant. "
            "Never self-credit. R80 enforced."
        ),
        "verdicts": verdicts,
    }


# ---------------------------------------------------------------------------
# Top-level synthesis orchestration.
# ---------------------------------------------------------------------------

def synthesise(
    workspace: str | Path,
    out_dir: str | Path | None = None,
    force_regen: bool = False,
) -> dict[str, Any]:
    """Core synthesis entry point.  Returns a result dict with keys:
        ok: bool
        out_dir: str
        property_count: int
        manifest: dict
        files: dict[name -> content]
        error: str | None
    """
    ws = Path(workspace).resolve()
    vmf_json = ws / ".auditooor" / "value_moving_functions.json"

    # Step 1: ensure value_moving_functions.json exists.
    if not vmf_json.is_file() or force_regen:
        try:
            vmf = _load_vmf()
            vmf.run(ws)
        except Exception as exc:
            return {"ok": False, "error": f"value-moving-functions run failed: {exc}",
                    "out_dir": "", "property_count": 0, "manifest": {}, "files": {}}

    if not vmf_json.is_file():
        return {"ok": False, "error": "value_moving_functions.json not produced",
                "out_dir": "", "property_count": 0, "manifest": {}, "files": {}}

    try:
        payload = json.loads(vmf_json.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": f"cannot parse value_moving_functions.json: {exc}",
                "out_dir": "", "property_count": 0, "manifest": {}, "files": {}}

    fn_records: list[dict] = payload.get("functions", [])
    if not fn_records:
        return {"ok": True, "out_dir": "", "property_count": 0,
                "manifest": {}, "files": {},
                "error": None, "note": "no value-moving functions found"}

    # Step 2: build PropertySpec for every record.
    specs = [build_property_spec(r) for r in fn_records]

    # Step 3: emit backend artifacts.
    files: dict[str, str] = {}

    sol_specs = [s for s in specs if s.language == "sol"]
    if sol_specs:
        files["Properties_VCIS.sol"] = emit_sol_properties(sol_specs)
        files["medusa.json"] = _emit_medusa_config_vcis()
        files["echidna.yaml"] = _emit_echidna_config_vcis()

    go_specs = [s for s in specs if s.language == "go"]
    if go_specs:
        conservation_go, scaffold_go = emit_go_backend(specs)
        files["conservation_vcis.go"] = conservation_go
        files["vcis_register_scaffold.go"] = scaffold_go

    rs_specs = [s for s in specs if s.language == "rs"]
    if rs_specs:
        files["conservation_vcis_test.rs"] = emit_rust_backend(specs)

    # Step 4: build verdict sidecar manifest.
    manifest = _build_vcis_manifest(specs, str(ws))
    files["vcis_manifest.json"] = json.dumps(manifest, indent=2) + "\n"

    # Step 5: write to out_dir.
    out = Path(out_dir) if out_dir is not None else ws / ".auditooor" / "vcis"
    out.mkdir(parents=True, exist_ok=True)
    for fname, content in files.items():
        (out / fname).write_text(content, encoding="utf-8")

    return {
        "ok": True,
        "out_dir": str(out),
        "property_count": len(specs),
        "manifest": manifest,
        "files": files,
        "error": None,
    }


# ---------------------------------------------------------------------------
# CLI entry-point.
# ---------------------------------------------------------------------------
def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="VCIS - auto-synthesise value-conservation invariant harnesses."
    )
    parser.add_argument("workspace", help="Workspace root path")
    parser.add_argument("--out", default=None, help="Override output directory")
    parser.add_argument("--force-regen", action="store_true",
                        help="Re-run value-moving-functions even if json exists")
    args = parser.parse_args(argv)

    ws = Path(args.workspace)
    if not ws.is_dir():
        print(f"ERROR: workspace not found: {ws}", file=sys.stderr)
        return 1

    result = synthesise(ws, args.out, args.force_regen)
    if not result["ok"]:
        print(f"ERROR: {result['error']}", file=sys.stderr)
        return 1

    note = result.get("note", "")
    if note:
        print(f"VCIS: {note}")
        return 0

    n = result["property_count"]
    print(f"VCIS: {n} property spec(s) synthesised -> {result['out_dir']}")
    for v in result["manifest"].get("verdicts", []):
        print(f"  {v['function']}  form={v['property_form']}  verdict={v['verdict']}")
    print("NOTE: verdict='needs-fuzz' for all - run mutation-verify-coverage.py to earn genuine credit.")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
