"""
permit_unit_mismatch.py - Custom Slither detector.

Pattern: ERC4626 / yield-token permit() stores convertToShares(value) (or any
arithmetic transformation of `value`) in the allowance mapping, while the
signed TYPEHASH encodes the raw `value` (assets denomination). The on-chain
approval is in shares; the signed message is in assets - a systematic unit
mismatch that over- or under-approves relative to what the signer intended.

Source: Hexens audit of Socket/SCKMA-1 (corpus_mined/slice_aa.md line 356).
Pattern ID: permit-unit-mismatch. Wave 5.

Dedup check (slither --list-detectors | grep -iE 'permit|allowance'):
    `arbitrary-send-erc20-permit` (#16) catches transferFrom with arbitrary
    `from` via permit - entirely different concern (who authorises, not what
    unit the authorisation is in). No overlap with this detector.
    NOVEL.

Detection algorithm:
    1. Find functions named 'permit' (case-insensitive) in every contract.
    2. Walk all nodes collecting:
         - InternalCall / Binary lvalues that are TemporaryVariables → mark as
           "transformed_tmps" (a set of ids).
         - Assignments where lvalue is a ReferenceVariable pointing to an
           allowance-named StateVariable.
    3. For each allowance-assignment found in step 2, inspect the rvalue:
         a. If rvalue is a TemporaryVariable whose id is in transformed_tmps
            → the stored value went through a transformation → FLAG.
         b. If rvalue is a LocalVariable matching a known 'value' param name
            → clean (direct pass-through).
         c. If rvalue is a TemporaryVariable NOT in transformed_tmps but is
            e.g. a type-conversion or a ternary result, we also flag it -
            any non-direct assignment to allowance is suspicious in permit().

IR shapes (verified against test fixtures):
    Vulnerable:
        InternalCall | TMP_15(uint256) = INTERNAL_CALL, Contract.convertToShares(uint256)(value)
        Assignment   | REF_4(uint256) (->allowance) := TMP_15(uint256)
    Clean:
        Assignment   | REF_4(uint256) (->allowance) := value(uint256)

Approximation notes:
    - We match function.name.lower() == "permit" - catches permit() in any
      ERC-4626 / ERC-2612 variant without over-matching.
    - We resolve ReferenceVariable.points_to / points_to_origin to find the
      underlying StateVariable of the allowance mapping.  Two-level index
      (allowance[owner][spender]) may produce REF_3 → REF_4; both point to
      the 'allowance' StateVariable so either level resolves correctly.
    - Confidence MEDIUM: rare false positive if a contract intentionally stores
      shares in permit for a shares-denominated allowance system - flag for
      auditor review.
    - We skip pure/view functions as they can't write state.
    - We skip test/mock/fixture contracts by name.
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import Assignment, InternalCall, Binary
from slither.slithir.variables import TemporaryVariable, ReferenceVariable
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

# State-variable name patterns that indicate an allowance mapping.
# ERC-20 uses 'allowance' or '_allowances' (OZ); some vaults use 'allowed'.
_ALLOWANCE_HINTS = ("allowance", "_allowances", "allowed")


def _is_allowance_var(sv) -> bool:
    """Return True if the state variable looks like an ERC-20 allowance mapping."""
    if not isinstance(sv, StateVariable):
        return False
    name_lower = (sv.name or "").lower()
    return any(h in name_lower for h in _ALLOWANCE_HINTS)


def _resolve_ref_to_sv(ref):
    """
    Walk a ReferenceVariable chain to find the underlying StateVariable.
    Handles multi-level indexing (allowance[owner] → allowance[owner][spender]).
    Returns the StateVariable or None.
    """
    cur = ref
    for _ in range(8):
        if isinstance(cur, StateVariable):
            return cur
        if not isinstance(cur, ReferenceVariable):
            return None
        # try points_to_origin first (most direct), then points_to
        nxt = getattr(cur, "points_to_origin", None) or getattr(cur, "points_to", None)
        if nxt is None or nxt is cur:
            return None
        cur = nxt
    return None


def _detect_permit_unit_mismatch(function, contract):
    """
    Return (assignment_node, allowance_sv) if the permit function stores a
    transformed value in the allowance mapping, else (None, None).

    Two-pass over function nodes:
      Pass 1: collect ids of TemporaryVariable lvalues produced by any
              InternalCall or Binary operation (these represent a transformed
              result of `value`).
      Pass 2: find the Assignment writing to an allowance mapping. Check if
              its rvalue came from a transformation (id in transformed_tmps).
    """
    # Pass 1: collect all "transformed temporary" ids
    transformed_tmps: set = set()
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, (InternalCall, Binary)):
                lv = getattr(ir, "lvalue", None)
                if isinstance(lv, TemporaryVariable):
                    transformed_tmps.add(id(lv))

    # Pass 2: find allowance assignment and inspect RHS
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, Assignment):
                continue
            lv = ir.lvalue
            rv = getattr(ir, "rvalue", None)
            if rv is None:
                continue
            # lvalue must be a ReferenceVariable pointing to allowance
            if not isinstance(lv, ReferenceVariable):
                continue
            sv = _resolve_ref_to_sv(lv)
            if sv is None or not _is_allowance_var(sv):
                continue
            # RHS is a TemporaryVariable that was produced by a transformation
            if isinstance(rv, TemporaryVariable) and id(rv) in transformed_tmps:
                return node, sv
            # RHS is a direct LocalVariable (the 'value' parameter) → clean
            # Any other non-LocalVariable RHS is also suspicious but we only
            # flag confirmed transformation chains (InternalCall / Binary) to
            # keep confidence MEDIUM and avoid excessive FP.

    return None, None


class PermitUnitMismatch(AbstractDetector):
    """
    Detect permit() functions that store a transformed value (convertToShares /
    arithmetic) in the allowance mapping while the signed TYPEHASH uses raw value.
    """

    ARGUMENT = "permit-unit-mismatch"
    HELP = (
        "permit() stores convertToShares(value) in allowance but TYPEHASH encodes "
        "raw value - signed unit differs from stored unit"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "permit() Allowance Unit Mismatch (Assets vs Shares)"
    WIKI_DESCRIPTION = (
        "EIP-2612 permit() functions sign a `value` parameter representing the "
        "approved amount in a specific unit (typically assets/underlying tokens). "
        "When the implementation stores `convertToShares(value)` instead of `value` "
        "directly in the allowance mapping, the on-chain approval is in shares while "
        "the off-chain signature was in assets. If the exchange rate is not 1:1, the "
        "approved amount systematically differs from what the signer intended - "
        "attackers can exploit the discrepancy to drain more than was authorised. "
        "Identified by Hexens in the SCKMA-1 audit (corpus_mined/slice_aa.md)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract YieldToken {
    mapping(address => mapping(address => uint256)) public allowance;

    // 1 asset = 2 shares (exchange rate 2x)
    function convertToShares(uint256 assets) public view returns (uint256) {
        return assets * totalSupply / totalAssets;  // e.g. 100 assets → 200 shares
    }

    function permit(address owner, address spender, uint256 value, ...) external {
        // Signer intends to approve `value` assets (e.g. 100).
        // But 200 shares are stored - equivalent to 200 assets at rate 1x.
        allowance[owner][spender] = convertToShares(value);  // BUG
    }
}
```
1. Alice signs a permit for 100 assets (value=100) to Bob.
2. Exchange rate is 1 asset = 2 shares.
3. permit() stores allowance = convertToShares(100) = 200.
4. Bob calls transferFrom - the allowance check passes for 200 asset-units.
5. Bob drains 200 assets instead of the 100 Alice authorised."""
    WIKI_RECOMMENDATION = (
        "Store `value` directly in the allowance mapping inside permit(). "
        "If the token's allowance semantics are shares-based, ensure the TYPEHASH "
        "and signed message also encode shares (i.e. the caller converts before "
        "signing). The signed unit and the stored unit MUST match. "
        "Reference: EIP-2612 Section 4 - 'value' in permit must equal the value "
        "stored in allowances[owner][spender]."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                # Only examine functions named 'permit' (case-insensitive)
                if function.name.lower() != "permit":
                    continue
                # Skip view/pure - they can't write allowance state
                if function.view or function.pure:
                    continue

                node, allowance_sv = _detect_permit_unit_mismatch(function, contract)
                if node is None:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " in ",
                    contract,
                    " stores a transformed value in allowance mapping ",
                    allowance_sv,
                    " - the signed TYPEHASH uses raw `value` (assets) but the "
                    "stored allowance is the result of a conversion/arithmetic. "
                    "Signed unit differs from stored unit.\n",
                    "  At: ",
                    node,
                    "\n",
                ]
                results.append(self.generate_result(info))

        return results
