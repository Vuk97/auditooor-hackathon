"""
eip1271_wallet_not_bound.py - Custom Slither detector.

Pattern (Bebop - EIP-1271 wallet address not bound to hash):
    A function calls `walletAddress.isValidSignature(hash, sig)` (EIP-1271)
    but the hash passed to isValidSignature was constructed WITHOUT including
    the `maker`/`owner`/`signer` field of the order struct in the abi.encode()
    call. The hash does not commit to a specific wallet address, so an attacker
    can substitute a different wallet address as `maker` and reuse the same
    pre-computed signature.

Detection strategy:
    1. Find functions that make a HighLevelCall to `isValidSignature`.
    2. In the same function, find the abi.encode() SolidityCall whose output
       feeds (directly or through keccak256) into the first argument of
       isValidSignature.
    3. Build a map of {id(ReferenceVariable.lvalue): member_field_name} from
       all Member IRs in the function (struct field accesses).
    4. Check whether any abi.encode argument ID appears in the Member map
       with a field name that contains "maker", "owner", "signer", or "from".
    5. If isValidSignature is called AND maker/owner/signer is NOT in the
       abi.encode args → flag.

Dedup check:
    slither --list-detectors | grep -i 1271    → nothing
    slither --list-detectors | grep -i wallet  → nothing matching
    slither --list-detectors | grep -i eip712  → eip712-domain-missing-chainid
        (wave4 custom) checks DOMAIN_SEPARATOR construction, not order hash
        binding. DIFFERENT surface. NOVEL.

Impact: HIGH - attacker can steal orders/swap maker with any wallet.
Confidence: LOW - struct field naming is heuristic; many abi.encode usages
                   are legitimate even without a maker field.

Source: reference/corpus_mined/slice_ac.md - Bebop order filling.
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
from slither.slithir.operations import HighLevelCall, SolidityCall, Member
from slither.slithir.variables import ReferenceVariable
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

# EIP-1271 signature validation function signature
_EIP1271_SIG = "isValidSignature(bytes32,bytes)"

# Struct field names that represent the wallet/signer that should be bound
_MAKER_FIELD_KEYWORDS = ("maker", "owner", "signer", "from", "sender", "account")


def _function_has_body(function) -> bool:
    return any(node.irs for node in function.nodes)


def _find_is_valid_signature_node(function):
    """
    Return the (node, ir) pair for the first HighLevelCall to isValidSignature
    in the function, or None.
    """
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, HighLevelCall):
                continue
            fn_sig = getattr(ir, "function_name", None) or ""
            if fn_sig == "isValidSignature":
                return (node, ir)
    return None


def _get_encode_maker_fields(function) -> set:
    """
    For each abi.encode() SolidityCall in the function, collect the set of
    struct field names (from Member IR variable_right) that appear in the
    encode args. Returns a set of lowercased field names included in any
    abi.encode call.

    Uses id()-based tracking: Member IR lvalue id → field name, then check
    if abi.encode argument ids match.
    """
    # Build Member lvalue-id → field name map for the entire function
    ref_id_to_field = {}
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, Member):
                field_name = str(ir.variable_right).lower()
                ref_id_to_field[id(ir.lvalue)] = field_name

    # Find all abi.encode calls and collect their argument field names
    encode_fields = set()
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, SolidityCall):
                continue
            fn_name = getattr(ir.function, "name", "") or ""
            if "encode" not in fn_name:
                continue
            for arg in ir.arguments:
                field_name = ref_id_to_field.get(id(arg))
                if field_name:
                    encode_fields.add(field_name)

    return encode_fields


class Eip1271WalletNotBound(AbstractDetector):
    """
    Detect EIP-1271 isValidSignature calls where the hash does not bind the
    maker/owner/signer wallet address.
    """

    ARGUMENT = "eip1271-wallet-not-bound"
    HELP = (
        "EIP-1271 isValidSignature call whose hash abi.encode() args do not "
        "include the maker/owner/signer field - wallet address not bound"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "EIP-1271 Wallet Not Bound - Maker Address Missing from Order Hash"
    WIKI_DESCRIPTION = (
        "EIP-1271 signature validation calls `walletAddress.isValidSignature(hash, sig)` "
        "where `walletAddress` is supplied by the caller as the maker/signer of an order. "
        "If the hash passed to isValidSignature is computed without including the "
        "maker address in the abi.encode() input, the hash is identical regardless "
        "of which wallet is specified as maker. An attacker can reuse a legitimate "
        "signature from wallet A to fill an order that names their own wallet B as "
        "maker - the hash matches because neither wallet is bound in the hash. "
        "The signature validates (wallet A's isValidSignature returns the magic value) "
        "while the order executes as if wallet B was the signer. "
        "Observed in the Bebop RFQ order-filling system audit."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
struct Order { address maker; address token; uint256 amount; uint256 price; }

function fillOrder(Order calldata order, bytes calldata sig) external {
    // BUG: hash encodes token/amount/price but NOT order.maker
    bytes32 hash = keccak256(abi.encode(order.token, order.amount, order.price));
    bytes4 res = IERC1271(order.maker).isValidSignature(hash, sig);
    require(res == 0x1626ba7e);
    // ... execute order with order.maker as the signer
}
```
1. Legitimate user (wallet A) signs hash = keccak256(abi.encode(tokenX, 100, 50)).
2. Attacker constructs Order{maker: walletB, token: tokenX, amount: 100, price: 50}.
3. Attacker calls fillOrder with wallet A's signature.
4. hash is identical (maker not in encode) → wallet A's isValidSignature returns magic.
5. Order executes as if wallet B signed - attacker impersonates any maker."""
    WIKI_RECOMMENDATION = (
        "Always include the maker/signer address in the hash: "
        "`keccak256(abi.encode(order.maker, order.token, order.amount, order.price))`. "
        "Better: use full EIP-712 typed-data hashing (DOMAIN_SEPARATOR + struct hash) "
        "where the struct type includes every field including the signer address. "
        "Reference: OpenZeppelin EIP712.sol `_hashTypedDataV4`."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not _function_has_body(function):
                    continue

                # Step 1: must call isValidSignature
                sig_pair = _find_is_valid_signature_node(function)
                if sig_pair is None:
                    continue

                # Step 2: get all struct field names that appear in any abi.encode
                encode_fields = _get_encode_maker_fields(function)

                # If no abi.encode call was found at all, skip (can't determine hash construction)
                if not encode_fields and not _has_any_encode_call(function):
                    continue

                # Step 3: check if any maker-like field is in the encode args
                has_maker_bound = any(
                    any(kw in field for kw in _MAKER_FIELD_KEYWORDS)
                    for field in encode_fields
                )

                if has_maker_bound:
                    continue

                # Flag: isValidSignature called but maker not in abi.encode args
                sig_node, _ = sig_pair
                info: DETECTOR_INFO = [
                    function,
                    " in ",
                    contract,
                    " calls isValidSignature() but the hash passed to it is "
                    "built from abi.encode() that does NOT include a "
                    "maker/owner/signer struct field. The wallet address is "
                    "not bound to the hash - attacker can substitute any wallet "
                    "as the signer and reuse a legitimate signature.\n",
                ]
                results.append(self.generate_result(info))

        return results


def _has_any_encode_call(function) -> bool:
    """Return True if the function contains any abi.encode* SolidityCall."""
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, SolidityCall):
                fn_name = getattr(ir.function, "name", "") or ""
                if "encode" in fn_name:
                    return True
    return False
