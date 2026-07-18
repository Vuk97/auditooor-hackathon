"""
async_vault_redemption_no_ttl.py - Custom Slither detector.

Pattern (Sukuk M-02, slice_ad):
    An ERC-7540 / ERC-7575 async vault stores a `pricePerShare` snapshot
    inside `fulfillRedeem(user, assets)` (or similar) but the subsequent
    `redeem(...)` call does NOT enforce a TTL on the snapshot - there is
    no `require(block.timestamp - snapshot.timestamp <= TTL)`. A stale
    snapshot can therefore be redeemed against updated vault state.

Detection strategy:
    1. The contract must declare BOTH a function named `fulfillRedeem`
       (any signature) AND a function named `redeem`.
    2. The redeem function must read a state variable that is a mapping
       whose value-type is a struct containing a field whose name matches
       the snapshot hints ("pricepershare", "pps", "sharestoassets",
       "rate", "exchangerate").
    3. The redeem function must NOT read `block.timestamp` (i.e. no TTL
       check anywhere in the body - analogous to oracle_staleness_guard).
    4. Flag the redeem function.

@author auditooor wave9
@pattern slice_ad / Sukuk M-02
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
from slither.core.variables.state_variable import StateVariable
from slither.core.solidity_types import MappingType, UserDefinedType
from slither.core.declarations import Structure
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_SNAPSHOT_FIELD_HINTS = (
    "pricepershare",
    "pps",
    "sharestoassets",
    "exchangerate",
    "rate",
    "snapshotrate",
)

_TIMESTAMP_NAMES = frozenset({"block.timestamp", "now"})


def _struct_has_snapshot_field(struct: Structure) -> bool:
    for field in struct.elems.values():
        nm = (getattr(field, "name", "") or "").lower()
        if any(h in nm for h in _SNAPSHOT_FIELD_HINTS):
            return True
    return False


def _is_mapping_to_snapshot_struct(sv) -> bool:
    """Return True if state var is mapping(.. => SomeStruct) where SomeStruct
    has a snapshot-like field name."""
    t = getattr(sv, "type", None)
    seen = 0
    while isinstance(t, MappingType) and seen < 4:
        t = t.type_to
        seen += 1
        if isinstance(t, UserDefinedType):
            inner = getattr(t, "type", None)
            if isinstance(inner, Structure):
                return _struct_has_snapshot_field(inner)
    return False


def _function_reads_timestamp(function) -> bool:
    for node in function.nodes:
        for sv in node.solidity_variables_read:
            if sv.name in _TIMESTAMP_NAMES:
                return True
    return False


class AsyncVaultRedemptionNoTtl(AbstractDetector):
    """Detect async-vault redeem() that consumes a stale price-per-share snapshot."""

    ARGUMENT = "async-vault-redemption-no-ttl"
    HELP = (
        "ERC-7540 redeem() consumes a fulfillRedeem snapshot without checking "
        "block.timestamp - snapshot.timestamp <= TTL - stale rate exploit"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Async Vault Redemption Snapshot Has No TTL"
    WIKI_DESCRIPTION = (
        "ERC-7540 / ERC-7575 async vaults split redemption into two phases: an "
        "operator first calls `fulfillRedeem(user, assets)` which records a "
        "`pricePerShare` (or equivalent rate) snapshot for the user, and the "
        "user later calls `redeem(...)` to actually withdraw against that "
        "snapshot. If the redeem step does not enforce a TTL "
        "(`require(block.timestamp - snapshot.timestamp <= MAX_AGE)`), an "
        "attacker can wait for the vault price to move favourably and then "
        "redeem against the stale (now under-priced) snapshot, extracting "
        "value from honest depositors. Reported in Sukuk M-02 (slice_ad)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
struct PendingRedeem { uint256 shares; uint256 pricePerShare; }
mapping(address => PendingRedeem) public pending;

function fulfillRedeem(address u, uint256 s) external onlyOperator {
    pending[u] = PendingRedeem(s, currentPPS());     // snapshot rate
}
function redeem(address u) external {
    uint256 assets = pending[u].shares * pending[u].pricePerShare / 1e18;
    // no TTL check - snapshot can be hours old
    delete pending[u];
    // transfer assets...
}
```
1. Operator fulfills Alice's redeem at PPS = 1.10.
2. Vault loses value to ~0.95.
3. Alice still redeems at the stale 1.10 snapshot, extracting value from
   the remaining LPs."""
    WIKI_RECOMMENDATION = (
        "Add a `timestamp` field to the snapshot struct, set it to "
        "`block.timestamp` in fulfillRedeem, and require "
        "`block.timestamp - snapshot.timestamp <= MAX_TTL` inside redeem(). "
        "Pick MAX_TTL based on expected vault volatility (e.g. one block, "
        "one hour)."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            # Step 1: contract must have BOTH fulfillRedeem and redeem functions
            fn_names = {(f.name or "") for f in contract.functions_declared}
            if "fulfillRedeem" not in fn_names:
                continue
            if "redeem" not in fn_names:
                continue

            # Snapshot mappings on this contract
            snapshot_svs = [
                sv for sv in contract.state_variables
                if isinstance(sv, StateVariable) and _is_mapping_to_snapshot_struct(sv)
            ]
            if not snapshot_svs:
                continue

            for function in contract.functions_declared:
                if (function.name or "") != "redeem":
                    continue
                if function.is_constructor:
                    continue

                # Must read the snapshot mapping
                reads_snapshot = any(
                    sv in snapshot_svs for sv in function.state_variables_read
                )
                if not reads_snapshot:
                    continue

                # Must NOT read block.timestamp
                if _function_reads_timestamp(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " consumes async-redeem snapshot ",
                    snapshot_svs[0],
                    " without checking block.timestamp - snapshot.timestamp "
                    "<= MAX_TTL. Stale pricePerShare can be redeemed against "
                    "updated vault state.\n",
                ]
                results.append(self.generate_result(info))

        return results
