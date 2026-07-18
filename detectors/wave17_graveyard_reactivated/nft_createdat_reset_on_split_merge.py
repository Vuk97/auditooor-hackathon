"""
nft_createdat_reset_on_split_merge.py - Custom Slither detector.

Pattern (SHIB SOU v2 / slice_ab): An NFT split or merge function creates a new
token by copying parent metadata into a struct but RESETS the time-based field
(createdAt, mintedAt, lockStart, cliff) to `block.timestamp` instead of copying
the parent's value. Any vesting schedule, time-lock, or cliff that was accrued
over the original token's lifetime is destroyed by splitting - a user can reset
their lock simply by splitting and merging.

Source: slice_ab SHIB SOU v2 NFT split/merge createdAt reset.

Dedup check: no Slither builtin covers struct timestamp propagation in NFT split.
    slither --list-detectors | grep -iE 'nft|split|merge|createdat|lockstart' → 0 match.

Detection strategy:
    1. Find functions named split / merge / combine / _split / _merge (name
       prefix/exact, case-insensitive).
    2. In these functions, find struct-field assignments (Member IR lvalue) to a
       field whose name (lowercased) contains a time-lock hint:
       "createdat", "mintedat", "lockstart", "cliff", "starttime", "lockedat".
    3. Check the RHS (the value assigned to the field): if the IR reads
       `block.timestamp` (SolidityVariableComposed("block.timestamp")), flag.
       If the RHS uses another variable (copied from parent struct), it is safe.

IR shape (from partial_struct_write.py and skip_log.md analysis):
    `vestings[newId].createdAt = block.timestamp` compiles to:
        Index:    REF_0 -> vestings[newId]
        Member:   REF_1(uint256) -> REF_0.createdAt   (field "createdAt")
        Assignment: REF_1 := SolidityVariableComposed("block.timestamp")

    `vestings[newId].createdAt = parent.createdAt` compiles to something like:
        Index:    REF_0 -> vestings[newId]
        Member:   REF_1(uint256) -> REF_0.createdAt
        Member:   TMP_parent_createdAt -> parent.createdAt
        Assignment: REF_1 := TMP_parent_createdAt
      → block.timestamp NOT in reads of the assignment node → safe.

We check: for the Assignment IR that writes to the time-lock field reference,
does the node containing that Assignment also read block.timestamp?

API notes:
    - Member IR: ir.variable_right.value gives the field name string.
    - Assignment IR: ir.lvalue is the ReferenceVariable set by the Member IR.
    - node.solidity_variables_read gives SolidityVariableComposed objects read
      in the node - use to check for "block.timestamp".
    - SolidityVariableComposed name for block.timestamp is "block.timestamp".

Approximation:
    - We match function names by startswith on lowercased name.
    - We check for "block.timestamp" in the SAME NODE as the assignment -
      it's possible the timestamp was assigned to a local var earlier in the
      function and then copied. That would be a false negative (acceptable at
      LOW confidence).
    - Confidence: LOW - function may legitimately reset timestamp on split for
      non-vesting purposes. Manual review required.

@author auditooor wave7
@pattern slice_ab SHIB SOU v2 NFT split createdAt reset
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
from slither.slithir.operations import Member, Assignment
from slither.slithir.variables import ReferenceVariable
from slither.core.declarations import SolidityVariableComposed
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

# Function name prefixes/exact matches indicating a split/merge operation.
_SPLIT_MERGE_PREFIXES = (
    "split",
    "_split",
    "merge",
    "_merge",
    "combine",
    "_combine",
    "fork",
    "_fork",
)

# Field name substrings (lowercased) indicating a time-lock / vesting timestamp.
_TIME_FIELD_HINTS = (
    "createdat",
    "mintedat",
    "lockstart",
    "cliff",
    "starttime",
    "lockedat",
    "veststart",
    "locktime",
    "startdate",
    "createdtime",
)

_BLOCK_TIMESTAMP = "block.timestamp"


def _is_split_merge_function(function) -> bool:
    """Return True if the function name matches a split/merge operation."""
    lower = function.name.lower()
    return any(lower.startswith(pfx) for pfx in _SPLIT_MERGE_PREFIXES)


def _node_reads_block_timestamp(node) -> bool:
    """Return True if any IR in this node reads block.timestamp."""
    for v in node.solidity_variables_read:
        if getattr(v, 'name', '') == _BLOCK_TIMESTAMP:
            return True
    return False


def _find_timestamp_reset_assignments(function):
    """
    Walk function nodes looking for Assignment to a time-lock struct field
    where the node also reads block.timestamp.

    Returns list of (node, field_name) for each flagged assignment.
    """
    hits = []

    for node in function.nodes:
        # Quick pre-filter: node must read block.timestamp
        if not _node_reads_block_timestamp(node):
            continue

        # Build map: id(ref_var) → field_name for Member IRs in this node
        # that target a time-lock field.
        ref_to_field: dict[int, str] = {}
        for ir in node.irs:
            if not isinstance(ir, Member):
                continue
            lv = ir.lvalue
            if not isinstance(lv, ReferenceVariable):
                continue
            field_name = getattr(ir.variable_right, 'value', None) or ''
            if not any(h in field_name.lower() for h in _TIME_FIELD_HINTS):
                continue
            ref_to_field[id(lv)] = field_name

        if not ref_to_field:
            continue

        # Now look for Assignment IRs writing to one of those ref vars.
        for ir in node.irs:
            if not isinstance(ir, Assignment):
                continue
            lv = ir.lvalue
            if not isinstance(lv, ReferenceVariable):
                continue
            field_name = ref_to_field.get(id(lv))
            if field_name is not None:
                hits.append((node, field_name))

    return hits


class NFTCreatedAtResetOnSplitMerge(AbstractDetector):
    """
    Detect NFT split/merge functions that reset createdAt/lockStart/cliff
    to block.timestamp instead of copying the parent value.
    """

    ARGUMENT = "nft-metadata-reset-on-split-merge"
    HELP = (
        "NFT split/merge function resets createdAt/lockStart/cliff to "
        "block.timestamp - time-based vesting lock bypassed by splitting"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "NFT CreatedAt Reset on Split/Merge - Vesting Lock Bypass"
    WIKI_DESCRIPTION = (
        "NFT split and merge functions create new tokens by copying metadata from "
        "a parent token. If the new token's time-based field (createdAt, mintedAt, "
        "lockStart, cliff) is set to `block.timestamp` instead of being inherited "
        "from the parent, any vesting period or time-lock the parent had accrued "
        "is destroyed. A user with a 1-year-old locked NFT can split it, receive "
        "a new NFT with a freshly reset lock date, and immediately redeem or sell "
        "it as if the lock just started. Observed in SHIB SOU v2 (slice_ab)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
struct VestingInfo {
    uint256 amount;
    uint256 createdAt;   // lock start time
    uint256 cliff;       // unlock time = createdAt + 365 days
    address owner;
}
mapping(uint256 => VestingInfo) public vestings;

function split(uint256 tokenId, uint256 splitAmount) external {
    VestingInfo storage v = vestings[tokenId];
    v.amount -= splitAmount;
    uint256 newId = _nextId++;
    vestings[newId] = VestingInfo({
        amount: splitAmount,
        createdAt: block.timestamp,   // BUG: resets lock - should be v.createdAt
        cliff: block.timestamp + 365 days,
        owner: msg.sender
    });
}
```
1. Alice holds a 1-year-old NFT with cliff = originalCreatedAt + 365 days.
2. The cliff is 11 months in the future from now.
3. Alice calls split(tokenId, totalAmount). New NFT gets cliff = now + 365 days.
4. The split NFT has a full fresh 365-day cliff - Alice's 1 year of accrued
   vesting is wiped. She can keep splitting to perpetually delay her unlock."""
    WIKI_RECOMMENDATION = (
        "Inherit time-based fields from the parent token when splitting: "
        "`createdAt: parent.createdAt` and `cliff: parent.cliff`. "
        "Never reset vesting / lock timestamps to `block.timestamp` in split "
        "or merge operations unless the protocol explicitly intends to restart "
        "the vesting schedule (document this clearly in NatSpec)."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not _is_split_merge_function(function):
                    continue
                if function.view or function.pure:
                    continue

                hits = _find_timestamp_reset_assignments(function)
                if not hits:
                    continue

                for node, field_name in hits:
                    info: DETECTOR_INFO = [
                        function,
                        " (split/merge) resets time-lock field `",
                        field_name,
                        "` to `block.timestamp` at ",
                        node,
                        ". Vesting / lock period of the parent token is lost - "
                        "copy the parent's `",
                        field_name,
                        "` value instead.\n",
                    ]
                    results.append(self.generate_result(info))

        return results
