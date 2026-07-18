"""
setter_forgets_companion_count.py - Custom Slither detector.

Pattern (Chakra M-05 validator-threshold-not-updated - slice_aa body finding):
    A contract stores a collection (array / mapping) and a companion "count"
    or "threshold" state variable that must stay in sync. A setter function
    rewrites the collection (e.g. `setValidators(address[] memory)`) but
    forgets to update the companion counter / threshold - downstream logic
    that compares against the stale counter then under- or over-authorizes.

Detection strategy:
    1. For each non-vendored contract, identify pairs of state variables:
         COLL   - array-typed or mapping-typed, name contains one of
                  (validators, members, signers, keys, whitelist, operators,
                  nodes, participants, committee).
         COUNT  - uint-typed state var, same name root plus a counter
                  suffix (count, length, total, size, num, threshold,
                  quorum, minSigs).
    2. Walk declared functions: find any that WRITES the COLL state var
       (element-wise push/assignment or wholesale replacement).
    3. For each such function, check whether it ALSO writes the COUNT
       state var. If it doesn't → flag.

Confidence: MEDIUM. We require both variables to exist and the function
to not-write the count. This produces one flag per (function, pair).

@author auditooor wave11
@pattern slice_aa body finding / Chakra M-05 validator-threshold-not-updated
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
from slither.core.solidity_types.array_type import ArrayType
from slither.core.solidity_types.mapping_type import MappingType
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_COLLECTION_HINTS = (
    "validator", "member", "signer", "operator", "node", "participant",
    "committee", "keys", "whitelist", "allowlist", "quorum",
)

_COUNT_SUFFIXES = (
    "count", "length", "total", "size", "num", "numof",
    "threshold", "quorum", "minsigs", "minsignatures", "required",
)


def _is_collection_sv(sv) -> bool:
    if not isinstance(sv, StateVariable):
        return False
    t = sv.type
    if not isinstance(t, (ArrayType, MappingType)):
        return False
    nm = (sv.name or "").lower()
    return any(h in nm for h in _COLLECTION_HINTS)


def _is_count_sv(sv) -> bool:
    if not isinstance(sv, StateVariable):
        return False
    t = sv.type
    if not isinstance(t, ElementaryType):
        return False
    if not t.name.startswith("uint"):
        return False
    nm = (sv.name or "").lower()
    return any(s in nm for s in _COUNT_SUFFIXES)


def _pair_root_overlap(coll_name: str, count_name: str) -> bool:
    """
    Heuristic: the two variables share a lexical root token. Example:
        validators / validatorCount       → root "validator" matches
        signers / threshold               → no match
    Also allow standalone "threshold"/"quorum" regardless of name root
    because they're commonly unnamed after the collection.
    """
    cn = coll_name.lower()
    kn = count_name.lower()
    for hint in _COLLECTION_HINTS:
        if hint in cn and hint in kn:
            return True
    # Allow generic "threshold"/"quorum" etc. - these are often global.
    for suf in ("threshold", "quorum", "minsigs", "minsignatures", "required"):
        if suf in kn:
            return True
    return False


class SetterForgetsCompanionCount(AbstractDetector):
    """Detect collection setters that forget to update a paired count/threshold."""

    ARGUMENT = "setter-forgets-companion-count"
    HELP = (
        "Function writes a validator/member/signer collection but fails to "
        "update the paired count/threshold - stale counter authorizes wrong set"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Collection Setter Forgets Companion Count"
    WIKI_DESCRIPTION = (
        "A contract keeps a collection (validators, signers, members) and a "
        "paired count or threshold state variable used to gate authorization. "
        "A setter that rewrites the collection must also rewrite the paired "
        "counter; when it doesn't, downstream checks compare against the "
        "stale value and either under-authorize (bricked) or over-authorize "
        "(security bypass). Reported in Chakra (M-05 validator-threshold-not-updated)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
address[] public validators;
uint256 public threshold;

function setValidators(address[] memory newSet) external onlyOwner {
    validators = newSet;
    // BUG: threshold is NOT updated. If newSet shrinks below the old
    // threshold, quorum is unreachable; if it grows, the old threshold
    // is still enforced and attackers can pass with < majority.
}
```
1. Initial: 5 validators, threshold = 3.
2. Owner replaces with 10 validators, forgets to bump threshold.
3. Quorum is still 3 of 10 - well below the 6-of-10 the new config intended."""
    WIKI_RECOMMENDATION = (
        "In the same setter, recompute and write the paired count/threshold "
        "(e.g. `threshold = (newSet.length * 2) / 3 + 1;`). Better: store "
        "only the collection and derive the threshold in a view function so "
        "drift is impossible."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            colls = [sv for sv in contract.state_variables if _is_collection_sv(sv)]
            counts = [sv for sv in contract.state_variables if _is_count_sv(sv)]
            if not colls or not counts:
                continue

            # Build pair candidates.
            pairs = []
            for c in colls:
                for k in counts:
                    if _pair_root_overlap(c.name, k.name):
                        pairs.append((c, k))
            if not pairs:
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                if function.view or function.pure:
                    continue
                written = set(function.state_variables_written)

                for coll_sv, count_sv in pairs:
                    if coll_sv not in written:
                        continue
                    if count_sv in written:
                        continue

                    info: DETECTOR_INFO = [
                        function,
                        " writes collection ",
                        coll_sv,
                        " but does not update paired counter/threshold ",
                        count_sv,
                        " - downstream authorization checks will use a "
                        "stale value.\n",
                    ]
                    results.append(self.generate_result(info))
                    break  # one finding per function

        return results
