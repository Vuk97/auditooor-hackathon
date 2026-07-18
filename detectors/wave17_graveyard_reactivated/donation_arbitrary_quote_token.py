"""
donation_arbitrary_quote_token.py - Custom Slither detector.

Pattern (GTE-launchpad H-06 / slice_ac):
    A distributor / vault / staking contract exposes
    `donate(address quoteToken, uint256 amount)` (or `addReward`,
    `distribute`, `injectRewards`) and pulls `quoteToken` via
    `transferFrom` without verifying it against a whitelist or hard-coded
    expected token. Attacker passes a token they control (mintable,
    rebase, fee-on-transfer) and inflates `totalRewards` arbitrarily,
    diluting honest stakeholder shares.

Detection strategy:
    1. For each non-vendored contract, find functions whose name matches
       `(?i)(donate|distribute|addreward|injectreward|fund|topup)` and
       which take an `address` parameter (the would-be quote token).
    2. Inside the function body, find a HighLevelCall whose
       solidity_signature is `transferFrom(address,address,uint256)` and
       whose destination is the address parameter.
    3. Flag if the function does NOT contain a require/assert that reads
       a state variable whose name matches `(?i)(allow|whitelist|valid|
       supported|approved|known)` (i.e. no allowlist gate).

@author auditooor wave9
@pattern GTE-launchpad H-06 / slice_ac
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

import re

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.core.declarations import Function
from slither.core.solidity_types import ElementaryType
from slither.slithir.operations import HighLevelCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_FN_NAME_RE = re.compile(
    r"(donate|distribute|addreward|injectreward|fund|topup|notifyreward)",
    re.IGNORECASE,
)
_ALLOWLIST_RE = re.compile(
    r"(allow|whitelist|valid|supported|approved|known|accepted|enabled)",
    re.IGNORECASE,
)
_TOKEN_PARAM_NAMES = {
    "token", "quotetoken", "rewardtoken", "asset", "currency", "stable", "stablecoin"
}


def _has_address_token_param(function):
    for p in function.parameters:
        nm = (p.name or "").lower()
        t = getattr(p, "type", None)
        if isinstance(t, ElementaryType) and t.name == "address" and nm in _TOKEN_PARAM_NAMES:
            return p
    return None


def _calls_transfer_from_on_param(function, token_param) -> bool:
    """Return True if a HighLevelCall to transferFrom uses token_param as
    the contract receiver (i.e. IERC20(token_param).transferFrom(...))."""
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, HighLevelCall):
                continue
            if not isinstance(ir.function, Function):
                continue
            sig = ir.function.solidity_signature
            if sig not in (
                "transferFrom(address,address,uint256)",
                "safeTransferFrom(address,address,uint256)",
            ):
                continue
            # destination is the contract instance - check if it traces to param
            dest = ir.destination
            if dest is token_param:
                return True
            # local var assigned from token_param earlier - be lenient: any
            # node that reads token_param in the same function is enough.
        # fall-through
    # Fallback heuristic: function reads token_param AND has a transferFrom
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, HighLevelCall):
                continue
            if not isinstance(ir.function, Function):
                continue
            sig = ir.function.solidity_signature
            if sig in (
                "transferFrom(address,address,uint256)",
                "safeTransferFrom(address,address,uint256)",
            ):
                if token_param in node.local_variables_read or token_param in function.parameters:
                    return True
    return False


def _has_allowlist_guard(function) -> bool:
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        for sv in node.state_variables_read:
            if _ALLOWLIST_RE.search(sv.name or ""):
                return True
    return False


class DonationArbitraryQuoteToken(AbstractDetector):
    """donate(token, amount) without whitelist - arbitrary inflation."""

    ARGUMENT = "donation-arbitrary-quote-token"
    HELP = (
        "donate/distribute/addReward function pulls an arbitrary user-"
        "supplied token without an allowlist - attacker can inflate "
        "totalRewards with a worthless token"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Donation with Arbitrary Quote Token"
    WIKI_DESCRIPTION = (
        "A distributor accepts `donate(address quoteToken, uint256 amount)`"
        " (or `addReward`, `distribute`) and pulls the token via "
        "`transferFrom` without checking that `quoteToken` belongs to a "
        "whitelist of protocol-approved assets. Attacker passes a token "
        "they control - mintable, fee-on-transfer, or rebase - and "
        "inflates `totalRewards` arbitrarily, diluting honest "
        "stakeholders' share of real rewards. Reported in GTE-launchpad "
        "H-06."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function donate(address quoteToken, uint256 amount) external {
    IERC20(quoteToken).transferFrom(msg.sender, address(this), amount);
    totalRewards += amount;
}
```
1. Attacker deploys MaliciousToken with mint(uint).
2. Attacker mints 1e30, calls donate(MaliciousToken, 1e30).
3. totalRewards += 1e30 → honest reward pool diluted to dust."""
    WIKI_RECOMMENDATION = (
        "Maintain `mapping(address => bool) isAllowedRewardToken` (or a "
        "single immutable `expectedToken`) and "
        "`require(isAllowedRewardToken[quoteToken])` at the top of donate."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_declared:
                if function.is_constructor:
                    continue
                if function.view or function.pure:
                    continue
                if function.visibility not in ("public", "external"):
                    continue
                if not _FN_NAME_RE.search(function.name or ""):
                    continue
                token_param = _has_address_token_param(function)
                if token_param is None:
                    continue
                if not _calls_transfer_from_on_param(function, token_param):
                    continue
                if _has_allowlist_guard(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    f" pulls user-supplied token `{token_param.name}` via "
                    "transferFrom without checking it against an allowlist "
                    "- attacker can donate a worthless token they control "
                    "and dilute the reward pool.\n",
                ]
                results.append(self.generate_result(info))

        return results
