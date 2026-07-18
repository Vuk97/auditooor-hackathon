"""
erc721_hook_self_transfer.py - Custom Slither detector.

ARG: erc721-hook-self-transfer

Pattern: ERC721/ERC1155 hook implementations (_beforeTokenTransfer,
_afterTokenTransfer) whose body does NOT check for self-transfer (from == to
or from != to).

If a reward/staking contract hooks into token transfers to accrue rewards but
doesn't guard against self-transfers, a user can call transferFrom(self, self, tokenId)
in a loop to double-claim rewards without moving their token.

Ported from: queries/erc721-hook-missing-self-transfer-guard-reward-log.py

Canonical pattern: Binary IR inspection (BinaryType.EQUAL / NOT_EQUAL) on
LocalVariable pairs - the from/to parameters. This avoids brittle string
matching on node expressions and works correctly with Slither's IR.

Implementation:
1. Find functions named _beforeTokenTransfer / _afterTokenTransfer with bodies.
2. Collect the first two address-type parameters (from, to).
3. Walk all Binary IR ops in the function: flag MISSING if no Binary(EQUAL/NOT_EQUAL)
   compares those two parameters against each other (both sides LocalVariable
   matching the from/to param names).
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.core.variables.local_variable import LocalVariable
from slither.slithir.operations import Binary, BinaryType
from slither.utils.output import Output


HOOK_NAMES = {
    "_beforeTokenTransfer",
    "_afterTokenTransfer",
    "onERC721Received",
    "onERC1155Received",
    "onERC1155BatchReceived",
}

# Name variants used for the from/to parameters in these hooks
FROM_NAMES = {"from", "_from", "operator", "sender"}
TO_NAMES = {"to", "_to", "recipient"}

SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _function_has_body(function) -> bool:
    """Return True if function has at least one IR instruction (not an empty stub)."""
    return any(node.irs for node in function.nodes)


def _has_self_transfer_guard(function) -> bool:
    """
    Return True if the function contains a Binary(EQUAL or NOT_EQUAL) IR op
    where both operands are LocalVariables whose names match the from/to parameter
    pattern. This catches `if (from == to) return;` and `require(from != to)`.
    """
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            if ir.type not in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
                continue
            left = ir.variable_left
            right = ir.variable_right
            if not isinstance(left, LocalVariable) or not isinstance(right, LocalVariable):
                continue
            left_name = left.name.lower()
            right_name = right.name.lower()
            # Check: (left is from-like AND right is to-like) OR vice versa
            if (left_name in FROM_NAMES and right_name in TO_NAMES) or \
               (left_name in TO_NAMES and right_name in FROM_NAMES):
                return True
    return False


class Erc721HookSelfTransfer(AbstractDetector):
    """
    ERC721/1155 hook (_beforeTokenTransfer/_afterTokenTransfer) missing
    a self-transfer guard (from == to check).
    """

    ARGUMENT = "erc721-hook-self-transfer"
    HELP = "ERC721/1155 hook missing self-transfer guard (from == to reward double-claim)"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "ERC721/1155 Hook Missing Self-Transfer Guard"
    WIKI_DESCRIPTION = (
        "Hooks like _beforeTokenTransfer and _afterTokenTransfer are called "
        "by the token contract on every transfer - including self-transfers "
        "(transferFrom(user, user, tokenId)). If a reward or staking contract "
        "accrues rewards inside these hooks without guarding against `from == to`, "
        "an attacker can call self-transfer in a loop to harvest rewards indefinitely "
        "without losing custody of their token."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function _beforeTokenTransfer(address from, address to, uint256 tokenId) external {
    rewards[from] += 1;  // No from == to guard!
}
```
Attacker calls nft.transferFrom(attacker, attacker, tokenId) 1000x, crediting
themselves 1000 reward units while never moving the token."""
    WIKI_RECOMMENDATION = (
        "Add `if (from == to) return;` at the top of any hook that accrues rewards. "
        "Self-transfers are economically meaningless and should be no-ops for reward logic."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:  # canonical: self.contracts
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue
            for function in contract.functions_and_modifiers_declared:
                if function.name not in HOOK_NAMES:
                    continue
                if not _function_has_body(function):
                    continue
                # SKILL_ISSUE #46: stateless receiver mixins (functions
                # that only return the magic selector and write no state)
                # are vacuously safe. Skip them.
                try:
                    if not function.all_state_variables_written():
                        continue
                except Exception:
                    pass
                if _has_self_transfer_guard(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " in ",
                    contract,
                    " is a token transfer hook but does not guard against "
                    "self-transfers (from == to). If this hook accrues rewards, "
                    "an attacker can self-transfer in a loop to double-claim.\n",
                ]
                results.append(self.generate_result(info))

        return results
