"""
approve_then_transfer_unspent.py - Custom Slither detector.

Pattern (P29): A function calls token.approve(user, amount) followed by
token.transfer(user, amount) in the same function body, both targeting the
same recipient. The direct transfer() call does NOT consume the allowance
set by approve(). If the contract later holds any token balance, the
approved spender can call token.transferFrom(contract, user, amount) again
for a second withdrawal - effectively doubling the payout.

Source: reference/corpus_mined/slice_ag.md - Rainmaker (Definitive).
Bug: "Extraneous Approval in Withdrawal Allows Double-Withdrawal" (CRITICAL).
In Rainmaker: withdraw() called approve(user, amount) then transfer(user, amount).
The approval was unspent; user called transferFrom to drain contract balance.

Detection strategy (verified against IR probe):

1. Walk functions in each contract.
2. For each function, collect all HighLevelCall IRs with:
     - solidity_signature == "approve(address,uint256)"  → approve_calls
     - solidity_signature in {"transfer(address,uint256)",
                               "safeTransfer(address,uint256)"} → transfer_calls
3. For each (approve_call, transfer_call) pair, check if arg[0] (the recipient
   address) is the SAME object (identity check `is`). This works because Slither
   uses the same LocalVariable object for the same parameter within a function.
4. If any such pair exists → flag.

IR shapes (verified):
  token.approve(user, amount)
    HighLevelCall TMP_0(bool) = HIGH_LEVEL_CALL, dest:token, function:approve,
                                arguments:['user', 'amount']
  token.transfer(user, amount)
    HighLevelCall TMP_1(bool) = HIGH_LEVEL_CALL, dest:token, function:transfer,
                                arguments:['user', 'amount']
  → ir.arguments[0] is the same LocalVariable object for both calls.

Confidence: MEDIUM - precise on same-function same-recipient approve+transfer.
Only fires when the recipient variable is identical (same IR object), which
prevents false positives from approve-then-transfer-to-different-address patterns.

@author auditooor
@pattern wave6 P29 approve-then-transfer-unspent-allowance
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
from slither.slithir.operations import HighLevelCall
from slither.core.declarations import Function
from slither.utils.output import Output


# Canonical ERC-20 approve signature
_APPROVE_SIG = "approve(address,uint256)"

# Direct-transfer signatures that do NOT consume an allowance
_TRANSFER_SIGS = frozenset({
    "transfer(address,uint256)",
    "safeTransfer(address,uint256)",
})

# Function / contract names to skip
_SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _collect_calls(function):
    """
    Walk a function's IR and return two lists:
        approve_calls  - list of (recipient_var, amount_var, node) for approve(addr, amt)
        transfer_calls - list of (recipient_var, amount_var, node) for transfer/safeTransfer
    """
    approve_calls = []
    transfer_calls = []

    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, HighLevelCall):
                continue
            fn = ir.function
            if not isinstance(fn, Function):
                continue
            if not hasattr(fn, "solidity_signature"):
                continue
            sig = fn.solidity_signature
            args = ir.arguments
            if len(args) < 2:
                continue

            if sig == _APPROVE_SIG:
                approve_calls.append((args[0], args[1], node))
            elif sig in _TRANSFER_SIGS:
                transfer_calls.append((args[0], args[1], node))

    return approve_calls, transfer_calls


class ApproveThenTransferUnspent(AbstractDetector):
    """
    Detect functions that call approve(recipient, amount) then transfer(recipient, amount)
    to the same address - the approval is unspent and creates a latent double-withdrawal.
    """

    ARGUMENT = "approve-then-transfer-unspent"
    HELP = (
        "Function calls approve(user, amount) then transfer(user, amount) - "
        "the approval is unspent and can be used for a second withdrawal via transferFrom"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Extraneous Approval Leaves Unspent Allowance (P29)"
    WIKI_DESCRIPTION = (
        "A function calls token.approve(user, amount) followed immediately by "
        "token.transfer(user, amount) to the same recipient. The direct transfer() "
        "call sends tokens but does NOT consume the ERC-20 allowance set by approve(). "
        "If the contract receives token funds at any later point, the approved user can "
        "call token.transferFrom(contract, user, amount) to withdraw the same amount a "
        "second time - effectively doubling their payout. "
        "This exact pattern was found in Rainmaker (Zellic audit): the CRITICAL finding "
        "'Extraneous Approval in Withdrawal Allows Double-Withdrawal'."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
IERC20 public token;

function withdraw(address user, uint256 amount) external {
    token.approve(user, amount);   // sets allowance: contract -> user = amount
    token.transfer(user, amount);  // sends tokens directly - allowance NOT consumed
    // allowance remains: user can call token.transferFrom(contract, user, amount)
}
```
1. Admin calls `withdraw(alice, 100e18)` to pay Alice.
2. `approve` grants Alice an allowance of 100 tokens.
3. `transfer` sends 100 tokens to Alice directly. Allowance unchanged.
4. Contract later receives 100 more tokens (e.g. from fees or donations).
5. Alice calls `token.transferFrom(contract, alice, 100e18)` - pulls another 100 tokens
   using the unspent approval. Alice has now received 200 tokens for 100 owed."""
    WIKI_RECOMMENDATION = (
        "Remove the approve() call entirely. Use only transfer() or safeTransfer() "
        "to send tokens directly. If an allowance must be granted for a third-party "
        "pull pattern, do NOT also call transfer() to the same recipient in the same "
        "transaction - use one mechanism or the other, not both."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                approve_calls, transfer_calls = _collect_calls(function)

                if not approve_calls or not transfer_calls:
                    continue

                # Check for matching (same recipient object) approve + transfer pairs
                for a_addr, _a_amt, a_node in approve_calls:
                    for t_addr, _t_amt, t_node in transfer_calls:
                        # Recipient identity: same local variable object used in both calls
                        if a_addr is not t_addr:
                            continue

                        info: DETECTOR_INFO = [
                            function,
                            " calls approve(",
                            str(getattr(a_addr, "name", a_addr)),
                            ", amount) at ",
                            a_node,
                            " then transfer(",
                            str(getattr(t_addr, "name", t_addr)),
                            ", amount) at ",
                            t_node,
                            " - the allowance is unspent after the direct transfer "
                            "and can be exploited via transferFrom for a second "
                            "withdrawal.\n",
                        ]
                        results.append(self.generate_result(info))
                        break  # one report per approve call is sufficient
                    else:
                        continue
                    break  # one report per function is sufficient

        return results
