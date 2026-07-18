"""
fee-withdraw-uses-eth-transfer-2300-gas-stipend — generated from reference/patterns.dsl/fee-withdraw-uses-eth-transfer-2300-gas-stipend.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fee-withdraw-uses-eth-transfer-2300-gas-stipend.yaml
Source: auditooor-R110-morpho-PublicAllocator
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeeWithdrawUsesEthTransfer2300GasStipend(AbstractDetector):
    ARGUMENT = "fee-withdraw-uses-eth-transfer-2300-gas-stipend"
    HELP = "A fee-collection / claim helper forwards native ETH to an admin-supplied recipient via `<addr>.transfer(amount)`, hard-capping the forwarded gas at 2300. Smart-contract recipients (Gnosis Safe, EIP-7702 delegate, custom multisig) that need >2300 gas in their fallback/receive will revert the transfer"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fee-withdraw-uses-eth-transfer-2300-gas-stipend.yaml"
    WIKI_TITLE = "Fee withdrawal uses `.transfer()` 2300-gas stipend — DoS for smart-contract recipients"
    WIKI_DESCRIPTION = "The `.transfer()` and `.send()` helpers on `address payable` forward a hardcoded 2300 gas stipend to the recipient — a budget chosen pre-EIP-2929 specifically so a `LOG` in the receiver could fit. Post-Berlin (EIP-2929) gas reprices and post-Cancun (EIP-1153 transient storage) bookkeeping have eaten into that budget; many production smart-wallet receivers (Gnosis Safe v1.4, ERC-4337 contract accou"
    WIKI_EXPLOIT_SCENARIO = "DAO sets up a `PublicAllocator` for its MetaMorpho vault and configures `feeRecipient` as a Gnosis Safe v1.4 multisig. Curator runs `transferFee(vault, safeAddress)` to collect 2 ETH of accrued public-allocator fees. The Safe's fallback consumes ~7K gas to dispatch the inbound ETH log; `.transfer()` forwards 2300 gas; the call reverts with out-of-gas. The whole tx reverts, leaving `accruedFee[vaul"
    WIKI_RECOMMENDATION = "Replace `recipient.transfer(amount)` with the OZ-recommended pattern: `(bool ok, ) = recipient.call{value: amount}(\"\"); require(ok, TransferFailed());`. Forwards all remaining gas, surfaces the boolean explicitly, and works for arbitrary recipients including Gnosis Safe, ERC-4337 wallets, and EIP-"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Allocator|Distributor|FeeRecipient|Treasury|Vault|Skimmer|Reward|Fee|Claim'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(_?transferFee|_?withdrawFee|_?claimFee|_?skim|_?sweep|_?withdrawEth|_?withdrawNative|_?claimRewards|_?collectFees|_?distributeFees)$'}, {'function.body_contains_regex': '\\b\\w+\\.transfer\\s*\\(\\s*\\w+\\s*\\)|payable\\s*\\(\\s*\\w+\\s*\\)\\.transfer\\s*\\(|feeRecipient\\.transfer|recipient\\.transfer'}, {'function.body_not_contains_regex': 'safeTransfer|SafeERC20|IERC20|SafeTransferLib|call\\s*\\{\\s*value\\s*:|sendValue\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" — fee-withdraw-uses-eth-transfer-2300-gas-stipend: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
