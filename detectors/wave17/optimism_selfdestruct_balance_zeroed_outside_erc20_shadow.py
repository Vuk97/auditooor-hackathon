"""
optimism-selfdestruct-balance-zeroed-outside-erc20-shadow — generated from reference/patterns.dsl/optimism-selfdestruct-balance-zeroed-outside-erc20-shadow.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py optimism-selfdestruct-balance-zeroed-outside-erc20-shadow.yaml
Source: auditooor-R76-immunefi-optimism-$2M
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OptimismSelfdestructBalanceZeroedOutsideErc20Shadow(AbstractDetector):
    ARGUMENT = "optimism-selfdestruct-balance-zeroed-outside-erc20-shadow"
    HELP = "SELFDESTRUCT zeros the native stateObject balance without routing through the shadow-ETH ERC-20 storage. Users can duplicate ETH by self-destructing into themselves in a loop."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/optimism-selfdestruct-balance-zeroed-outside-erc20-shadow.yaml"
    WIKI_TITLE = "SELFDESTRUCT bypasses shadow-ETH ERC-20 on modified L2 geth"
    WIKI_DESCRIPTION = "Chains that implement ETH as an internal ERC-20 (OVM_ETH, MNT, native-to-wrap shadow) must mirror every native-balance mutation onto the ERC-20 storage slot. A modified go-ethereum that still contains `stateObject.Balance = new(big.Int)` inside the SELFDESTRUCT handler zeros only the native mirror. If the rest of the chain reads from the ERC-20 storage for transferability, the user keeps their bal"
    WIKI_EXPLOIT_SCENARIO = "On Optimism pre-Bedrock, a single tx looped: create contract, send all ETH into it, SELFDESTRUCT back to self. The stateObject.Balance was zeroed, but OVM_ETH storage still reflected the full balance. Each loop doubled funds. Fix PR #2146 gated the zeroing on `UsingOVM` and routed through OVM_ETH. Payout: $2M."
    WIKI_RECOMMENDATION = "On any shadow-ETH L2, remove direct stateObject.Balance mutations from the EVM. Every native-balance change (selfdestruct transfer, CREATE refund, beacon deposit) must route through the ERC-20 contract via MINT/BURN system calls. Add a state-trie invariant check: sum(OVM_ETH balances) == sum(stateOb"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'chain.is_l2_with_shadow_eth_erc20': True}]
    _MATCH = [{'function.kind': 'geth_state_mutator'}, {'function.name_matches': '(?i)Selfdestruct|Suicide|Destroy'}, {'function.body_contains_regex': '(?i)\\.Balance\\s*=\\s*new\\(big\\.Int\\)|SetBalance\\(\\s*new\\(big\\.Int\\)\\)|\\.data\\.Balance\\s*=\\s*common\\.Big0'}, {'function.body_not_contains_regex': '(?i)UsingOVM|OVM_ETH|usingOVM|erc20_eth|l2_eth_token'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — optimism-selfdestruct-balance-zeroed-outside-erc20-shadow: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
