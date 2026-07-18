"""
chainlink-feed-registry-address-hardcoded — generated from reference/patterns.dsl/chainlink-feed-registry-address-hardcoded.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py chainlink-feed-registry-address-hardcoded.yaml
Source: solodit-cluster-CLREG
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ChainlinkFeedRegistryAddressHardcoded(AbstractDetector):
    ARGUMENT = "chainlink-feed-registry-address-hardcoded"
    HELP = "Chainlink FeedRegistry address hardcoded to the Ethereum-mainnet deployment (0x47Fb2585D2C56Fe188D0E6ec628a38b74FCeeeDF). The contract will consume garbage / revert on every oracle read once deployed to any non-mainnet chain (Arbitrum, Optimism, Base, Polygon, BNB, Avalanche, L2s) where the registry"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/chainlink-feed-registry-address-hardcoded.yaml"
    WIKI_TITLE = "Chainlink FeedRegistry address hardcoded — not portable off mainnet"
    WIKI_DESCRIPTION = "The Chainlink FeedRegistry contract is only deployed on Ethereum mainnet (0x47Fb2585D2C56Fe188D0E6ec628a38b74FCeeeDF). A contract that hardcodes this address — either as an immutable literal, a `FeedRegistry(0x...)` cast, or a named constant `FEED_REGISTRY_ADDRESS = 0x...` — is non-portable: every chain other than mainnet either has no FeedRegistry or has it at a different address. No chain-id bra"
    WIKI_EXPLOIT_SCENARIO = "The team forks the protocol from mainnet onto Arbitrum to chase TVL. The audit'd `PriceOracle` contract hardcodes the mainnet FeedRegistry at 0x47Fb2585D2C56Fe188D0E6ec628a38b74FCeeeDF. On Arbitrum that address is an empty slot, so every call to `registry.latestRoundData(base, quote)` reverts. Any flow that depends on the oracle — deposits, borrows, liquidations, redemptions — is DoS'd from block "
    WIKI_RECOMMENDATION = "Do not hardcode the FeedRegistry address. Accept it as a constructor / initializer argument and store it in an immutable / mutable (upgradeable-aware) variable, with a `require(registry.code.length > 0)` sanity check at construction. If a single compiled artifact must support multiple chains, gate t"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '0x47Fb2585D2C56Fe188D0E6ec628a38b74FCeeeDF|FeedRegistry\\s*\\(\\s*0x|FeedRegistryInterface\\s*\\(\\s*0x|FEED_REGISTRY_ADDRESS\\s*=\\s*0x|CHAINLINK_REGISTRY\\s*=\\s*0x'}, {'function.body_not_contains_regex': 'block\\.chainid\\s*==|chainId\\s*!=|ethereumMainnet|_isMainnet'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — chainlink-feed-registry-address-hardcoded: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
