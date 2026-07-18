"""
glider-chainlink-vrf-request-confirmations-too-low — generated from reference/patterns.dsl/glider-chainlink-vrf-request-confirmations-too-low.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-chainlink-vrf-request-confirmations-too-low.yaml
Source: glider/request-confirmation-is-too-low-in-chainlink-vrf-i
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderChainlinkVrfRequestConfirmationsTooLow(AbstractDetector):
    ARGUMENT = "glider-chainlink-vrf-request-confirmations-too-low"
    HELP = "Chainlink VRF `requestConfirmations` set below 3 — miner reorg can bias randomness."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-chainlink-vrf-request-confirmations-too-low.yaml"
    WIKI_TITLE = "Chainlink VRF requestConfirmations below safe threshold"
    WIKI_DESCRIPTION = "Chainlink VRF V2's security model assumes randomness is finalised only after REQUEST_CONFIRMATIONS blocks. Below 3, a miner with stake in the outcome can reorg the chain and force re-fulfilment on a branch that yields a different random value."
    WIKI_EXPLOIT_SCENARIO = "Gambling dApp mints NFT with trait determined by VRF, uses requestConfirmations=1 to save latency. A miner who receives a rare trait can accept it; when they receive a bad trait, they orphan their own block and re-submit, producing a different VRF draw, skewing the rarity distribution."
    WIKI_RECOMMENDATION = "Set `requestConfirmations >= 3` per Chainlink VRF V2 docs. For high-value outcomes use >= 20 on Ethereum mainnet. Never hardcode below the coordinator minimum."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'VRFCoordinator|requestRandomWords|IVRFV2|VRFConsumerBase'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': 'requestRandomWords\\s*\\('}, {'function.body_contains_regex': 'requestConfirmations\\s*[=:]\\s*(1|2)\\b|uint16\\s*\\(\\s*(1|2)\\s*\\)|,\\s*(1|2)\\s*,\\s*\\d+\\s*,'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-chainlink-vrf-request-confirmations-too-low: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
