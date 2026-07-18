"""
constructor-uint-cast-address-privileged-mapping-backdoor — generated from reference/patterns.dsl/constructor-uint-cast-address-privileged-mapping-backdoor.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py constructor-uint-cast-address-privileged-mapping-backdoor.yaml
Source: defimon-eos-mine-r97/TAI_2025-07-17_post-1504 (Tagger AI $130K)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ConstructorUintCastAddressPrivilegedMappingBackdoor(AbstractDetector):
    ARGUMENT = "constructor-uint-cast-address-privileged-mapping-backdoor"
    HELP = "Constructor takes a numeric argument, casts it via address(uint160(...)) to an address, and writes that address into a privileged-bypass mapping (_excluded / isExcludedFromFee / whitelisted / etc). The deployer can encode an arbitrary backdoor address as a uint constructor arg, hidden from casual in"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/constructor-uint-cast-address-privileged-mapping-backdoor.yaml"
    WIKI_TITLE = "Constructor uint argument cast to address and inserted into privileged-bypass mapping"
    WIKI_DESCRIPTION = "Tax-token / fee-on-transfer ERC20 forks commonly maintain `_excluded` (or `isExcludedFromFee`) mappings that bypass tax / max-tx / cooldown checks for designated addresses (LP, treasury, marketing). When the deployment script lets an opaque numeric constructor arg flow through `address(uint160(...))` and into that mapping, the deployer can encode any backdoor address by passing its uint160 represe"
    WIKI_EXPLOIT_SCENARIO = "Tagger AI (TAI) token deployed July 17, 2025 ($130K rug, Ethereum). Constructor was passed `_dd = 1189465217628782104793422269063241062475210122326`. Inside `_mint`, the value was cast `address(uint160(_dd))` yielding `0xa0d932850c78148c985753a48087403152a6390a` and inserted into `_excluded[that]= true`. The scammer's address was then exempt from the contract's transfer-restriction logic and calle"
    WIKI_RECOMMENDATION = "Never accept a numeric constructor argument that flows into `address(uint160(...))` and lands in a privileged-bypass mapping. If a designated bypass address is needed, accept it as an explicit `address` parameter (so it shows up in the deploy receipt as a typed address, not a decimal int), and emit "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)constructor|_excluded|isExcluded|isExcludedFromFee|isWhitelisted|isOperator|isAdmin|whitelisted|privilegedRouter'}]
    _MATCH = [{'function.is_constructor': True}, {'function.body_contains_regex': '(?i)address\\s*\\(\\s*uint160\\s*\\(|\\.toAddress\\s*\\(\\s*uint160'}, {'function.body_contains_regex': '(?i)(_excluded|isExcludedFromFee|isExcludedFromTax|whitelisted|isWhitelisted|isOperator|isAdmin|privilegedRouter|canMint|allowedSpender|trustedForwarder|automatedMarketMakerPairs|isExcludedFromMaxTx)\\s*\\[[^\\]]+\\]\\s*=\\s*(true|1)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — constructor-uint-cast-address-privileged-mapping-backdoor: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
