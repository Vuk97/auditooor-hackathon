"""
l1-l2-token-address-mapping-unchecked — generated from reference/patterns.dsl/l1-l2-token-address-mapping-unchecked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py l1-l2-token-address-mapping-unchecked.yaml
Source: solodit-cluster-C0215
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class L1L2TokenAddressMappingUnchecked(AbstractDetector):
    ARGUMENT = "l1-l2-token-address-mapping-unchecked"
    HELP = "Bridge function treats L1 and L2 token addresses as distinct by address alone — an attacker who controls a token at the same address on both chains can deposit L1-side and withdraw a different L2-side token, stealing funds."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/l1-l2-token-address-mapping-unchecked.yaml"
    WIKI_TITLE = "Bridge L1/L2 token pairing does not guard against shared-address collision"
    WIKI_DESCRIPTION = "Bridges that pair an L1 token with an L2 token by raw `address` assume the two address spaces cannot collide. On chains that reuse the same 20-byte address space (CREATE2 collisions, pre-computed salts, or chains that inherit the same address for a counterfactually-deployed contract), an attacker can set up a token at the same address on both L1 and L2, register a bogus pairing, and use the mismat"
    WIKI_EXPLOIT_SCENARIO = "An attacker pre-computes a CREATE2 address `A` that resolves to a valid ERC20 on L1 and deploys a malicious ERC20 at the same address `A` on L2. They call `deposit(A, amount)` on the L1 bridge, which escrows real tokens; the bridge then mints / releases on L2 at address `A`, which is the attacker's contract. Because the bridge never required `l1Token != l2Token` nor consulted an enumerated `tokenM"
    WIKI_RECOMMENDATION = "Reject deposits when the L1 and L2 token addresses are equal (`require(l1Token != l2Token)`), or — better — require both addresses to come from an admin-governed enumerated `tokenMap[]` registry. Additionally, include the chainId in any off-chain commitment used to authenticate a pair, and never tru"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(bridge|deposit|withdraw|depositERC20|withdrawERC20|_bridge|_deposit|lock|unlock)$'}, {'function.has_param_of_type': 'address'}, {'function.body_contains_regex': {'regex': 'l1Token|l2Token|crossToken|remoteToken|otherChainToken'}}, {'function.body_not_contains_regex': 'require\\s*\\(.*l1\\s*!=\\s*l2|crossChainId|chainId\\s*!=|tokenMap\\[|_validateL1L2'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — l1-l2-token-address-mapping-unchecked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
