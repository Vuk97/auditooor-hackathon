"""
mph88-nft-init-unprotected-anyone-becomes-owner — generated from reference/patterns.dsl/mph88-nft-init-unprotected-anyone-becomes-owner.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py mph88-nft-init-unprotected-anyone-becomes-owner.yaml
Source: auditooor-R76-immunefi-88mph-$42k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Mph88NftInitUnprotectedAnyoneBecomesOwner(AbstractDetector):
    ARGUMENT = "mph88-nft-init-unprotected-anyone-becomes-owner"
    HELP = "init()/initialize() has no initializer modifier and no caller restriction. Attacker calls it first, becomes owner, then abuses owner-gated mint/burn to steal NFTs and underlying deposits."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/mph88-nft-init-unprotected-anyone-becomes-owner.yaml"
    WIKI_TITLE = "Unprotected init() lets anyone become owner of NFT / deposit contract"
    WIKI_DESCRIPTION = "Upgradeable NFT or deposit-receipt contracts are typically initialized via `init()` instead of a constructor. When init() lacks both the `initializer` modifier (from OZ Initializable) AND any caller authentication (onlyOwner, onlyFactory, msg.sender == creator), an attacker can race the deployer: front-run the init transaction (or call init again if no flag guards it), seize ownership, and use own"
    WIKI_EXPLOIT_SCENARIO = "88mph's deposit-NFT init() was unprotected and re-callable. Attacker calls init(), becomes owner, then uses owner-only mint()/burn() to mint NFTs representing existing user deposits to themselves, or burn user NFTs and redeem underlying. 88mph whitehacked $6.5M in crvRenWBTC before the attacker; $42k bounty."
    WIKI_RECOMMENDATION = "ALWAYS use OZ's Initializable `initializer`/`reinitializer` modifiers. ALWAYS call `_disableInitializers()` in the constructor of the implementation. For factory-deployed proxies, bind init to `msg.sender == factory`. Include a deployment-script test: call init twice and assert the second call rever"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.is_upgradeable_or_proxy': True}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^init$|^initialize$|^setup$|^__[A-Za-z0-9_]+_init$'}, {'function.has_modifier_not': 'initializer|reinitializer|onlyOwner|onlyFactory|onlyProxy'}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.body_contains_regex': '(?i)_owner\\s*=|owner\\s*=\\s*(?:msg\\.sender|_owner_)|_transferOwnership\\s*\\(|_name\\s*=|_symbol\\s*='}, {'function.body_not_contains_regex': '(?i)require\\s*\\(\\s*(?:_initialized|initialized)\\s*(?:==|<)|_disableInitializers'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — mph88-nft-init-unprotected-anyone-becomes-owner: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
