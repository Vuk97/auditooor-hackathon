"""
glider-missing-chainid-in-signature-domain — generated from reference/patterns.dsl/glider-missing-chainid-in-signature-domain.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-missing-chainid-in-signature-domain.yaml
Source: hexens-glider/cross-chain-replay-attacks-due-to-missing-chain-id
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderMissingChainidInSignatureDomain(AbstractDetector):
    ARGUMENT = "glider-missing-chainid-in-signature-domain"
    HELP = "Signature verification recomputes a digest that does not bind block.chainid — signatures produced on chain A can be replayed on chain B where the same contract is deployed."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-missing-chainid-in-signature-domain.yaml"
    WIKI_TITLE = "Signature digest missing chain id — cross-chain replay"
    WIKI_DESCRIPTION = "When a contract is deployed to multiple chains using the same address (CREATE2 or deterministic deployer) and verifies user signatures, failing to bind block.chainid into the digest allows signatures minted on one chain to be replayed on another. This breaks withdrawal authorizations, governance votes, and order execution."
    WIKI_EXPLOIT_SCENARIO = "Victim signs a withdrawal on Ethereum mainnet. The same contract exists at the same address on Arbitrum. Attacker replays the signature on Arbitrum and drains the victim's Arbitrum balance before the victim realizes a cross-chain replay has occurred."
    WIKI_RECOMMENDATION = "Include block.chainid in the EIP-712 domain separator or pre-image. For EIP-712, use the library's DOMAIN_SEPARATOR() that recomputes when chainid changes (post-fork)."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ecrecover\\s*\\(|SignatureChecker|EIP712'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': 'ecrecover\\s*\\(|SignatureChecker\\.isValidSignatureNow'}, {'function.body_not_contains_regex': 'block\\.chainid|CHAIN_ID|DOMAIN_SEPARATOR|chainId'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-missing-chainid-in-signature-domain: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
