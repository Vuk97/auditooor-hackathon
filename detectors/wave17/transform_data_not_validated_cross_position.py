"""
transform-data-not-validated-cross-position — generated from reference/patterns.dsl/transform-data-not-validated-cross-position.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py transform-data-not-validated-cross-position.yaml
Source: auditooor-R75-c4-yield-2024-03-revert-lend-214
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TransformDataNotValidatedCrossPosition(AbstractDetector):
    ARGUMENT = "transform-data-not-validated-cross-position"
    HELP = "transform() forwards `data` to transformer without asserting the tokenId inside `data` equals the outer `tokenId` argument — any vault depositor can pilfer other users' approved positions."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/transform-data-not-validated-cross-position.yaml"
    WIKI_TITLE = "Transformer sandwich: `data` parameter not tied to outer tokenId lets any borrower hijack another user's approved position"
    WIKI_DESCRIPTION = "Vaults that delegate position management to shared transformer contracts (AutoCompound, AutoRange) approve the transformer over many different NFT positions. If the vault's `transform(tokenId, transformer, data)` blindly forwards `data` without asserting that the tokenId encoded in `data` matches the outer `tokenId` argument, any authorized borrower can craft `data` that targets a different victim"
    WIKI_EXPLOIT_SCENARIO = "Revert V3Vault.transform: Alice has a position in the vault. Bob has delegated AutoRange approval over his external position to the same AutoRange contract. Alice calls transform(aliceTokenId, autoRange, dataTargetingBobTokenId). Vault approves AutoRange over aliceTokenId (no-op) and forwards call; AutoRange acts on bobTokenId because Bob already approved it. Bob's liquidity rebalanced or withdraw"
    WIKI_RECOMMENDATION = "Decode the tokenId (or function selector + first arg) from `data` and assert it matches the outer `tokenId`. Prefer a typed, selector-specific dispatch where the vault builds `data` itself from trusted parameters instead of forwarding user bytes."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'contract.name_matches: (?i)(vault|position.*manager|collateral.*manager)']
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(transform|executeAction|runTransformer)'}, {'function.parameters_include': '(bytes|calldata).*data'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': '(?i)(transformer|executor|strategy)\\.(call|delegatecall|execute)\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, "!function.body_contains_regex: '(?i)(decode.*data.*tokenId|_decodeTokenId|data\\.tokenId\\s*==\\s*tokenId|require.*tokenIdFromData\\s*==)'", {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — transform-data-not-validated-cross-position: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
