"""
w69-vault-share-mint-division-before-multiplication — generated from reference/patterns.dsl/w69-vault-share-mint-division-before-multiplication.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py w69-vault-share-mint-division-before-multiplication.yaml
Source: W69 Phase-E weak-class recall lift - production vault share arithmetic shape
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class W69VaultShareMintDivisionBeforeMultiplication(AbstractDetector):
    ARGUMENT = "w69-vault-share-mint-division-before-multiplication"
    HELP = "Vault deposit computes shares as assets / totalAssets() * totalSupply(), so small deposits round shares to zero before transferring assets and minting zero shares: an arithmetic bug causing fund loss."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/w69-vault-share-mint-division-before-multiplication.yaml"
    WIKI_TITLE = "Vault share mint divides before multiplying"
    WIKI_DESCRIPTION = "A vault deposit path calculates `shares = assets / totalAssets() * totalSupply()` before pulling assets and minting shares. When `assets < totalAssets()`, integer division rounds to zero; the user transfers assets and receives zero shares. The precise production-source shape is a deposit/join entrypoint with division-before-multiplication share math, SafeERC20 transferFrom, `_mint(receiver, shares"
    WIKI_EXPLOIT_SCENARIO = "Vault deposit computes shares as assets / totalAssets() * totalSupply(), so small deposits round shares to zero before transferring assets and minting zero shares: an arithmetic bug causing fund loss."
    WIKI_RECOMMENDATION = "Compute shares with full-precision multiplication before division, preferably `mulDiv`, and reject zero-share deposits."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(deposit|vault|share|totalAssets|totalSupply|safeTransferFrom)'}, {'contract.source_matches_regex': '_mint\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(deposit|join|stake|mintShares)$'}, {'function.body_ordered_regex': {'first': '\\bshares\\s*=\\s*assets\\s*/\\s*totalAssets\\s*\\(\\s*\\)\\s*\\*\\s*totalSupply\\s*\\(\\s*\\)', 'second': 'safeTransferFrom\\s*\\(', 'ignore_comments_and_strings': True}}, {'function.body_contains_regex': '_mint\\s*\\(\\s*receiver\\s*,\\s*shares\\s*\\)'}, {'function.body_not_contains_regex': '(?i)ZeroShares|shares\\s*==\\s*0|shares\\s*>\\s*0|Math\\.mulDiv|mulDiv|assets\\s*\\*\\s*totalSupply\\s*\\(\\s*\\)\\s*/\\s*totalAssets\\s*\\(\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — w69-vault-share-mint-division-before-multiplication: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
