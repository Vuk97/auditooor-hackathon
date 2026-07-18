"""
art-settings-mutable-after-mint-harms-holders — generated from reference/patterns.dsl/art-settings-mutable-after-mint-harms-holders.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py art-settings-mutable-after-mint-harms-holders.yaml
Source: auditooor-R75-code4rena-2024-08-phi-14
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ArtSettingsMutableAfterMintHarmsHolders(AbstractDetector):
    ARGUMENT = "art-settings-mutable-after-mint-harms-holders"
    HELP = "Creator can mutate royalty/soulbound/URI after mints — no cap or time-lock — retroactively harming holders who bought under different terms."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/art-settings-mutable-after-mint-harms-holders.yaml"
    WIKI_TITLE = "updateArtSettings has no caps or pre-mint gate, letting creator retroactively harm holders"
    WIKI_DESCRIPTION = "`updateArtSettings` lets the creator change royaltyBps, soulbound flag, and URI at any time. Holders bought based on the at-mint terms but the creator can later (a) lock the token (soulbound = true) to trap holders, (b) set royaltyBps = 10_000 to capture all resale value, (c) repoint URI to a different (malicious or defaced) asset. No cap is enforced and the function works even after the first min"
    WIKI_EXPLOIT_SCENARIO = "Creator deploys art with 5% royalty and normal transferable status. 1000 NFTs mint at 0.1 ETH each (100 ETH volume). Creator calls updateArtSettings with royaltyBps = 9500. Secondary resale of 50 ETH takes 47.5 ETH as royalty. Alternatively creator sets soulbound = true — holders cannot sell at all."
    WIKI_RECOMMENDATION = "Enforce a MAX_ROYALTY_BPS (e.g. 1000). Freeze critical flags (soulbound, URI) after first mint or the auction's end. Implement a timelock with holder-vote for any setting that affects existing mints."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)updateArtSettings|updateTokenSettings|setRoyalty\\w*|setSoulbound|setURI'}, {'function.body_contains_regex': '(?i)onlyArtCreator|onlyCreator|onlyArtist|onlyOwner'}, {'function.body_contains_regex': '(?i)(royalty|soulBounded|uri|mintFee|maxSupply)\\s*='}, {'function.body_not_contains_regex': '(?i)require\\s*\\([^)]*totalSupply\\s*(==|<=)\\s*0|require\\s*\\([^)]*before\\w*Mint|require\\s*\\([^)]*royalty\\w*\\s*<=\\s*\\d+|MAX_ROYALTY_BPS'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — art-settings-mutable-after-mint-harms-holders: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
