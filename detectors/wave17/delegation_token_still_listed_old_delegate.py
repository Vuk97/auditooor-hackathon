"""
delegation-token-still-listed-old-delegate - generated from reference/patterns.dsl/delegation-token-still-listed-old-delegate.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py delegation-token-still-listed-old-delegate.yaml
Source: solodit-8730-c4-golom-array-retention-split
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DelegationTokenStillListedOldDelegate(AbstractDetector):
    ARGUMENT = "delegation-token-still-listed-old-delegate"
    HELP = "NOT_SUBMIT_READY fixture-smoke detector: redelegation rewrites a token delegate and appends the token to the new delegate list without removing it from the old delegate list."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/delegation-token-still-listed-old-delegate.yaml"
    WIKI_TITLE = "Delegated token remains listed under old delegate"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Delegation systems that store per-delegate token lists must remove a token from the old delegate before appending it to the new delegate. If the old list entry remains live, vote accounting can count the same token under multiple delegates."
    WIKI_EXPLOIT_SCENARIO = "A token holder delegates token 1 to delegate A, then delegates token 1 to delegate B. The contract rewrites `delegatedTo[1]` and pushes token 1 into B's list, but never removes token 1 from A's list. Vote tally code that iterates both lists can count token 1 twice."
    WIKI_RECOMMENDATION = "Before writing the new delegation edge or appending to the destination list, remove the token from the old delegate's list with a swap-and-pop helper or a canonical move-delegation helper. Add a regression test that repeated redelegation of one token cannot increase total delegated voting power."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(delegate|redelegat|delegatedTo|delegateOf|delegationOf|delegatedTokenIds|delegateTokenIds|tokensByDelegate|tokenIdsByDelegate|nftsByDelegate|locksByDelegate|checkpoints)'}, {'contract.source_matches_regex': '(?i)(push\\s*\\(|oldDelegate|currentDelegate|previousDelegate|priorDelegate)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(delegate|redelegate|setDelegate|changeDelegate|updateDelegation|moveDelegation|assignDelegate|reassignDelegate)$'}, {'function.source_matches_regex': '(?is)(oldDelegate|currentDelegate|previousDelegate|priorDelegate|fromDelegate)\\s*=\\s*(delegatedTo|delegateOf|delegationOf|tokenDelegate|tokenDelegates)\\s*\\[[^\\]]+\\]'}, {'function.source_matches_regex': '(?is)(delegatedTo|delegateOf|delegationOf|tokenDelegate|tokenDelegates)\\s*\\[[^\\]]+\\]\\s*=\\s*(newDelegate|newDelegatee|toDelegate|toTokenId|delegatee|delegateTo|to)'}, {'function.source_matches_regex': '(?is)((delegatedTokenIds|delegateTokenIds|tokensByDelegate|tokenIdsByDelegate|nftsByDelegate|locksByDelegate)\\s*\\[[^\\]]+\\]\\s*\\.push\\s*\\([^\\)]*(tokenId|lockId|nftId|sourceId)[^\\)]*\\)|\\.(delegatedTokenIds|delegateTokenIds|tokens|tokenIds|nfts|locks)\\s*\\.push\\s*\\([^\\)]*(tokenId|lockId|nftId|sourceId)[^\\)]*\\))'}, {'function.not_source_matches_regex': '(?is)(removeDelegation|_removeDelegation|removeTokenFromDelegate|_removeTokenFromDelegate|detachDelegate|clearOldDelegate|deleteOldDelegate|removeFromOldDelegate|removeOldDelegate|swapAndPop|swap\\s*and\\s*pop|_moveDelegateVotes|moveDelegateVotes|moveDelegationPower)\\s*\\('}, {'function.not_source_matches_regex': '(?is)\\.(pop)\\s*\\(|delete\\s+(delegatedTokenIds|delegateTokenIds|tokensByDelegate|tokenIdsByDelegate|nftsByDelegate|locksByDelegate)\\s*\\['}, {'function.not_in_skip_list': True}, {'function.not_slither_synthetic': True}]

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
                info = [f, f" - delegation-token-still-listed-old-delegate: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
