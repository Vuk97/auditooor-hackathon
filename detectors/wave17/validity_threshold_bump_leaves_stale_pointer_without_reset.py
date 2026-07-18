"""
validity-threshold-bump-leaves-stale-pointer-without-reset — generated from reference/patterns.dsl/validity-threshold-bump-leaves-stale-pointer-without-reset.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py validity-threshold-bump-leaves-stale-pointer-without-reset.yaml
Source: auditooor-R111-base-azul-FN-B-stale-anchor
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ValidityThresholdBumpLeavesStalePointerWithoutReset(AbstractDetector):
    ARGUMENT = "validity-threshold-bump-leaves-stale-pointer-without-reset"
    HELP = "An external lever bumps a validity-threshold storage slot (retirementTimestamp / freshnessFloor / minValidEpoch) used to mark previous state as invalid, but does NOT atomically clear the currently-pointed canonical object pointer (anchorGame / latestFeed / currentRoot). A raw-reader getter keeps ser"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/validity-threshold-bump-leaves-stale-pointer-without-reset.yaml"
    WIKI_TITLE = "Forward-only validity-threshold bump leaves a stale canonical pointer the contract itself rejects"
    WIKI_DESCRIPTION = "An external function performs a 'blanket invalidation' by bumping a forward-only timestamp / epoch / block-number storage slot (`retirementTimestamp`, `freshnessFloor`, `minValidEpoch`, `nullificationEpoch`). Under the contract's own validity predicates, every pre-existing element is now invalid. But a separate canonical-pointer slot (`anchorGame`, `latestFeed`, `currentRoot`) was set BEFORE the b"
    WIKI_EXPLOIT_SCENARIO = "An optimistic-rollup AnchorStateRegistry exposes `updateRetirementTimestamp()` (Guardian-only blanket invalidation). After a bad-resolution incident the Guardian calls it: `retirementTimestamp = block.timestamp`. Every existing dispute game now has `isGameRetired(g) == true` so `isGameClaimValid(g) == false`. But the `anchorGame` storage slot still points at the pre-bump anchor. `getAnchorRoot()` "
    WIKI_RECOMMENDATION = "Make the threshold-bump and pointer-clear atomic:\n\n```solidity\nfunction updateRetirementTimestamp() external onlyGuardian {\n    retirementTimestamp = uint64(block.timestamp);\n    anchorGame = IGame(address(0));      // atomic clear\n    emit RetirementTimestampSet(block.timestamp);\n    emit An"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Registry|Anchor|Aggregator|Oracle|Feed|Permission|RootKeeper|Snapshot|Validity|Threshold|Recoverable|Token)'}, {'contract.source_matches_regex': '(?i)\\b(anchorGame|latestFeed|currentSource|activeFeed|lastValidProof|currentRoot|currentAnchor|trustedSource|canonicalRoot)\\b'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '(?i)\\b(retirementTimestamp|nullificationEpoch|freezeBlock|revokedAt|minValidTimestamp|invalidatedAt|stalenessFloor|freshnessFloor|firstValidRound|minValidEpoch)\\s*=\\s*[^;]+;'}, {'function.body_not_contains_regex': '(?i)\\b(anchorGame|latestFeed|currentSource|activeFeed|lastValidProof|currentRoot|currentAnchor|trustedSource|canonicalRoot)\\s*=\\s*(address\\(0\\)|IGame\\(address\\(0\\)\\)|0|bytes32\\(0\\))|\\bdelete\\s+(anchorGame|latestFeed|currentSource|activeFeed|lastValidProof|currentRoot|currentAnchor|trustedSource|canonicalRoot)\\b'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — validity-threshold-bump-leaves-stale-pointer-without-reset: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
