"""
r94-loop-mint-unrestricted — generated from reference/patterns.dsl/r94-loop-mint-unrestricted.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-mint-unrestricted.yaml
Source: loop-cycle-2-solidity-sibling-of-r94_unrestricted_mint
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopMintUnrestricted(AbstractDetector):
    ARGUMENT = "r94-loop-mint-unrestricted"
    HELP = (
        "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: public or "
        "external mint entrypoints that call `_mint` without an access-control "
        "modifier or inline caller check."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-mint-unrestricted.yaml"
    WIKI_TITLE = "Public mint path without access control"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row "
        "proves only the owned Solidity shape where a public or external "
        "`mint`/`mintTo`/`mintFor`/`issue` entrypoint reaches `_mint(...)` "
        "without a visible `onlyOwner`/`onlyRole`/`msg.sender == ...` gate in "
        "the same function. It does not yet claim corpus-backed impact beyond "
        "the fixture pair."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A caller invokes `mint(address to, uint256 amount)` and the function "
        "writes supply via `_mint(to, amount)` with no access-control modifier "
        "or inline authorization check. Any account can inflate token supply "
        "and assign it to an arbitrary recipient. This row remains fixture-smoke "
        "only."
    )
    WIKI_RECOMMENDATION = (
        "Add a role gate or explicit caller check before any mint call, and "
        "keep the row NOT_SUBMIT_READY until broader evidence exists."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    _PRECONDITIONS = [{'contract.source_matches_regex': '(_mint|\\bmint\\b|\\bissue\\b)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(mint|mintTo|mintFor|issue|airdrop|rewardMint)$'}, {'function.source_matches_regex': '_mint\\s*\\(|\\bmint\\s*\\('}, {'function.not_source_matches_regex': '(?i)(onlyOwner|onlyAdmin|onlyMinter|onlyGovernance|onlyRole|authOnly|whenNotPaused|nonReentrant)'}, {'function.not_source_matches_regex': 'require\\s*\\(\\s*(msg\\.sender\\s*==\\s*(owner|admin|minter|governance)|\nhasRole\\s*\\(|\\.isOwner\\s*\\(|\\.checkPerm\\s*\\()\n'}]

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
                info = [f, f" — r94-loop-mint-unrestricted: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
