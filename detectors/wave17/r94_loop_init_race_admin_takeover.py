"""
r94-loop-init-race-admin-takeover — generated from reference/patterns.dsl/r94-loop-init-race-admin-takeover.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-init-race-admin-takeover.yaml
Source: loop-cycle-6-solidity-sibling-of-frontrun_initialize_takeover
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopInitRaceAdminTakeover(AbstractDetector):
    ARGUMENT = "r94-loop-init-race-admin-takeover"
    HELP = "NOT_SUBMIT_READY detector-fixture-smoke-only: flags public/external initialize-style functions that persist admin/owner with only an initialized-flag gate and no deployer/factory binding."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-init-race-admin-takeover.yaml"
    WIKI_TITLE = "Initializer race allows first caller to seize admin ownership"
    WIKI_DESCRIPTION = "Detector-fixture-smoke-only. NOT_SUBMIT_READY. This row stays intentionally narrow and only proves the owned Solidity shape where a public/external initialize path persists admin/owner authority under an initialized-flag gate without a deployer/factory caller binding."
    WIKI_EXPLOIT_SCENARIO = "A contract exposes `initialize(address newOwner)` publicly and guards only with `require(!initialized)`. The first external caller sets privileged ownership before the intended deployer can initialize, permanently taking admin control."
    WIKI_RECOMMENDATION = "Bind initialization to a trusted deployer/factory or atomically initialize during deployment. Keep this row NOT_SUBMIT_READY and advisory-only until evidence expands beyond the owned fixture pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(initialize|initializer|AlreadyInitialized)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(initialize|init|setup|bootstrap)$'}, {'function.source_matches_regex': '(owner|admin|minter|governor|authority)\\s*=\\s*(\\w+|msg\\.sender)|\n_setupRole\\s*\\(\\s*[A-Z_]+,\\s*\\w+\\s*\\)|\n_grantRole\\s*\\(\\s*[A-Z_]+,\\s*\\w+\\s*\\)\n'}, {'function.not_source_matches_regex': 'require\\s*\\(\\s*msg\\.sender\\s*==\\s*(factory|deployer|creator|DEPLOYER)|\nonlyFactory|onlyDeployer|onlyCreator\n'}, {'function.source_matches_regex': 'require\\s*\\(\\s*!\\s*initialized|initializer|_disableInitializers|\nAlreadyInitialized|has_been_initialized\n'}]

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
                info = [f, f" — r94-loop-init-race-admin-takeover: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
