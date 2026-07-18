"""
comet-configurator-immutability-sentinel-on-mutable-field — generated from reference/patterns.dsl/comet-configurator-immutability-sentinel-on-mutable-field.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py comet-configurator-immutability-sentinel-on-mutable-field.yaml
Source: auditooor-R71-fixdiff-mined-compound-comet-814100b600
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CometConfiguratorImmutabilitySentinelOnMutableField(AbstractDetector):
    ARGUMENT = "comet-configurator-immutability-sentinel-on-mutable-field"
    HELP = "Contract gates 'already initialized' check on a field (`governor`) that is later mutable. If governance resets that field to address(0) via its own setter, the init guard is bypassed and the entire configuration — including supposedly immutable fields like `baseToken` and `trackingIndexScale` — can "
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/comet-configurator-immutability-sentinel-on-mutable-field.yaml"
    WIKI_TITLE = "Init-once sentinel on mutable field enables re-initialization"
    WIKI_DESCRIPTION = "A configurator / registry uses the pattern `if (oldConfiguration.governor != address(0)) revert ConfigurationAlreadyExists();` to detect whether a configuration slot has been populated. The problem is that `governor` is a mutable field: the same contract exposes a setter that lets the current governor (or, in a more elaborate attack, an adversarial proposal) reset it to `address(0)`. Once cleared,"
    WIKI_EXPLOIT_SCENARIO = "Comet Configurator originally used `if (oldConfiguration.governor != address(0)) revert ConfigurationAlreadyExists();` (see OpenZeppelin audit finding fixed in commit 814100b600). A malicious governance proposal (a) calls a `setGovernor(address(0))` / `removeGovernor` path exposed elsewhere in the codebase, (b) calls `setConfiguration(cometProxy, newConfiguration)` with a brand-new `baseToken` poi"
    WIKI_RECOMMENDATION = "Replace the sentinel with the genuinely immutable field: `if (oldConfiguration.baseToken != address(0)) revert ConfigurationAlreadyExists();`. Better: give the Configuration struct a dedicated `bool exists` or `uint256 version > 0` flag that no other code path writes to. Audit every 'first-time writ"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Configuration|ConfiguratorStorage|configuratorParams|setConfiguration'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(setConfiguration|registerConfiguration|initConfiguration|createMarket|addMarket)$'}, {'function.body_contains_regex': 'oldConfiguration\\.governor\\s*!=\\s*address\\(0\\)|oldConfig\\.governor\\s*!=\\s*address\\(0\\)|existing\\.governor\\s*!=\\s*address\\(0\\)|config\\.governor\\s*!=\\s*address\\(0\\)'}, {'function.body_not_contains_regex': 'oldConfiguration\\.baseToken\\s*!=\\s*address\\(0\\)|existing\\.baseToken\\s*!=\\s*address\\(0\\)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — comet-configurator-immutability-sentinel-on-mutable-field: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
