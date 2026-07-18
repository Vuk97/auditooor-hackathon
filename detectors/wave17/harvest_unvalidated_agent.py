"""
harvest-unvalidated-agent — generated from reference/patterns.dsl/harvest-unvalidated-agent.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py harvest-unvalidated-agent.yaml
Source: solodit-novel/slice_aa-Astrolab
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HarvestUnvalidatedAgent(AbstractDetector):
    ARGUMENT = "harvest-unvalidated-agent"
    HELP = "`harvest(address agent)` / `execute(target)` invokes an arbitrary `agent` via low-level call without verifying it against a whitelist. Attacker passes a malicious contract to drain funds via `delegatecall` storage hijack or authorize false reward claims."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/harvest-unvalidated-agent.yaml"
    WIKI_TITLE = "Harvest/execute accepts unvalidated external agent address"
    WIKI_DESCRIPTION = "Strategies and keeper networks often parametrize the executor address. Without `require(isAgent[agent])` or equivalent whitelist, anyone can pass a contract that mints phantom rewards, transfers approved tokens, or drains via delegatecall."
    WIKI_EXPLOIT_SCENARIO = "Keeper calls `harvest(maliciousAgent)`. `maliciousAgent.harvest()` returns fake `(profit, loss)` triple. Vault thinks it earned 10M USDC, mints shares accordingly, then withdraw by attacker."
    WIKI_RECOMMENDATION = "Whitelist agents via `mapping(address=>bool) isAgent` with admin-only setter. Add `require(isAgent[agent])` first."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'isAgent|agents|strategy'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(harvest|execute|callAgent|delegate|forward)'}, {'function.has_param_name_matching': 'agent|target|executor|strategy'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': '\\w+\\.(call|delegatecall|staticcall)\\s*[\\({]'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*isAgent|require\\s*\\(\\s*agents\\s*\\[|whitelist\\s*\\[|require\\s*\\(\\s*\\w+\\s*==\\s*(strategy|approvedAgent)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — harvest-unvalidated-agent: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
