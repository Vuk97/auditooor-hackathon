"""
minting-unrestricted — generated from reference/patterns.dsl/minting-unrestricted.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py minting-unrestricted.yaml
Source: solodit-cluster/C0275
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MintingUnrestricted(AbstractDetector):
    ARGUMENT = "minting-unrestricted"
    HELP = "Public/external mint-like function writes to balance/supply state with no access-control modifier."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/minting-unrestricted.yaml"
    WIKI_TITLE = "Unrestricted token minting"
    WIKI_DESCRIPTION = "A public or external function whose name matches the mint/issue family increases balance or supply state without any access-control modifier (onlyOwner, onlyRole, onlyMinter, etc.). Anyone can call it and mint tokens at will, instantly destroying the token's value."
    WIKI_EXPLOIT_SCENARIO = "Attacker calls the unrestricted mint function from any EOA, minting an arbitrary balance to themselves. They then dump the minted tokens on a DEX, extracting all liquidity before anyone notices."
    WIKI_RECOMMENDATION = "Add an access-control modifier (onlyOwner, onlyRole(MINTER_ROLE), or a role-checked require) to every externally-callable mint entry point. If _mint must remain internal, verify no public wrapper forwards to it without guards."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(mint|_mint|mintTokens|mintTo|mintFor|mintMany|mintBatch|mintPublic|issueTokens|issue|_issue|issueTo|issueMany)$'}, {'function.writes_storage_matching': '(balance|supply|total)'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyRole', 'hasRole', 'onlyAdmin', 'onlyMinter', 'onlyGovernance', 'onlyGovernor', 'authorized', 'restricted', 'onlyAuthorized', 'requiresAuth', 'auth'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — minting-unrestricted: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
