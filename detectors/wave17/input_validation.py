"""
input-validation — generated from reference/patterns.dsl/input-validation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py input-validation.yaml
Source: g1-002-solodit-30522-safe-fallback-handler
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InputValidation(AbstractDetector):
    ARGUMENT = "input-validation"
    HELP = "Safe guard observes setFallbackHandler(address) transaction data without rejecting or allowlisting the supplied fallback handler."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/input-validation.yaml"
    WIKI_TITLE = "Safe fallback handler setter missing address guard"
    WIKI_DESCRIPTION = "A Safe guard or rental guard inspects transaction data containing setFallbackHandler(address) but does not reject the selector or validate the decoded handler address against a trusted allowlist. In rental or delegated custody systems this lets a borrower route fallback callbacks through attacker-controlled code."
    WIKI_EXPLOIT_SCENARIO = "A renter submits Safe transaction calldata for setFallbackHandler(address) with their own handler address. The guard notices the selector but only checks unrelated fields, so the Safe installs the attacker handler. Later ERC721/ERC1155 callbacks route through that handler and can be abused to hijack borrowed assets."
    WIKI_RECOMMENDATION = "When guard calldata targets setFallbackHandler(address), either revert outright or decode the handler parameter and require it to equal a trusted handler / configured allowlist entry."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)\\b(BaseGuard|SafeGuard|IGuard|Guard|GnosisSafe|ISafe|Enum\\.Operation)\\b'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(checkTransaction|checkSafeCall|preExec|preExecution|validateSafeTx|validateTransaction|checkAfterExecution)$'}, {'function.source_matches_regex': '(?is)(setFallbackHandler\\s*\\(|SET_FALLBACK_HANDLER_SELECTOR|0xf08a0323|fallbackHandler\\s*=)'}, {'function.source_matches_regex': '(?is)(bytes\\s+(calldata|memory)\\s+(data|transactionData|safeTxData)|Enum\\.Operation|operation)'}, {'function.not_source_matches_regex': '(?is)(allowedFallbackHandlers?\\s*\\[|isAllowedFallbackHandler\\s*\\(|trustedFallbackHandler\\b|require\\s*\\([^;]*(handler|newHandler|fallbackHandler)[^;]*(==|!=|allowed|trusted)|if\\s*\\([^)]*(setFallbackHandler|SET_FALLBACK_HANDLER_SELECTOR|0xf08a0323)[^)]*\\)\\s*\\{[^{}]*(revert|require)|revert\\s+\\w*\\s*\\([^;]*(handler|fallback))'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — input-validation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
