"""
related-bps-config-invariant-missing — generated from reference/patterns.dsl/related-bps-config-invariant-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py related-bps-config-invariant-missing.yaml
Source: oz-2025-graph-disputemanager-fishermancut-vs-maxverifiercut
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RelatedBpsConfigInvariantMissing(AbstractDetector):
    ARGUMENT = "related-bps-config-invariant-missing"
    HELP = "A contract has two related bps/cut/fee/cap config variables with independent setters; neither setter cross-validates the inter-variable invariant (e.g. `fishermanRewardCut <= maxVerifierCut`); and a downstream function combines both in arithmetic. Configurations that violate the implicit invariant c"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/related-bps-config-invariant-missing.yaml"
    WIKI_TITLE = "Related bps/cut config setters lack cross-variable invariant"
    WIKI_DESCRIPTION = "A contract maintains two basis-point or cut configuration variables that are implicitly related — e.g. fishermanRewardCut + maxVerifierCut, protocolFeeBps + maxFeeBps, liquidatorFeeCap + liquidatorFeePct — with independent setters. Each setter validates only its own variable (or nothing at all) and never references the sibling. A downstream function then uses both in arithmetic where the implicit "
    WIKI_EXPLOIT_SCENARIO = "Governance multisig accepts a proposal to bump `fishermanRewardCut` from 50_000 PPM to 600_000 PPM (60%). The setter validates that the new value is below MAX_PPM (1_000_000) — passes. Nothing checks against `maxVerifierCut`, which is still 500_000 PPM (50%). When a dispute is later accepted, slash() computes `fishermanShare = slashAmount * 600_000 / 1_000_000` and `verifierBudget = provisionToken"
    WIKI_RECOMMENDATION = "When two bps/cut/fee/cap variables are co-arithmetic in any downstream function, the setter for either MUST cross-validate against the sibling: `require(newFishermanCut <= maxVerifierCut, 'invariant');`. Better: refactor to a single `setCuts(fishermanCut, verifierCut)` function that takes both and v"

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\b(uint256|uint96|uint64|uint32|uint16)\\s+(public\\s+|internal\\s+|private\\s+)?\\w*(Cut|Bps|Fee|Cap|Rate|Pct|Percentage|Ppm)\\b'}, {'contract.has_function_body_matching': '(\\w*(Cut|Bps|Fee|Cap|Rate|Pct|Percentage|Ppm))\\s*[\\*\\/\\+\\-]\\s*\\w+|\\w+\\s*[\\*\\/\\+\\-]\\s*\\w*(Cut|Bps|Fee|Cap|Rate|Pct|Percentage|Ppm)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(set|update|configure|_set)[A-Z][A-Za-z0-9]*(Cut|Bps|Fee|Cap|Rate|Pct|Percentage|Ppm)[A-Za-z0-9]*$'}, {'function.writes_storage_matching': '(Cut|Bps|Fee|Cap|Rate|Pct|Percentage|Ppm)'}, {'function.body_not_contains_regex': 'require\\s*\\([^)]*(<=?|>=?|<|>)\\s*(?-i:[a-z])[a-zA-Z0-9_]*(?-i:Cut|Bps|Fee|Cap|Rate|Pct|Percentage|Ppm)\\b|if\\s*\\([^)]*(?-i:[a-z])[a-zA-Z0-9_]*(?-i:Cut|Bps|Fee|Cap|Rate|Pct|Percentage|Ppm)\\b[^)]*\\)\\s*\\{?\\s*revert'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — related-bps-config-invariant-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
