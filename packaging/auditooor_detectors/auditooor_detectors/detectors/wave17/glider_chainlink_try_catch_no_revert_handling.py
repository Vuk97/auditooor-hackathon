"""
glider-chainlink-try-catch-no-revert-handling — generated from reference/patterns.dsl/glider-chainlink-try-catch-no-revert-handling.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-chainlink-try-catch-no-revert-handling.yaml
Source: hexens-glider/chainlink-oracle-calls-without-proper-error-except
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderChainlinkTryCatchNoRevertHandling(AbstractDetector):
    ARGUMENT = "glider-chainlink-try-catch-no-revert-handling"
    HELP = "Chainlink `latestRoundData` / `getRoundData` is wrapped in a try/catch whose catch block silently swallows the error. If the feed reverts, the function returns stale/default zeros without alerting the protocol."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-chainlink-try-catch-no-revert-handling.yaml"
    WIKI_TITLE = "Chainlink try/catch with empty catch — silent oracle failure"
    WIKI_DESCRIPTION = "Wrapping `latestRoundData` in `try/catch` is sound only if the catch branch either reverts, triggers a fallback oracle, or sets a safe state. An empty `catch {}` or `catch { /* no-op */ }` converts a feed revert into a silent zero price, which every downstream `_usd = amount * price / 1e8` collapses into 0 — enabling under-priced liquidations and free collateral."
    WIKI_EXPLOIT_SCENARIO = "Feed is under maintenance and reverts for a short window. Contract's try/catch swallows the failure; `getCollateralValue` returns 0 for the affected asset; attacker opens a zero-collateral borrow against it."
    WIKI_RECOMMENDATION = "Either drop the try/catch (let the tx revert) or implement a concrete fallback: `catch { (price, ts) = _backupFeed.latestRoundData(); }`. Never leave the catch empty."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'latestRoundData|getRoundData|AggregatorV3'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': 'try\\s+\\w+\\s*\\.\\s*(latestRoundData|getRoundData)\\s*\\([^\\)]*\\)'}, {'function.body_not_contains_regex': 'catch\\s*(\\(|Error\\s*\\(|Panic\\s*\\(|\\{[^\\}]*revert|\\{[^\\}]*require|\\{[^\\}]*fallback|\\{[^\\}]*backup|\\{[^\\}]*_[a-zA-Z]*FallbackPrice)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-chainlink-try-catch-no-revert-handling: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
