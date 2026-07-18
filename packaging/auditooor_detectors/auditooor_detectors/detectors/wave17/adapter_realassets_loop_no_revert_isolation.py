"""
adapter-realassets-loop-no-revert-isolation — generated from reference/patterns.dsl/adapter-realassets-loop-no-revert-isolation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py adapter-realassets-loop-no-revert-isolation.yaml
Source: auditooor-R110-morpho-MorphoMarketV1Adapter
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AdapterRealassetsLoopNoRevertIsolation(AbstractDetector):
    ARGUMENT = "adapter-realassets-loop-no-revert-isolation"
    HELP = "Vault adapter's `realAssets()` (or sibling aggregator) iterates over an on-chain market/strategy list and accumulates an external view call per element with no `try`/`catch` isolation. A single revert in any one element (broken IRM, bricked oracle, OOG) propagates to the entire aggregator, which pro"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/adapter-realassets-loop-no-revert-isolation.yaml"
    WIKI_TITLE = "Adapter `realAssets()` loop reverts entire vault accrual when any element reverts"
    WIKI_DESCRIPTION = "Aggregator-over-external-views: a vault adapter (or basket strategy / multi-market index) reports its assets to the parent vault by looping over a stored list of markets / vaults / strategies and summing per-element external view calls (`MorphoBalancesLib.expectedSupplyAssets(...)`, `IERC4626.previewRedeem(IERC4626.balanceOf(self))`, etc.). Solidity's default no-isolation execution means: any one "
    WIKI_EXPLOIT_SCENARIO = "Curator adds 6 Morpho Blue markets to a VaultV2 with `MorphoMarketV1Adapter`. Market #4 uses `OracleX`. After 9 months, `OracleX` operator stops paying Chainlink node fees and `latestRoundData()` starts reverting. Attacker (or simple time-passage) triggers any vault interaction. `accrueInterest()` calls `adapter.realAssets()`, which loops; iteration `i=4` calls `expectedSupplyAssets` → Morpho `_is"
    WIKI_RECOMMENDATION = "Wrap the per-element external call in `try`/`catch` so one bricked element only loses ITS contribution, not the whole vault: `try IERC4626(market).previewRedeem(shares) returns (uint256 v) { total += v; } catch { /* optionally: fall back to last-known-value or skip */ }`. Document the fallback seman"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Adapter|Strategy|Aggregator|Vault|Allocator'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(_?realAssets|_?totalAssets|_?expectedAssets|_?expectedSupplyAssets|_?underlyingAssets|_?aggregateAssets|_?indexValue)$'}, {'function.state_mutability': 'view'}, {'function.body_contains_regex': 'for\\s*\\(\\s*uint\\d*\\s+i\\s*=?\\s*\\d*\\s*;\\s*i\\s*<\\s*\\w+\\.length\\s*;[^)]*\\)|for\\s*\\(\\s*uint\\d*\\s+i\\s*;\\s*i\\s*<\\s*\\w+\\.length\\s*;[^)]*\\)'}, {'function.body_contains_regex': '\\+=\\s*[\\w.]+\\s*\\(|\\+=\\s*\\w+Lib\\.\\w+\\(|\\+=\\s*IERC4626\\(|\\+=\\s*IERC20\\(|\\+=\\s*IMarket\\(|\\+=\\s*MorphoBalancesLib|expectedSupplyAssets|previewRedeem|convertToAssets'}, {'function.body_not_contains_regex': '\\btry\\s+\\w+\\.\\w+|\\btry\\s+IERC|\\bcatch\\s*\\{|catch\\s*\\(|gasleft\\s*\\(\\s*\\)\\s*<'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — adapter-realassets-loop-no-revert-isolation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
