"""
timelock-calldata-whitelist-partial-coverage-hotsigner-bypass — generated from reference/patterns.dsl/timelock-calldata-whitelist-partial-coverage-hotsigner-bypass.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py timelock-calldata-whitelist-partial-coverage-hotsigner-bypass.yaml
Source: auditooor-R75-c4-mined-2024-10-kleidi-10
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TimelockCalldataWhitelistPartialCoverageHotsignerBypass(AbstractDetector):
    ARGUMENT = "timelock-calldata-whitelist-partial-coverage-hotsigner-bypass"
    HELP = "A timelock/hot-signer scheme lets the timelock register `addCalldataCheck(target, selector, startIndex, endIndex, allowedBytes)` — a per-byte-range whitelist. `execute()` by a hot signer validates only the ranges that have entries. Parameters in the selector that are NOT covered by any range pass un"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/timelock-calldata-whitelist-partial-coverage-hotsigner-bypass.yaml"
    WIKI_TITLE = "Timelock per-index calldata whitelist leaves uncovered parameters fully bypassable"
    WIKI_DESCRIPTION = "Timelock.addCalldataCheck(target, selector, startIndex, endIndex, data) whitelists a contiguous byte range of a calldata payload. Multiple ranges can be added to cover multiple parameters. The _checkCalldata hook in execute() only verifies ranges that have been registered. For a function `foo(address a, uint256 b)`, the timelock schedules two addCalldataCheck ops (one for [4,36), one for [36,68))."
    WIKI_EXPLOIT_SCENARIO = "Safe owners schedule two ops: (1) addCalldataCheck(addr=DEX, sel=swap, [4,36), allowed={USDC}) and (2) addCalldataCheck(DEX, swap, [36,68), allowed={100e6}). Hot signer executes only op (1). Now swap is whitelisted as long as the token is USDC; the amount parameter is unrestricted. Hot signer calls `DEX.swap(USDC, protocolTreasuryBalance)` — drains protocol treasury because the amount check never "
    WIKI_RECOMMENDATION = "Enforce full calldata coverage: in _checkCalldata, compute `coveredLength = sum(endIdx-startIdx for registered ranges)` and require it equals `calldata.length - 4` (i.e., every byte of params covered). addCalldataCheck must be atomic per-selector: all parameter ranges must be added in a single tx (o"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Timelock|CalldataCheck|addCalldataCheck|hotSigner|HotSigner'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '^(execute|executeWhitelisted|_executeWhitelisted|checkCalldata|_checkCalldata)$'}, {'function.body_contains_regex': 'calldataCheck|startIndex|endIndex|dataHashes'}, {'function.body_not_contains_regex': '(fullCalldataCoverage|verifyFullSelector|require\\s*\\(\\s*coverage\\s*==\\s*calldata\\.length|assertFullCoverage|totalCoveredLength\\s*==)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — timelock-calldata-whitelist-partial-coverage-hotsigner-bypass: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
