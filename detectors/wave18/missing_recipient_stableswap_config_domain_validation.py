"""
missing-recipient-stableswap-config-domain-validation — generated from reference/patterns.dsl/missing-recipient-stableswap-config-domain-validation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py missing-recipient-stableswap-config-domain-validation.yaml
Source: phase-g-external-recall-worker-ak-2026-05-17
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MissingRecipientStableswapConfigDomainValidation(AbstractDetector):
    ARGUMENT = "missing-recipient-stableswap-config-domain-validation"
    HELP = "StableSwap factory/constructor accepts amp or hook fee domain parameters without rejecting zero amp or dynamic-fee sentinel values before deployment/math use."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/missing-recipient-stableswap-config-domain-validation.yaml"
    WIKI_TITLE = "StableSwap config parameter domain validation is missing"
    WIKI_DESCRIPTION = "A StableSwap-style deployment or constructor path accepts externally supplied amp or fee-domain parameters and forwards them into pool/hook state while only checking an upper bound or creation-code hash. Zero amp and Uniswap v4 dynamic-fee sentinel values are not valid arithmetic-domain inputs; accepting them can brick swaps, block ramp recovery, or make fee math use sentinel encodings as percenta"
    WIKI_EXPLOIT_SCENARIO = "A pool is deployed with baseAmp set to zero or lpFeePercentage set to a v4 dynamic-fee sentinel. The deployment succeeds because the factory/constructor validates only code hash or the high side of the range. Later swaps or ramp updates hit amp-derived denominators or fee arithmetic that cannot handle the accepted value, causing pool liveness failure or impossible fee calculation."
    WIKI_RECOMMENDATION = "Validate config domains at the external factory/constructor boundary: require amp > 0 and amp < MAX_AMP, and require fee values to be inside the arithmetic fee range while explicitly rejecting v4 sentinel encodings before building PoolKey or storing hook fee state."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(StableSwap|PoolKey|Create2|Hooks|baseAmp|lpFeePercentage|FEE_PRECISION|AMP_PRECISION)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.has_param_name_matching': '(?i)^_?(baseAmp|amp|lpFeePercentage|feePercentage)$'}, {'function.body_contains_regex': '(?i)(?:_?baseAmp[\\s\\S]{0,160}(?:>=|>)\\s*MAX_AMP|(?:keccak256\\s*\\(\\s*_creationCode\\s*\\)|Create2\\.deploy|abi\\.encodePacked|abi\\.encode\\s*\\()[\\s\\S]{0,900}_?lpFeePercentage|_?lpFeePercentage[\\s\\S]{0,900}(?:Create2\\.deploy|abi\\.encodePacked|abi\\.encode\\s*\\())'}, {'function.body_not_contains_regex': '(?i)(?:_?baseAmp\\s*==\\s*0|0\\s*==\\s*_?baseAmp|_?baseAmp\\s*(?:<=|<)\\s*0|require\\s*\\([^;]*_?baseAmp[^;]*(?:>|>=|!=)\\s*0|_?lpFeePercentage\\s*(?:<=|<)\\s*(?:MAX_|LPFeeLibrary\\.MAX|1_000_000|1000000)|DYNAMIC_FEE_FLAG|isDynamicFee|MAX_LP_FEE)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|harness)\\b'}]

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
                info = [f, f" — missing-recipient-stableswap-config-domain-validation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
