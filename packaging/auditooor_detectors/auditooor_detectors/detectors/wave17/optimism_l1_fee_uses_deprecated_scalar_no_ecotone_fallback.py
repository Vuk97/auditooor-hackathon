"""
optimism-l1-fee-uses-deprecated-scalar-no-ecotone-fallback — generated from reference/patterns.dsl/optimism-l1-fee-uses-deprecated-scalar-no-ecotone-fallback.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py optimism-l1-fee-uses-deprecated-scalar-no-ecotone-fallback.yaml
Source: lisa-mine-r99-case-00308-sherlock-perennial-v2-3-2024-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OptimismL1FeeUsesDeprecatedScalarNoEcotoneFallback(AbstractDetector):
    ARGUMENT = "optimism-l1-fee-uses-deprecated-scalar-no-ecotone-fallback"
    HELP = "Optimism L1-fee accounting calls `OptGasInfo.scalar()` directly. After the Ecotone upgrade (March 2024) Optimism's `GasPriceOracle.scalar()` was deprecated and reverts with `GasPriceOracle: scalar() is deprecated`. Any contract that calls it on the new fee oracle DoSes — typically the on-chain fee-c"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/optimism-l1-fee-uses-deprecated-scalar-no-ecotone-fallback.yaml"
    WIKI_TITLE = "Calls deprecated `OptGasInfo.scalar()` — reverts post-Ecotone"
    WIKI_DESCRIPTION = "Pattern fires on functions whose body calls `<oracle>.scalar()` where `<oracle>` is an Optimism / OP-stack `OptGasInfo` / `GasPriceOracle` instance, AND the function does NOT wrap the call in a try/catch nor branch on the post-Ecotone API (`baseFeeScalar` / `blobBaseFeeScalar` / `isEcotone` flag / `isFjord`). On Optimism mainnet (and Base, OP-stack rollups) this call started reverting after the Ma"
    WIKI_EXPLOIT_SCENARIO = "Perennial v2.3 deploys `Kept_Optimism` to OP mainnet. After Ecotone hits, every `keep()` reverts inside `_calldataFee` because `OPT_GAS.scalar()` returns the deprecation error. Order settlement halts; positions that should be closed (liquidations, expirations) sit open accruing PnL — the protocol must redeploy with the Ecotone-aware fee helper while users absorb mark-to-market losses on stuck posi"
    WIKI_RECOMMENDATION = "Either (a) use OP-stack's high-level helper `IGasPriceOracle.getL1Fee(callData)` which transparently handles pre-/post-Ecotone fee math, or (b) explicitly branch on the upgrade flag: `try OPT_GAS.isEcotone() returns (bool ecotone) { ... use baseFeeScalar+blobBaseFeeScalar ... } catch { ... legacy sc"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'OptGasInfo|GasPriceOracle|0x420000000000000000000000000000000000000F'}]
    _MATCH = [{'function.kind': 'any'}, {'function.not_slither_synthetic': True}, {'function.body_contains_regex': '\\b[A-Z_][A-Za-z0-9_]*\\s*\\.\\s*scalar\\s*\\(\\s*\\)'}, {'function.body_not_contains_regex': 'try\\s+[A-Z_][A-Za-z0-9_]*\\s*\\.\\s*scalar|isEcotone|isFjord|getL1FeeEcotone|baseFeeScalar|blobBaseFeeScalar|0x49948e0e'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — optimism-l1-fee-uses-deprecated-scalar-no-ecotone-fallback: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
