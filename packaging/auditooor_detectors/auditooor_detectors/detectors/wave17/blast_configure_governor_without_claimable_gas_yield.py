"""
blast-configure-governor-without-claimable-gas-yield — generated from reference/patterns.dsl/blast-configure-governor-without-claimable-gas-yield.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py blast-configure-governor-without-claimable-gas-yield.yaml
Source: lisa-mine-r99-case-00336-sherlock-axis-finance-2024-03
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BlastConfigureGovernorWithoutClaimableGasYield(AbstractDetector):
    ARGUMENT = "blast-configure-governor-without-claimable-gas-yield"
    HELP = "Blast L2 module's constructor calls `IBlast(...).configureGovernor(parent_)` to delegate gas-yield governance, but never calls `configureClaimableGas` / `configureClaimableYield`. By default Blast contracts have `GasMode.VOID` and `YieldMode.VOID` — gas yield and ETH yield accrued by this contract i"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/blast-configure-governor-without-claimable-gas-yield.yaml"
    WIKI_TITLE = "Blast module configures governor but never sets gas yield mode to CLAIMABLE"
    WIKI_DESCRIPTION = "Pattern fires on contracts that import Blast's `IBlast` interface and whose constructor calls `IBlast(0x4300...0002).configureGovernor(...)` (or a wrapper) without ALSO calling `configureClaimableGas()` / `configureClaimableYield()` (or the lower-level `configureContract` setting both `YieldMode.CLAIMABLE` and `GasMode.CLAIMABLE`). The default Blast modes are VOID, meaning accrued gas yield is des"
    WIKI_EXPLOIT_SCENARIO = "Axis Finance deploys `BlastLinearVesting` and `BlastEMPAM` to Blast mainnet. Both extend `BlastGas`, whose constructor only calls `configureGovernor(parent_)`. As the auction modules accrue gas yield over months of trading volume, that yield is silently void-burned by the precompile because the gas mode was never flipped to CLAIMABLE. The auction-house governor has the right to claim yield it can "
    WIKI_RECOMMENDATION = "In the constructor, call `IBlast(0x4300...0002).configureClaimableGas()` and `IBlast(0x4300...0002).configureClaimableYield()` (for ETH balance accrual) immediately before or after `configureGovernor`. Equivalent: use the lower-level `configureContract(address(this), YieldMode.CLAIMABLE, GasMode.CLA"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'IBlast|configureGovernor|0x4300000000000000000000000000000000000002'}]
    _MATCH = [{'function.kind': 'any'}, {'function.is_constructor': True}, {'function.body_contains_regex': 'configureGovernor\\s*\\('}, {'function.body_not_contains_regex': 'configureClaimableGas|configureClaimableYield|configureContract\\s*\\(|YieldMode\\.CLAIMABLE|GasMode\\.CLAIMABLE'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — blast-configure-governor-without-claimable-gas-yield: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
