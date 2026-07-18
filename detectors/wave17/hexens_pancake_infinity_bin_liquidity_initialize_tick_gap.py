"""
hexens-pancake-infinity-bin-liquidity-initialize-tick-gap — generated from reference/patterns.dsl/hexens-pancake-infinity-bin-liquidity-initialize-tick-gap.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py hexens-pancake-infinity-bin-liquidity-initialize-tick-gap.yaml
Source: auditooor-R75-hexens-PancakeInfinity-BinLiquidity-followup
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HexensPancakeInfinityBinLiquidityInitializeTickGap(AbstractDetector):
    ARGUMENT = "hexens-pancake-infinity-bin-liquidity-initialize-tick-gap"
    HELP = "BinPool-style AMMs that re-initialize a bin without checking whether it was already active allow a second initialize to overwrite `activeId` / bin-state, dropping existing LP positions into an unreachable state."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/hexens-pancake-infinity-bin-liquidity-initialize-tick-gap.yaml"
    WIKI_TITLE = "Bin AMM missing 'already-initialized' guard — second init zeros live LP bin"
    WIKI_DESCRIPTION = "Pancake Infinity / Trader Joe Liquidity-Book / similar discretized-bin AMMs track per-bin liquidity in a mapping. The `initialize` path writes a non-zero entry for the active bin. If the same bin can be re-initialized (no `require(!bins[id].initialized)` gate), a follow-up call after LPs have added liquidity to that bin can overwrite reserves / active flag / fee accumulator. Depending on the overw"
    WIKI_EXPLOIT_SCENARIO = "Pancake Infinity BinPool: bin 8388608 has active=true, liquidity=1000e18 from LP Alice. Attacker calls `initialize(binId=8388608, ...)` from any role that can init — possibly an ungated factory wrapper. The init path does `bins[binId] = BinInfo({liquidity: 0, active: true, cumFee: 0})` unconditionally, wiping Alice's position. When Alice calls `removeLiquidity`, the contract sees `liquidity=0` and"
    WIKI_RECOMMENDATION = "Add an initialized-guard: `require(!bins[binId].initialized, 'already-init');` at the top of every bin init entry point. Make init callable only once per bin per pool. Separate 'initialize bin bookkeeping' from 'mint into bin' so users never touch init. Alternative: collapse init + mint into a singl"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'BinPool|InfinityBin|binLiquidity|activeId|initializeBin'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': 'initialize|initializeBin|mint|addLiquidity|getBin'}, {'function.body_contains_regex': 'activeId|binId|binStep|binReserves'}, {'function.body_contains_regex': 'bins\\s*\\[[^\\]]+\\]\\s*=|binReserves\\s*\\[|liquidity\\s*\\[\\s*binId\\s*\\]'}, {'function.body_not_contains_regex': 'if\\s*\\(\\s*bins\\[[^\\]]+\\]\\.initialized|require\\s*\\(\\s*!initialized\\s*\\[|require\\s*\\(\\s*bins\\[[^\\]]+\\]\\.liquidity\\s*==\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — hexens-pancake-infinity-bin-liquidity-initialize-tick-gap: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
