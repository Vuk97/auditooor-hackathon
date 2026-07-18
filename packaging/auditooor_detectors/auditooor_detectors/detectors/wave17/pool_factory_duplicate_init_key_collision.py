"""
pool-factory-duplicate-init-key-collision — generated from reference/patterns.dsl/pool-factory-duplicate-init-key-collision.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pool-factory-duplicate-init-key-collision.yaml
Source: solodit-cluster/C0175
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PoolFactoryDuplicateInitKeyCollision(AbstractDetector):
    ARGUMENT = "pool-factory-duplicate-init-key-collision"
    HELP = "Pool factory derives registry key from keccak256(tokenA, tokenB) without canonical ordering or duplicate-existence check; two 'different' pools with identical token pair can be registered with divergent state."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pool-factory-duplicate-init-key-collision.yaml"
    WIKI_TITLE = "Pool factory createPool: missing canonical ordering and duplicate-key check"
    WIKI_DESCRIPTION = "A factory's createPool / deployPool / initializePool / registerPool entrypoint computes the pool's registry slot from `keccak256(abi.encode(tokenA, tokenB, ...))` (or `abi.encodePacked`, or a `getPoolId` helper) without first requiring that `tokenA < tokenB` (or `token0 < token1`) and without checking whether that key is already populated. A caller can therefore register the same logical pool twic"
    WIKI_EXPLOIT_SCENARIO = "Alice deploys the canonical WETH/USDC pool via `factory.createPool(WETH, USDC, 3000)`. The factory stores it at `pools[keccak256(abi.encode(WETH, USDC, 3000))]`. Bob calls `factory.createPool(USDC, WETH, 3000)` with the arguments reversed. Because the factory does not enforce `require(token0 < token1)`, the key `keccak256(abi.encode(USDC, WETH, 3000))` is different — a second pool contract is depl"
    WIKI_RECOMMENDATION = "In every createPool / deployPool / initializePool / registerPool entrypoint: (1) canonicalise the token pair with `require(tokenA < tokenB, 'unordered')` or swap them into `(token0, token1)` so the registry key is order-independent; (2) require the slot is empty before writing — `require(pools[key] "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'pools|poolByKey|factory|allPools'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'createPool|deployPool|initializePool|registerPool|_createPool'}, {'function.body_contains_regex': {'regex': 'keccak256\\s*\\(\\s*abi\\.encode|keccak256\\s*\\(\\s*abi\\.encodePacked|getPoolId'}}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*tokenA\\s*<\\s*tokenB|require\\s*\\(\\s*token0\\s*<\\s*token1|sort\\s*\\(|require\\s*\\(\\s*!\\s*exists|require\\s*\\(\\s*pools\\[.*\\]\\s*==\\s*address\\s*\\(\\s*0\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — pool-factory-duplicate-init-key-collision: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
