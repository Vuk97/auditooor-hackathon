"""
public-factory-invalid-pool-config-liveness-failure — generated from reference/patterns.dsl/public-factory-invalid-pool-config-liveness-failure.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py public-factory-invalid-pool-config-liveness-failure.yaml
Source: revert-shape/public-factory-config-liveness
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PublicFactoryInvalidPoolConfigLivenessFailure(AbstractDetector):
    ARGUMENT = "public-factory-invalid-pool-config-liveness-failure"
    HELP = "Public factory deploys official pools from caller-supplied amp/fee config, including a max-uint fee sentinel/default branch, without rejecting amp=0 or out-of-domain fees. The pool is registered as official but later core operations revert."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/public-factory-invalid-pool-config-liveness-failure.yaml"
    WIKI_TITLE = "Public factory accepts invalid pool config that bricks official pool liveness"
    WIKI_DESCRIPTION = "When official pool factories are permissionless, constructor or initializer parameters become protocol-facing invariants. The factory must reject zero amplification and fees outside the supported domain before the pool address is registered. If it instead accepts a sentinel fee value or forwards unchecked fee fields, anyone can create an official pool that is discoverable by routers but whose swap"
    WIKI_EXPLOIT_SCENARIO = "An attacker calls `createPool(tokenA, tokenB, 0, type(uint256).max, 2_000_000)`. The factory treats the max-uint swap-fee field as a default sentinel and deploys/registers the official pool, but it never rejects `amp == 0` or an out-of-domain protocol fee. Routers now route to a registered pool whose invariant math divides by amplification or whose fee accounting rejects the oversized fee, causing"
    WIKI_RECOMMENDATION = "Validate every public factory parameter before deployment/registration: reject zero amplification, reject unsupported sentinel values unless they are normalized into bounded values, and require all fee fields to be within the pool implementation's exact domain. Add a regression test that a pool crea"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Factory|PoolFactory|createPool|deployPool|PoolConfig|amplification|swapFee|protocolFee|feeBps)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(createPool|deployPool|newPool|create)$'}, {'function.body_contains_regex': '(?s)(new\\s+\\w*Pool\\s*\\([^;]*(amp|amplification)[^;]*(fee|Fee|feeBps|swapFee|protocolFee)|\\.initialize\\s*\\([^;]*(amp|amplification)[^;]*(fee|Fee|feeBps|swapFee|protocolFee))'}, {'function.body_contains_regex': '(?s)(if\\s*\\([^)]*(swapFeeBps|feeBps|fee)\\s*==\\s*type\\(uint(256)?\\)\\.max|type\\(uint(256)?\\)\\.max[\\s\\S]{0,160}(default|fee|Fee))'}, {'function.body_not_contains_regex': '(?is)(require\\s*\\([^;{}]*(amp|amplification)[^;{}]*(>|>=|!=)\\s*0[^;{}]*\\)\\s*;|if\\s*\\([^)]*((amp|amplification)[^)]*==\\s*0|0\\s*==\\s*(amp|amplification))[^)]*\\)\\s*(revert\\s+\\w+|{\\s*revert\\s+\\w+)|if\\s*\\([^)]*((amp|amplification)[^)]*(<=|<)\\s*0|0\\s*(>=|>)\\s*(amp|amplification))[^)]*\\)\\s*(revert\\s+\\w+|{\\s*revert\\s+\\w+))[\\s\\S]{0,1200}(new\\s+\\w*Pool|\\.initialize|officialPools\\.push)'}, {'function.body_not_contains_regex': '(?is)(require\\s*\\([^;{}]*(fee|swapFee|protocolFee|feeBps)[^;{}]*(<=|<)\\s*(MAX_|max|[0-9])[^;{}]*\\)\\s*;|if\\s*\\([^)]*(fee|swapFee|protocolFee|feeBps)[^)]*(>|>=)\\s*(MAX_|max|[0-9])[^)]*\\)\\s*(revert\\s+\\w+|{\\s*revert\\s+\\w+))[\\s\\S]{0,1200}(new\\s+\\w*Pool|\\.initialize|officialPools\\.push)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" — public-factory-invalid-pool-config-liveness-failure: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
