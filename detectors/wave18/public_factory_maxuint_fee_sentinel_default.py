"""
public-factory-maxuint-fee-sentinel-default — generated from reference/patterns.dsl/public-factory-maxuint-fee-sentinel-default.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py public-factory-maxuint-fee-sentinel-default.yaml
Source: revert-shape/public-factory-maxuint-fee-sentinel
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PublicFactoryMaxuintFeeSentinelDefault(AbstractDetector):
    ARGUMENT = "public-factory-maxuint-fee-sentinel-default"
    HELP = "Public factory treats `type(uint256).max` as a fee sentinel/default branch and deploys or initializes a pool without explicitly rejecting the sentinel."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/public-factory-maxuint-fee-sentinel-default.yaml"
    WIKI_TITLE = "Public factory accepts max-uint fee sentinel without rejection"
    WIKI_DESCRIPTION = "Factory/configuration entrypoints are protocol-facing input-validation boundaries. If a public pool factory treats `type(uint256).max` as a convenient default fee sentinel and then deploys or initializes an official pool without explicitly rejecting the sentinel, callers can register pools with unbounded or malformed fee state. That is a distinct input-validation miss from ordinary zero-value chec"
    WIKI_EXPLOIT_SCENARIO = "An attacker calls `createPool(tokenA, tokenB, amp, type(uint256).max)`. The factory silently rewrites the sentinel to a default fee and registers the pool as official. If the default is not the exact bounded value the protocol intended, later swaps or joins operate with a fee state that was never explicitly approved. In the worst case the factory copies the sentinel into downstream config and the "
    WIKI_RECOMMENDATION = "Reject `type(uint256).max` explicitly at the factory boundary unless the code immediately normalizes it into a bounded, auditable constant before any deployment/registration side effect. If a sentinel is supported, validate it in one place and make the fallback impossible to confuse with a real call"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Factory|PoolFactory|PoolConfig|createPool|deployPool|newPool|swapFee|protocolFee|feeBps|sentinel)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(createPool|deployPool|newPool|create|initialize|configure)$'}, {'function.body_contains_regex': '(?is)new\\s+\\w*Pool\\s*\\([^;]*(fee|feeBps|swapFee|protocolFee)|\\.initialize\\s*\\([^;]*(fee|feeBps|swapFee|protocolFee)'}, {'function.body_contains_regex': '(?is)type\\(uint(256)?\\)\\.max[\\s\\S]{0,180}(default|fallback|sentinel|normalize)|(?:feeBps|swapFee|protocolFee|fee)\\s*==\\s*type\\(uint(256)?\\)\\.max'}, {'function.body_not_contains_regex': '(?is)require\\s*\\([^;{}]*(feeBps|swapFee|protocolFee|fee)[^;{}]*!=\\s*type\\(uint(256)?\\)\\.max|if\\s*\\([^)]*(feeBps|swapFee|protocolFee|fee)[^)]*==\\s*type\\(uint(256)?\\)\\.max[^)]*\\)\\s*(revert|throw)|revert\\s+\\w+\\s*\\([^;{}]*type\\(uint(256)?\\)\\.max'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" — public-factory-maxuint-fee-sentinel-default: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
