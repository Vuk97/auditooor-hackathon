"""
unbounded-loop-gas-dos — generated from reference/patterns.dsl/unbounded-loop-gas-dos.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py unbounded-loop-gas-dos.yaml
Source: solodit/C0089
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UnboundedLoopGasDos(AbstractDetector):
    ARGUMENT = "unbounded-loop-gas-dos"
    HELP = "External function iterates a user-growable storage array with no per-call bound; as the array grows, calls hit the block gas limit and the function becomes permanently unreachable (DoS)."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/unbounded-loop-gas-dos.yaml"
    WIKI_TITLE = "Unbounded loop over user-controlled storage array causes gas-limit DoS"
    WIKI_DESCRIPTION = "A public/external function sweeps a storage collection whose length is controlled by untrusted users (stakers, depositors, positions, participants, rewarded addresses, etc.) without enforcing a per-call cap, pagination, or early-break. Gas cost grows linearly with the collection. Once the array exceeds the block gas limit the function reverts for every caller, which may brick core protocol flows: "
    WIKI_EXPLOIT_SCENARIO = "A liquidity-mining contract exposes `distributeRewards()` which loops over `stakers[]`. Registration is permissionless and costs near-zero gas. An attacker scripts thousands of dust-stake calls from fresh addresses, inflating `stakers.length` until `distributeRewards()` exceeds the block gas limit. Every honest staker loses access to pending rewards until the contract is redeployed or an upgrade r"
    WIKI_RECOMMENDATION = "Replace the sweep with a pull-based pattern (users claim for themselves), or introduce explicit pagination: take `uint256 start, uint256 end` arguments and require `end - start <= MAX_BATCH`. Guard registration with a minimum-stake / deposit bond so growing the collection is economically expensive. "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.not_slither_synthetic': True}, {'function.is_mutating': True}, {'function.body_contains_regex': 'for\\s*\\([^)]*\\.length|while\\s*\\([^)]*\\.length'}, {'function.body_not_contains_regex': 'require\\s*\\([^)]*length\\s*(<=|<)|\\.length\\s*<=?\\s*(MAX|BATCH|LIMIT)|MAX_ITER|MAX_LENGTH|MAX_LOOP|BATCH_SIZE|batchSize|maxLen|maxBatch|\\bbreak\\s*;|\\bi\\s*<\\s*(maxLen|batchSize|limit|cap)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — unbounded-loop-gas-dos: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
