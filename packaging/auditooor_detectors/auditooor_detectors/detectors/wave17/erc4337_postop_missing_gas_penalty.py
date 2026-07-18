"""
erc4337-postop-missing-gas-penalty — generated from reference/patterns.dsl/erc4337-postop-missing-gas-penalty.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc4337-postop-missing-gas-penalty.yaml
Source: solodit-cluster-C0174
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc4337PostopMissingGasPenalty(AbstractDetector):
    ARGUMENT = "erc4337-postop-missing-gas-penalty"
    HELP = "ERC-4337 paymaster _postOp callback references actualGasCost/gasUsed but does not apply the unused-gas penalty or reset the nuisance-gas accumulator, letting senders over-budget without cost."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc4337-postop-missing-gas-penalty.yaml"
    WIKI_TITLE = "Paymaster postOp skips unused-gas penalty"
    WIKI_DESCRIPTION = "An ERC-4337 paymaster (or GasTank-style wrapper) implements the _postOp hook to settle gas after a user operation executes, but the body does not subtract the unused-gas penalty the contract documents. Two variants exist: (a) the nuisance-gas accumulator is never reset to zero, so subsequent ops inherit a stale ceiling; (b) the refund is computed without the penalty rate, so senders who intentiona"
    WIKI_EXPLOIT_SCENARIO = "A sender builds a userOp with gasLimit = 5M but the op actually needs 500k. The paymaster refunds 4.5M worth of gas at spot cost with no penalty. Across thousands of ops the attacker reserves block-gas capacity they never consume, starving honest bundlers of throughput. In the nuisance-gas variant, the first malicious op leaves the counter at its cap and every subsequent op from the same sender re"
    WIKI_RECOMMENDATION = "The _postOp body must (a) compute `unusedGas = gasLimit - actualGasUsed`, (b) apply the documented penalty rate `penalty = unusedGas * PENALTY_BPS / 10000`, (c) deduct the penalty from the sender's deposit, and (d) reset any `nuisanceGas` accumulator to zero before returning. Add a unit test asserti"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '(_postOp|postOp|gasTank|GasTank)'}]
    _MATCH = [{'function.kind': 'internal|external_or_public'}, {'function.name_matches': '^(_postOp|postOp)$'}, {'function.body_contains_regex': 'actualGasCost|gasUsed|preOpGas|gasLimit|nuisanceGas|gasPenalty'}, {'function.body_not_contains_regex': '(nuisanceGas\\s*=\\s*0|unusedGas|gasPenalty|PENALTY_BPS|PENALTY_RATE|gasLimit\\s*-\\s*(actualGasCost|gasUsed))'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc4337-postop-missing-gas-penalty: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
