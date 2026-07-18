"""
zksync-unconstrained-witness-allocation-mantissa — generated from reference/patterns.dsl/zksync-unconstrained-witness-allocation-mantissa.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py zksync-unconstrained-witness-allocation-mantissa.yaml
Source: auditooor-R76-immunefi-zksync-$200k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ZksyncUnconstrainedWitnessAllocationMantissa(AbstractDetector):
    ARGUMENT = "zksync-unconstrained-witness-allocation-mantissa"
    HELP = "Witness allocated without any circuit constraint tying it to its expected derivation. A malicious prover can set the witness to any value and produce a valid proof for arbitrary inputs."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/zksync-unconstrained-witness-allocation-mantissa.yaml"
    WIKI_TITLE = "Unconstrained witness in ZK circuit allows arbitrary proof forgery"
    WIKI_DESCRIPTION = "In a ZK circuit, every witness must be constrained by a relation that pins it to its intended value. When a helper (e.g. a packed-float decoder) uses `AllocatedNum::alloc()` to create a mantissa witness and then forgets to enforce bit-decomposition or mantissa*2^exponent == packed, the prover is free to pick any mantissa. The verifier still accepts because the missing constraint is not present to "
    WIKI_EXPLOIT_SCENARIO = "franklin-crypto's parse_with_exponent_le allocated the mantissa without enforcing that `packed == mantissa * 10^exponent`. A malicious prover could pack amount=1 but decode it as amount=10^18, minting/transferring forged balances on zkSync Lite. $200k bounty."
    WIKI_RECOMMENDATION = "Audit every `AllocatedNum::alloc` / `Variable::new_witness` call: the witness MUST be followed by an `enforce`/`LinearCombination` that ties it back to declared inputs. Introduce helper `into_allocated_num` that bundles allocation + constraint. Add a Clippy/lint pass forbidding raw `alloc` without a"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'chain.is_zk_circuit': True}]
    _MATCH = [{'function.kind': 'rust_fn_circuit'}, {'function.name_matches': '(?i)parse_with_exponent|unpack\\w*|decode_\\w*|convert_to_\\w+'}, {'function.body_contains_regex': '(?i)AllocatedNum::\\s*alloc\\s*\\(|allocate_without_constraint|Num::from_raw|UnconstrainedWitness'}, {'function.body_not_contains_regex': '(?i)enforce_\\w+|CS::enforce|LinearCombination|into_allocated_num|\\.pack_into_inputs|bit_decompose_enforce'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — zksync-unconstrained-witness-allocation-mantissa: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
