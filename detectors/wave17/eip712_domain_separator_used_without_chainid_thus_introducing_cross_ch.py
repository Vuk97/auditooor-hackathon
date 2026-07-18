"""
eip712-domain-separator-used-without-chainid-thus-introducing-cross-ch — generated from reference/patterns.dsl/eip712-domain-separator-used-without-chainid-thus-introducing-cross-ch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py eip712-domain-separator-used-without-chainid-thus-introducing-cross-ch.yaml
Source: hexens-glider/cross-chain-replay-attacks-due-to-missing-chain-id
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Eip712DomainSeparatorUsedWithoutChainidThusIntroducingCrossCh(AbstractDetector):
    ARGUMENT = "eip712-domain-separator-used-without-chainid-thus-introducing-cross-ch"
    HELP = "An EIP-712 DOMAIN_SEPARATOR is computed without chainId, so signatures can be replayed across chains."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/eip712-domain-separator-used-without-chainid-thus-introducing-cross-ch.yaml"
    WIKI_TITLE = "EIP-712 DOMAIN_SEPARATOR missing chainId enables cross-chain replay"
    WIKI_DESCRIPTION = "If a verifier computes its EIP-712 domain separator without `block.chainid`, the same signed payload can remain valid on any chain where the contract is deployed at the same address. This breaks replay isolation across L1/L2s and sidechains."
    WIKI_EXPLOIT_SCENARIO = "A user signs a bridge withdrawal on chain A. The verifier on chain B uses the same domain separator because chainId was omitted. An attacker replays the signature on chain B and executes the withdrawal there too."
    WIKI_RECOMMENDATION = "Include `block.chainid` in the EIP-712 domain encoding or use a standard EIP712 implementation that caches and recomputes the domain separator correctly."

    _PRECONDITIONS = []
    _MATCH = []

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
                info = [f, f" — eip712-domain-separator-used-without-chainid-thus-introducing-cross-ch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
