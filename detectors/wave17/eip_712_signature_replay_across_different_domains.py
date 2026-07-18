"""
eip-712-signature-replay-across-different-domains — generated from reference/patterns.dsl/eip-712-signature-replay-across-different-domains.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py eip-712-signature-replay-across-different-domains.yaml
Source: hexens-glider/eip-712-signature-replay-across-different-domains
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Eip712SignatureReplayAcrossDifferentDomains(AbstractDetector):
    ARGUMENT = "eip-712-signature-replay-across-different-domains"
    HELP = "A permit/delegate-style signature digest omits the EIP-712 domain binding, so the same signature can replay across different verifier domains."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/eip-712-signature-replay-across-different-domains.yaml"
    WIKI_TITLE = "EIP-712 signature digest missing domain binding"
    WIKI_DESCRIPTION = "If a contract verifies a permit/delegate-style struct by hashing only the struct fields and directly calling `ecrecover`, the recovered digest is not bound to a unique EIP-712 domain. A signature created for one protocol, deployment, or sibling verifier can remain valid against another compatible verifier."
    WIKI_EXPLOIT_SCENARIO = "A user signs a permit for protocol A. Protocol B verifies the same typed struct but never mixes `DOMAIN_SEPARATOR` into the digest. An attacker submits the signature to protocol B, which recovers the same signer and accepts an authorization that was never meant for B."
    WIKI_RECOMMENDATION = "Compute the final digest with the contract's own EIP-712 domain separator, preferably via `_hashTypedDataV4` or `ECDSA.toTypedDataHash`, and ensure the domain binds both `block.chainid` and `address(this)`."

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
                info = [f, f" — eip-712-signature-replay-across-different-domains: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
