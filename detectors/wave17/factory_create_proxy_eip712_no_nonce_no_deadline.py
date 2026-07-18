"""
factory-create-proxy-eip712-no-nonce-no-deadline — generated from reference/patterns.dsl/factory-create-proxy-eip712-no-nonce-no-deadline.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py factory-create-proxy-eip712-no-nonce-no-deadline.yaml
Source: auditooor-r112-polymarket-source-mine-SafeFactory.createProxy
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FactoryCreateProxyEip712NoNonceNoDeadline(AbstractDetector):
    ARGUMENT = "factory-create-proxy-eip712-no-nonce-no-deadline"
    HELP = "Factory recovers EIP-712 signer to authorize proxy creation but the signed struct contains no nonce or deadline — signature is replayable indefinitely."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/factory-create-proxy-eip712-no-nonce-no-deadline.yaml"
    WIKI_TITLE = "Proxy factory accepts EIP-712 signature without nonce or deadline — indefinite replay window"
    WIKI_DESCRIPTION = "A common factory pattern is for the future-owner of a Safe/proxy to sign an EIP-712 message authorizing the factory to deploy on their behalf, often with payment terms (`paymentToken`, `payment`, `paymentReceiver`). When the signed struct lacks BOTH `nonce` and `deadline`, the signature has no temporal scope: the relayer (or anyone holding the sig) can deploy at any future block. CREATE2 with an o"
    WIKI_EXPLOIT_SCENARIO = "Alice signs a CreateProxy(paymentToken=USDC, payment=5, paymentReceiver=Bob) message in March, then forgets about it. In December, Bob (or anyone who scraped the signature from a public mempool) submits the deployment. Alice's wallet pays 5 USDC and a Safe proxy is deployed with Alice as sole owner. Alice did not want a Safe at the December block (e.g., she has since switched to a multisig setup)."
    WIKI_RECOMMENDATION = "Bind the EIP-712 struct hash to a `nonce` (e.g., per-signer monotonic counter consumed at deploy time) AND a `deadline` (`require(block.timestamp <= deadline, SignatureExpired())`). The nonce closes the deploy-once-vs-deploy-twice gap; the deadline closes the deploy-now-vs-deploy-later gap. CREATE2 "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)CREATE_PROXY_TYPEHASH|CREATE_WALLET_TYPEHASH|MAKE_PROXY_TYPEHASH|create.*Proxy.*signature|deployProxy.*sig'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)^_?createProxy|^_?deployProxy|^_?makeProxy|^_?createWallet|^_?makeWallet|^_?getSigner|^_?recoverSigner'}, {'function.has_high_level_call_named': '(?i)^(recover|tryRecover|_recover|recoverSigner|_recoverSigner|isValidSignatureNow|ecrecover)$'}, {'function.body_contains_regex': '(?i)keccak256\\s*\\(\\s*\\"[^\\"]*\\(([^)]*)\\)\\s*\\"\\s*\\)|TYPEHASH\\s*=\\s*keccak256\\s*\\(|_recover\\s*\\(|ECDSA\\.recover|\\.recover\\s*\\(\\s*digest|ecrecover\\s*\\(\\s*digest'}, {'function.body_not_contains_regex': '(?i)\\bnonce\\b|\\bdeadline\\b|\\bexpir(?:y|ation|es)\\b|block\\.timestamp\\s*[<>=]|signedAt|validUntil|notBefore|notAfter'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — factory-create-proxy-eip712-no-nonce-no-deadline: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
