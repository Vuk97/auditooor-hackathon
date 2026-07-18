"""
signature-verification-trusts-caller-supplied-sysvar-account — generated from reference/patterns.dsl/signature-verification-trusts-caller-supplied-sysvar-account.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py signature-verification-trusts-caller-supplied-sysvar-account.yaml
Source: auditooor-R76-rekt-wormhole-2022
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SignatureVerificationTrustsCallerSuppliedSysvarAccount(AbstractDetector):
    ARGUMENT = "signature-verification-trusts-caller-supplied-sysvar-account"
    HELP = "Bridge signature-verification reads a caller-supplied verifier / sysvar account rather than a hard-coded/immutable precompile address, allowing the caller to substitute a fake verifier that always returns 'valid'."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/signature-verification-trusts-caller-supplied-sysvar-account.yaml"
    WIKI_TITLE = "Cross-chain signature verifier address is caller-controlled, enabling spoofed verification"
    WIKI_DESCRIPTION = "Cross-chain bridges often delegate signature verification to a precompile or sister-contract (Ecrecover, Secp256k1 sysvar on Solana, a verifier interface on EVM). If the address of that verifier is sourced from the calldata / an account argument rather than being immutable or a protocol constant, an attacker can pass in a contract they control that returns `true` for any signature set. This was th"
    WIKI_EXPLOIT_SCENARIO = "Attacker deploys a contract FakeVerifier whose `verify(bytes,bytes32)` always returns true. The bridge's `verifySignatures(address verifier, bytes sig, bytes message)` does not hard-code `verifier`; it simply calls `verifier.verify(...)`. Attacker calls with their FakeVerifier, fabricates an arbitrary VAA authorizing a 120k whETH mint, and the bridge mints the wrapped tokens."
    WIKI_RECOMMENDATION = "Make the signature verifier address `immutable` in the constructor, or a compiled-in constant. Never accept the verifier as a function argument or from a mutable storage slot that is itself writable. For precompiles, reference them by their well-known address constant (e.g. `address(0x01)` for ecrec"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'Function verifies signatures by reading an account / contract address whose identity is controlled by the caller rather than hardcoded or constructor-immutable.']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)verifySignatures|postVAA|verifyVAA|postMessage|parseAndVerifyVM|completeTransfer'}, {'function.body_contains_regex': '(?i)ISignatureVerifier|verifier\\.|precompile|sigVerifier|SignatureSet|guardianSet'}, {'function.body_not_contains_regex': '(?i)immutable\\s+\\w*(verifier|precompile|guardian)|address\\s+constant\\s+\\w*(VERIFIER|PRECOMPILE)|address\\s*\\(\\s*0x01\\s*\\)|ECDSA\\.recover\\b|ecrecover\\b'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — signature-verification-trusts-caller-supplied-sysvar-account: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
