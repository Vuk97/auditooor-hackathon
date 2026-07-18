"""
signature-missing-chainid-enables-cross-chain-replay — generated from reference/patterns.dsl/signature-missing-chainid-enables-cross-chain-replay.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py signature-missing-chainid-enables-cross-chain-replay.yaml
Source: auditooor-R75-code4rena-2024-08-phi-254
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SignatureMissingChainidEnablesCrossChainReplay(AbstractDetector):
    ARGUMENT = "signature-missing-chainid-enables-cross-chain-replay"
    HELP = "Direct-entry signatureClaim decodes encodeData without extracting chainId — same signature is valid on every chain; artId/id reuse lets attacker mint stolen-valuable art."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/signature-missing-chainid-enables-cross-chain-replay.yaml"
    WIKI_TITLE = "signatureClaim ignores chainId, enabling cross-chain signature replay on disparate art/nonce spaces"
    WIKI_DESCRIPTION = "An off-chain signer issues signatures over `(expiresIn, minter, ref, verifier, artId, chainId, data)`. The `signatureClaim` entry-point tuple-decodes but skips the chainId slot (`,, bytes32 data_`) and verifies over `keccak256(encodeData_)` directly, meaning chainId is never bound. An attacker captures a signature valid on chain A (cheap art), creates `artId` on chain B filling up nonces until the"
    WIKI_EXPLOIT_SCENARIO = "Chain A artId 7 = cheap meme; chain B artId 7 = rare collab piece (not yet minted). Legit user claims on chain A with signature S. Attacker replays S on chain B to mint the rare piece."
    WIKI_RECOMMENDATION = "Always include `block.chainid` in the signed digest and verify it matches. Use EIP-712 typed data with domain separator bound to chainId so the signature is unforgeable cross-chain. Also add a nullifier per chain to prevent replay within the same chain."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)signatureClaim|verifySig|claimWithSig|signatureMint'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': '(?i)_recoverSigner|ECDSA\\.recover|SignatureChecker'}, {'function.body_contains_regex': '(?i)abi\\.decode\\s*\\([^)]*,\\s*\\([^)]*\\)\\s*\\)|encodeData_'}, {'function.body_not_contains_regex': '(?i)chainid|CHAINID|chain_id|block\\.chainid'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — signature-missing-chainid-enables-cross-chain-replay: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
