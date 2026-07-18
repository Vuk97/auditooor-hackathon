"""
bridge-notary-hardcoded-chain-identity-bypasses-verifier — generated from reference/patterns.dsl/bridge-notary-hardcoded-chain-identity-bypasses-verifier.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-notary-hardcoded-chain-identity-bypasses-verifier.yaml
Source: auditooor-R73-fixdiff-mined-wormhole-ee26e052ee
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeNotaryHardcodedChainIdentityBypassesVerifier(AbstractDetector):
    ARGUMENT = "bridge-notary-hardcoded-chain-identity-bypasses-verifier"
    HELP = "Cross-chain notaries / transfer verifiers that early-return Approve when the emitter chain is not Ethereum (literal `!= ChainIDEthereum`) become silent rubber stamps the moment the project ships a transfer verifier for a second chain (Sepolia, Sui, Solana). The chain check must be `!IsSupported(chai"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-notary-hardcoded-chain-identity-bypasses-verifier.yaml"
    WIKI_TITLE = "Wormhole-style Notary hardcoded to ChainIDEthereum auto-approves every other chain"
    WIKI_DESCRIPTION = "The Wormhole Notary's original logic: `if EmitterChain != ChainIDEthereum { return Approve }`. The intent was \"until we have verifiers for other chains, just let non-Ethereum through\". But Sui and EVM Sepolia gained transfer-verifier implementations, and the Notary kept approving their transfers automatically — defeating the entire point of the verifier. Any bug found by the Sui TransferVerifier"
    WIKI_EXPLOIT_SCENARIO = "Sui transfer verifier detects an anomalous token bridge transfer: huge amount without matching lockup. Sets VerificationState=Rejected on the MessagePublication. MessagePublication reaches the Notary. Notary early-exits on `EmitterChain != ChainIDEthereum` → Approve. Guardians sign the VAA, transfer mints wrapped tokens on destination. Attacker profits the full anomalous amount. The fix registers "
    WIKI_RECOMMENDATION = "Replace hardcoded origin-chain checks with a lookup into a registry keyed by every chain that has an implemented verifier/classifier. When a new verifier ships, its chain must atomically get added to the registry. Add an integration test that asserts a Rejected MessagePublication from every verifier"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Notary|TransferVerifier|ProcessMsg|Verdict'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': 'ProcessMsg|processMsg|verify|classify'}, {'function.body_contains_regex': '(EmitterChain|chainID|emitterChain)\\s*!=\\s*(vaa\\.)?ChainIDEthereum'}, {'function.body_contains_regex': '(return\\s+Approve|automatically\\s+approving|approve\\b).*(not\\s+from|non-?ethereum|from\\s+a\\s+chain)'}, {'function.body_not_contains_regex': 'IsSupported\\s*\\(|HasTransferVerifier|txverifier\\.Supports'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — bridge-notary-hardcoded-chain-identity-bypasses-verifier: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
