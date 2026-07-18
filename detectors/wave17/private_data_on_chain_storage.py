"""
private-data-on-chain-storage — generated from reference/patterns.dsl/private-data-on-chain-storage.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py private-data-on-chain-storage.yaml
Source: solodit-informational-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PrivateDataOnChainStorage(AbstractDetector):
    ARGUMENT = "private-data-on-chain-storage"
    HELP = "Secret-named state var (password/secret/privateKey/seed/mnemonic) is written to storage. All on-chain storage is publicly readable regardless of the `private` keyword — the `private` visibility is a Solidity-level access modifier, not a confidentiality guarantee."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/private-data-on-chain-storage.yaml"
    WIKI_TITLE = "Private data stored on-chain: `private` keyword does not imply confidentiality"
    WIKI_DESCRIPTION = "The `private` visibility modifier in Solidity prevents other contracts from reading the variable via getter/inheritance, but it does NOT encrypt the value. All contract storage is persisted in the world state trie and is readable by anyone via `eth_getStorageAt`, block explorers, archive nodes, or direct state root traversal. Storing any value whose name implies secrecy — `password`, `secret`, `pr"
    WIKI_EXPLOIT_SCENARIO = "A contract declares `bytes32 private password;` and a setter `setPassword(bytes32 p) { password = p; }`. The user calls `setPassword('opensesame')`. Anyone who queries the contract with `web3.eth.getStorageAt(address, slot)` immediately reads the value. Worse, the plaintext appears in the transaction calldata and is permanently indexed by every full node and archival block explorer."
    WIKI_RECOMMENDATION = "Never store secrets on-chain. If access control is what you need, store a commitment (`keccak256(secret)`) rather than the secret itself, and have users reveal the preimage at usage time. If off-chain encryption is required, encrypt client-side with a key that never touches the contract, and store o"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '(password|_password|secret|_secret|privateKey|_privateKey|apiKey|_apiKey)\\s*=|seedPhrase|mnemonic'}, {'function.writes_storage_matching': '.*'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — private-data-on-chain-storage: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
