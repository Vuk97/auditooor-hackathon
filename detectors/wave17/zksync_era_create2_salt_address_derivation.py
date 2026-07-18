"""
zksync-era-create2-salt-address-derivation — generated from reference/patterns.dsl/zksync-era-create2-salt-address-derivation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py zksync-era-create2-salt-address-derivation.yaml
Source: auditooor-R73-chain-specific-zksync
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ZksyncEraCreate2SaltAddressDerivation(AbstractDetector):
    ARGUMENT = "zksync-era-create2-salt-address-derivation"
    HELP = "zkSync Era's CREATE2 address derivation differs from standard EVM: it uses `keccak256(CREATE2_PREFIX, sender, salt, bytecodeHash, input_hash)` not the EVM's `0xff || sender || salt || init_code_hash`. Cross-chain-deployed contracts at 'same' address are actually at different addresses on zkSync."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/zksync-era-create2-salt-address-derivation.yaml"
    WIKI_TITLE = "zkSync Era CREATE2 address derivation differs from EVM — cross-chain address predictions break"
    WIKI_DESCRIPTION = "zkSync Era's EraVM doesn't accept arbitrary bytecode at deployment — contracts are deployed by hash. The derivation is `address = keccak256(CREATE2_PREFIX, sender, salt, bytecodeHash, keccak256(input))[12:]` where CREATE2_PREFIX is a fixed 32-byte constant. Contracts that predict their address via the standard EVM formula `keccak256(0xff, sender, salt, init_code_hash)[12:]` get the wrong address o"
    WIKI_EXPLOIT_SCENARIO = "A project deploys the same factory contract on Ethereum and zkSync with `CREATE2` using identical salts. On Ethereum the address is 0xABC…; the project distributes `0xABC…` as the public address. A user sends tokens to 0xABC… on zkSync — but the actual zkSync deployment lives at 0xDEF…; 0xABC… on zkSync has no code. Tokens are either stuck or swept by whoever deploys code at 0xABC… later on zkSync"
    WIKI_RECOMMENDATION = "For zkSync Era deployments, use `L2ContractHelper.computeCreate2Address(sender, salt, bytecodeHash, keccak256(constructorInput))` — never the EVM formula. For cross-chain vanity address parity, migrate to L2 solutions like Base/Optimism that preserve EVM CREATE2 semantics. Document which chains a fa"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)CREATE2|computeCreate2Address|deploy\\s*\\('}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.body_contains_regex': '(?i)(computeAddress|create2Address|predictDeterministicAddress|keccak256\\s*\\(\\s*abi\\.encodePacked\\s*\\(\\s*0xff)'}, {'function.body_not_contains_regex': '(?i)(CREATE2_PREFIX|zksyncCreate2|L2ContractHelper|codeHash)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — zksync-era-create2-salt-address-derivation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
