"""
chain-id-hardcoded-eip712 — generated from reference/patterns.dsl/chain-id-hardcoded-eip712.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py chain-id-hardcoded-eip712.yaml
Source: auditooor-cross-cluster
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ChainIdHardcodedEip712(AbstractDetector):
    ARGUMENT = "chain-id-hardcoded-eip712"
    HELP = "EIP-712 domain separator uses a hardcoded chain id (e.g. `1`) instead of `block.chainid`. After a fork or L2 redeployment, signatures replay to the wrong chain."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/chain-id-hardcoded-eip712.yaml"
    WIKI_TITLE = "Hardcoded chainId in EIP-712 domain separator enables cross-chain signature replay"
    WIKI_DESCRIPTION = "The contract builds its EIP-712 DOMAIN_SEPARATOR with a literal chain id baked into the abi.encode(...) / typehash construction rather than reading `block.chainid` at the time of hash construction. The EIP-712 specification requires the domain separator to bind signatures to a specific chain so that a signature valid on one network cannot be replayed on another. Hardcoding the chain id defeats tha"
    WIKI_EXPLOIT_SCENARIO = "A permit-style function on mainnet uses DOMAIN_SEPARATOR = keccak256(abi.encode(TYPEHASH, name, version, 1, address(this))). The same bytecode is redeployed on an L2 (chain id 10) at the same address under CREATE2. A user signs a Permit for mainnet. An attacker replays the identical signature on the L2 contract: because DOMAIN_SEPARATOR on the L2 still encodes `1`, the signature validates and the "
    WIKI_RECOMMENDATION = "Always construct the EIP-712 domain separator from `block.chainid` at build time, and rebuild the cached separator when block.chainid changes. Prefer OpenZeppelin's EIP712 base contract which implements the rebuild-on-fork pattern correctly. Never substitute a literal chain id — not even `1` as a ma"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.body_contains_regex': 'keccak256\\s*\\(\\s*abi\\.encode[^)]*,\\s*1\\s*[,)]|EIP712_DOMAIN_TYPEHASH.*,\\s*1\\s*,|DOMAIN_SEPARATOR.*chainId\\s*=\\s*1\\b'}, {'function.body_not_contains_regex': 'block\\.chainid|_chainId\\s*\\(\\s*\\)|getChainId\\s*\\(\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — chain-id-hardcoded-eip712: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
