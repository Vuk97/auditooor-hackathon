"""
r74-auth-cross-contract-signature-replay — generated from reference/patterns.dsl/r74-auth-cross-contract-signature-replay.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-auth-cross-contract-signature-replay.yaml
Source: r74b-cross-firm-oz+tob
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74AuthCrossContractSignatureReplay(AbstractDetector):
    ARGUMENT = "r74-auth-cross-contract-signature-replay"
    HELP = "Typed-data hash built without binding to chainid + address(this); signatures valid on one deployment replay against sibling deployments with the same type layout."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-auth-cross-contract-signature-replay.yaml"
    WIKI_TITLE = "Typed-data signature missing chainid / contract-address binding"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. EIP-712's DOMAIN_SEPARATOR is the binding between a signature and the specific (chain, contract, name, version) tuple it was meant for. Contracts that pre-compute DOMAIN_SEPARATOR in the constructor and cache it immutable are vulnerable when chainid changes (fork) or when the contract is deployed twice with the same name+version (staging, te"
    WIKI_EXPLOIT_SCENARIO = "A claim-vault is deployed to mainnet and the team forgets and also deploys it to Base with the same TYPEHASH/version/name. A user signs an off-chain claim intent for Base (intending to withdraw from Base). An operator-controlled indexer also replays the signed message against mainnet — where DOMAIN_SEPARATOR matches because address(this) and chainid were not bound into the hash. The user's mainnet"
    WIKI_RECOMMENDATION = "Always recompute DOMAIN_SEPARATOR when block.chainid differs from the cached value: `_domainSeparatorV4() { return (block.chainid == _CACHED_CHAINID) ? _CACHED_DOMAIN_SEPARATOR : _buildDomainSeparator(); }`. Include address(this) in the domain separator's fields (OpenZeppelin EIP712 base does this b"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(_DOMAIN_SEPARATOR|EIP712|_TYPEHASH|_hashTypedData|ecrecover)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '_hashTypedDataV4\\s*\\(|_hashTypedData\\s*\\(|keccak256\\s*\\(\\s*abi\\.encode\\s*\\([^)]*_TYPEHASH'}, {'function.has_high_level_call_named': '(?i)^(recover|_recover|tryRecover|recoverSigner|_recoverSigner|isValidSignatureNow)$'}, {'function.body_not_contains_regex': 'block\\.chainid|chainId|address\\s*\\(\\s*this\\s*\\)|_buildDomainSeparator|_getDomainSeparator\\s*\\(\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-auth-cross-contract-signature-replay: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
