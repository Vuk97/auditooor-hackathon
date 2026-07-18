"""
domain-separator-user-supplied — generated from reference/patterns.dsl/domain-separator-user-supplied.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py domain-separator-user-supplied.yaml
Source: code4arena/slice_ab-NextGen-H01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DomainSeparatorUserSupplied(AbstractDetector):
    ARGUMENT = "domain-separator-user-supplied"
    HELP = "EIP-712 signature verification reads the domain separator / typed-data hash from a caller-supplied parameter instead of computing it internally. Attacker supplies any domain, defeating the chainId / verifyingContract binding."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/domain-separator-user-supplied.yaml"
    WIKI_TITLE = "EIP-712 domain separator taken from caller input"
    WIKI_DESCRIPTION = "The purpose of `DOMAIN_SEPARATOR` in EIP-712 is to bind each signature to a specific chain and verifying contract, so signatures cannot be replayed across forks, chains, or sibling deployments. When the domain separator (or its composition — chainId, name, version, verifyingContract) is passed into the verification function by the caller, that binding collapses: the caller picks whichever context "
    WIKI_EXPLOIT_SCENARIO = "Contract A's `executeMetaTx(bytes32 domainSeparator, bytes sig, bytes call)` recomputes the typed-data hash using the caller's `domainSeparator`. Alice signed a typed-data message for Contract B on Polygon (her intent). Mallory submits that signature to Contract A on Ethereum, passing B's domain separator. `ecrecover` returns Alice, call is executed on Contract A — Alice's intent was routed to the"
    WIKI_RECOMMENDATION = "Compute the domain separator inside the contract at init / per tx: `_domainSeparatorV4()` from OpenZeppelin's EIP712. Never read it from calldata. If caching, re-derive it when `block.chainid` diverges from the cached value."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ecrecover|_hashTypedData|toTypedDataHash|EIP712'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_of_type': 'bytes32'}, {'function.has_param_name_matching': '(domainSeparator|_DOMAIN|DOMAIN_SEPARATOR|domainHash|typedDataHash)'}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.body_contains_regex': 'keccak256\\s*\\(\\s*abi\\.encodePacked\\s*\\(\\s*"\\\\x19\\\\x01"|ECDSA\\.toTypedDataHash\\s*\\(\\s*\\w+(domainSeparator|domainHash|typedDataHash)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — domain-separator-user-supplied: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
