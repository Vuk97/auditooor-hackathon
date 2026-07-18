"""
bridge-proof-leaf-omits-source-destination-domain — generated from reference/patterns.dsl/bridge-proof-leaf-omits-source-destination-domain.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-proof-leaf-omits-source-destination-domain.yaml
Source: roadmap-slice-6-bridge-proof-domain-bypass-worker-bn
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeProofLeafOmitsSourceDestinationDomain(AbstractDetector):
    ARGUMENT = "bridge-proof-leaf-omits-source-destination-domain"
    HELP = "Bridge proof verifier accepts source/destination domains but computes the proof leaf or consumed key without binding either domain."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-proof-leaf-omits-source-destination-domain.yaml"
    WIKI_TITLE = "Bridge proof leaf omits source and destination domain binding"
    WIKI_DESCRIPTION = "Bridge proof verifiers commonly accept a claimed source domain and destination domain alongside a Merkle proof, withdrawal proof, or message proof. If the verified leaf/replay key is computed only from root, leaf, nonce, recipient, amount, or payload fields, the domains remain caller-controlled metadata rather than committed proof inputs. A proof valid for one bridge lane can then be replayed or m"
    WIKI_EXPLOIT_SCENARIO = "An attacker obtains a valid withdrawal proof for sourceDomain=10 and destinationDomain=20. The verifier checks `keccak256(abi.encode(leaf, root, nonce))` and records `consumed[proofLeaf]`, but emits and routes using caller-provided domains that were never in the proof leaf. The attacker resubmits the same root/leaf/nonce tuple with sourceDomain=30 and destinationDomain=20. Because the proof hash i"
    WIKI_RECOMMENDATION = "Bind both source and destination domains into the proof leaf and replay key, and assert the destination domain equals the local chain/domain before dispatch. Prefer `keccak256(abi.encode(sourceDomain, destinationDomain, address(this), root, leaf, nonce, payloadHash))` over route metadata checked out"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|cross.?chain|portal|gateway|verifier|proof|withdraw|relay)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(verify|process|consume|finalize|prove|relay|claim).*(Proof|Message|Withdrawal|Bridge)?|^(verifyProof|processProof|finalizeWithdrawal|relayMessage|claim)$'}, {'function.source_matches_regex': '(?i)\\b(source|src|origin)\\w*(ChainId|Domain|DomainId|NetworkId)\\b'}, {'function.source_matches_regex': '(?i)\\b(destination|dest|dst|target|local)\\w*(ChainId|Domain|DomainId|NetworkId)\\b'}, {'function.body_contains_regex': 'keccak256\\s*\\(\\s*abi\\.encode(?:Packed)?\\s*\\('}, {'function.body_contains_regex': '(?i)\\b(root|leaf|nonce|payload|message|withdrawal|commitment)\\b'}, {'function.body_not_contains_regex': 'keccak256\\s*\\(\\s*abi\\.encode(?:Packed)?\\s*\\([^;]*(?:(?:source|src|origin)\\w*(?:ChainId|Domain|DomainId|NetworkId)[^;]*(?:destination|dest|dst|target|local)\\w*(?:ChainId|Domain|DomainId|NetworkId)|(?:destination|dest|dst|target|local)\\w*(?:ChainId|Domain|DomainId|NetworkId)[^;]*(?:source|src|origin)\\w*(?:ChainId|Domain|DomainId|NetworkId))'}, {'function.body_not_contains_regex': '(?i)(DOMAIN_SEPARATOR|domainSeparator|_domainSeparatorV4|InvalidDomain|WrongDomain|WrongDestination|destination\\w*(?:ChainId|Domain)\\s*==\\s*(?:block\\.chainid|LOCAL_\\w+|local\\w*(?:ChainId|Domain)))'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" — bridge-proof-leaf-omits-source-destination-domain: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
