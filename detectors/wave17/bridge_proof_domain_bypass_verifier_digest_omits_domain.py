"""
bridge-proof-domain-bypass-verifier-digest-omits-domain - generated from reference/patterns.dsl/bridge-proof-domain-bypass-verifier-digest-omits-domain.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-proof-domain-bypass-verifier-digest-omits-domain.yaml
Source: capability-lift-p1-01-bridge-proof-domain-bypass
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeProofDomainBypassVerifierDigestOmitsDomain(AbstractDetector):
    ARGUMENT = "bridge-proof-domain-bypass-verifier-digest-omits-domain"
    HELP = "Bridge/proof verifier derives an accepted digest, leaf, transcript, or challenge from proof material while omitting available domain binding fields."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-proof-domain-bypass-verifier-digest-omits-domain.yaml"
    WIKI_TITLE = "Bridge proof verifier digest omits domain binding"
    WIKI_DESCRIPTION = "Bridge proof and finality verifiers must bind the source domain, destination domain, route id, validator-set identity, protocol version, and exported commitment marker into the exact digest, leaf, transcript, or challenge they verify. If the verifier receives or stores those fields but hashes only the message/proof payload, a proof from one lane or validator domain can be replayed in another conte"
    WIKI_EXPLOIT_SCENARIO = "A bridge verifier receives `sourceDomain`, `destinationDomain`, a route id, and proof material, but verifies `keccak256(abi.encode(proofRoot, messageHash))`. The same proof root and message hash can be replayed across routes or chains because the accepted leaf is not scoped to either bridge domain."
    WIKI_RECOMMENDATION = "Bind every cross-domain identifier and verification-domain separator into the accepted digest or transcript: source domain, destination domain, route id or bridge id, validator-set id and length, protocol version, and exported commitment marker. Add regression tests proving the same payload produces"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?is)\\b(bridge|cross[-_ ]?chain|proof|transcript|finalit(?:y|ies)|validator[-_ ]?set|route|message|packet|commitment|source\\s*chain|destination\\s*chain)\\b'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches_regex': '(?i)(verify|process|consume|finalize|prove|relay|submit|derive|create|compute).*(proof|message|commitment|digest|leaf|transcript|hash|challenge|header|packet|route)?'}, {'function.source_matches_regex': '(?is)\\b(keccak256|sha256)\\s*\\('}, {'function.source_matches_regex': '(?is)\\b(proof|message|payload|packet|commitment|leaf|root|header|digest|transcript|signature|ballot|nonce|bitFieldHash|commitmentHash)\\b'}, {'function.source_matches_regex': '(?is)\\b(source\\w*|src\\w*|origin\\w*|remote\\w*|destination\\w*|dst\\w*|target\\w*|local\\w*|validatorSet\\w*|validator[-_ ]?set|vset\\w*|route\\w*|version\\w*|exported\\w*|domain\\w*|FIAT_SHAMIR_DOMAIN_ID|DOMAIN_ID|isV2|isV1)\\b'}, {'function.source_matches_regex': '(?is)(keccak256\\s*\\(\\s*abi\\.encode(?:Packed)?\\s*\\([^;{}]*(proof|message|payload|packet|commitment|leaf|root|digest|recipient|amount|nonce)|sha256\\s*\\(\\s*(bytes\\.concat\\s*\\()?[^;{}]*(commitmentHash|bitFieldHash|validatorSetRoot|commitment|payload|message|root|leaf))'}, {'function.not_source_matches_regex': '(?is)(keccak256|sha256)\\s*\\([^;{}]*(FIAT_SHAMIR_DOMAIN_ID|DOMAIN_ID|source(?:Chain|Domain|Id)?|src(?:Chain|Domain|Id)?|origin(?:Chain|Domain|Id)?|destination(?:Chain|Domain|Id)?|dst(?:Chain|Domain|Id)?|target(?:Chain|Domain|Id)?|local(?:Chain|Domain|Id)?|remote(?:Chain|Domain|Id)?|routeId|route|version|isV2|isV1|validatorSetId|validatorSetLen|validatorSetLength|vset\\.id|vset\\.length|currentSet\\.id|currentSet\\.length|exportedCommitment)'}, {'function.not_source_matches_regex': '(?is)\\b(test|mock|fixture|onlyOwner|trustedRelayer|authorizedRelayer|knownGateway)\\b'}, {'function.not_in_skip_list': True}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" - bridge-proof-domain-bypass-verifier-digest-omits-domain: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
