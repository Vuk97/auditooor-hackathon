"""
bridge-replay-key-omits-chain-domain - generated from reference/patterns.dsl/bridge-replay-key-omits-chain-domain.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-replay-key-omits-chain-domain.yaml
Source: slice56-bridge-proof-domain-bypass-recall
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeReplayKeyOmitsChainDomain(AbstractDetector):
    ARGUMENT = "bridge-replay-key-omits-chain-domain"
    HELP = "Bridge replay/proof key stores consumed/processed state without binding source/destination chain or domain in the key preimage."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-replay-key-omits-chain-domain.yaml"
    WIKI_TITLE = "Bridge replay key omits chain/domain binding"
    WIKI_DESCRIPTION = "Bridge receivers and proof consumers usually derive a consumed or processed key from nonce, leaf, root, sender, or payload fields. If the function also accepts source/destination chain or domain context, but that context is not included in the replay-key preimage, a proof or message from one lane can collide with another lane's consumed namespace."
    WIKI_EXPLOIT_SCENARIO = "A bridge receiver accepts `sourceDomain`, `destinationDomain`, `nonce`, `sender`, and `payload`, but computes `processedKey = keccak256(abi.encode(sender, nonce, payload))`. The same sender/nonce/payload tuple can be replayed across source domains or destination deployments because neither domain is bound to the key."
    WIKI_RECOMMENDATION = "Bind source domain, destination domain, local chain id, and the destination contract address into every replay/proof key: `keccak256(abi.encode(sourceDomain, destinationDomain, address(this), sender, nonce, payloadHash))`. Also reject messages whose destination domain is not the local domain."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|cross.?chain|gateway|portal|relay|proof|message|domain|chain)'}, {'contract.source_matches_regex': '(?i)(consumed|processed|used|spent|seen)\\w*\\s*\\['}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(verify|receive|process|relay|claim|finalize|consume|execute).*(Proof|Message|Withdrawal|Bridge|Transfer)?|^(verifyProof|receiveMessage|processProof|relayMessage|claim)$'}, {'function.source_matches_regex': '(?i)\\b(source|src|origin|from|remote|destination|dest|dst|target|local)\\w*(ChainId|Domain|DomainId|NetworkId|chain|domain)\\b'}, {'function.body_contains_regex': 'keccak256\\s*\\(\\s*abi\\.encode(?:Packed)?\\s*\\('}, {'function.body_contains_regex': '(?i)\\b(root|leaf|nonce|payload|message|sender|recipient|commitment)\\b'}, {'function.body_contains_regex': '(?i)(consumed|processed|used|spent|seen)\\w*\\s*\\['}, {'function.body_contains_regex': '(?i)(consumed|processed|used|spent|seen)\\w*\\s*\\[[^\\]]+\\]\\s*=\\s*(true|1)'}, {'function.body_not_contains_regex': '(?is)keccak256\\s*\\(\\s*abi\\.encode(?:Packed)?\\s*\\([^;{}]*(source|src|origin|from|remote)\\w*(ChainId|Domain|DomainId|NetworkId|chain|domain)'}, {'function.body_not_contains_regex': '(?is)keccak256\\s*\\(\\s*abi\\.encode(?:Packed)?\\s*\\([^;{}]*(destination|dest|dst|target|local)\\w*(ChainId|Domain|DomainId|NetworkId|chain|domain|block\\.chainid)'}, {'function.body_not_contains_regex': '(?is)keccak256\\s*\\(\\s*abi\\.encode(?:Packed)?\\s*\\([^;{}]*(address\\s*\\(\\s*this\\s*\\)|DOMAIN_SEPARATOR|domainSeparator|_domainSeparatorV4)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" - bridge-replay-key-omits-chain-domain: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
