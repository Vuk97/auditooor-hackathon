"""
Row-local detector for observer/TSS vote ballot identifiers that omit payload.

The generated version targeted a Cosmos message-shape regex that could not be
closed against Solidity fixtures. This repair keeps the same detector argument
but narrows execution to Solidity digest helpers used by observer/TSS voting.
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ObserverConsensusVoteIndexMissingPayloadFieldAllowsCollision(AbstractDetector):
    ARGUMENT = "observer-consensus-vote-index-missing-payload-field-allows-collision"
    HELP = "Observer/TSS vote ballot identifier hashes consensus key fields but omits a payload field that can change the final action."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/observer-consensus-vote-index-missing-payload-field-allows-collision.yaml"
    WIKI_TITLE = "Observer ballot index omits payload field, last voter substitutes malicious TSS pubkey"
    WIKI_DESCRIPTION = "The ballot uniqueness key hashes fields such as chainId, creator, txHash, and observerType, while the voted payload is written or finalized separately. If newPubKey, gasLimit, asset, eventIndex, or coinType is omitted, two votes with different payloads can share one ballot index."
    WIKI_EXPLOIT_SCENARIO = "During TSS rotation, honest observers vote for one new public key. A malicious final observer votes with the same chain/tx/observer fields but a different newPubKey. Because the digest omits newPubKey, the vote collides with the honest ballot and the finalizing write can adopt the attacker's payload."
    WIKI_RECOMMENDATION = "Include every consensus-relevant payload field in the ballot identifier preimage and version the digest domain when adding fields."

    _PRECONDITIONS = [
        {'contract.source_matches_regex': '(?i)(observer|tss|ballot|vote|quorum|threshold)'},
        {'contract.source_matches_regex': '(?i)(newPubKey|tssPubKey|tss_pubkey|publicKey|newKey|gasLimit|eventIndex|asset|coinType)'},
    ]
    _MATCH = [
        {'function.kind': 'external_or_public_or_internal'},
        {'function.name_matches': '(?i)(digest|ballotIdentifier|ballotId|computeIndex|voteIndex|index)$'},
        {'function.body_contains_regex': '(?is)(keccak256|sha256)\\s*\\(\\s*(abi\\.encode(Packed)?\\s*)?\\([^;]*(chainId|chainID|creator|txHash|observerType|nonce)'},
        {'function.body_not_contains_regex': '(?i)(newPubKey|tssPubKey|tss_pubkey|publicKey|newKey|gasLimit|eventIndex|asset|coinType)'},
        {'function.not_in_skip_list': True},
        {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'},
    ]

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
                info = [f, f" — observer-consensus-vote-index-missing-payload-field-allows-collision: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
