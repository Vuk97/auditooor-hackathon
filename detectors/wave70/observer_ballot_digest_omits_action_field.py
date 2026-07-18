"""
observer-ballot-digest-omits-action-field — generated from reference/patterns.dsl/observer-ballot-digest-omits-action-field.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py observer-ballot-digest-omits-action-field.yaml
Source: auditooor-R75-c4-mined-2023-11-zetachain-133-327-sibling-batch6
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ObserverBallotDigestOmitsActionField(AbstractDetector):
    ARGUMENT = "observer-ballot-digest-omits-action-field"
    HELP = "Observer/consensus vote submission function computes ballot index omitting action payload field, then writes payload separately. Two votes with different payloads share the same ballot index."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/observer-ballot-digest-omits-action-field.yaml"
    WIKI_TITLE = "Observer vote submission writes action field outside ballot index preimage"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Sibling of observer-consensus-vote-index-missing-payload-field-allows-collision. An external vote submission function computes a ballot identifier from consensus fields (chainId, creator, txHash, observerType) but writes the action payload (newPubKey, gasLimit, asset) into storage separately, outside the index preimage. Two votes with differ"
    WIKI_EXPLOIT_SCENARIO = "submitTssVote computes index = keccak256(abi.encode(vote.chainId, vote.creator, vote.txHash, vote.observerType)) then writes payloadByBallot[index] = vote.newPubKey. A malicious observer with the same chainId/creator/txHash/observerType but a different newPubKey writes to the same index, overwriting the honest payload."
    WIKI_RECOMMENDATION = "Include all consensus-relevant payload fields in the ballot identifier preimage. Invariant: two vote messages that differ in any consensus-relevant field must produce different ballot identifiers."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(observer|tss|ballot|vote|quorum|threshold|TSS)'}, {'contract.source_matches_regex': '(?i)(newPubKey|tssPubKey|tss_pubkey|publicKey|newKey|gasLimit|coinType|asset)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(submit|cast|record|register)(Tss|Observer|Vote|Ballot|Consensus).*$|^(submitTssVote|castVote|recordVote|observerVote|registerVote|submitVote)$'}, {'function.body_contains_regex': '(?i)\\bindex\\s*=\\s*\\w+Identifier\\s*\\('}, {'function.body_contains_regex': '(?i)\\[index\\]\\s*=\\s*\\w+\\.(newPubKey|tssPubKey|publicKey|newKey|gasLimit|coinType|asset|eventIndex)'}, {'contract.source_matches_regex': '(?i)function\\s+(?:ballotIdentifier|ballotId|computeIndex|voteIndex)\\b'}, {'contract.not_source_matches_regex': '(?is)function\\s+(?:ballotIdentifier|ballotId|computeIndex|voteIndex)\\s*\\([^)]*\\)[^{]*\\{[^}]*(newPubKey|tssPubKey|publicKey|newKey|gasLimit|coinType|asset|eventIndex)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" — observer-ballot-digest-omits-action-field: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
