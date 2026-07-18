"""
deprecated-voter-handler-no-consensus-single-writer-nonce-overwrite — generated from reference/patterns.dsl/deprecated-voter-handler-no-consensus-single-writer-nonce-overwrite.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py deprecated-voter-handler-no-consensus-single-writer-nonce-overwrite.yaml
Source: auditooor-R75-c4-mined-2023-11-zetachain-547
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DeprecatedVoterHandlerNoConsensusSingleWriterNonceOverwrite(AbstractDetector):
    ARGUMENT = "deprecated-voter-handler-no-consensus-single-writer-nonce-overwrite"
    HELP = "A 'voter' message handler in a Cosmos-SDK keeper is restricted to `IsAuthorized(observer)` but then skips the ballot/threshold logic entirely and directly writes state via `SetChainNonces(ctx, nonce)`. Despite the name/comment claiming it is 'deprecated' or 'TODO: implement voting', the handler is s"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/deprecated-voter-handler-no-consensus-single-writer-nonce-overwrite.yaml"
    WIKI_TITLE = "Observer-voter handler skips consensus, single observer can set chain nonces"
    WIKI_DESCRIPTION = "NonceVoter(ctx, MsgNonceVoter) validates the sender via `IsAuthorized(msg.Creator, chain)`, then jumps straight to `k.SetChainNonces(ctx, chainNonce)` — no ballot creation, no vote counting, no threshold check. The comment may say 'deprecated' but the handler is live in the MsgServer registration. Any one of the n observers can call this once and set the chain nonce to any value. Nonce desynchroni"
    WIKI_EXPLOIT_SCENARIO = "Observer Mallory is one of 10 bonded observers on chain 1337. She calls `zetacored tx crosschain nonce-voter 1337 0xDEADBEEF --from mallory`. NonceVoter authorizes her, skips the commented-out voting logic, calls SetChainNonces(ctx, {chain:1337, nonce:0xDEADBEEF}). Chain 1337's TSS now believes the next outbound nonce is 0xDEADBEEF. All in-flight CCTXs with nonces < 0xDEADBEEF become unmatched bec"
    WIKI_RECOMMENDATION = "Either (a) delete the deprecated handler and drop its MsgServer registration entirely, or (b) replace the body with a ballot-creating path identical to other *Voter handlers (AddVote, FinalizeBallot, threshold check). Add a CI test that greps every *Voter handler for `SetChainNonces`/`SetX` and asse"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'NonceVoter|ChainNonce|keeper_chain_nonces|MsgNonceVoter'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '^(NonceVoter|SetChainNonce|UpdateChainNonce|SubmitNonce)$'}, {'function.body_contains_regex': '(zetaObserverKeeper|observerKeeper)\\.IsAuthorized|onlyObserver'}, {'function.body_contains_regex': 'SetChainNonces?\\s*\\(\\s*ctx,\\s*\\w+Nonce\\s*\\)|k\\.SetChainNonces'}, {'function.body_not_contains_regex': '(AddVote|FindBallot|BallotCreated|hasReachedThreshold|majorityReached|voteOnBallot|submitVote\\()'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — deprecated-voter-handler-no-consensus-single-writer-nonce-overwrite: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
