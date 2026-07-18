"""
event-emits-stale-recipient-after-fallback — generated from reference/patterns.dsl/event-emits-stale-recipient-after-fallback.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py event-emits-stale-recipient-after-fallback.yaml
Source: auditooor-R75-c4-yield-2024-06-thorchain-17
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EventEmitsStaleRecipientAfterFallback(AbstractDetector):
    ARGUMENT = "event-emits-stale-recipient-after-fallback"
    HELP = "On ETH .send() failure the payload bounces to msg.sender, but the emitted event still reports the original `to`. Off-chain indexers mis-credit the original recipient."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/event-emits-stale-recipient-after-fallback.yaml"
    WIKI_TITLE = "Event emits original recipient after .send() bounce-back, mis-informing off-chain bridge parser"
    WIKI_DESCRIPTION = "Bridge routers that emit a `TransferOut` / `Bridged` event read by off-chain validators must reflect the actual final recipient. A common bug: `to.send(value)` may fail silently (2300-gas, reentrant receive, etc.), the code falls back to `msg.sender.transfer(value)` to bounce the funds back to the vault, but the unchanged local variable `to` is still emitted in the event. Off-chain parsers (THORCh"
    WIKI_EXPLOIT_SCENARIO = "ThorChain_Router.transferOut: vault instructs transferOut(to=contract_rejecting_eth, asset=ETH). to.send() fails; eth bounces to vault via msg.sender.transfer. emit TransferOut(from, to, asset, safeAmount, memo) — `to` is still the rejecting contract. THORChain credits the user's address with the ETH, debits the vault. User retries via THORChain, gets paid again — vault double-pays."
    WIKI_RECOMMENDATION = "On fallback, overwrite `to = msg.sender` (or emit a distinct `TransferOutBounced` event) before the emit. Off-chain parsers should also track ETH balance deltas rather than trusting event payloads alone."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(transferOut|send|bridgeOut|_transferOut)'}, {'function.body_contains_regex': '\\.send\\s*\\('}, {'function.body_contains_regex': 'payable\\s*\\(\\s*(address\\(msg\\.sender\\)|msg\\.sender)\\s*\\)\\s*\\.(transfer|send)'}, {'function.body_contains_regex': 'emit\\s+\\w+\\s*\\([^)]*,\\s*to\\s*,'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — event-emits-stale-recipient-after-fallback: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
