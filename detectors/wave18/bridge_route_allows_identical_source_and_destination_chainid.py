"""
bridge-route-allows-identical-source-and-destination-chainid — generated from reference/patterns.dsl/bridge-route-allows-identical-source-and-destination-chainid.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-route-allows-identical-source-and-destination-chainid.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeRouteAllowsIdenticalSourceAndDestinationChainid(AbstractDetector):
    ARGUMENT = "bridge-route-allows-identical-source-and-destination-chainid"
    HELP = "Bridge route configuration accepts identical sourceChainId and destinationChainId. Messages can collapse onto a self-route and become stuck, misrouted, or non-replayable."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-route-allows-identical-source-and-destination-chainid.yaml"
    WIKI_TITLE = "Bridge route config does not reject identical source and destination chain ids"
    WIKI_DESCRIPTION = "Cross-chain bridges usually key a route by `(sourceChainId, destinationChainId)` and assume the pair describes two different domains. If a config or initialization path stores both ids without a `source != destination` guard, the route can collapse into a self-route. Downstream effects vary by implementation: a peer lookup may point back to the origin, a transfer may be marked outbound and inbound"
    WIKI_EXPLOIT_SCENARIO = "A bridge admin or deployment script calls `configureRoute(sourceChainId=8888, destinationChainId=8888, remoteGateway=0xBEEF...)`. The contract accepts the route and stores it in `routes[8888][8888]`. Later, user deposits on chain 8888 and the bridge emits an outbound transfer keyed to the same chain id on both sides. The destination lookup resolves to the self-route, the relay path never reaches t"
    WIKI_RECOMMENDATION = "Reject degenerate routes at the config boundary: `require(sourceChainId != destinationChainId, SameChainId());`. Add regression tests that attempt to configure or initialize a route with equal ids and assert revert. If the bridge maintains a bidirectional route registry, also enforce the inequality "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|cross.?chain|gateway|route|path|peer)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)^(configure|set|register|initialize)[A-Z]\\w*(Route|Path|Peer|Chain)|^(configureRoute|setRoute|registerPath|initializeBridge)$'}, {'function.source_matches_regex': '(?i)\\b(source|src)\\w*ChainId\\b'}, {'function.source_matches_regex': '(?i)\\b(destination|dest|dst|remote|target)\\w*ChainId\\b'}, {'function.body_contains_regex': '(?i)(source|src)\\w*ChainId\\s*=\\s*_?(source|src)\\w*ChainId'}, {'function.body_contains_regex': '(?i)(destination|dest|dst|remote|target)\\w*ChainId\\s*=\\s*_?(destination|dest|dst|remote|target)\\w*ChainId'}, {'function.body_not_contains_regex': '(?i)(require|assert)\\s*\\(\\s*_?(source|src)\\w*ChainId\\s*!=\\s*_?(destination|dest|dst|remote|target)\\w*ChainId|(require|assert)\\s*\\(\\s*_?(destination|dest|dst|remote|target)\\w*ChainId\\s*!=\\s*_?(source|src)\\w*ChainId|if\\s*\\(\\s*_?(source|src)\\w*ChainId\\s*==\\s*_?(destination|dest|dst|remote|target)\\w*ChainId\\s*\\)\\s*revert|if\\s*\\(\\s*_?(destination|dest|dst|remote|target)\\w*ChainId\\s*==\\s*_?(source|src)\\w*ChainId\\s*\\)\\s*revert|InvalidSameChain|SameChainId'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" — bridge-route-allows-identical-source-and-destination-chainid: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
