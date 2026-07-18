"""
crosschain-handler-partial-source-chain-validation — generated from reference/patterns.dsl/crosschain-handler-partial-source-chain-validation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py crosschain-handler-partial-source-chain-validation.yaml
Source: r106-centrifuge-v3-MessageProcessor.handle
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CrosschainHandlerPartialSourceChainValidation(AbstractDetector):
    ARGUMENT = "crosschain-handler-partial-source-chain-validation"
    HELP = "Cross-chain message handler enforces `require(srcChain == m.embeddedId.chainId())` on some branches but omits it on others within the same `if/else if` dispatcher. A rogue adapter on chain X can spoof a message labelled as originating from chain Y, corrupting Y-targeted state on the destination chai"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/crosschain-handler-partial-source-chain-validation.yaml"
    WIKI_TITLE = "Cross-chain dispatcher enforces source-chain guard on only some message branches"
    WIKI_DESCRIPTION = "A multi-kind cross-chain message handler is the choke-point through which all inbound bridge traffic must pass. Each branch decodes a payload that embeds an asset/pool/share identifier whose first bytes encode the source chain. Idiomatic implementations add `require(srcChain == m.id.chainId(), OnlyFromSource())` to bind authority. The bug is selective application: privileged-looking kinds (`Regist"
    WIKI_EXPLOIT_SCENARIO = "Attacker takes over one of the supported chain's adapters (e.g. by exploiting an unrelated bug in that chain's deployment). They build an `UpdateHoldingAmount` message with `m.poolId.chainId() = ChainY` and submit it through their compromised ChainX adapter. The destination's `handle(ChainX, m)` reaches the `UpdateHoldingAmount` branch, which has no `require(ChainX == m.poolId.chainId())`, and for"
    WIKI_RECOMMENDATION = "Audit every branch of the dispatcher for the same `require(srcChain == decoded.X.chainId())` invariant. Either lift it to a single check at the top of the function (when every message-kind has a recoverable source-id), or add explicit `require` per branch and document why a branch is exempt. Static-"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(handle|process|dispatch|receive|deliver|execute)\\w*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(handle|process|dispatch|receive|deliver|execute|onMessage|lzReceive|_lzReceive|wormholeReceive)\\w*'}, {'function.body_contains_regex': 'require\\s*\\(\\s*\\w+\\s*==\\s*\\w+\\.\\s*(?:chainId|centrifugeId|eid|domain|networkId|sourceChain|origin)\\w*\\s*\\([^)]*\\)'}, {'function.body_contains_regex': 'else\\s+if\\s*\\(\\s*kind\\s*==\\s*[\\w.]+\\s*\\)\\s*\\{(?:(?!require)[^{}])*?\\b(?:hubHandler|spoke|balanceSheet|sender|gateway|registry|handler|target|multiAdapter|processor|handlerCallback|tokenRecoverer|scheduleAuth|contractUpdater|vaultRegistry)\\s*\\.\\s*\\w+\\s*\\('}, {'function.body_not_contains_regex': 'for\\s*\\([^)]*kind[^)]*\\)\\s*\\{[^}]*require\\s*\\([^)]*srcChain'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — crosschain-handler-partial-source-chain-validation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
