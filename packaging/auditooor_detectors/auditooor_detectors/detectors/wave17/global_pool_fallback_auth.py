"""
global-pool-fallback-auth — generated from reference/patterns.dsl/global-pool-fallback-auth.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py global-pool-fallback-auth.yaml
Source: auditooor-r38d-drill2
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GlobalPoolFallbackAuth(AbstractDetector):
    ARGUMENT = "global-pool-fallback-auth"
    HELP = "Cross-chain receiver authenticates admin-class messages (ScheduleUpgrade, RecoverTokens, SetPoolAdapters) through a GLOBAL_POOL (poolId == 0) fallback adapter set — admin traffic rides the weakest per-pool configuration."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/global-pool-fallback-auth.yaml"
    WIKI_TITLE = "Cross-chain admin message authentication collapses into GLOBAL_POOL adapter slot"
    WIKI_DESCRIPTION = "Hub-and-spoke cross-chain messaging contracts authenticate inbound payloads by reading `adapters[chainId][poolId]` where `poolId` is decoded from the payload. For pool-independent / admin-class messages (upgrade scheduling, token recovery, adapter reconfiguration, pool notification), the decoder returns `poolId == 0` — a shared GLOBAL_POOL slot. Because a single adapter set at that slot gates ever"
    WIKI_EXPLOIT_SCENARIO = "A MultiAdapter contract exposes `handle(uint16 chainId, bytes payload)`. The adapter lookup reads `_adapterDetails[chainId][messagePoolId(payload)][msg.sender]`. A governance message `ScheduleUpgrade(newImpl)` has no PoolId field, so `messagePoolId` returns `PoolId(0)`. The deployer configured GLOBAL_POOL with a single adapter (quorum 1, threshold 1) because 'all pool traffic flows through per-poo"
    WIKI_RECOMMENDATION = "Split admin-class messages onto a separate authentication path that does not share the GLOBAL_POOL (poolId == 0) slot with pool notification traffic. Options: (a) require an explicit high-threshold GLOBAL_ADMIN_ADAPTERS configuration enforced at deploy time with `require(threshold >= N)`; (b) route "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_declaration_matching': 'mapping\\s*\\([^;]*PoolId[^;]*\\)'}, {'contract.has_function_matching': '^(handle|receiveMessage|dispatchMessage|processMessage|onMessageReceived|relayMessage)$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.not_slither_synthetic': True}, {'function.is_mutating': True}, {'function.name_matches': '^(handle|receiveMessage|dispatchMessage|processMessage|onMessageReceived|relayMessage)$'}, {'function.body_contains_regex': 'messagePoolId\\s*\\(|messageProperties\\s*\\.\\s*messagePoolId|decodePoolId\\s*\\(|poolIdOf\\s*\\(|_poolId\\s*=\\s*.*payload'}, {'function.body_contains_regex': '(adapters|_adapterDetails|adapterSet|_adapters|routers|endpoints)\\s*\\[[^\\]]*(centrifugeId|chainId|srcChainId|remoteChainId|_chainId)[^\\]]*\\]\\s*\\[[^\\]]*(poolId|_poolId|PoolId)'}, {'function.body_not_contains_regex': 'ScheduleUpgrade|RecoverTokens|SetPoolAdapters|(admin|upgrade|recover|global)Adapters|_adminAdapters|GLOBAL_ADMIN_ADAPTERS'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — global-pool-fallback-auth: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
