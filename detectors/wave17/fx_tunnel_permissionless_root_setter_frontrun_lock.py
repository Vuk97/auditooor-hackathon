"""
fx-tunnel-permissionless-root-setter-frontrun-lock — generated from reference/patterns.dsl/fx-tunnel-permissionless-root-setter-frontrun-lock.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-tunnel-permissionless-root-setter-frontrun-lock.yaml
Source: auditooor-R75-c4-mined-2023-12-autonolas-404
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxTunnelPermissionlessRootSetterFrontrunLock(AbstractDetector):
    ARGUMENT = "fx-tunnel-permissionless-root-setter-frontrun-lock"
    HELP = "`setFxRootTunnel(address)` / `setFxChildTunnel(address)` / `setPeer(address)` is external and gated ONLY by `require(current == address(0))` — one-shot permissionless. After deployment, anyone can front-run the legitimate setup tx and set peer = attackerAddress. Because the setter is one-shot, the a"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-tunnel-permissionless-root-setter-frontrun-lock.yaml"
    WIKI_TITLE = "Fx/AMB tunnel peer-setter is permissionless one-shot, front-runnable at deploy"
    WIKI_DESCRIPTION = "The FxBaseChildTunnel-style pattern stores a `fxRootTunnel` that is the only authorized sender of cross-domain messages. The setter is external with `require(fxRootTunnel == address(0))` and no access control. The deployer is expected to call it post-deploy to wire up the peer. A mempool observer sees the legitimate `setFxRootTunnel(realRoot)` tx, front-runs with `setFxRootTunnel(attackerAddr)`. B"
    WIKI_EXPLOIT_SCENARIO = "Autonolas deploys FxERC20ChildTunnel on Polygon. Deployer's next tx (nonce+1) is `setFxRootTunnel(0xRealRoot)`. Mempool watcher on Polygon submits the same call with parameter `0xAttacker` at higher gas. Attacker's tx mines first. State: fxRootTunnel = 0xAttacker, and the one-shot guard now rejects any further setFxRootTunnel. Deployer's tx reverts. All subsequent L1→L2 OLAS transfers fail validat"
    WIKI_RECOMMENDATION = "Make the setter callable only by `onlyOwner` / `onlyGovernance` so the deployer always wins. Alternatively, pass the counterpart address into the constructor and make it immutable (preferred, since cross-chain peers are typically deterministic-deployed). Invariant: after deployment, only the configu"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'FxBaseChildTunnel|FxBaseRootTunnel|setFxRootTunnel|setFxChildTunnel'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(setFxRootTunnel|setFxChildTunnel|setRemoteBridge|setPeer|setCounterpart)$'}, {'function.body_contains_regex': 'require\\s*\\(\\s*(fxRootTunnel|fxChildTunnel|peer|counterpart)\\s*==\\s*address\\s*\\(\\s*0x?0?\\s*\\)'}, {'function.body_contains_regex': '(fxRootTunnel|fxChildTunnel|peer|counterpart)\\s*=\\s*_?\\w+'}, {'function.body_not_contains_regex': '(onlyOwner|onlyAdmin|onlyGovernance|hasRole|_authorize|require\\s*\\(\\s*msg\\.sender\\s*==)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-tunnel-permissionless-root-setter-frontrun-lock: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
