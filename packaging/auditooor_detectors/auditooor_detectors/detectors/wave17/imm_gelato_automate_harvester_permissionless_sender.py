"""
imm-gelato-automate-harvester-permissionless-sender — generated from reference/patterns.dsl/imm-gelato-automate-harvester-permissionless-sender.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py imm-gelato-automate-harvester-permissionless-sender.yaml
Source: immunefi/alchemix-access-control-harvest
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ImmGelatoAutomateHarvesterPermissionlessSender(AbstractDetector):
    ARGUMENT = "imm-gelato-automate-harvester-permissionless-sender"
    HELP = "Harvester gates msg.sender to Gelato's generic Automate contract rather than a dedicated proxy. Because Automate.createTask is permissionless, anyone can queue a task that calls harvest() with minimumAmountOut=1, sandwiching the protocol's own yield swap."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/imm-gelato-automate-harvester-permissionless-sender.yaml"
    WIKI_TITLE = "Harvester allows Gelato Automate as caller without dedicated-msg-sender proxy (Alchemix)"
    WIKI_DESCRIPTION = "Keeper frameworks like Gelato expose a generic `Automate` contract (or `Ops`) that forwards task calls to the target on behalf of anyone who calls `createTask`. If the harvester restricts its privileged harvest entrypoint with `require(msg.sender == address(Automate))` this check is equivalent to no check at all: an attacker calls `Automate.createTask(target=harvester, data=harvest(..., minOut=1))"
    WIKI_EXPLOIT_SCENARIO = "Alchemix harvester (Sep 2023): `harvest(yieldToken, minimumAmountOut)` is gated by `require(msg.sender == ops)` where `ops` is the Gelato `Automate` contract. An attacker calls `ops.createTask(harvester, abi.encodeWithSelector(harvest.selector, alETH, 1))`, sandwiches the internal Curve swap with a large imbalance, and extracts the harvest proceeds. Fix shipped as a redeploy using Gelato's `dedica"
    WIKI_RECOMMENDATION = "Two layers: (1) use Gelato's `dedicatedMsgSender` derived from a protocol-owned EOA so only tasks the protocol team itself creates satisfy the sender check; (2) do not accept user-supplied slippage on privileged harvest paths — compute `minimumAmountOut` inline from an oracle (`expectedOut * (1 - ma"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'gelato|IAutomate|Automate|OpsReady|onlyGelato|_gelatoPoker|keeperFee'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(harvest|_harvest|harvestAndCompound|keeperHarvest|performUpkeep)$'}, {'function.body_contains_regex': 'msg\\.sender\\s*==\\s*(AUTOMATE|automate|_ops|ops\\b|gelato|_gelatoPoker|OPS_PROXY)|require\\s*\\(\\s*msg\\.sender\\s*==\\s*(AUTOMATE|automate|_ops|ops\\b|gelato|_gelatoPoker)'}, {'function.body_contains_regex': 'minimumAmountOut|minAmountOut|minReturnAmount|slippageBps|expectedOut'}, {'function.body_not_contains_regex': 'dedicatedMsgSender|DEDICATED_MSG_SENDER|keeperRegistry|whitelistedKeeper|trustedCaller|onlyTrustedKeeper'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — imm-gelato-automate-harvester-permissionless-sender: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
