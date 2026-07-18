"""
cosmwasm-arb-trampoline-caller-supplied-owner-address — generated from reference/patterns.dsl/cosmwasm-arb-trampoline-caller-supplied-owner-address.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cosmwasm-arb-trampoline-caller-supplied-owner-address.yaml
Source: auditooor-R76-c4-rujira-bug-bounty-26-24
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CosmwasmArbTrampolineCallerSuppliedOwnerAddress(AbstractDetector):
    ARGUMENT = "cosmwasm-arb-trampoline-caller-supplied-owner-address"
    HELP = "Public Arb wrapper self-executes attacker bytes. Target handlers check only `info.sender == env.contract.address` and trust caller-supplied owner address — permissionless cancel/modify of victim orders."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cosmwasm-arb-trampoline-caller-supplied-owner-address.yaml"
    WIKI_TITLE = "CosmWasm Arb trampoline + self-call gate = confused deputy over victim orders"
    WIKI_DESCRIPTION = "`ExecuteMsg::Arb { then: Binary }` is a public wrapper that self-executes any serialised ExecuteMsg as the contract itself: `CosmosMsg::Wasm(WasmMsg::Execute { contract_addr: env.contract.address, msg: attacker_bytes, funds: info.funds })`. Inner handlers like `DoOrder((recipient, ...))` / `DoSwap((sender, ...))` authenticate only via `info.sender == env.contract.address` — trivially satisfied by "
    WIKI_EXPLOIT_SCENARIO = "Victim has a sell at price 1000. Attacker places a buy at 500 (no crossing). Attacker sends `ExecuteMsg::Arb { then: Some(to_json_binary(ExecuteMsg::DoOrder((victim, (vec![(Side::Base, 1000, Some(0)), (Side::Base, 500, Some(200))], None)))).unwrap()) }`. The contract retracts the victim's 1000 sell (target=0) and recreates it at 500, which immediately matches the attacker's buy. Attacker withdraws"
    WIKI_RECOMMENDATION = "In the Arb handler, decode `then` and enforce caller identity: if `info.sender != env.contract.address`, require that the embedded `DoOrder((recipient, _))` has `recipient == info.sender` (and same for DoSwap.sender). Better: make `Arb` non-public or gate by a privileged role. Never let a self-call "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)\\.rs$|contract\\.rs'}, {'contract.has_function_matching': '(?i)execute|ExecuteMsg'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)execute|ExecuteMsg::Arb|arb_handler|trampoline'}, {'function.body_contains_regex': '(?i)WasmMsg::Execute\\s*\\{\\s*contract_addr:\\s*env\\.contract\\.address|contract_addr:\\s*env\\.contract\\.address\\.to_string\\(\\)'}, {'function.body_contains_regex': '(?i)ExecuteMsg::DoOrder|ExecuteMsg::DoSwap|DoBorrow|DoClose|DoWithdraw'}, {'function.body_not_contains_regex': '(?i)ensure_eq!\\s*\\(\\s*(recipient|sender|user|owner)\\s*,\\s*info\\.sender|ensure_eq!\\s*\\(\\s*info\\.sender\\s*,\\s*(recipient|sender|user|owner)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cosmwasm-arb-trampoline-caller-supplied-owner-address: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
