"""
cross-chain-eid-collision-enables-message-forgery — generated from reference/patterns.dsl/cross-chain-eid-collision-enables-message-forgery.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cross-chain-eid-collision-enables-message-forgery.yaml
Source: auditooor-R75-zellic-layerzero-dvn-HIGH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CrossChainEidCollisionEnablesMessageForgery(AbstractDetector):
    ARGUMENT = "cross-chain-eid-collision-enables-message-forgery"
    HELP = "Cross-chain message adapters (DVNs, bridge routers, IBC light-client configs) maintain bidirectional maps between local chain identifiers (chainName/srcConfig) and canonical endpoint-IDs (eid/dstConfig). If only one side is guarded by a 'set-once' check, an admin can register a new chainName that ma"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cross-chain-eid-collision-enables-message-forgery.yaml"
    WIKI_TITLE = "Cross-chain adapter eid/chainId mapping is not uniquely enforced in both directions"
    WIKI_DESCRIPTION = "LayerZero-style DVN adapters guard dstConfig[eid] from being overwritten but do not prevent multiple srcConfig[chainName] entries from resolving to the same eid. An attacker-admin on the adapter can add a new chain that the base oApp does not trust, register its srcConfig with an eid that another, trusted chain already owns, and route an Axelar/CCIP message on behalf of the trusted eid."
    WIKI_EXPLOIT_SCENARIO = "LayerZero supports chains A(eid=1), B(eid=2), C(eid=3). An Axelar adapter admin calls setDstConfig with chainName='D', eid=1. They deploy a malicious contract on chain D; _assertPeer passes because it checks the admin-settable peer; _decodeAndVerify passes because srcEid%30000==1. Applications trusting messages from eid 1 (chain A) now receive attacker-authored messages from chain D."
    WIKI_RECOMMENDATION = "Enforce that the eid → chainName mapping is bijective: on every setSrcConfig/setDstConfig, also revert if the target eid is already claimed by a different chainName. Consider making the mapping immutable once set, or use a separate trusted-setter multisig flow for chain-addition."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(srcConfig|dstConfig|chainId.*peer|endpointId|eid)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(setSrcConfig|setDstConfig|setPeer|setChain|addChain|setRemote)'}, {'function.body_contains_regex': 'if\\s*\\(\\s*[a-zA-Z_0-9.]+\\[[^\\]]+\\]\\.(eid|chainId|peer)\\s*==\\s*(0|address\\(0\\)|bytes\\(\\"\\")'}, {'function.body_not_contains_regex': '(reverseLookup|eidToChain|chainToEid|_assertUniqueEid)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cross-chain-eid-collision-enables-message-forgery: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
