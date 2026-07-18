"""
teller-beacon-proxy-initialize-zero-beacon — generated from reference/patterns.dsl/teller-beacon-proxy-initialize-zero-beacon.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py teller-beacon-proxy-initialize-zero-beacon.yaml
Source: auditooor-R76-immunefi-teller-$1M-DAI-at-risk
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TellerBeaconProxyInitializeZeroBeacon(AbstractDetector):
    ARGUMENT = "teller-beacon-proxy-initialize-zero-beacon"
    HELP = "Beacon proxy's initialize sets the beacon address without guarding against re-init or unauthorized caller. Anyone can front-run and install a malicious beacon, then selfdestruct the proxy."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/teller-beacon-proxy-initialize-zero-beacon.yaml"
    WIKI_TITLE = "BeaconProxy initialize has no caller/beacon-slot guard — front-runnable hijack"
    WIKI_DESCRIPTION = "A BeaconProxy variant with public `initialize(address beacon)` is vulnerable when: (a) the beacon storage slot reads zero before init, (b) initialize has no msg.sender restriction, and (c) no factory-created salt binds the proxy to a legitimate beacon. Between deployment and the legitimate initialize, an attacker front-runs with a malicious beacon. Subsequent proxy calls delegatecall into the atta"
    WIKI_EXPLOIT_SCENARIO = "Teller's InitializeableBeaconProxy was deployed and left with beacon=0. An attacker could front-run initialize, set beacon to a malicious implementation containing selfdestruct, then call any proxy method — proxy gets destroyed with ~1M DAI locked. Fix: the factory pre-initialized beacon to address(1), making subsequent initialize attempts silently no-op."
    WIKI_RECOMMENDATION = "Either (a) initialize beacon inside the proxy's constructor (CREATE2 salt-includes-beacon), (b) pre-initialize to address(1) sentinel, or (c) restrict initialize to the factory address. Add deployment test: immediately after proxy deploy, any external initialize call MUST revert."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^initialize$|^initializeProxy$|^setBeacon$'}, {'function.body_contains_regex': '(?i)_setBeacon\\s*\\(|_beacon\\s*=|ERC1967Upgrade\\._setBeacon|beacon\\s*=\\s*\\w+'}, {'function.body_not_contains_regex': '(?i)require\\s*\\(\\s*_beacon\\s*==\\s*address\\s*\\(\\s*0\\s*\\)|_getBeacon\\(\\)\\s*==\\s*address\\s*\\(\\s*0\\s*\\)\\s*\\&\\&|onlyOwner|msg\\.sender\\s*==\\s*(?:creator|factory|owner)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — teller-beacon-proxy-initialize-zero-beacon: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
