"""
gnosis-safe-factory-create-based-address-replay-across-chains — generated from reference/patterns.dsl/gnosis-safe-factory-create-based-address-replay-across-chains.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py gnosis-safe-factory-create-based-address-replay-across-chains.yaml
Source: auditooor-R76-rekt-wintermute-2022
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GnosisSafeFactoryCreateBasedAddressReplayAcrossChains(AbstractDetector):
    ARGUMENT = "gnosis-safe-factory-create-based-address-replay-across-chains"
    HELP = "Proxy/Safe factory uses CREATE (not CREATE2). Deployed addresses are nonce-derived, so an attacker on another chain can burn nonces until the factory reaches the target nonce and redeploy a proxy at an address matching an existing owner on another chain."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/gnosis-safe-factory-create-based-address-replay-across-chains.yaml"
    WIKI_TITLE = "Proxy factory uses CREATE instead of CREATE2, allowing nonce-burn address replay on other chains"
    WIKI_DESCRIPTION = "When a factory deploys proxies with the CREATE opcode, the deployed address is `keccak256(rlp([factory_address, factory_nonce]))[12:]` — depending only on the factory and its transaction nonce. If the same factory exists at the same address on another chain (common for deterministic/CREATE2-deployed factories or for EOA-created deterministic deployments), an attacker can submit filler transactions"
    WIKI_EXPLOIT_SCENARIO = "Wintermute ships 20M OP tokens to 0x4f3a120e72c76c22ae802d129f599bfdbc31cb81, which is the address of their Gnosis Safe on Ethereum. That Safe was never deployed on Optimism. Attacker watches, then calls Optimism's GnosisSafeProxyFactory.createProxy repeatedly with dummy configs; with each call the factory nonce increments. Eventually the factory nonce reaches the value that made the Ethereum Safe"
    WIKI_RECOMMENDATION = "ALWAYS use CREATE2 with a salt derived from the owner set and initial config (Gnosis Safe v1.3.0+ does this with `createProxyWithNonce(..., saltNonce)`). Never rely on CREATE-based address determinism across chains. Additionally, before bridging assets to a 'known address', verify the target chain a"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'Proxy / Safe factory uses the `create` opcode to deploy clones, where the deployed-address is purely a function of (factory, nonce).']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)createProxy|createSafe|deployClone|createWallet|proxyCreation'}, {'function.body_contains_regex': '(?i)new\\s+\\w+Proxy\\s*\\(|assembly\\s*\\{[\\s\\S]*create\\s*\\(\\s*0\\s*,|create\\s*\\(\\s*0\\s*,\\s*add\\s*\\('}, {'function.body_not_contains_regex': '(?i)create2\\s*\\(|salt|keccak256.*salt|deploy\\s*\\([^)]*bytes32'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — gnosis-safe-factory-create-based-address-replay-across-chains: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
