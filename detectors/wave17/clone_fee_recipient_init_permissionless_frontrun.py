"""
clone-fee-recipient-init-permissionless-frontrun — generated from reference/patterns.dsl/clone-fee-recipient-init-permissionless-frontrun.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py clone-fee-recipient-init-permissionless-frontrun.yaml
Source: auditooor-R108-kiln-v1-fee-recipient-clone
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CloneFeeRecipientInitPermissionlessFrontrun(AbstractDetector):
    ARGUMENT = "clone-fee-recipient-init-permissionless-frontrun"
    HELP = "CREATE2-cloned receiver contract has an `external init()` gated only by a boolean `initialized` flag. The init() assigns a critical destination address (dispatcher / factory / vault) from a function parameter, but does NOT validate `msg.sender == expectedFactory`. Anyone can call init() between the "
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/clone-fee-recipient-init-permissionless-frontrun.yaml"
    WIKI_TITLE = "Cloned receiver init() lacks msg.sender factory gate, attacker can inject dispatcher"
    WIKI_DESCRIPTION = "OpenZeppelin `Clones.cloneDeterministic` produces a deterministic address derived from `(implementation, salt)`. The clone has no constructor — initial state is set by an `init()` call after deployment. When the init() is gated only by a boolean `initialized` flag (no `msg.sender` validation), any address can race the parent factory's intended initialize. The attacker calls `init(maliciousDispatch"
    WIKI_EXPLOIT_SCENARIO = "Kiln V1 staking-contract deployment uses CREATE2-deterministic FeeRecipient clones with salt `sha256(prefix || pubKeyRoot)`. The address is fully predictable from the public key root before any deposit. An attacker monitors the staking contract for `addValidators` (which publishes the public key roots). For each pubKeyRoot the attacker pre-computes the EL+CL FeeRecipient addresses. When a user cal"
    WIKI_RECOMMENDATION = "Bake the trusted parent inside init() and gate every downstream entry point. Replace:\n\n```solidity\nfunction init(address _dispatcher, bytes32 _publicKeyRoot) external {\n    if (initialized) revert AlreadyInitialized();\n    initialized = true;\n    dispatcher = IFeeDispatcher(_dispatcher);\n    "

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Clones\\.|cloneDeterministic|predictDeterministicAddress|ERC1167|FeeRecipient|MinipoolReceiver|RewardRecipient|VaultClone|ProxyRecipient'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(init|initialize|__init|initRecipient)$'}, {'function.body_contains_regex': 'if\\s*\\(\\s*initialized\\s*\\)[\\s\\S]{0,40}revert\\s+[A-Za-z]|if\\s*\\(\\s*_initialized\\s*\\)[\\s\\S]{0,40}revert|require\\s*\\(\\s*!\\s*initialized|require\\s*\\(\\s*!\\s*_initialized'}, {'function.body_contains_regex': '(dispatcher|stakingContract|factory|vault|recipient|target|aggregator|distributor|router)\\s*=\\s*[A-Za-z_][A-Za-z0-9_]*'}, {'function.body_not_contains_regex': 'msg\\.sender\\s*==\\s*[A-Za-z_]*[Ff]actory|msg\\.sender\\s*==\\s*[A-Za-z_]*[Ss]taking|msg\\.sender\\s*==\\s*[A-Za-z_]*[Pp]arent|msg\\.sender\\s*==\\s*expected|msg\\.sender\\s*==\\s*deployer|stakingContract\\s*=\\s*msg\\.sender|factory\\s*=\\s*msg\\.sender|onlyFactory|onlyStakingContract|onlyParent|onlyDeployer'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — clone-fee-recipient-init-permissionless-frontrun: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
