"""
imm-aurora-withdraw-proof-missing-origin-check — generated from reference/patterns.dsl/imm-aurora-withdraw-proof-missing-origin-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py imm-aurora-withdraw-proof-missing-origin-check.yaml
Source: immunefi/aurora-withdrawal-logic-error
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ImmAuroraWithdrawProofMissingOriginCheck(AbstractDetector):
    ARGUMENT = "imm-aurora-withdraw-proof-missing-origin-check"
    HELP = "Bridge withdraw() parses a cross-chain proof, checks only that an embedded `ethCustodian` field equals address(this), but never verifies the proof actually came from a real burn on the source chain (no relayer allowlist, no outcome/merkle root check). Attacker forges arbitrary payloads."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/imm-aurora-withdraw-proof-missing-origin-check.yaml"
    WIKI_TITLE = "Cross-chain withdraw validates self-address but not proof origin (Aurora EthCustodian)"
    WIKI_DESCRIPTION = "Light-client / relayer bridges decode a serialized receipt from the remote chain on the finalizing side. Valid receipts embed a destination-address field so a payload minted on Bridge A can be distinguished from one for Bridge B. If the destination check is the ONLY validation — `require(parsed.ethCustodian == address(this))` — an attacker who can construct arbitrary bytes can forge a receipt that"
    WIKI_EXPLOIT_SCENARIO = "Aurora EthCustodian (Jun 2022): `withdraw(bytes proofData)` decoded `BurnResult { amount, recipient, ethCustodian }` and checked `ethCustodian == address(this)`. The remote `burn` logic happened to be reachable as a NEAR `view` function — attacker used it to generate receipt bytes for arbitrary `amount` / `recipient` without actually burning anything on Aurora, then called `withdraw(forged)` on Et"
    WIKI_RECOMMENDATION = "Every finalizing-side bridge function must verify the proof ORIGIN, not just its destination: (a) check the proof against a trusted relayer / light-client header set, (b) verify an outcome or receipt merkle root against a stored trusted root, or (c) restrict `withdraw` to a whitelist of relayer EOAs"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'withdraw\\s*\\(\\s*bytes|parseProof|BurnResult|_parseBurnResult|OutcomeProof|ReceiptProof|nearProof'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(withdraw|_withdraw|finalizeWithdraw|executeWithdraw)$'}, {'function.body_contains_regex': 'parseProof|BurnResult|_parseBurnResult|decodeProof|abi\\.decode\\s*\\([^)]*proofData'}, {'function.body_contains_regex': 'ethCustodian|bridgeAddress|custodianAddress'}, {'function.body_contains_regex': '(ethCustodian|bridgeAddress|custodianAddress)\\s*==\\s*address\\s*\\(\\s*this\\s*\\)'}, {'function.body_not_contains_regex': 'trustedRelayer|relayerWhitelist|verifyOutcome|outcomeRoot|merkleRoot|IRainbowBridge\\.verify|isRelayer|onlyRelayer|proofOrigin|_verifyHeader'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — imm-aurora-withdraw-proof-missing-origin-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
