"""
chainsec-spark-savings-intent-signature-replay-crosschain — generated from reference/patterns.dsl/chainsec-spark-savings-intent-signature-replay-crosschain.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py chainsec-spark-savings-intent-signature-replay-crosschain.yaml
Source: auditooor-R75-chainsec-Spark-SavingsIntents
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ChainsecSparkSavingsIntentSignatureReplayCrosschain(AbstractDetector):
    ARGUMENT = "chainsec-spark-savings-intent-signature-replay-crosschain"
    HELP = "Cross-chain intents (e.g. Spark Savings Intents that route between Ethereum mainnet and an L2) sign an EIP-712 hash that does not include the destination chainId — a mainnet-signed intent can be replayed on the L2 where the same contract address is deployed, draining twice."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/chainsec-spark-savings-intent-signature-replay-crosschain.yaml"
    WIKI_TITLE = "Savings/order intent signature omits destination chainId — cross-chain replay"
    WIKI_DESCRIPTION = "Multi-chain intent systems (Spark Savings Intents, CoW solver intents, 1inch cross-chain) typically use EIP-712 where the domain separator binds to `chainid`. If the inner INTENT_TYPEHASH struct also fails to include an explicit `destinationChainId` (distinct from the current chainid captured in the domain separator), and the intent contract is deployed to the same address on multiple chains (via "
    WIKI_EXPLOIT_SCENARIO = "Spark Savings Intents: Alice signs intent{asset=USDS, amount=1M, destChain=Ethereum, nonce=7}. Solver relays on Ethereum, pulls 1M USDS from Alice's Ethereum account. The signed struct includes only {asset, amount, nonce} — destChain exists as metadata but is not hashed. Same intent bytes + signature are replayed on a second chain where Alice also has a balance: domain-separator there recomputes, "
    WIKI_RECOMMENDATION = "Include `uint256 destinationChainId` as an explicit field in the EIP-712 typed struct AND check `require(intent.destinationChainId == block.chainid, 'wrong chain');` before filling. Additionally ensure per-user nonces are partitioned per chain. Make domain-separator binding include `name`, `version`"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Intent|SavingsIntent|EIP712|DOMAIN_SEPARATOR|chainId'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'fillIntent|executeIntent|settleIntent|_verifyIntent|_hashIntent'}, {'function.body_contains_regex': 'DOMAIN_SEPARATOR|_domainSeparatorV4|EIP712'}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.body_contains_regex': 'keccak256\\s*\\(\\s*abi\\.encode\\s*\\(\\s*INTENT_TYPEHASH'}, {'function.body_not_contains_regex': 'block\\.chainid|chainId|CHAIN_ID|intent\\.chainId|domainSeparator\\s*\\(\\s*block\\.chainid'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — chainsec-spark-savings-intent-signature-replay-crosschain: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
