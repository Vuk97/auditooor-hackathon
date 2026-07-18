"""
signer-binds-tokens-only-not-amount — generated from reference/patterns.dsl/signer-binds-tokens-only-not-amount.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py signer-binds-tokens-only-not-amount.yaml
Source: defimon-2026-04-22-kipseli-72k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SignerBindsTokensOnlyNotAmount(AbstractDetector):
    ARGUMENT = "signer-binds-tokens-only-not-amount"
    HELP = "Off-chain quote signer signs only (tokenIn, tokenOut, timestamp); amount and rate are not part of the digest. The on-chain settle path trusts the signature, but pricing computes amount in tokenIn's decimals (e.g. USDC=6) and transfers it AS tokenOut (cbBTC=8) — decimals mismatch drains balance."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/signer-binds-tokens-only-not-amount.yaml"
    WIKI_TITLE = "Quote signature binds tokens but not amount/rate, enabling decimals-mismatch overpayment"
    WIKI_DESCRIPTION = "Off-chain quote/RFQ signers in some protocols sign a typed-data digest covering only (tokenIn, tokenOut, timestamp) and rely on the on-chain code to derive the executed amount via an oracle. When the signed pair has mismatched decimals (e.g. tokenIn=USDC@6dp, tokenOut=cbBTC@8dp), the on-chain pricing produces a quantity scaled to tokenIn's decimals and transfers that quantity AS the tokenOut. Beca"
    WIKI_EXPLOIT_SCENARIO = "Kipseli.capital (Apr 22 2026, ~$72K cbBTC drained, tx 0x96edeeb3d49d7a54c60d227bedce5bf64df5d52effd9fd80334175a9553db3bb): the protocol's quote-key signed `hashTypedDataV4(keccak256(abi.encode(QUOTE_TYPEHASH, tokenIn, tokenOut, block.timestamp)))` — note the absence of any amount field. Attacker initiated a swap with tokenIn=USDC (6 decimals), tokenOut=cbBTC (8 decimals). The settlement helper com"
    WIKI_RECOMMENDATION = "Sign the FULL trade tuple, not just the token pair. Required fields: `(tokenIn, tokenOut, amountIn, amountOut, recipient, deadline, nonce)`. Add a normalizing scalar at quote time and assert decimal alignment: `require(IERC20(tokenIn).decimals() == IERC20(tokenOut).decimals() || quoteCarriesScalar, "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(quote|swap|exchange|aggregator|router|otc|rfq)'}, {'contract.source_matches_regex': '(?i)(_TYPEHASH|EIP712|hashTypedData|ecrecover|ECDSA\\.recover|recoverSigner)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)(verifyQuote|hashQuote|_hashQuote|_verifyQuote|authorizeSwap|verifySwap|_verifySwap|hashOrder|_hashOrder|verifyOrder|recoverQuoteSigner|verifyTrade|hashTrade)'}, {'function.body_contains_regex': '(?i)abi\\.encode\\s*\\(\\s*\\w*_?TYPEHASH\\b'}, {'function.body_contains_regex': '(?i)abi\\.encode\\s*\\([^)]*\\b(tokenIn|tokenOut|assetIn|assetOut|fromToken|toToken|tokenA|tokenB)\\b'}, {'function.body_not_contains_regex': '(?i),\\s*(amount|amountIn|amountOut|fromAmount|toAmount|rate|price|quoteAmount|inAmount|outAmount)\\s*[,\\)]'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — signer-binds-tokens-only-not-amount: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
