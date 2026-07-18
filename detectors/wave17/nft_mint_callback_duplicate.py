"""
nft-mint-callback-duplicate — generated from reference/patterns.dsl/nft-mint-callback-duplicate.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py nft-mint-callback-duplicate.yaml
Source: solodit-cluster/C0257
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class NftMintCallbackDuplicate(AbstractDetector):
    ARGUMENT = "nft-mint-callback-duplicate"
    HELP = "NFT mint entry point uses _safeMint (ERC721Received callback) without nonReentrant; attacker contract can re-enter before tokenId counter increments and mint duplicate IDs."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/nft-mint-callback-duplicate.yaml"
    WIKI_TITLE = "Duplicate NFT mint via onERC721Received callback reentrancy"
    WIKI_DESCRIPTION = "A public/external mint function uses _safeMint (or safeMint) which triggers onERC721Received on the recipient. Without a reentrancy guard, an attacker-controlled recipient can re-enter the mint function inside the callback before the tokenId counter (or a `minted[to] = true` flag, or totalSupply) is incremented. The same tokenId is then minted a second time, or per-address mint caps are bypassed."
    WIKI_EXPLOIT_SCENARIO = "Attacker deploys a malicious ERC721 receiver contract. Contract calls publicMint(). Inside the original _safeMint invocation, onERC721Received fires on the attacker contract, which re-enters publicMint() before the tokenId counter has incremented. Two NFTs are minted with the same ID (or the per-wallet cap is bypassed). Result: unexpected supply inflation, broken rarity/provenance invariants, loss"
    WIKI_RECOMMENDATION = "Apply OpenZeppelin's ReentrancyGuard and decorate every mint entry point with nonReentrant. Alternatively use the CEI pattern: increment the tokenId counter and any per-caller mint accounting BEFORE calling _safeMint. Using _mint instead of _safeMint also eliminates the callback surface but trades o"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '(?i)(^|_)(safeMint|mint|mintTo|mintFor|publicMint|whitelistMint|presaleMint)$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(mint|_mint|safeMint|_safeMint|mintTo|mintFor|publicMint|whitelistMint|presaleMint)$'}, {'function.body_contains_regex': '_safeMint\\s*\\(|\\bsafeMint\\s*\\('}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — nft-mint-callback-duplicate: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
