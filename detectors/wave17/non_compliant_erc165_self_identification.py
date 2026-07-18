"""
non-compliant-erc165-self-identification

Manual graveyard repair for the Hexens Glider row. The generated detector used
placeholder "missing guard call" logic that did not model ERC165 at all.

This repaired detector intentionally stays narrow and honest: it only flags an
exact public/external `supportsInterface(bytes4)`-style function whose source
compares the queried interface id against at least one explicit interface id,
but never explicitly returns true for the ERC165 self id.

This is fixture-smoke / source-shape evidence only and should remain
`submission_posture: NOT_SUBMIT_READY`.

Spec: reference/patterns.dsl/non-compliant-erc165-self-identification.yaml
"""

import re
import sys
from pathlib import Path as _Path

_DETECTORS_ROOT = _Path(__file__).resolve().parent.parent
if str(_DETECTORS_ROOT) not in sys.path:
    sys.path.insert(0, str(_DETECTORS_ROOT))

from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_LINE_COMMENT_RE = re.compile(r"//.*?$", re.MULTILINE)
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_COMPARES_INTERFACE_ID_RE = re.compile(
    r"(\binterfaceId\b\s*==|==\s*\binterfaceId\b)", re.IGNORECASE
)
_ERC165_SELF_ID_RE = re.compile(
    r"0x01ffc9a7|"
    r"type\s*\(\s*I?ERC165\s*\)\s*\.\s*interfaceId|"
    r"supportsInterface\s*\.\s*selector",
    re.IGNORECASE,
)
_SUPER_SUPPORTS_INTERFACE_RE = re.compile(
    r"\bsuper\s*\.\s*supportsInterface\s*\(", re.IGNORECASE
)


def _strip_comments(source: str) -> str:
    without_blocks = _BLOCK_COMMENT_RE.sub("", source)
    return _LINE_COMMENT_RE.sub("", without_blocks)


def _is_public_or_external(function) -> bool:
    return getattr(function, "visibility", None) in ("public", "external")


class NonCompliantErc165SelfIdentification(AbstractDetector):
    ARGUMENT = "non-compliant-erc165-self-identification"
    HELP = "supportsInterface omits explicit ERC165 self-identification"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/"
        "reference/patterns.dsl/non-compliant-erc165-self-identification.yaml"
    )
    WIKI_TITLE = "Non-Compliant ERC165 Self-Identification"
    WIKI_DESCRIPTION = (
        "Flags the narrow source shape where a public or external "
        "`supportsInterface` implementation returns explicit interface-id "
        "comparisons but omits the ERC165 self id `0x01ffc9a7`."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A marketplace or wallet first checks ERC165 support before probing a "
        "token-specific interface. The contract answers true for that token "
        "interface but false for ERC165 itself, so the integration treats the "
        "contract as non-compliant and refuses the flow."
    )
    WIKI_RECOMMENDATION = (
        "Include `interfaceId == type(IERC165).interfaceId`, the literal "
        "`0x01ffc9a7`, or delegate to a known-good ERC165 base via "
        "`super.supportsInterface(interfaceId)`. Keep this row NOT_SUBMIT_READY "
        "until evidence expands beyond fixture smoke."
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor or function.name != "supportsInterface":
                    continue
                if not _is_public_or_external(function):
                    continue

                body = _strip_comments(function.source_mapping.content or "")
                if not body:
                    continue
                if not _COMPARES_INTERFACE_ID_RE.search(body):
                    continue
                if _ERC165_SELF_ID_RE.search(body):
                    continue
                if _SUPER_SUPPORTS_INTERFACE_RE.search(body):
                    continue

                info = [
                    function,
                    " compares `interfaceId` against explicit interface ids but "
                    "does not self-identify ERC165 via `0x01ffc9a7`, "
                    "`type(IERC165).interfaceId`, or `super.supportsInterface`. ",
                    "This row is fixture-smoke / source-shape proof only and "
                    "remains NOT_SUBMIT_READY.",
                ]
                results.append(self.generate_result(info))
        return results
