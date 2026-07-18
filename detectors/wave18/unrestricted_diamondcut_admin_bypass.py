"""
unrestricted_diamondcut_admin_bypass.py - custom Slither detector.

Roadmap slice 6 admin-bypass recall lift: flag ERC-2535-style diamondCut
entrypoints that can mutate selector-to-facet routing without an owner, role,
or governance guard on the externally reachable function.
"""

from __future__ import annotations

import re
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DETECTOR_INFO,
    DetectorClassification,
)
from slither.slithir.operations import InternalCall
from slither.utils.output import Output


_DIAMOND_SOURCE_RE = re.compile(
    r"(diamondCut|FacetCut|selectorToFacet|facetAddress|facetAddressAndSelectorPosition)",
    re.IGNORECASE,
)
_DIAMOND_ENTRY_RE = re.compile(r"^diamondCut$", re.IGNORECASE)
_DIAMOND_HELPER_RE = re.compile(
    r"(diamondCut|applyDiamondCut|addFunctions|replaceFunctions|removeFunctions|"
    r"initializeDiamondCut)",
    re.IGNORECASE,
)
_FACET_MUTATION_RE = re.compile(
    r"(selectorToFacet|facetAddressAndSelectorPosition|facetFunctionSelectors|"
    r"\bfacets\s*\[|\bfacetAddress\s*\[)",
    re.IGNORECASE,
)
_AUTH_MODIFIER_RE = re.compile(
    r"(onlyOwner|onlyAdmin|onlyRole|onlyGovernance|onlyGovernor|requiresAuth|auth)",
    re.IGNORECASE,
)
_AUTH_BODY_RE = re.compile(
    r"(enforceIsContractOwner|_checkOwner|_authorizeDiamondCut|hasRole\s*\(|"
    r"AccessControl|Ownable|"
    r"require\s*\([^;]*(?:msg\.sender|_msgSender\(\))\s*==\s*"
    r"(?:owner|admin|governance|governor|contractOwner|diamondOwner|_owner)\b|"
    r"require\s*\([^;]*(?:owner|admin|governance|governor|contractOwner|diamondOwner|_owner)"
    r"\s*==\s*(?:msg\.sender|_msgSender\(\)))",
    re.IGNORECASE | re.DOTALL,
)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _is_external_entry(function) -> bool:
    return (
        getattr(function, "visibility", None) in {"public", "external"}
        and not getattr(function, "is_constructor", False)
        and not getattr(function, "is_receive", False)
        and not getattr(function, "is_fallback", False)
        and not getattr(function, "view", False)
        and not getattr(function, "pure", False)
    )


def _has_auth_guard(function, src: str) -> bool:
    for modifier in getattr(function, "modifiers", []) or []:
        if _AUTH_MODIFIER_RE.search(getattr(modifier, "name", "") or ""):
            return True
        if _AUTH_BODY_RE.search(_source(modifier)):
            return True
    return bool(_AUTH_BODY_RE.search(src))


def _calls_diamond_mutation_helper(function, src: str) -> bool:
    if _FACET_MUTATION_RE.search(src):
        return True
    for node in getattr(function, "nodes", []) or []:
        for ir in getattr(node, "irs", []) or []:
            if not isinstance(ir, InternalCall):
                continue
            callee = getattr(ir, "function", None)
            if callee is None:
                continue
            callee_name = getattr(callee, "name", "") or ""
            if _DIAMOND_HELPER_RE.search(callee_name):
                return True
            if _FACET_MUTATION_RE.search(_source(callee)):
                return True
    return False


class UnrestrictedDiamondcutAdminBypass(AbstractDetector):
    ARGUMENT = "unrestricted-diamondcut-admin-bypass"
    HELP = "Diamond diamondCut entrypoint mutates selector/facet routing without an authorization guard"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "unrestricted-diamondcut-admin-bypass.yaml"
    )
    WIKI_TITLE = "Unrestricted diamondCut admin bypass"
    WIKI_DESCRIPTION = (
        "An ERC-2535-style diamond exposes a public or external diamondCut "
        "entrypoint that applies facet additions, replacements, or removals "
        "without enforcing owner, role, or governance authorization."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An attacker calls diamondCut with a facet implementing privileged "
        "logic or replacing an existing admin selector. Future calls delegate "
        "into attacker-controlled code using the diamond's storage context."
    )
    WIKI_RECOMMENDATION = (
        "Gate every external diamondCut path with the diamond owner, governance, "
        "or an explicit upgrade role before applying selector mutations."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            contract_src = _source(contract)
            if not _DIAMOND_SOURCE_RE.search(contract_src):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not _is_external_entry(function):
                    continue
                if not _DIAMOND_ENTRY_RE.search(getattr(function, "name", "") or ""):
                    continue

                src = _source(function)
                if _has_auth_guard(function, src):
                    continue
                if not _calls_diamond_mutation_helper(function, src):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " applies a diamondCut selector/facet mutation without an owner, role, "
                    "or governance guard in ",
                    contract,
                    ".\n",
                ]
                results.append(self.generate_result(info))

        return results
