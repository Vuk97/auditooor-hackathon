"""
Missing Access Control on `_authorizeUpgrade`.

Row-local graveyard repair: detect a UUPS-shaped contract that overrides
`_authorizeUpgrade(address)` without any visible access-control modifier or
inline owner/role/auth check.

This is intentionally narrow fixture-smoke/source-shape coverage and remains
NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

from _template_utils import is_vendored_or_test_contract


def _source_text(obj) -> str:
    source_mapping = getattr(obj, "source_mapping", None)
    return getattr(source_mapping, "content", "") or ""


class MissingAccessControlOnAuthorizeupgrade(AbstractDetector):
    ARGUMENT = "missing-access-control-on-authorizeupgrade"
    HELP = (
        "Fixture-smoke heuristic for UUPS-shaped `_authorizeUpgrade(address)` "
        "hooks that have no visible access-control gate."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Missing Access Control on _authorizeUpgrade"
    WIKI_DESCRIPTION = (
        "A UUPS-shaped contract that overrides `_authorizeUpgrade(address)` "
        "without a visible owner/role/auth gate can let unauthorized callers "
        "approve implementation upgrades. This repair only proves the local "
        "fixture pair and remains NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A contract exposes the normal UUPS `upgradeTo` path, but its "
        "`_authorizeUpgrade(address)` override is just bookkeeping and never "
        "checks who is calling. Any caller that reaches the upgrade entrypoint "
        "can install attacker-controlled logic."
    )
    WIKI_RECOMMENDATION = (
        "Gate `_authorizeUpgrade(address)` with the project's upgrade "
        "authority, such as `onlyOwner`, `onlyRole(UPGRADER_ROLE)`, or an "
        "equivalent inline authorization check."
    )

    _FN_NAME_REGEX = re.compile(r"^_authorizeUpgrade$", re.IGNORECASE)
    _UUPS_CONTRACT_REGEX = re.compile(
        r"(?i)\bUUPSUpgradeable\b|\bproxiableUUID\s*\(|\bupgradeToAndCall\s*\("
        r"|\bupgradeTo\s*\(",
    )
    _BLOCKLIST_MODIFIER_NAMES = {
        "onlyOwner",
        "onlyAdmin",
        "onlyGovernance",
        "onlyGovernor",
        "onlyUpgrader",
        "onlyRole",
        "onlyAuthorized",
        "onlyAuth",
        "requireAuth",
        "requireOwner",
        "authorized",
        "auth",
        "restricted",
        "whenAuthorized",
    }
    _INLINE_GUARD_REGEX = re.compile(
        r"(?is)"
        r"_checkOwner\s*\(|_checkRole\s*\(|hasRole\s*\(|"
        r"require\s*\([^)]*(?:owner|admin|governance|role|auth|msg\.sender)[^)]*\)|"
        r"assert\s*\([^)]*(?:owner|admin|governance|role|auth|msg\.sender)[^)]*\)|"
        r"revert\s+\w*(?:NotOwner|NotAdmin|Unauthorized|AccessControl|Forbidden|NotAuthorized)|"
        r"msg\.sender\s*==\s*(?:owner|admin|governance|_owner|_admin)|"
        r"(?:owner|admin|governance)\s*\(\s*\)\s*==\s*msg\.sender",
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_source = _source_text(contract)
            if not contract_source or not self._UUPS_CONTRACT_REGEX.search(contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not self._FN_NAME_REGEX.search(function.name):
                    continue
                if not getattr(function, "is_implemented", False):
                    continue

                modifier_names = {
                    getattr(modifier, "name", "") for modifier in getattr(function, "modifiers", [])
                }
                if modifier_names & self._BLOCKLIST_MODIFIER_NAMES:
                    continue

                source = _source_text(function)
                if not source:
                    continue
                if self._INLINE_GUARD_REGEX.search(source):
                    continue

                info = [
                    function,
                    " — missing-access-control-on-authorizeupgrade: "
                    "`_authorizeUpgrade(address)` appears in a UUPS-shaped "
                    "contract without a visible owner/role/auth gate. "
                    "NOT_SUBMIT_READY: fixture-smoke/source-shape proof only.",
                ]
                results.append(self.generate_result(info))
        return results
