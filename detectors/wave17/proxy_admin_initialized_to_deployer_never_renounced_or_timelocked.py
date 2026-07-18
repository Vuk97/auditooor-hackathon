"""
proxy-admin-initialized-to-deployer-never-renounced-or-timelocked

Conservative fixture-smoke detector for upgradeable contracts whose initializer
assigns proxy/admin ownership to the deployer and shows no local handoff to a
timelock, multisig, governance address, or renounce/revoke step.
"""

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_INIT_NAME_RE = re.compile(r"^(initialize|__init\w*|initializeVault|reinitialize)$", re.IGNORECASE)
_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.MULTILINE | re.DOTALL)
_DEPLOYER_ADMIN_RE = re.compile(
    r"(?is)"
    r"(?:\b(?:_?admin|proxyAdmin|_?owner)\s*=\s*(?:msg\.sender|tx\.origin)\b)"
    r"|(?:\b(?:_setAdmin|_changeAdmin|_transferOwnership|transferOwnership|"
    r"__Ownable_init|_grantRole|grantRole)\s*\(\s*"
    r"(?:(?:DEFAULT_ADMIN_ROLE|ADMIN_ROLE)\s*,\s*)?(?:msg\.sender|tx\.origin)\b)"
)
_HANDOFF_RE = re.compile(
    r"(?is)"
    r"(?:\b(?:timelock|timeLock|TIMELOCK|multisig|multiSig|MULTISIG|gnosis|safe|"
    r"governance|governor|dao)\b)"
    r"|(?:\b(?:renounceOwnership|renounceRole|revokeRole)\s*\()"
)
_UPGRADE_SURFACE_RE = re.compile(
    r"(?is)\b(?:upgradeTo|upgradeToAndCall|_authorizeUpgrade|changeAdmin|_changeAdmin|"
    r"ProxyAdmin|UUPSUpgradeable|TransparentUpgradeableProxy|ERC1967Upgrade|implementation)\b"
)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _code_without_comments(obj) -> str:
    return _COMMENT_RE.sub("", _source(obj))


def _is_initializer(function) -> bool:
    name = getattr(function, "name", "") or ""
    if not _INIT_NAME_RE.search(name):
        return False
    return (getattr(function, "visibility", "") or "") in {"public", "external"}


def _contract_has_upgrade_surface(contract) -> bool:
    src = _code_without_comments(contract)
    if _UPGRADE_SURFACE_RE.search(src):
        return True
    try:
        for f in getattr(contract, "functions_and_modifiers_declared", []) or []:
            if _UPGRADE_SURFACE_RE.search(getattr(f, "name", "") or ""):
                return True
    except Exception:
        pass
    return False


def _has_local_handoff(function, contract) -> bool:
    function_src = _code_without_comments(function)
    contract_src = _code_without_comments(contract)
    return bool(_HANDOFF_RE.search(function_src) or _HANDOFF_RE.search(contract_src))


class ProxyAdminInitializedToDeployerNeverRenouncedOrTimelocked(AbstractDetector):
    ARGUMENT = "proxy-admin-initialized-to-deployer-never-renounced-or-timelocked"
    HELP = (
        "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: upgradeable initializer "
        "assigns proxy admin/owner to msg.sender or tx.origin with no local timelock, "
        "multisig, governance, or renounce handoff."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "proxy-admin-initialized-to-deployer-never-renounced-or-timelocked.yaml"
    )
    WIKI_TITLE = "Upgradeable proxy initializer assigns admin to deployer without handoff"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. Flags initializer code that grants "
        "upgrade/admin ownership to the deployer while the contract exposes an upgrade "
        "surface and has no visible timelock, multisig, governance, or renounce handoff."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "Deployer initializes a proxy admin role to msg.sender, waits for deposits, "
        "then upgrades to a malicious implementation that drains assets."
    )
    WIKI_RECOMMENDATION = (
        "Initialize admin to a timelock or multisig directly, or atomically hand off "
        "and renounce/revoke deployer authority before accepting user funds."
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not _contract_has_upgrade_surface(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                if not _is_initializer(function):
                    continue

                function_src = _code_without_comments(function)
                if not _DEPLOYER_ADMIN_RE.search(function_src):
                    continue
                if _has_local_handoff(function, contract):
                    continue

                info = [
                    function,
                    " — proxy-admin-initialized-to-deployer-never-renounced-or-timelocked: "
                    "initializer grants deployer-controlled upgrade authority without a "
                    "visible timelock, multisig, governance, or renounce handoff.",
                ]
                results.append(self.generate_result(info))
        return results
