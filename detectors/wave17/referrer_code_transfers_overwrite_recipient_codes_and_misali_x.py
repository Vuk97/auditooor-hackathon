"""
referrer-code-transfers-overwrite-recipient-codes-and-misali-x.

Fixture-smoke detector for referral-code ownership transfers that overwrite the
recipient's code slot and leave referrer tiers unsynchronised. This remains
detector-fixture coverage only, not proof of exploitability or severity.
"""

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


def _src(obj) -> str:
    return getattr(getattr(obj, "source_mapping", None), "content", "") or ""


def _address_param_names(function) -> list[str]:
    names: list[str] = []
    for param in getattr(function, "parameters", []):
        if "address" in str(getattr(param, "type", "")).lower():
            names.append(param.name)
    return names


def _ident(name: str) -> str:
    return re.escape(name)


class ReferrerCodeTransfersOverwriteRecipientCodesAndMisaliX(AbstractDetector):
    ARGUMENT = "referrer-code-transfers-overwrite-recipient-codes-and-misali-x"
    HELP = "referral code transfer overwrites recipient code slot and does not synchronise referrer tiers"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/referrer-code-transfers-overwrite-recipient-codes-and-misali-x.yaml"
    WIKI_TITLE = "Referrer-code transfers overwrite recipient codes and misalign tiers"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof for setCodeOwner-style transfer paths that write "
        "codeOwners[_code], delete the sender's code slot, and assign codes[_newAccount] "
        "without checking whether the recipient already owns a code and without tier migration."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A current code owner transfers a referral code to an address that already owns a code. "
        "The recipient's code slot is overwritten, while sender/recipient tiers stay out of sync "
        "because the transfer never migrates tier metadata. Real exploitability still needs target-specific proof."
    )
    WIKI_RECOMMENDATION = (
        "Require recipient acceptance or an empty recipient code slot, and explicitly migrate or clear "
        "both sender and recipient tier state during the transfer."
    )

    _FN_NAME_REGEX = re.compile(r"(?i)(setCodeOwner|transfer.*Code|transfer.*Referral|set.*Referral.*Owner)")
    _CONTRACT_CONTEXT_REGEX = re.compile(r"(?is)\b(codeOwners|codes|accountCodes|referrerTiers|feeTiers)\b")
    _CODE_OWNER_WRITE_TEMPLATE = r"\bcodeOwners\s*\[[^\]]+\]\s*=\s*{recipient}\b"
    _SENDER_CODE_DELETE_REGEX = re.compile(
        r"\bdelete\s+(?:codes|accountCodes|codeByAccount|codeOf|referralCodeOf|userCode|referrerCode)\s*\[[^\]]+\]",
        re.IGNORECASE,
    )
    _RECIPIENT_CODE_WRITE_TEMPLATE = (
        r"\b(?:codes|accountCodes|codeByAccount|codeOf|referralCodeOf|userCode|referrerCode)\s*"
        r"\[\s*{recipient}\s*\]\s*="
    )
    _TIER_TOUCH_TEMPLATE = (
        r"\b(?:referrerTiers|feeTiers|accountTiers|tiers|discountTiers|rebateTiers)\s*"
        r"\[[^\]]*(?:{recipient}|account|oldOwner|msg\s*\.\s*sender)[^\]]*\]\s*="
    )
    _RECIPIENT_CODE_GUARD_TEMPLATE = (
        r"(?:require|assert)\s*\([^;{}]*"
        r"(?:codes|accountCodes|codeByAccount|codeOf|referralCodeOf|userCode|referrerCode|hasCode|ownsCode)"
        r"(?:\s*\[\s*{recipient}\s*\]|\s*\(\s*{recipient}\s*\))"
        r"[^;{}]*(?:==|!=)\s*(?:bytes32\s*\(\s*0\s*\)|address\s*\(\s*0\s*\)|0|false)"
        r"|(?:require|assert)\s*\([^;{}]*!\s*"
        r"(?:hasCode|ownsCode|hasRegisteredCode)\s*(?:\[\s*{recipient}\s*\]|\(\s*{recipient}\s*\))"
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            contract_source = _src(contract)
            if not self._CONTRACT_CONTEXT_REGEX.search(contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not self._FN_NAME_REGEX.search(function.name):
                    continue

                body = _src(function)
                if not body:
                    continue

                for recipient in _address_param_names(function):
                    rec = _ident(recipient)
                    code_owner_write = re.search(
                        self._CODE_OWNER_WRITE_TEMPLATE.replace("{recipient}", rec), body, re.IGNORECASE
                    )
                    recipient_code_write = re.search(
                        self._RECIPIENT_CODE_WRITE_TEMPLATE.replace("{recipient}", rec), body, re.IGNORECASE
                    )
                    sender_code_delete = self._SENDER_CODE_DELETE_REGEX.search(body)
                    tier_update = re.search(
                        self._TIER_TOUCH_TEMPLATE.replace("{recipient}", rec), body, re.IGNORECASE
                    )
                    recipient_guard = re.search(
                        self._RECIPIENT_CODE_GUARD_TEMPLATE.replace("{recipient}", rec), body, re.IGNORECASE
                    )

                    if not code_owner_write or not sender_code_delete or not recipient_code_write:
                        continue
                    if recipient_guard and tier_update:
                        continue

                    info = [
                        function,
                        " - referrer-code-transfers-overwrite-recipient-codes-and-misali-x: "
                        "code transfer overwrites recipient code state or leaves tier state unsynchronised. ",
                    ]
                    results.append(self.generate_result(info))
                    break
        return results
