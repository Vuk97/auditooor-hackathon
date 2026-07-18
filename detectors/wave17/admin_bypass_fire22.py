"""
admin-bypass-fire22

Recall-lift detector for Solidity governance-only or protocol-parameter state
mutations that are exposed as public or external functions without a caller
authority guard. This is distinct from Fire21, which covers packed digest
authorization, CCIP receiver domain binding, and transfer-to-pair route trust.

Source anchors:
- auditooor.vault_cross_language_pattern_lift.v1:d824ff1b49bd6916
- reference/patterns.dsl/r94-loop-governance-only-state-fn-exposed-as-public.yaml
- Solodit #61824 / Code4rena Virtuals Protocol ServiceNft

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "admin-bypass-fire22"
DETECTOR_SEVERITY_DEFAULT = "High"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b")
_GOVERNANCE_FUNCTION_RE = re.compile(
    r"(?i)^(?:"
    r"updateImpact|submitImpactUpdate|mintServiceNft|setProtocolParam|"
    r"adjustEmission|updateConsensusScore|setGovernanceWeight|"
    r"updateOraclePrice"
    r")$"
)
_GOVERNANCE_STATE_WRITE_RE = re.compile(
    r"(?is)\b(?:"
    r"impact|impactScore|impactByService|serviceImpact|proposalImpact|"
    r"datasetImpact|consensusScore|validatorScore|governanceWeight|"
    r"protocolParam|protocolParams|emission|emissionRate|rewardRate|"
    r"oraclePrice|priceFeed|serviceMinted"
    r")[A-Za-z0-9_]*(?:\s*\[[^\]]+\])?\s*(?:[+\-*/]?=|\+\+|--)"
)
_MINT_EFFECT_RE = re.compile(r"(?is)\b(?:_safeMint|_mint|mint)\s*\(")
_AUTH_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:onlyOwner|onlyAdmin|onlyRole|onlyRoles|onlyGovernance|onlyGovernor|"
    r"onlyGov|onlyDao|onlyDAO|onlyTimelock|requiresAuth|requireAuth|"
    r"restricted|auth)\b|"
    r"\b(?:hasRole|_checkRole|_checkOwner|isOwner|isAdmin|isAuthorized|"
    r"enforceIsOwner|enforceIsGovernance|enforceIsContractOwner)\s*\(|"
    r"\brequire\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r"[^;{}]*(?:owner|admin|governance|governor|gov|dao|DAO|timelock|"
    r"controller|manager|operator|authorized)|"
    r"\brequire\s*\([^;{}]*(?:owner|admin|governance|governor|gov|dao|DAO|"
    r"timelock|controller|manager|operator|authorized)[^;{}]*(?:msg\.sender|"
    r"_msgSender\s*\(\s*\))"
    r")"
)
_SELF_SERVICE_WRITE_RE = re.compile(
    r"(?is)\b[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r"[^\]]*\]\s*(?:[+\-*/]?=|\+\+|--)"
)
_NON_SELF_KEY_RE = re.compile(
    r"(?is)\[[^\]]*(?:tokenId|serviceId|proposalId|datasetId|validator|account|"
    r"user|delegate|asset|key|param|id)[^\]]*\]"
)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _split_functions(source: str) -> list[tuple[str, str, str, int]]:
    out: list[tuple[str, str, str, int]] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        i = match.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            if source[i] == "(":
                depth_paren += 1
            elif source[i] == ")":
                depth_paren -= 1
            i += 1

        body_start = -1
        j = i
        while j < len(source):
            if source[j] == ";":
                break
            if source[j] == "{":
                body_start = j
                break
            j += 1
        if body_start < 0:
            pos = max(i, j)
            continue

        depth = 1
        k = body_start + 1
        while k < len(source) and depth > 0:
            if source[k] == "{":
                depth += 1
            elif source[k] == "}":
                depth -= 1
            k += 1

        header = source[match.start():body_start]
        body = source[body_start + 1:k - 1]
        line = source.count("\n", 0, match.start()) + 1
        out.append((name, header, body, line))
        pos = k
    return out


def _is_external_entry(header: str) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(header)) and not _VIEW_HEADER_RE.search(header)


def _has_privileged_mutation(name: str, body: str) -> bool:
    if _GOVERNANCE_STATE_WRITE_RE.search(body):
        return True
    return name == "mintServiceNft" and bool(_MINT_EFFECT_RE.search(body))


def _is_self_service_only(body: str) -> bool:
    if not _SELF_SERVICE_WRITE_RE.search(body):
        return False
    return not _NON_SELF_KEY_RE.search(body)


def _governance_only_public_state_mutation(name: str, header: str, body: str) -> bool:
    if not _is_external_entry(header):
        return False
    if not _GOVERNANCE_FUNCTION_RE.search(name):
        return False
    text = f"{header}\n{body}"
    if _AUTH_GUARD_RE.search(text):
        return False
    if not _has_privileged_mutation(name, body):
        return False
    return not _is_self_service_only(body)


def _finding(file_path: str, line: int, function: str) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            "governance-only state mutation is public or external without a caller "
            "authority guard. NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for name, header, body, line in _split_functions(code):
        if _governance_only_public_state_mutation(name, header, body):
            findings.append(_finding(file_path, line, name))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
