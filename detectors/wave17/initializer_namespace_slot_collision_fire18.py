"""
initializer-namespace-slot-collision-fire18

Focused Solidity recall lift for initializer-front-run misses that Fire17's
first pass did not close cleanly:

* cross-chain account-abstraction address symmetry written by a first caller,
* ERC-7201 namespace or storage-slot collisions during migrations, and
* constructor or initializer fee config written without the same cap enforced
  by later setters.

The detector is candidate evidence only. It does not prove exploitability
without a real entrypoint, a real impact path, and a negative control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "initializer-namespace-slot-collision-fire18"
DETECTOR_SEVERITY_DEFAULT = "High"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CONSTRUCTOR_RE = re.compile(r"\bconstructor\s*\(")
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b")
_INIT_NAME_RE = re.compile(
    r"(?i)^(?:initialize|init|setup|bootstrap|configure|register|create|add|set|"
    r"migrate|upgrade)(?:[A-Z_].*)?$"
)

_FIRST_CALLER_CONTEXT_RE = re.compile(
    r"(?is)("
    r"\binitializer\b|\breinitializer\s*\(|\bonlyInitializing\b|"
    r"\binitialized\b|_initialized|first(?:Call|Caller|Writer)|"
    r"\bconstructor\b|"
    r"\b(?:setup|bootstrap|configure|register|migrate|upgrade)\b"
    r")"
)

_AA_OR_ROUTE_WRITE_RE = re.compile(
    r"(?is)("
    r"(?:remoteAccounts?|localAccounts?|accountFor|accountOwner|walletFor|"
    r"aaAddressFor|smartAccountFor|entryPointFor|counterpartFor|gatewayFor|"
    r"routes?|trustedRemoteLookup|trustedRemotes?)\s*\[[^;{}]+\]\s*=|"
    r"(?:layout\s*\([^;{}]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*"
    r"(?:remoteAccount|localAccount|accountAbstractionAddress|aaAddress|"
    r"smartAccount|entryPoint|wallet|gateway|peer|counterpart)\s*=|"
    r"\b(?:remoteAccount|localAccount|accountAbstractionAddress|aaAddress|"
    r"smartAccount|entryPoint|wallet|gateway|peer|counterpart)\b\s*="
    r")"
)

_NAMESPACE_OR_SLOT_WRITE_RE = re.compile(
    r"(?is)("
    r"(?:namespaceOwner|namespaceFor|namespaceUsed|layoutByNamespace|"
    r"storageSlotFor|slotFor|slotOwner)\s*\[[^;{}]+\]\s*=|"
    r"(?:layout\s*\([^;{}]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*"
    r"(?:namespace|storageSlot|slot|layoutSlot)\s*=|"
    r"\b(?:namespace|storageSlot|layoutSlot|erc7201Slot)\b\s*="
    r")"
)

_FEE_WRITE_RE = re.compile(
    r"(?is)("
    r"(?:layout\s*\([^;{}]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*"
    r"(?:fee|feeBps|protocolFee|protocolFeeBps|swapFee|mintFee|borrowFee|"
    r"flashFee|managementFee|performanceFee)\s*=|"
    r"\b(?:fee|feeBps|protocolFee|protocolFeeBps|swapFee|mintFee|borrowFee|"
    r"flashFee|managementFee|performanceFee)\b\s*="
    r")"
)

_AUTH_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyFactory|"
    r"onlyDeployer|onlyConfigurator|onlyRole|onlyBridgeAdmin|onlyProxy|"
    r"requiresAuth|requireAuth|auth|restricted)\b|"
    r"\b_checkOwner\s*\(|\b_checkRole\s*\(|\bhasRole\s*\(|"
    r"\brequire\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r"[^;{}]*(?:owner|admin|governance|governor|deployer|factory|"
    r"configurator|guardian|authority|controller|registry|expectedActor)|"
    r"\brequire\s*\([^;{}]*(?:owner|admin|governance|governor|deployer|"
    r"factory|configurator|guardian|authority|controller|registry|"
    r"expectedActor)[^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))|"
    r"\bif\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r"[^;{}]*!=[^;{}]*(?:owner|admin|governance|governor|deployer|factory|"
    r"configurator|guardian|authority|controller|registry|expectedActor)"
    r"[^;{}]*\)\s*revert|"
    r"\bif\s*\([^;{}]*(?:owner|admin|governance|governor|deployer|factory|"
    r"configurator|guardian|authority|controller|registry|expectedActor)"
    r"[^;{}]*!=[^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r"[^;{}]*\)\s*revert"
    r")"
)

_DOMAIN_OR_AA_GUARD_RE = re.compile(
    r"(?is)("
    r"Same(?:Chain|Domain|Account|Address|Wallet|Eid)|"
    r"Invalid(?:Chain|Domain|Account|Address|Wallet|Eid)|"
    r"Zero(?:Address|Account|Wallet|Gateway|Peer|Remote|Endpoint)|"
    r"AddressZero|"
    r"\brequire\s*\([^;{}]*(?:source|src|origin|local|from)\w*"
    r"(?:ChainId|Domain|Eid)[^;{}]*!="
    r"[^;{}]*(?:destination|dest|dst|remote|target|to)\w*"
    r"(?:ChainId|Domain|Eid)|"
    r"\brequire\s*\([^;{}]*(?:destination|dest|dst|remote|target|to)\w*"
    r"(?:ChainId|Domain|Eid)[^;{}]*!="
    r"[^;{}]*(?:source|src|origin|local|from)\w*"
    r"(?:ChainId|Domain|Eid)|"
    r"\brequire\s*\([^;{}]*(?:localAccount|remoteAccount|account|wallet|"
    r"aaAddress|smartAccount)[^;{}]*!=\s*address\s*\(\s*0\s*\)|"
    r"\brequire\s*\([^;{}]*(?:localAccount|account|wallet|aaAddress)"
    r"[^;{}]*!=[^;{}]*(?:remoteAccount|remoteWallet|remoteAa|remoteAA)|"
    r"\bif\s*\([^;{}]*(?:localAccount|account|wallet|aaAddress)"
    r"[^;{}]*==[^;{}]*(?:remoteAccount|remoteWallet|remoteAa|remoteAA)"
    r"[^;{}]*\)\s*revert"
    r")"
)

_NAMESPACE_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:usedNamespace|namespaceUsed|registeredNamespace|namespaceOwner|"
    r"layoutByNamespace|storageSlotFor|slotOwner)\s*\[[^;{}]+\]\s*"
    r"(?:==|!=)|"
    r"\brequire\s*\([^;{}]*(?:namespace|storageSlot|layoutSlot|erc7201Slot)"
    r"[^;{}]*(?:==|!=)[^;{}]*(?:EXPECTED|expected|constant|DEFAULT|0x|"
    r"keccak256|type\s*\(|address\s*\(\s*0\s*\))|"
    r"\brequire\s*\([^;{}]*(?:EXPECTED|expected|constant|DEFAULT|0x|"
    r"keccak256)[^;{}]*(?:==|!=)[^;{}]*(?:namespace|storageSlot|layoutSlot|"
    r"erc7201Slot)|"
    r"\bif\s*\([^;{}]*(?:namespace|storageSlot|layoutSlot|erc7201Slot)"
    r"[^;{}]*(?:==|!=)[^;{}]*\)\s*revert"
    r")"
)

_FEE_CAP_RE = re.compile(
    r"(?is)("
    r"\bMAX_[A-Z0-9_]*FEE\b|FEE_CAP|MAX_BPS|BASIS_POINTS|"
    r"\brequire\s*\([^;{}]*(?:fee|feeBps|protocolFee|protocolFeeBps|"
    r"swapFee|mintFee|borrowFee|flashFee|managementFee|performanceFee)"
    r"[^;{}]*(?:<=|<)[^;{}]*(?:MAX|CAP|BPS|10_?000|10000|1e4)|"
    r"\bif\s*\([^;{}]*(?:fee|feeBps|protocolFee|protocolFeeBps|"
    r"swapFee|mintFee|borrowFee|flashFee|managementFee|performanceFee)"
    r"[^;{}]*(?:>|>=)[^;{}]*(?:MAX|CAP|BPS|10_?000|10000|1e4)"
    r"[^;{}]*\)\s*revert"
    r")"
)

_LOCAL_DECL_PREFIX_RE = re.compile(
    r"(?is)(?:uint(?:8|16|32|64|128|256)?|int(?:8|16|32|64|128|256)?|"
    r"bool|address|bytes(?:[0-9]+)?|string)\s+$"
)

_NAMESPACE_LITERAL_RE = re.compile(
    r"(?is)\b(?:bytes32\s+)?(?:internal\s+|private\s+|public\s+|constant\s+)*"
    r"[A-Z0-9_]*(?:NAMESPACE|STORAGE_SLOT|STORAGE_LOCATION|LAYOUT_SLOT)"
    r"[A-Z0-9_]*\s*="
    r"\s*(?:bytes32\s*\(\s*)?(?:uint256\s*\(\s*)?keccak256\s*\("
    r"\s*(?:abi\.encode(?:Packed)?\s*\(\s*)?([\"'])(?P<name>[^\"']+)\1"
)

_REMOVED_FIELD_COLLISION_RE = re.compile(
    r"(?is)("
    r"(?:removed|deprecated|legacy|tombstone)[\s\S]{0,240}"
    r"mapping\s*\([^)]*\)\s+[A-Za-z_][A-Za-z0-9_]*\s*;"
    r"[\s\S]{0,260}(?:SparseBitmap|BitMap|BitMaps\.|uint(?:8|16|32|64|128|256)?|"
    r"mapping\s*\([^)]*\))|"
    r"mapping\s*\([^)]*\)\s+[A-Za-z_][A-Za-z0-9_]*\s*;"
    r"[\s\S]{0,240}(?:removed|deprecated|legacy|tombstone)[\s\S]{0,260}"
    r"(?:SparseBitmap|BitMap|BitMaps\.|uint(?:8|16|32|64|128|256)?|"
    r"mapping\s*\([^)]*\))"
    r")"
)
_GAP_RE = re.compile(
    r"(?is)\b(?:__gap|_gap|_reserved|_storage_gap|_padding)\b"
    r"\s*(?:\[[^\]]+\])?\s*;"
)
_NAMESPACE_SOURCE_RE = re.compile(
    r"(?is)(erc7201|@custom:storage-location|\.storage|_STORAGE_SLOT|"
    r"STORAGE_LOCATION|NAMESPACE|layout\s*\(\s*\)|assembly\s*\{[^{}]*\.slot\s*:=)"
)


def _strip_comments_preserve(source: str) -> str:
    def repl(match: re.Match[str]) -> str:
        text = match.group(0)
        return "".join("\n" if ch == "\n" else " " for ch in text)

    return _COMMENT_RE.sub(repl, source)


def _split_functions_and_constructors(source: str) -> List[tuple[str, str, str, int, bool]]:
    items: list[tuple[int, re.Match[str], bool]] = []
    for match in _FN_HEADER_RE.finditer(source):
        items.append((match.start(), match, False))
    for match in _CONSTRUCTOR_RE.finditer(source):
        items.append((match.start(), match, True))
    items.sort(key=lambda row: row[0])

    out: List[tuple[str, str, str, int, bool]] = []
    pos = 0
    for _start, match, is_constructor in items:
        if match.start() < pos:
            continue
        name = "constructor" if is_constructor else match.group("name")
        i = match.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            char = source[i]
            if char == "(":
                depth_paren += 1
            elif char == ")":
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
            pos = max(j, i)
            continue

        depth = 1
        k = body_start + 1
        while k < len(source) and depth > 0:
            char = source[k]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            k += 1
        header = source[match.start():body_start]
        body = source[body_start + 1:k - 1]
        function_line = source.count("\n", 0, match.start()) + 1
        out.append((name, header, body, function_line, is_constructor))
        pos = k
    return out


def _is_local_declaration(body: str, start: int) -> bool:
    prefix = body[max(0, start - 80):start]
    prefix = prefix.rsplit(";", 1)[-1]
    prefix = prefix.rsplit("{", 1)[-1]
    return bool(_LOCAL_DECL_PREFIX_RE.search(prefix))


def _state_writes(body: str) -> list[tuple[str, re.Match[str]]]:
    candidates: list[tuple[int, str, re.Match[str]]] = []
    for label, regex in (
        ("account-abstraction or route", _AA_OR_ROUTE_WRITE_RE),
        ("namespace or storage-slot", _NAMESPACE_OR_SLOT_WRITE_RE),
        ("fee configuration", _FEE_WRITE_RE),
    ):
        for match in regex.finditer(body):
            if _is_local_declaration(body, match.start()):
                continue
            candidates.append((match.start(), label, match))
            break
    candidates.sort(key=lambda row: row[0])
    return [(label, match) for _start, label, match in candidates]


def _safe_for_label(label: str, text: str) -> bool:
    if _AUTH_GUARD_RE.search(text):
        return True
    if label == "account-abstraction or route":
        return bool(_DOMAIN_OR_AA_GUARD_RE.search(text))
    if label == "namespace or storage-slot":
        return bool(_NAMESPACE_GUARD_RE.search(text))
    if label == "fee configuration":
        return bool(_FEE_CAP_RE.search(text))
    return False


def _namespace_collision_findings(source: str, file_path: str) -> list[Finding]:
    if not _NAMESPACE_SOURCE_RE.search(source):
        return []
    if _GAP_RE.search(source):
        return []

    findings: list[Finding] = []
    seen_literals: dict[str, re.Match[str]] = {}
    for match in _NAMESPACE_LITERAL_RE.finditer(source):
        name = match.group("name")
        prior = seen_literals.get(name)
        if prior is None:
            seen_literals[name] = match
            continue
        line = source.count("\n", 0, match.start()) + 1
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=line,
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=None,
                message=(
                    "Duplicate ERC-7201 namespace or storage-slot literal "
                    f"`{name}` can make two layouts share the same slot. Use a "
                    "unique namespace per layout and keep obsolete fields as "
                    "reserved storage."
                ),
            )
        )

    removed_match = _REMOVED_FIELD_COLLISION_RE.search(source)
    if removed_match:
        line = source.count("\n", 0, removed_match.start()) + 1
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=line,
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=None,
                message=(
                    "Namespaced storage appears to remove or deprecate a "
                    "mapping before adding a new field without a reserved gap. "
                    "That migration can read stale mapping data as the new "
                    "field's slot."
                ),
            )
        )
    return findings


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    clean_source = _strip_comments_preserve(source)
    findings = _namespace_collision_findings(source, file_path)

    for function_name, header, body, function_line, is_constructor in (
        _split_functions_and_constructors(clean_source)
    ):
        header_and_body = f"{header}\n{body}"
        if not is_constructor:
            if not _PUBLIC_HEADER_RE.search(header):
                continue
            if _VIEW_HEADER_RE.search(header):
                continue
            if not _INIT_NAME_RE.search(function_name):
                continue
        if not _FIRST_CALLER_CONTEXT_RE.search(header_and_body):
            continue

        writes = _state_writes(body)
        if not writes:
            continue
        for label, match in writes:
            if _safe_for_label(label, header_and_body):
                continue

            line = function_line + body.count("\n", 0, match.start())
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=function_name,
                    message=(
                        f"`{function_name}` writes {label} state during an "
                        "initializer, constructor, reinitializer, or "
                        "first-caller setup path without the matching caller "
                        "binding, domain or namespace uniqueness check, or fee "
                        "cap."
                    ),
                )
            )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
