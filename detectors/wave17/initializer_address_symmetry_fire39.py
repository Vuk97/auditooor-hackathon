"""
initializer-address-symmetry-fire39

Solidity recall-lift detector for initializer-front-run candidates where an
externally callable initializer, setup, or route registration path binds a
remote or destination address from the local caller address. This targets the
cross-chain address-symmetry assumption: EOAs often share an address across
chains, but AA wallets, Safes, and custom counterfactual accounts do not.

Provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- attack_class: initializer-front-run
- context_pack_id: auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c
- context_pack_hash: cbdd9eeb5255863c4870d83e88642e9c4a3eef8e7cdfb8b5fb9a8ee7ac5a25d8
- MCP receipt: .auditooor/memory_context_receipt.json
- source ref: reports/detector_lift_fire38_20260605/post_priorities_solidity.md
- source ref: reference/patterns.dsl/cross-chain-aa-address-symmetry.yaml
- source ref: reference/patterns.dsl/erc7201-namespace-struct-field-removal-slot-collision.yaml
- source ref: reference/patterns.dsl/fx-pendle-uninitialized-return-array.yaml

NOT_SUBMIT_READY. R40/R76/R80 caveat: detector hits are source-review
candidates only, not proof.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "initializer-address-symmetry-fire39"
DETECTOR_SEVERITY_DEFAULT = "High"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"


@dataclass(frozen=True)
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


@dataclass(frozen=True)
class FunctionSlice:
    name: str
    header: str
    body: str
    function_line: int


@dataclass(frozen=True)
class SymmetryWrite:
    lhs: str
    rhs: str
    line: int


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
_ENTRYPOINT_NAME_RE = re.compile(
    r"(?i)^(?:initialize|init|setup|bootstrap|configure|register|"
    r"set|add|create|bind)[A-Za-z0-9_]*(?:Remote|Route|Peer|Endpoint|"
    r"Recipient|Receiver|Account|Wallet|Bridge|Chain|Domain|Config)?$|"
    r"^(?:setTrustedRemote|setPeer|registerPeer|registerRemote|"
    r"initializeRemoteAccount|setupRoute|configureRoute|bindRemoteAccount)$"
)
_PARAM_RE = re.compile(
    r"(?is)(?:^|,)\s*"
    r"(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?|"
    r"bytes(?:[0-9]+)?|uint(?:[0-9]+)?|int(?:[0-9]+)?|address|string|bool)"
    r"(?:\s*\[[^\]]*\])?\s+"
    r"(?:(?:calldata|memory|storage)\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_CROSS_CHAIN_OR_AA_CONTEXT_RE = re.compile(
    r"(?is)\b(?:"
    r"crossChain|cross_chain|destinationChain|sourceChain|remoteChain|"
    r"remoteChainId|targetChain|localChain|chainId|chainSelector|"
    r"dstChain|srcChain|dstEid|srcEid|remoteEid|endpoint|LayerZero|"
    r"OFT|CCIP|Axelar|Wormhole|bridge|remoteRoute|remoteRoutes|"
    r"remoteAccount|remoteWallet|remoteRecipient|remoteReceiver|"
    r"trustedRemote|peer|Peer|counterpart|account abstraction|ERC4337|"
    r"ERC-4337|EntryPoint|smartAccount|Safe|Gnosis|Argent|wallet"
    r")\b"
)
_REMOTE_LHS_RE = re.compile(
    r"(?i)(?:"
    r"remote|destination|dest|dst|target|counterpart|peer|trustedRemote|"
    r"trustedPeer|receiver|recipient|toAccount|toWallet|accountOnChain|"
    r"walletOnChain|routeRecipient|routeReceiver|bridgeRecipient"
    r")"
)
_LOCAL_ADDRESS_NAME_RE = re.compile(
    r"(?i)^(?:"
    r"owner|user|sender|caller|account|wallet|localAccount|localWallet|"
    r"sourceAccount|sourceWallet|from|fromAccount|sourceRecipient|"
    r"sourceReceiver"
    r")$"
)
_REMOTE_PARAM_NAME_RE = re.compile(
    r"(?i)(?:"
    r"remote|destination|dest|dst|target|counterpart|peer|recipient|"
    r"receiver|toAccount|toWallet|remoteAccount|remoteWallet|remoteRecipient|"
    r"destinationRecipient|destinationReceiver"
    r")"
)
_CHAIN_PARAM_NAME_RE = re.compile(
    r"(?i)(?:source|src|destination|dest|dst|remote|target|local)?"
    r"(?:ChainId|ChainSelector|Eid|Domain)"
)
_FIRST_CALL_GATE_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:initializer|reinitializer)\b|"
    r"\brequire\s*\([^;{}]*(?:!\s*_?initialized|_?initialized\s*==\s*false|"
    r"_?initialized\s*!=\s*true)[^;{}]*\)|"
    r"\b(?:initialized|_initialized|isInitialized)\s*=\s*true\b|"
    r"\brequire\s*\([^;{}]*(?:remote|remoteAccount|destination|peer|route|recipient|receiver|"
    r"accountOnChain|walletOnChain)[^;{}]*(?:==|!=)\s*"
    r"(?:address\s*\(\s*0\s*\)|0|bytes32\s*\(\s*0\s*\)|false)[^;{}]*\)|"
    r"\bif\s*\([^;{}]*(?:remote|remoteAccount|destination|peer|route|recipient|receiver|"
    r"accountOnChain|walletOnChain)[^;{}]*(?:==|!=)\s*"
    r"(?:address\s*\(\s*0\s*\)|0|bytes32\s*\(\s*0\s*\)|false)[^;{}]*\)"
    r")"
)
_AUTH_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyFactory|"
    r"onlyDeployer|onlyRole|onlyRoles|onlyBridge|onlyEndpoint|onlyRouter|"
    r"onlyConfigurator|requiresAuth|requireAuth|restricted|auth)\b|"
    r"\b(?:_checkOwner|_checkRole|hasRole|isOwner|isAdmin|_authorize)\s*\(|"
    r"\brequire\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r"[^;{}]*(?:owner|admin|governance|governor|deployer|factory|"
    r"bridge|endpoint|router|authority|controller|manager|operator)|"
    r"\brequire\s*\([^;{}]*(?:owner|admin|governance|governor|deployer|"
    r"factory|bridge|endpoint|router|authority|controller|manager|operator)"
    r"[^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))|"
    r"\bif\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))\s*!=\s*"
    r"(?:owner|admin|governance|governor|deployer|factory|bridge|endpoint|"
    r"router|authority|controller|manager|operator)[^;{}]*\)\s*revert"
    r")"
)
_DOMAIN_OR_SYMMETRY_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"\bblock\s*\.\s*chainid\b|\bchainid\s*\(\s*\)|"
    r"\b(?:source|src|destination|dest|dst|remote|target|local)?"
    r"(?:ChainSelector|Domain)\b|"
    r"\b(?:SALT_DOMAIN|saltDomain|DOMAIN_SEPARATOR|domainSeparator|"
    r"verifyingContract|address\s*\(\s*this\s*\))\b|"
    r"Same(?:Chain|Domain|Account|Address|Wallet|Recipient)|"
    r"Invalid(?:Chain|Domain|Account|Address|Wallet|Recipient)|"
    r"AddressSymmetry|Zero(?:Address|Account|Wallet|Recipient|Receiver)|"
    r"\brequire\s*\([^;{}]*(?:local|source|from)\w*"
    r"(?:Account|Wallet|Recipient|Receiver|Address)[^;{}]*!="
    r"[^;{}]*(?:remote|destination|dest|dst|target|to)\w*"
    r"(?:Account|Wallet|Recipient|Receiver|Address)|"
    r"\brequire\s*\([^;{}]*(?:remote|destination|dest|dst|target|to)\w*"
    r"(?:Account|Wallet|Recipient|Receiver|Address)[^;{}]*!="
    r"[^;{}]*(?:local|source|from)\w*"
    r"(?:Account|Wallet|Recipient|Receiver|Address)|"
    r"\brequire\s*\([^;{}]*(?:remote|destination|dest|dst|target|to)\w*"
    r"(?:Account|Wallet|Recipient|Receiver|Address)[^;{}]*!="
    r"\s*(?:address|bytes32)\s*\(\s*0\s*\)"
    r")"
)
_STATE_RELOAD_OR_CONSUME_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:Route|Peer|Remote|Destination)\s+storage\s+|"
    r"\bstorage\s+(?:route|peer|remote|destination)\b|"
    r"\b(?:checkpoint|lastSynced|lastProcessed|nonce|consumed|used|seen)"
    r"[A-Za-z0-9_]*\b|"
    r"\b(?:consume|markConsumed|_consume|_checkpoint|checkpointRoute|"
    r"reloadRoute|_reloadRoute)\s*\("
    r")"
)
_SAFE_ARITHMETIC_RE = re.compile(
    r"(?is)\b(?:SafeMath|SafeCast|Math\.(?:mulDiv|min|max)|"
    r"mulDiv\s*\(|checked(?:Add|Sub|Mul|Div)|saturating)"
)
_ASSIGN_RE = re.compile(
    r"(?is)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^;\n]+\])?"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)?)\s*=\s*(?P<rhs>[^;\n]+);"
)
_STRUCT_FIELD_RE = re.compile(
    r"(?is)(?P<lhs>(?:remote|destination|dest|dst|target|peer|recipient|"
    r"receiver)[A-Za-z0-9_]*)\s*:\s*(?P<rhs>[^,}]+)"
)
_CALLER_RE = re.compile(r"(?is)\b(?:msg\.sender|_msgSender\s*\(\s*\)|tx\.origin)\b")
_CALLER_ADDRESS_CAST_RE = re.compile(
    r"(?is)(?:"
    r"bytes32\s*\(\s*uint256\s*\(\s*uint160\s*\(\s*"
    r"(?:msg\.sender|_msgSender\s*\(\s*\)|[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*\)\s*\)\s*\)|"
    r"addressToBytes32\s*\(\s*(?:msg\.sender|_msgSender\s*\(\s*\)|"
    r"[A-Za-z_][A-Za-z0-9_]*)\s*\)"
    r")"
)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _find_matching(source: str, open_pos: int, open_char: str, close_char: str) -> int:
    if open_pos < 0 or open_pos >= len(source) or source[open_pos] != open_char:
        return -1
    depth = 1
    pos = open_pos + 1
    while pos < len(source) and depth > 0:
        if source[pos] == open_char:
            depth += 1
        elif source[pos] == close_char:
            depth -= 1
        pos += 1
    return pos - 1 if depth == 0 else -1


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break

        open_paren = source.find("(", match.end() - 1)
        close_paren = _find_matching(source, open_paren, "(", ")")
        if close_paren < 0:
            pos = match.end()
            continue

        body_start = -1
        scan_pos = close_paren + 1
        while scan_pos < len(source):
            if source[scan_pos] == ";":
                break
            if source[scan_pos] == "{":
                body_start = scan_pos
                break
            scan_pos += 1
        if body_start < 0:
            pos = max(close_paren + 1, scan_pos)
            continue

        body_end = _find_matching(source, body_start, "{", "}")
        if body_end < 0:
            pos = body_start + 1
            continue

        out.append(
            FunctionSlice(
                name=match.group("name"),
                header=source[match.start():body_start],
                body=source[body_start + 1:body_end],
                function_line=source.count("\n", 0, match.start()) + 1,
            )
        )
        pos = body_end + 1
    return out


def _is_external_entry(fn: FunctionSlice) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _parameter_section(header: str) -> str:
    start = header.find("(")
    if start < 0:
        return ""
    end = _find_matching(header, start, "(", ")")
    if end < 0:
        return ""
    return header[start + 1:end]


def _param_names(header: str) -> set[str]:
    return {match.group("name") for match in _PARAM_RE.finditer(_parameter_section(header))}


def _has_distinct_remote_param(params: set[str]) -> bool:
    return any(
        _REMOTE_PARAM_NAME_RE.search(name) and not _CHAIN_PARAM_NAME_RE.search(name)
        for name in params
    )


def _has_chain_param(params: set[str]) -> bool:
    return any(_CHAIN_PARAM_NAME_RE.search(name) for name in params)


def _rhs_contains_local_address(rhs: str, params: set[str]) -> bool:
    if _CALLER_RE.search(rhs):
        return True
    for param in params:
        if not _LOCAL_ADDRESS_NAME_RE.search(param):
            continue
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(param)}(?![A-Za-z0-9_])", rhs):
            return True
    return bool(_CALLER_ADDRESS_CAST_RE.search(rhs))


def _unsafe_symmetry_writes(body: str, params: set[str], function_line: int) -> list[SymmetryWrite]:
    writes: list[SymmetryWrite] = []
    for match in _ASSIGN_RE.finditer(body):
        lhs = re.sub(r"\s+", "", match.group("lhs"))
        rhs = match.group("rhs").strip()
        if not _REMOTE_LHS_RE.search(lhs):
            continue
        if not _rhs_contains_local_address(rhs, params):
            continue
        writes.append(
            SymmetryWrite(
                lhs=lhs[:120],
                rhs=re.sub(r"\s+", " ", rhs)[:120],
                line=function_line + body.count("\n", 0, match.start()),
            )
        )

    for match in _STRUCT_FIELD_RE.finditer(body):
        lhs = match.group("lhs")
        rhs = match.group("rhs").strip()
        if not _rhs_contains_local_address(rhs, params):
            continue
        writes.append(
            SymmetryWrite(
                lhs=lhs[:120],
                rhs=re.sub(r"\s+", " ", rhs)[:120],
                line=function_line + body.count("\n", 0, match.start()),
            )
        )
    return writes


def _safe_boundary_present(text: str, params: set[str]) -> bool:
    if _AUTH_GUARD_RE.search(text):
        return True
    if _DOMAIN_OR_SYMMETRY_GUARD_RE.search(text):
        return True
    if _STATE_RELOAD_OR_CONSUME_RE.search(text):
        return True
    if _SAFE_ARITHMETIC_RE.search(text):
        return True
    if _has_distinct_remote_param(params) and _has_chain_param(params):
        return True
    return False


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    code = _strip_comments_and_strings(source or "")
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if not _is_external_entry(fn):
            continue
        if not _ENTRYPOINT_NAME_RE.search(fn.name):
            continue

        function_text = f"{fn.name}\n{fn.header}\n{fn.body}"
        if not _CROSS_CHAIN_OR_AA_CONTEXT_RE.search(function_text):
            continue
        if not _FIRST_CALL_GATE_RE.search(function_text):
            continue

        params = _param_names(fn.header)
        if _safe_boundary_present(function_text, params):
            continue

        writes = _unsafe_symmetry_writes(fn.body, params, fn.function_line)
        if not writes:
            continue

        write = writes[0]
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=write.line,
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    "Initializer or setup path binds remote/destination address "
                    f"{write.lhs} from local caller value {write.rhs}. This can "
                    "encode an address-symmetry assumption for AA or cross-chain "
                    "wallets. Require an explicit remote recipient, domain "
                    "binding, state reload/checkpoint, consume-once guard, or "
                    "privileged factory/owner gate before treating this as proof."
                ),
            )
        )
    return findings


__all__ = ["DETECTOR_NAME", "Finding", "scan"]
