"""
initializer-cross-chain-account-symmetry-fire27

Regex recall-lift detector for account abstraction, proxy, factory, and
cross-chain account initializer paths that derive account addresses or
authority salts without binding the chain, entry point, factory, salt domain,
or implementation.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:5a4dc5fcabec4193
- context_pack_hash: 5a4dc5fcabec419385f40cc3f83d3a24f63a01e0d5c301ab1ef08763094a3fe5
- attack_class: initializer-front-run
- target miss family: cross-chain-aa-address-symmetry
- source refs:
  - reference/patterns.dsl/cross-chain-aa-address-symmetry.yaml
  - reference/patterns.dsl/erc7201-namespace-struct-field-removal-slot-collision.yaml
  - reference/patterns.dsl/fx-pendle-uninitialized-return-array.yaml

This detector intentionally targets deterministic account and proxy address
domain omissions. It is not a generic uninitialized proxy or first-caller
initializer check. Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "initializer-cross-chain-account-symmetry-fire27"
DETECTOR_SEVERITY_DEFAULT = "High"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b")
_ENTRYPOINT_NAME_RE = re.compile(
    r"(?i)^(?:initialize|init|setup|bootstrap|configure|register|create|deploy|"
    r"predict|build)[A-Za-z0-9_]*(?:Account|Wallet|Proxy|Factory|EntryPoint|"
    r"Implementation|Impl|Authority|Chain|Domain|Salt)?$|"
    r"^(?:createAccount|deployAccount|registerAccount|initializeAccount|"
    r"createProxy|deployProxy|deployWallet|registerWallet|predictAccount|"
    r"accountFor|walletFor|proxyFor)$"
)
_ACCOUNT_OR_PROXY_CONTEXT_RE = re.compile(
    r"(?is)\b(?:"
    r"account\s*abstraction|ERC4337|ERC-4337|IEntryPoint|EntryPoint|entryPoint|"
    r"UserOperation|smartAccount|accountImplementation|accountFactory|"
    r"walletFactory|wallet|Safe|Gnosis|Argent|proxy|ERC1967Proxy|"
    r"TransparentUpgradeableProxy|BeaconProxy|factory|implementation|"
    r"counterfactual"
    r")\b"
)
_CROSS_CHAIN_CONTEXT_RE = re.compile(
    r"(?is)\b(?:"
    r"crossChain|cross_chain|destinationChain|sourceChain|remoteChain|"
    r"targetChain|localChain|chainId|chainSelector|dstChain|srcChain|dstEid|"
    r"srcEid|LayerZero|CCIP|OFT|Axelar|Wormhole|bridge|remoteAccount"
    r")\b"
)
_CREATE2_OR_DEPLOY_RE = re.compile(
    r"(?is)(?:"
    r"\bCREATE2\b|\bcreate2\b|Create2\s*\.\s*computeAddress|"
    r"\bcomputeAddress\s*\(|predictDeterministicAddress\s*\(|"
    r"cloneDeterministic\s*\(|deployDeterministic\s*\(|"
    r"\bnew\s+[A-Za-z_][A-Za-z0-9_]*\s*\{[^{}]*\bsalt\s*:|"
    r"\bsalt\s*:"
    r")"
)
_HASH_ASSIGN_RE = re.compile(
    r"(?is)(?:bytes32\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"keccak256\s*\(\s*abi\s*\.\s*encode(?P<packed>Packed)?\s*\("
    r"(?P<args>[^;{}]+?)\)\s*\)"
)
_INLINE_SALT_HASH_RE = re.compile(
    r"(?is)keccak256\s*\(\s*abi\s*\.\s*encode(?:Packed)?\s*\("
    r"(?P<args>[^;{}]+?)\)\s*\)"
)
_SALT_OR_AUTH_NAME_RE = re.compile(
    r"(?i)(salt|account|wallet|proxy|authority|address|counterfactual|deploy|init)"
)
_BYTECODE_HASH_ARG_RE = re.compile(
    r"(?i)\b(?:initCode|creationCode|bytecode|byteCode|runtimeCode|codeHash|"
    r"implementationCode)\b"
)
_DOMAIN_BINDING_RE = re.compile(
    r"(?is)(?:"
    r"\bblock\s*\.\s*chainid\b|\bchainid\s*\(\s*\)|"
    r"\b(?:source|src|destination|dest|dst|remote|target|local)?"
    r"(?:ChainId|ChainSelector|Eid|Domain)\b|"
    r"\bentryPoint\b|\bENTRY_POINT\b|\bIEntryPoint\b|"
    r"\bfactory\b|\bFACTORY\b|\baddress\s*\(\s*this\s*\)|"
    r"\bimplementation\b|\bImplementation\b|\bIMPLEMENTATION\b|\bimpl\b|"
    r"\bbeacon\b|\bSALT_DOMAIN\b|\bsaltDomain\b|\bdomainSeparator\b|"
    r"\bDOMAIN_SEPARATOR\b|\bverifyingContract\b|\bCREATE2_PREFIX\b|"
    r"\baccountImplementation\b|\bproxyImplementation\b"
    r")"
)
_STATE_EFFECT_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:accounts?|wallets?|proxies?|accountOnChain|accountFor|walletFor|"
    r"proxyFor|remoteAccounts?|counterfactualAccounts?|deployedAccounts?)"
    r"\s*\[[^;\]]+\]\s*=|"
    r"\b(?:authorityFor|ownerOfAccount|ownerForAccount|accountOwner|"
    r"accountAuthority|authorizedAccount|entryPointFor|implementationFor)"
    r"\s*\[[^;\]]+\]\s*=|"
    r"\b(?:account|wallet|proxy|predicted|deployed)\s*=\s*"
    r"(?:Create2\s*\.\s*computeAddress|computeAddress|address\s*\(\s*new)|"
    r"\bnew\s+[A-Za-z_][A-Za-z0-9_]*\s*\{[^{}]*\bsalt\s*:"
    r")"
)


def _strip_comments_preserve(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "".join("\n" if ch == "\n" else " " for ch in text)

    return _COMMENT_RE.sub(replace, source or "")


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


def _has_required_context(function_text: str, contract_text: str) -> bool:
    scope = f"{function_text}\n{contract_text}"
    if not _CREATE2_OR_DEPLOY_RE.search(function_text):
        return False
    if not _ACCOUNT_OR_PROXY_CONTEXT_RE.search(scope):
        return False
    return bool(_CROSS_CHAIN_CONTEXT_RE.search(scope) or _CREATE2_OR_DEPLOY_RE.search(scope))


def _hash_is_domain_bound(args: str) -> bool:
    return bool(_DOMAIN_BINDING_RE.search(args))


def _is_bytecode_hash(args: str) -> bool:
    return bool(_BYTECODE_HASH_ARG_RE.search(args)) and not _SALT_OR_AUTH_NAME_RE.search(args)


def _unsafe_derivations(body: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for match in _HASH_ASSIGN_RE.finditer(body):
        name = match.group("name") or ""
        args = match.group("args").strip()
        if not _SALT_OR_AUTH_NAME_RE.search(name):
            continue
        if _is_bytecode_hash(args):
            continue
        if _hash_is_domain_bound(args):
            continue
        out.append((match.start(), re.sub(r"\s+", " ", args)[:160]))

    if out:
        return out

    for match in _INLINE_SALT_HASH_RE.finditer(body):
        args = match.group("args").strip()
        context = body[max(0, match.start() - 120):match.end() + 120]
        if _is_bytecode_hash(args):
            continue
        if _hash_is_domain_bound(args):
            continue
        if not (_CREATE2_OR_DEPLOY_RE.search(context) or _SALT_OR_AUTH_NAME_RE.search(context)):
            continue
        out.append((match.start(), re.sub(r"\s+", " ", args)[:160]))
        break
    return out


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    code = _strip_comments_preserve(source)
    findings: list[Finding] = []
    for function_name, header, body, function_line in _split_functions(code):
        function_text = f"{function_name}\n{header}\n{body}"
        if not _is_external_entry(header):
            continue
        if not _ENTRYPOINT_NAME_RE.search(function_name):
            continue
        if not _has_required_context(function_text, code):
            continue
        if not _STATE_EFFECT_RE.search(body):
            continue

        unsafe = _unsafe_derivations(body)
        if not unsafe:
            continue

        offset, args = unsafe[0]
        line = function_line + body.count("\n", 0, offset)
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=line,
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=function_name,
                message=(
                    f"`{function_name}` derives a deterministic account, proxy, "
                    f"or authority salt from `{args}` without chain id, entry "
                    "point, factory, salt-domain, or implementation binding. "
                    "The same owner and salt can produce cross-chain account "
                    "or authority symmetry. NOT_SUBMIT_READY: regex fixture "
                    "evidence only."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
