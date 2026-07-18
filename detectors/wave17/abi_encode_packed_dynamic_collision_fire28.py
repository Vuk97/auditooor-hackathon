"""
abi-encode-packed-dynamic-collision-fire28

Solidity recall-lift detector for authorization, permit, claim, role, bridge,
or signature digests built from packed concatenation of two or more dynamic or
ambiguous user-controlled values.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:86c2076101171056
- context_pack_hash: 86c2076101171056d88e0073a7354a1cf2324d92f13627249a1c5ece0c70b722
- source ref: reference/patterns.dsl/abi-encode-packed-hash-collision.yaml
- source ref: reference/patterns.dsl.r76_glider/glider-hash-collision-with-abiencode-packed-and-dynamic-t-py.yaml
- parent class: admin-bypass
- same-class precedent: admin-abi-packed-hash-collision-fire26

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "abi-encode-packed-dynamic-collision-fire28"
DETECTOR_SEVERITY_DEFAULT = "High"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


@dataclass
class FunctionSlice:
    name: str
    header: str
    body: str
    line: int


@dataclass
class PackedSite:
    args: str
    builder: str
    prefix: str
    suffix: str
    digest_var: Optional[str]


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CALLABLE_HEADER_RE = re.compile(r"\b(?:external|public|internal)\b")
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b")
_PARAM_RE = re.compile(
    r"(?is)(?:^|,)\s*"
    r"(?P<type>"
    r"(?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?|"
    r"bytes(?:[0-9]+)?|uint(?:[0-9]+)?|int(?:[0-9]+)?|address|string|bool)"
    r"(?:\s*\[[^\]]*\])*"
    r")\s+"
    r"(?:(?:calldata|memory|storage)\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_PACKED_START_RE = re.compile(
    r"(?is)keccak256\s*\(\s*"
    r"(?P<builder>abi\s*\.\s*encodePacked|bytes\s*\.\s*concat|string\s*\.\s*concat)"
    r"\s*\("
)
_PACKED_ASSIGN_PREFIX_RE = re.compile(
    r"(?is)(?:bytes32\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*$"
)
_AUTH_CONTEXT_RE = re.compile(
    r"(?is)\b("
    r"auth|authoriz|permit|claim|role|bridge|crosschain|crossChain|signature|"
    r"signer|recover|ecrecover|isValidSignature|SignatureChecker|proof|merkle|"
    r"mint|withdraw|redeem|execute|grant|operator|admin"
    r")\b"
)
_SIGNATURE_AUTH_RE = re.compile(
    r"(?is)\b(?:"
    r"ecrecover|ECDSA\s*\.\s*recover|SignatureChecker|isValidSignature|"
    r"isValidSignatureNow|recoverSigner"
    r")\b"
)
_CHECK_CONTEXT_RE = re.compile(
    r"(?is)\b(?:"
    r"require|if|revert|hasRole|_checkRole|claimed|used|processed|executed|"
    r"consumed|authorized|approved|permit|roles?|bridge|messages?|proofs?|"
    r"signers?|adminSigners|operatorSigners"
    r")\b"
)
_DYNAMIC_FIELD_NAME_RE = re.compile(
    r"(?i)\b("
    r"data|payload|calldata|callData|extraData|memo|metadata|uri|path|route|"
    r"message|reason|commands|params|description|claimData|proofData|permitData|"
    r"bridgeData|roleData|authData|signatureData|leaves|proof|proofs"
    r")\b"
)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _find_matching(source: str, open_index: int, open_char: str, close_char: str) -> int:
    depth = 1
    i = open_index + 1
    while i < len(source) and depth > 0:
        char = source[i]
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
        i += 1
    return i - 1 if depth == 0 else -1


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if not match:
            break
        name = match.group("name")
        params_end = _find_matching(source, match.end() - 1, "(", ")")
        if params_end < 0:
            pos = match.end()
            continue

        body_start = -1
        cursor = params_end + 1
        while cursor < len(source):
            if source[cursor] == ";":
                break
            if source[cursor] == "{":
                body_start = cursor
                break
            cursor += 1
        if body_start < 0:
            pos = max(cursor, params_end + 1)
            continue

        body_end = _find_matching(source, body_start, "{", "}")
        if body_end < 0:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        body = source[body_start + 1:body_end]
        line = source.count("\n", 0, match.start()) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, line=line))
        pos = body_end + 1
    return out


def _parameter_section(header: str) -> str:
    start = header.find("(")
    if start < 0:
        return ""
    end = _find_matching(header, start, "(", ")")
    if end < 0:
        return ""
    return header[start + 1:end]


def _param_types(header: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for match in _PARAM_RE.finditer(_parameter_section(header)):
        params[match.group("name")] = re.sub(r"\s+", "", match.group("type"))
    return params


def _is_callable_check_surface(header: str, body: str) -> bool:
    if _VIEW_HEADER_RE.search(header):
        return False
    if _CALLABLE_HEADER_RE.search(header):
        return True
    return bool(_CHECK_CONTEXT_RE.search(body) and _AUTH_CONTEXT_RE.search(body))


def _digest_var_from_prefix(prefix: str) -> Optional[str]:
    match = _PACKED_ASSIGN_PREFIX_RE.search(prefix)
    return match.group("name") if match else None


def _packed_sites(body: str) -> list[PackedSite]:
    sites: list[PackedSite] = []
    for match in _PACKED_START_RE.finditer(body):
        args_start = match.end()
        args_end = _find_matching(body, args_start - 1, "(", ")")
        if args_end < 0:
            continue
        prefix = body[max(0, match.start() - 160):match.start()]
        suffix = body[args_end:min(len(body), args_end + 260)]
        builder = re.sub(r"\s+", "", match.group("builder"))
        sites.append(
            PackedSite(
                args=body[args_start:args_end],
                builder=builder,
                prefix=prefix,
                suffix=suffix,
                digest_var=_digest_var_from_prefix(prefix),
            )
        )
    return sites


def _split_top_level_args(args: str) -> list[str]:
    out: list[str] = []
    start = 0
    paren = 0
    bracket = 0
    brace = 0
    for i, char in enumerate(args):
        if char == "(":
            paren += 1
        elif char == ")" and paren > 0:
            paren -= 1
        elif char == "[":
            bracket += 1
        elif char == "]" and bracket > 0:
            bracket -= 1
        elif char == "{":
            brace += 1
        elif char == "}" and brace > 0:
            brace -= 1
        elif char == "," and paren == 0 and bracket == 0 and brace == 0:
            out.append(args[start:i].strip())
            start = i + 1
    out.append(args[start:].strip())
    return [arg for arg in out if arg]


def _contains_word(text: str, name: str) -> bool:
    return bool(re.search(rf"\b{re.escape(name)}\b", text))


def _is_dynamic_param_type(param_type: str) -> bool:
    clean = param_type.lower().replace(" ", "")
    return clean == "string" or clean == "bytes" or "[]" in clean


def _is_pre_hashed_or_length_prefixed(arg: str) -> bool:
    return bool(
        re.search(r"(?is)\bkeccak256\s*\(", arg)
        or re.search(r"(?is)\babi\s*\.\s*encode\s*\(", arg)
    )


def _dynamic_labels_for_arg(arg: str, params: dict[str, str]) -> set[str]:
    if _is_pre_hashed_or_length_prefixed(arg):
        return set()

    labels: set[str] = set()
    for name, param_type in params.items():
        if _is_dynamic_param_type(param_type) and _contains_word(arg, name):
            labels.add(name)

    for match in re.finditer(
        r"\b[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)+\b",
        arg,
    ):
        expr = re.sub(r"\s+", "", match.group(0))
        tail = expr.split(".")[-1]
        if _DYNAMIC_FIELD_NAME_RE.search(tail):
            labels.add(expr)

    if not labels and _DYNAMIC_FIELD_NAME_RE.search(arg):
        words = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", arg)
        for word in words:
            if _DYNAMIC_FIELD_NAME_RE.fullmatch(word):
                labels.add(word)
    return labels


def _dynamic_args_used(header: str, args: str) -> set[str]:
    params = _param_types(header)
    labels: set[str] = set()
    for arg in _split_top_level_args(args):
        labels.update(_dynamic_labels_for_arg(arg, params))
    return labels


def _digest_var_consumed_by_check(var: str, body: str) -> bool:
    escaped = re.escape(var)
    patterns = [
        rf"(?is)\b(?:ecrecover|recover|isValidSignature|isValidSignatureNow)\s*\([^;{{}}]*\b{escaped}\b",
        rf"(?is)\b(?:require|if)\s*\([^;{{}}]*\b{escaped}\b",
        rf"(?is)\b[A-Za-z_][A-Za-z0-9_]*(?:claimed|used|processed|executed|consumed|authorized|approved|permit|role|bridge|message|proof|signer)[A-Za-z0-9_]*\s*\[\s*\b{escaped}\b\s*\]",
        rf"(?is)\bhasRole\s*\([^;{{}}]*\b{escaped}\b",
    ]
    return any(re.search(pattern, body) for pattern in patterns)


def _site_feeds_auth_gate(fn: FunctionSlice, site: PackedSite) -> bool:
    text = f"{fn.name}\n{fn.header}\n{fn.body}"
    if not _AUTH_CONTEXT_RE.search(text):
        return False
    if _SIGNATURE_AUTH_RE.search(site.suffix):
        return True
    if _SIGNATURE_AUTH_RE.search(fn.body) and site.digest_var:
        return _digest_var_consumed_by_check(site.digest_var, fn.body)
    if site.digest_var and _digest_var_consumed_by_check(site.digest_var, fn.body):
        return True

    local = f"{site.prefix}\n{site.suffix}"
    return bool(_CHECK_CONTEXT_RE.search(local) and _AUTH_CONTEXT_RE.search(local))


def _dynamic_collision_gap(fn: FunctionSlice) -> tuple[Optional[PackedSite], set[str]]:
    if not _is_callable_check_surface(fn.header, fn.body):
        return None, set()

    for site in _packed_sites(fn.body):
        dynamic_labels = _dynamic_args_used(fn.header, site.args)
        if len(dynamic_labels) < 2:
            continue
        if not _site_feeds_auth_gate(fn, site):
            continue
        return site, dynamic_labels
    return None, set()


def _finding(file_path: str, fn: FunctionSlice, site: PackedSite, dynamic_labels: set[str]) -> Finding:
    labels = ", ".join(sorted(dynamic_labels))
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=fn.line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=fn.name,
        message=(
            f"{site.builder} feeds an authorization digest with multiple dynamic "
            f"field(s): {labels}. Packed encoding does not length-prefix dynamic "
            "values, so a colliding tuple can satisfy the same auth, role, claim, "
            "permit, bridge, or signature check. NOT_SUBMIT_READY: detector "
            "fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        site, dynamic_labels = _dynamic_collision_gap(fn)
        if site is not None:
            findings.append(_finding(file_path, fn, site, dynamic_labels))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
