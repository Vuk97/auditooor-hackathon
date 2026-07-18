"""
bridge_domain_binding_companion_fire16.py

Rust bridge-proof-domain-bypass recall companion for Fire16.

This detector closes three same-class Rust gaps without broadening into a
generic hash smell:
- bridge signal or message hashes that omit value or fee fields before signal
  consumption or custody release
- validator-set checkpoint hashes that omit visible chain or checkpoint domain
- CCIP receive handlers that process token amounts without source-chain
  allowlist validation
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
)


DETECTOR_ID = "rust_wave1.bridge_domain_binding_companion_fire16"

_BRIDGE_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"bridge|cross[_-]?chain|ccip|gateway|portal|relay|relayer|"
    r"signal|message|proof|validator[_-]?set|checkpoint|attestation"
    r")\b"
)

_SIGNAL_FN_RE = re.compile(
    r"(?i)\b(send|process|consume|finalize|release|claim|relay)"
    r"[A-Za-z0-9_]*(signal|message|bridge)"
    r"|(signal|message|bridge)[A-Za-z0-9_]*"
    r"(send|process|consume|finalize|release|claim|relay)\b"
)

_CCIP_FN_RE = re.compile(r"(?i)\b_?ccip_?receive\b")

_VALIDATOR_FN_RE = re.compile(
    r"(?i)(validator[_-]?set|checkpoint|committee).*"
    r"(hash|digest|verify|checkpoint)"
)

_HASH_CALL_RE = re.compile(
    r"(?is)\b(?:keccak256|sha256|blake2(?:b|s)?|blake3|digest|hash)"
    r"\s*\([^;{}]{0,1000}\)"
)

_LET_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*=\s*(?P<expr>[^;]{0,1600});"
)

_SIGNAL_STORE_RE = re.compile(
    r"(?is)\b(?:signals?|messages?|processed|consumed)"
    r"[A-Za-z0-9_]*\s*\.\s*(?:insert|get|remove|contains)"
    r"\s*\("
)

_VALUE_DEFENSE_RE = re.compile(
    r"(?is)\bstored\s*\.\s*(?:value|fee|amount|token_amount)"
    r"\s*(?:==|!=)\s*msg\s*\.\s*(?:value|fee|amount|token_amount)"
    r"|msg\s*\.\s*(?:value|fee|amount|token_amount)"
    r"\s*(?:==|!=)\s*stored\s*\.\s*(?:value|fee|amount|token_amount)"
)

_CCIP_EFFECT_RE = re.compile(
    r"(?is)\b("
    r"token_amounts?|total_minted|mint|mint_to|release|transfer|"
    r"transfer_to|credit|credit_to|payout|saturating_add"
    r")\b"
)

_SOURCE_CHAIN_CHECK_RE = re.compile(
    r"(?is)("
    r"(?:allowed|trusted|valid|authorized)[A-Za-z0-9_]*"
    r"\s*\.\s*contains\s*\(\s*&?\s*(?:message|msg)\s*\."
    r"source_chain_selector\s*\)"
    r"|(?:message|msg)\s*\.\s*source_chain_selector\s*(?:==|!=)"
    r"|(?:ensure|require|assert)[A-Za-z0-9_]*\s*\([^;{}]{0,300}"
    r"source_chain_selector"
    r")"
)

_ALLOWLIST_RE = re.compile(
    r"(?i)\b(?:allowed|trusted|authorized|valid)"
    r"[A-Za-z0-9_]*(?:source_)?chains?\b"
)

_VALIDATOR_SET_RE = re.compile(
    r"(?i)\b(validator[_-]?set|validators?|committee|signatures?)\b"
)

_DOMAIN_PATTERNS = (
    ("checkpoint", re.compile(r"\bcheckpoint\b", re.IGNORECASE)),
    ("chain_id", re.compile(r"\b(?:chain_id|chainid|network_id)\b", re.IGNORECASE)),
    ("domain", re.compile(r"\b(?:domain|domain_separator|bridge_id)\b", re.IGNORECASE)),
    ("epoch", re.compile(r"\b(?:epoch|round|height|set_id|fork_id)\b", re.IGNORECASE)),
)

_MESSAGE_FIELD_PATTERNS = (
    ("sender", re.compile(r"\b(?:sender|from_addr|from_address)\b", re.IGNORECASE)),
    ("recipient", re.compile(r"\b(?:recipient|receiver|to_addr|to_address)\b", re.IGNORECASE)),
    ("payload", re.compile(r"\b(?:data|payload|message|body)\b", re.IGNORECASE)),
    ("value", re.compile(r"\b(?:value|amount|token_amount)\b", re.IGNORECASE)),
    ("fee", re.compile(r"\bfee\b", re.IGNORECASE)),
    ("source", re.compile(r"\b(?:source_chain|source_chain_selector|src_chain)\b", re.IGNORECASE)),
)


def _signature_text(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _groups(patterns, text: str) -> set[str]:
    return {name for name, pattern in patterns if pattern.search(text)}


def _assignment_exprs(body: str) -> dict[str, str]:
    return {
        match.group("name"): match.group("expr")
        for match in _LET_ASSIGN_RE.finditer(body)
    }


def _hash_inputs(body: str) -> list[str]:
    assigns = _assignment_exprs(body)
    inputs: list[str] = []
    for expr in assigns.values():
        if _HASH_CALL_RE.search(expr) or ".concat" in expr or "hash_input" in expr:
            inputs.append(expr)

    for match in _HASH_CALL_RE.finditer(body):
        call = match.group(0)
        inputs.append(call)
        for name, expr in assigns.items():
            if re.search(rf"\b{name}\b", call):
                inputs.append(expr)

    return inputs


def _signal_hash_value_or_fee_missing(name: str, fn_text: str, body: str, file_text: str) -> set[str]:
    if not _SIGNAL_FN_RE.search(name):
        return set()
    if not _BRIDGE_CONTEXT_RE.search(fn_text):
        return set()
    if not _SIGNAL_STORE_RE.search(body):
        return set()
    if _VALUE_DEFENSE_RE.search(body):
        return set()

    file_fields = _groups(_MESSAGE_FIELD_PATTERNS, file_text)
    if not {"value", "fee"} & file_fields:
        return set()

    hash_inputs = _hash_inputs(body)
    if not hash_inputs:
        return set()

    best_hash_fields = set()
    for expr in hash_inputs:
        expr_fields = _groups(_MESSAGE_FIELD_PATTERNS, expr)
        if {"sender", "recipient", "payload"} & expr_fields:
            best_hash_fields = max(best_hash_fields, expr_fields, key=len)

    if not best_hash_fields:
        return set()

    missing = ({"value", "fee"} & file_fields) - best_hash_fields
    return missing


def _ccip_source_chain_missing(name: str, fn_text: str, body: str, file_text: str) -> bool:
    if not (_CCIP_FN_RE.search(name) or "Any2EVMMessage" in fn_text):
        return False
    if "source_chain_selector" not in fn_text and "source_chain_selector" not in file_text:
        return False
    if not _CCIP_EFFECT_RE.search(body):
        return False
    if not (_ALLOWLIST_RE.search(file_text) or "allowed_source_chains" in file_text):
        return False
    return _SOURCE_CHAIN_CHECK_RE.search(body) is None


def _validator_set_domain_missing(name: str, signature: str, body: str) -> set[str]:
    if not _VALIDATOR_FN_RE.search(name):
        return set()
    if not _VALIDATOR_SET_RE.search(signature + "\n" + body):
        return set()

    visible_domains = _groups(_DOMAIN_PATTERNS, signature)
    if not visible_domains:
        return set()

    hash_inputs = _hash_inputs(body)
    if not hash_inputs:
        return set()

    best_hash_domains = set()
    for expr in hash_inputs:
        if not _VALIDATOR_SET_RE.search(expr):
            continue
        best_hash_domains = max(
            best_hash_domains,
            _groups(_DOMAIN_PATTERNS, expr),
            key=len,
        )

    if not best_hash_domains and not any(_VALIDATOR_SET_RE.search(expr) for expr in hash_inputs):
        return set()

    return visible_domains - best_hash_domains


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    file_text = source.decode("utf-8", errors="replace")

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        body_node = fn_body(fn)
        if body_node is None:
            continue

        signature = _signature_text(fn, body_node, source)
        body = body_text_nocomment(body_node, source)
        fn_text = f"{signature}\n{body}"

        missing_signal_fields = _signal_hash_value_or_fee_missing(
            name,
            fn_text,
            body,
            file_text,
        )
        if missing_signal_fields:
            line, col = line_col(fn)
            hits.append(
                {
                    "detector_id": DETECTOR_ID,
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source)[:220],
                    "message": (
                        f"pub fn `{name}` consumes a bridge signal or message "
                        "hash while the hash input omits financial fields: "
                        f"{', '.join(sorted(missing_signal_fields))}. A signal "
                        "accepted for one value or fee can authorize a forged "
                        "bridge payout."
                    ),
                }
            )
            continue

        if _ccip_source_chain_missing(name, fn_text, body, file_text):
            line, col = line_col(fn)
            hits.append(
                {
                    "detector_id": DETECTOR_ID,
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source)[:220],
                    "message": (
                        f"pub fn `{name}` receives CCIP bridge messages and "
                        "processes token effects without checking "
                        "`source_chain_selector` against the configured "
                        "allowlist. Messages from an untrusted chain can enter "
                        "the same bridge domain."
                    ),
                }
            )
            continue

        missing_validator_domains = _validator_set_domain_missing(
            name,
            signature,
            body,
        )
        if missing_validator_domains:
            line, col = line_col(fn)
            hits.append(
                {
                    "detector_id": DETECTOR_ID,
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source)[:220],
                    "message": (
                        f"pub fn `{name}` hashes bridge validator-set "
                        "checkpoint material without binding visible domain "
                        f"fields: {', '.join(sorted(missing_validator_domains))}. "
                        "A checkpoint digest can be replayed across bridge "
                        "domains or checkpoints."
                    ),
                }
            )

    return hits
