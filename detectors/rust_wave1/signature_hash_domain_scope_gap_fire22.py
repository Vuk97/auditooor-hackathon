"""
signature_hash_domain_scope_gap_fire22.py

Rust same-class recall lift for signature-hash-domain-scope-gap.

Flags consensus or verification paths that build a transaction signature
digest while omitting replay-scope fields such as network, consensus branch,
entrypoint, transparent or shielded scope, or transaction context.

Detector hits are candidate evidence only, not exploit proof.
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
    source_nocomment,
    text_of,
)


DETECTOR_ID = "rust_wave1.signature_hash_domain_scope_gap_fire22"
ATTACK_CLASS = "signature-hash-domain-scope-gap"

_STRING_RE = re.compile(r"(?s)b?r#*\".*?\"#*|b?'(?:\\.|[^'\\])+'")

_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"sighash|signature|signed|verify|verifier|Message::from_digest|"
    r"consensus|transaction|transparent|shielded|sapling|orchard|"
    r"network_upgrade|branch_id|entrypoint"
    r")\b"
)

_DIGEST_RE = re.compile(
    r"(?is)\b("
    r"sighash_v4_raw|sighash|signature_hash|tx_signature_hash|"
    r"blake2b|blake2s|blake3|sha256|keccak256|hash"
    r")\s*\("
    r"|Message::from_digest\s*\("
    r"|\.finalize\s*\("
)

_VERIFY_RE = re.compile(
    r"(?is)\b("
    r"verify_callback|verify_signature|verify_sig|ed25519_verify|"
    r"secp256k1_recover|secp256r1_verify|ecdsa_verify"
    r")\s*\("
)

_ZEBRA_UNSCOPED_SIGHASH_RE = re.compile(
    r"(?is)\bsighash\s*\(\s*&?[A-Za-z_][A-Za-z0-9_]*"
    r"[^;{}]{0,300}\)"
)

_ZEBRA_SAFE_SCOPE_RE = re.compile(
    r"(?i)\b("
    r"NetworkUpgrade|network_upgrade|BranchId|branch_id|"
    r"to_librustzcash\s*\(|version\s*\(\)|version_group_id|"
    r"sighash_v4_raw\s*\(|raw_bits\s*\(|InvalidConsensusBranchId"
    r")\b"
)

_DIRECT_DIGEST_CALL_RE = re.compile(
    r"(?is)\b(?:sighash_v4_raw|sighash|signature_hash|tx_signature_hash|"
    r"blake2b|blake2s|blake3|sha256|keccak256|hash)"
    r"\s*\((?P<arg>[^;{}]{0,1400})\)"
)

_MESSAGE_DIGEST_RE = re.compile(
    r"(?is)Message::from_digest\s*\((?P<arg>[^;{}]{0,900})\)"
)

_UPDATE_OR_EXTEND_RE = re.compile(
    r"(?is)(?:\.update|\.extend_from_slice|\.push)\s*"
    r"\((?P<arg>[^;{}]{0,900})\)"
)

_LET_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?::[^=;]+)?=\s*(?P<expr>[^;]{0,1800});"
)

_SCOPE_FIELDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "network",
        re.compile(r"(?i)\b(network|network_id|network_upgrade|mainnet|testnet)\b"),
    ),
    (
        "branch",
        re.compile(r"(?i)\b(branch_id|branch|BranchId|consensus_branch)\b"),
    ),
    (
        "entrypoint",
        re.compile(r"(?i)\b(entry_?point|entrypoint_id|entrypoint_hash)\b"),
    ),
    (
        "transparent_scope",
        re.compile(
            r"(?i)\b("
            r"transparent|transparent_scope|transparent_spend|outpoint|utxo|"
            r"script_code"
            r")\b"
        ),
    ),
    (
        "shielded_scope",
        re.compile(
            r"(?i)\b("
            r"shielded|shielded_scope|sapling|orchard|note_commitment|"
            r"nullifier"
            r")\b"
        ),
    ),
    (
        "transaction_context",
        re.compile(
            r"(?i)\b("
            r"tx_context|transaction_context|tx_version|transaction_version|"
            r"expiry_height|lock_time"
            r")\b"
        ),
    ),
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_strings(text: str) -> str:
    return _STRING_RE.sub(_blank, text)


def _signature_text(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _field_groups(text: str) -> set[str]:
    clean = _strip_strings(text)
    return {name for name, pattern in _SCOPE_FIELDS if pattern.search(clean)}


def _assignments(body: str) -> dict[str, str]:
    return {
        match.group("name"): match.group("expr")
        for match in _LET_ASSIGN_RE.finditer(body)
    }


def _expand_expr(expr: str, assignments: dict[str, str]) -> list[str]:
    out = [expr]
    changed = True
    while changed and len(out) < 24:
        changed = False
        for item in list(out):
            for name, assigned in assignments.items():
                if assigned in out:
                    continue
                if re.search(rf"\b{re.escape(name)}\b", item):
                    out.append(assigned)
                    changed = True
    return out


def _digest_input_text(body: str) -> str:
    assignments = _assignments(body)
    inputs: list[str] = []

    for match in _UPDATE_OR_EXTEND_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assignments))

    for match in _DIRECT_DIGEST_CALL_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assignments))

    for match in _MESSAGE_DIGEST_RE.finditer(body):
        inputs.extend(_expand_expr(match.group("arg"), assignments))

    for expr in assignments.values():
        if _DIGEST_RE.search(expr):
            inputs.extend(_expand_expr(expr, assignments))

    return "\n".join(inputs)


def _zebra_consensus_sighash_without_domain(name: str, signature: str, body: str) -> str | None:
    context = f"{name}\n{signature}\n{body}"
    if not re.search(r"(?i)(consensus|transaction|sighash|verify)", context):
        return None
    if not (_ZEBRA_UNSCOPED_SIGHASH_RE.search(body) and _VERIFY_RE.search(body)):
        return None
    if _ZEBRA_SAFE_SCOPE_RE.search(context):
        return None
    return (
        "zebra consensus sighash path verifies a transaction digest without "
        "network upgrade, branch id, or version-domain binding"
    )


def _visible_scope_omitted(signature: str, body: str) -> set[str]:
    visible = _field_groups(f"{signature}\n{body}")
    if not visible:
        return set()

    digest_inputs = _digest_input_text(body)
    if not digest_inputs:
        return set()

    bound = _field_groups(digest_inputs)
    missing = visible - bound

    # A transparent or shielded token mentioned only in a helper name is noisy
    # unless another replay-scope family is also visible.
    if missing <= {"transparent_scope", "shielded_scope"} and len(visible) == len(missing):
        return set()
    return missing


def run(tree, source: bytes, filepath: str):
    hits = []
    file_nc = source_nocomment(source)
    if not (_DIGEST_RE.search(file_nc) and _CONTEXT_RE.search(file_nc)):
        return hits

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        body_node = fn_body(fn)
        if body_node is None:
            continue

        name = fn_name(fn, source)
        signature = _signature_text(fn, body_node, source)
        body = body_text_nocomment(body_node, source)
        context = f"{name}\n{signature}\n{body}"
        if not (_CONTEXT_RE.search(context) and _DIGEST_RE.search(body)):
            continue

        findings: list[str] = []
        zebra_detail = _zebra_consensus_sighash_without_domain(name, signature, body)
        if zebra_detail:
            findings.append(zebra_detail)

        missing = _visible_scope_omitted(signature, body)
        if missing and (_VERIFY_RE.search(body) or re.search(r"(?i)sighash|consensus", context)):
            findings.append(
                "signature digest omits visible replay scope fields: "
                + ", ".join(sorted(missing))
            )

        if not findings:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "attack_class": ATTACK_CLASS,
                "severity": "high",
                "file": filepath,
                "line": line,
                "col": col,
                "fn_name": name,
                "snippet": snippet_of(fn, source)[:260],
                "message": (
                    f"fn `{name}` matches {ATTACK_CLASS}: "
                    f"{'; '.join(findings)}. Bind signature digest material "
                    "to network, branch, entrypoint, transparent or shielded "
                    "scope, and transaction context before verification."
                ),
            }
        )

    return hits
