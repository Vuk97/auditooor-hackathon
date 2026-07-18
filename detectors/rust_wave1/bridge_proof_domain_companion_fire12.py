"""
bridge_proof_domain_companion_fire12.py

Flags Rust bridge proof or signal release handlers where proof material
authorizes a custody movement, but the authorization hash or verifier call
does not bind payout fields such as account, payout amount, or asset id.

Confirmed corpus anchor:
- bridge-signal-hash-forge-drain-protocol-via-collision
  (Solodit #34319 / OpenZeppelin Taiko SignalService)

This companion is intentionally separate from the Fire10 bridge detectors:
- bridge_manager_burn_without_owner_check_fire10 covers owner checks before
  destructive NFT effects.
- bridge_recipient_payload_length_missing_fire10 covers malformed recipient
  byte length and recipient domain validation.
- bridge_queue_message_domain_unbound_fire10 covers unscoped queue keys.
- bridge_signal_hash_domain_collision_fire10 covers release domain fields
  such as chain, route, bridge address, receiver, and entrypoint.

Fire12 targets payout-field binding in a proof or signal authorization path.
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


DETECTOR_ID = "rust_wave1.bridge_proof_domain_companion_fire12"

_FN_NAME_RE = re.compile(
    r"(?i)("
    r"(claim|release|finalize|settle|process|execute|redeem|payout|withdraw)"
    r".*(bridge|proof|signal|message|receipt|attestation)"
    r"|bridge.*(claim|release|finalize|proof|signal|message|payout)"
    r"|proof.*(claim|release|finalize|payout)"
    r"|signal.*(claim|release|finalize|payout)"
    r")"
)

_BRIDGE_AUTH_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"bridge|cross[_-]?chain|gateway|portal|relay|relayer|"
    r"proof|merkle|root|receipt|signal|message|attestation|commitment"
    r")\b"
)

_AUTH_MATERIAL_RE = re.compile(
    r"(?i)\b("
    r"proof|proof_hash|proof_root|root|state_root|storage_root|"
    r"receipt|receipt_hash|signal|signal_hash|message|message_hash|"
    r"payload|payload_hash|leaf|leaf_hash|attestation|commitment|"
    r"merkle|header"
    r")\b"
)

_HASH_EXPR_RE = re.compile(
    r"(?is)\b(?:"
    r"keccak256|sha256|blake2(?:b|s)?|blake3|digest|"
    r"[A-Za-z0-9_]*hash[A-Za-z0-9_]*"
    r")\s*\([^;{}]{0,900}\)"
)

_VERIFY_EXPR_RE = re.compile(
    r"(?is)\b(?:[A-Za-z0-9_]+::|[A-Za-z0-9_\.]+\.)?"
    r"(?:verify|verify_proof|verify_merkle|verify_merkle_proof|"
    r"verify_message|verify_signal|verify_receipt|verify_attestation|"
    r"check_proof|validate_proof|validate_message|authenticate|prove)"
    r"[A-Za-z0-9_]*\s*\([^;{}]{0,900}\)"
)

_AUTH_SET_EXPR_RE = re.compile(
    r"(?is)\b(?:accepted|authorized|approved|valid|trusted|seen|used|"
    r"processed|consumed|settled|executed)[A-Za-z0-9_]*"
    r"\s*\.\s*(?:contains|get|remove|insert|set)\s*\([^;{}]{0,700}\)"
)

_CUSTODY_MOVEMENT_RE = re.compile(
    r"(?is)(?:"
    r"\.\s*(?:release|release_to|withdraw|payout|pay|credit|credit_to|"
    r"mint|mint_to|transfer|transfer_to|send_to)\s*\("
    r"[^;{}]{0,320}(?:account|payee|recipient|receiver|beneficiary|"
    r"payout|amount|value|quantity|qty|token_id|asset_id)"
    r"|\b(?:release|release_to|withdraw|payout|pay|credit|credit_to|"
    r"mint|mint_to|transfer|transfer_to|send_to)\s*\("
    r"[^;{}]{0,320}(?:account|payee|recipient|receiver|beneficiary|"
    r"payout|amount|value|quantity|qty|token_id|asset_id)"
    r")"
)

_SAFE_BINDING_HELPER_RE = re.compile(
    r"(?i)\b("
    r"bind_payout|bind_release|payout_bound|release_bound|"
    r"domain_separated_payout|scoped_payout|verified_payout|"
    r"decode_verified_message|decode_bound_message"
    r")\b"
)

_FIELD_GROUPS = (
    (
        "account",
        re.compile(
            r"\b(?:account|payee|recipient|receiver|beneficiary|"
            r"destination_account|payout_account|to_addr|to_address)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "payout",
        re.compile(
            r"\b(?:payout|amount|value|fee|quantity|qty|token_amount|"
            r"release_amount|withdraw_amount|mint_amount)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "asset",
        re.compile(
            r"\b(?:token_id|asset_id|nft_id|coin_id|denom|currency|"
            r"asset|token)\b",
            re.IGNORECASE,
        ),
    ),
)


def _signature_text(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _field_groups(text: str) -> set[str]:
    return {name for name, pattern in _FIELD_GROUPS if pattern.search(text)}


def _candidate_auth_exprs(text: str) -> list[str]:
    exprs = []
    for pattern in (_HASH_EXPR_RE, _VERIFY_EXPR_RE, _AUTH_SET_EXPR_RE):
        for match in pattern.finditer(text):
            expr = match.group(0)
            if _SAFE_BINDING_HELPER_RE.search(expr):
                continue
            if not _AUTH_MATERIAL_RE.search(expr):
                continue
            exprs.append(expr)
    return exprs


def _has_authorization_path(text: str) -> bool:
    return bool(_VERIFY_EXPR_RE.search(text) or _AUTH_SET_EXPR_RE.search(text))


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        signature = _signature_text(fn, body, source)
        body_nc = body_text_nocomment(body, source)
        fn_text = f"{signature}\n{body_nc}"

        if not _BRIDGE_AUTH_CONTEXT_RE.search(fn_text):
            continue
        if not _has_authorization_path(body_nc):
            continue
        if not _CUSTODY_MOVEMENT_RE.search(body_nc):
            continue

        visible_fields = _field_groups(fn_text)
        if "payout" not in visible_fields or len(visible_fields) < 2:
            continue

        candidates = _candidate_auth_exprs(body_nc)
        if not candidates:
            continue

        if any(visible_fields <= _field_groups(expr) for expr in candidates):
            continue

        best_expr = max(candidates, key=lambda expr: len(_field_groups(expr)))
        omitted = visible_fields - _field_groups(best_expr)
        if not omitted:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` verifies bridge proof or signal material "
                    f"before releasing custody, but no authorization expression "
                    f"binds payout field groups: {', '.join(sorted(omitted))}. "
                    "A proof or signal accepted for one payout can authorize a "
                    "different account, amount, or asset release."
                ),
            }
        )

    return hits
