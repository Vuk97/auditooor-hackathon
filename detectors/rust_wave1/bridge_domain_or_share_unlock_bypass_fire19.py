"""
bridge_domain_or_share_unlock_bypass_fire19.py

Fire19 Rust lift for bridge-proof-domain-bypass gaps where a bridge or
cross-domain dispatch consumes caller-controlled target, channel, payload,
gas-cost, destination, share, or unlock metadata without binding it to the
verified bridge domain or a consume-once state transition.

Seed misses:
- depositandbridge-bypasses-shareunlocktime-positive
- generic-bridge-facet-allows-arbitrary-target-call-steals-via-user-allowance-positive
- layerzero-channel-blocked-via-variable-gas-cost-payload-save-positive

Detector hits are candidate evidence only.
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


DETECTOR_ID = "rust_wave1.bridge_domain_or_share_unlock_bypass_fire19"

_BRIDGE_CONTEXT_RE = re.compile(
    r"(?i)("
    r"bridge|cross[_-]?chain|gateway|layerzero|lz_?receive|endpoint|"
    r"channel|relayer|route|destination|dest_chain|dst_chain|payload|"
    r"proof|domain|packet|message|share|unlock"
    r")"
)

_MINT_OR_SHARE_RE = re.compile(
    r"(?is)\b(?:mint|deposit|preview_deposit)\s*\([^;{}]{0,300}\)"
    r"|(?:total_supply|balances?|shares?)\s*(?:\+=|-=|=|\.insert\s*\()"
)

_BRIDGE_SEND_RE = re.compile(
    r"(?is)\b(?:bridge|gateway|client|endpoint|relayer)\s*\."
    r"(?:send|dispatch|execute|call|transfer|bridge)\s*\([^;{}]{0,500}\)"
    r"|\b(?:send_bridge|bridge_send|bridge_to|dispatch_bridge|"
    r"dispatch_message|route_payload)\s*\([^;{}]{0,500}\)"
)

_SUPPLY_BURN_OR_DEBIT_RE = re.compile(
    r"(?is)\b(?:total_supply|balances?|shares?)\s*(?:-=|\.insert\s*\()"
    r"|\b(?:burn|debit|withdraw)\s*\([^;{}]{0,320}\)"
)

_UNLOCK_GUARD_RE = re.compile(
    r"(?is)\b(?:check_unlocked|share_unlock_time|unlock_at|unlock_time|"
    r"unlock_times|cooldown|ensure_unlocked|assert_unlocked)\b"
    r"|now\s*\(\s*\)\s*(?:>=|>|<|<=)\s*[^;{}]{0,120}unlock"
    r"|\b(?:burn|checked_burn)\s*\([^;{}]{0,260}\)"
)

_TARGET_PARAM_RE = re.compile(
    r"(?is)\bfn\s+\w+\s*\([^)]*\b(?:target|call_data|calldata|"
    r"external_target|destination|dest|payload)\s*:"
)

_CALLER_TARGET_DISPATCH_RE = re.compile(
    r"(?is)\b(?:execute_swap|execute_call|external_call|call_contract|"
    r"invoke_contract|try_invoke_contract|dispatch_target|route_to_target)"
    r"\s*\([^;{}]{0,520}\b(?:target|call_data|calldata|payload)\b"
    r"|\b(?:target|external_target|destination|dest)\s*\."
    r"(?:call|delegate_call|invoke)\s*\("
)

_TARGET_GUARD_RE = re.compile(
    r"(?is)\b(?:allowed|trusted|approved|whitelist|allowlist|valid)"
    r"[A-Za-z0-9_]*\s*\.\s*(?:contains|get)\s*\(\s*&?\s*target\s*\)"
    r"|\b(?:validate|check|require|ensure|assert)[A-Za-z0-9_!]*"
    r"\s*\([^;{}]{0,320}\btarget\b"
    r"|\btarget\s*(?:==|!=)\s*(?:expected|trusted|configured|self\.)"
)

_RAW_PAYLOAD_STORE_RE = re.compile(
    r"(?is)\b(?:failed_messages|failedMessages|stored_payloads|"
    r"storedPayloads|pending_payloads|pendingPayloads|failed_payloads)"
    r"\s*\.\s*(?:insert|push|set)\s*\([^;{}]{0,760}\bpayload\b"
    r"|storage\s*\.\s*set\s*\([^;{}]{0,520}\bpayload\b"
)

_PAYLOAD_DEFENSE_RE = re.compile(
    r"(?is)\bpayload\s*\.\s*len\s*\(\s*\)\s*(?:<=|<)\s*[A-Za-z0-9_]+"
    r"|\bpayload\s*\.\s*len\s*\(\s*\)\s*(?:<=|<)\s*\d+"
    r"|\b(?:keccak256|sha256|blake2(?:b|s)?|blake3|digest|hash)"
    r"\s*\(\s*&?\s*payload\b"
    r"|\bpayload_hash\b|\bfailed_message_hashes\b|\bstored_payload_hashes\b"
)

_DOMAIN_OR_CONSUME_GUARD_RE = re.compile(
    r"(?is)\b(?:domain_separator|verified_domain|proof_domain|bind_domain|"
    r"verify_domain|check_domain|expected_domain|trusted_domain|"
    r"allowed_domains|allowed_chains|trusted_chains|valid_channel|"
    r"channel_bound|bind_channel|source_chain|src_chain|dest_chain)"
    r"[A-Za-z0-9_\s\.\(\)&!=<>]{0,260}"
    r"(?:==|!=|contains|ensure|require|assert|validate|check)"
    r"|\b(?:processed|consumed|used|seen|executed)[A-Za-z0-9_]*"
    r"\s*\.\s*(?:insert|contains|get|remove)\s*\("
)


def _signature_text(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _share_unlock_bypass(body: str, file_text: str) -> bool:
    if "unlock" not in file_text.lower() and "cooldown" not in file_text.lower():
        return False
    if not _MINT_OR_SHARE_RE.search(body):
        return False
    if not _BRIDGE_SEND_RE.search(body):
        return False
    if not _SUPPLY_BURN_OR_DEBIT_RE.search(body):
        return False
    return _UNLOCK_GUARD_RE.search(body) is None


def _caller_target_bypass(signature: str, body: str) -> bool:
    if not _TARGET_PARAM_RE.search(signature):
        return False
    if not _CALLER_TARGET_DISPATCH_RE.search(body):
        return False
    if _TARGET_GUARD_RE.search(body):
        return False
    return _DOMAIN_OR_CONSUME_GUARD_RE.search(body) is None


def _raw_payload_save_bypass(signature: str, body: str) -> bool:
    if "payload" not in signature.lower() and "payload" not in body.lower():
        return False
    if not _RAW_PAYLOAD_STORE_RE.search(body):
        return False
    return _PAYLOAD_DEFENSE_RE.search(body) is None


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    file_text = source.decode("utf-8", errors="replace")

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
        fn_text = f"{signature}\n{body}"
        if not _BRIDGE_CONTEXT_RE.search(fn_text + "\n" + file_text):
            continue

        reason = ""
        if _share_unlock_bypass(body, file_text):
            reason = (
                "mints or accounts bridge shares, dispatches them cross-domain, "
                "and debits supply without the available unlock or checked burn"
            )
        elif _caller_target_bypass(signature, body):
            reason = (
                "dispatches caller-controlled target and calldata without an "
                "allowlist, proof-domain binding, or consume-once guard"
            )
        elif _raw_payload_save_bypass(signature, body):
            reason = (
                "stores a raw failure payload keyed by channel metadata without "
                "a fixed-size digest or payload-size cap"
            )

        if not reason:
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
                    f"pub fn `{name}` {reason}. Bridge dispatch metadata "
                    "must be bound to the verified domain or consumed once "
                    "before the downstream effect."
                ),
            }
        )

    return hits
