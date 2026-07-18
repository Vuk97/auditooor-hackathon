"""
r94_loop_shared_aggregate_cap_doses_independent_items.py

Flags single-item execute/validate paths that compare a shared
balance/cap against the aggregate total across all pending
listings/orders/requests/items. One oversized or stale sibling item can
exhaust the shared cap and block unrelated items.

Generalizes the all-listings shared-escrow DoS shape beyond an
ERC1155-specific marketplace implementation.

Also acts as a same-class recall lift for sibling dos-cap weakening shapes:
global pending queues bounded only by a shared cap, caller-controlled global
halt/deadline/cap state, and swap/router calls that pass the current block time
as the deadline.

Class: shared-aggregate-cap-doses-independent-items (both).
Attack-class suggestion: dos-cap-weakening.
"""

from __future__ import annotations

import re

_AGGREGATE_PATTERNS = [
    r"\b(total_needed|total_required|aggregate_needed|aggregate_required|"
    r"aggregate_amount|total_pending|get_total_(amount|needed|required|pending)|"
    r"sum_(orders|items|requests|listings)|total_for_(token|asset|market|item|order|request))\b",
    r"for\s+\w+\s+in\s+(?:&\s*)?(?:self\.)?(listings|orders|requests|items|pending)"
    r"[\s\S]{0,240}?saturating_add\s*\(\s*\w+\.(amount|qty|quantity|size|required)\b",
]

_SHARED_CAP_PATTERNS = [
    r"\b(shared_balance|escrow_balance|available_balance|vault_balance|"
    r"pool_balance|inventory_balance|available_inventory|usable_inventory|"
    r"remaining_capacity|shared_cap)\b",
    r"\bget_(balance|inventory|capacity)\s*\(",
]

_GATE_PATTERNS = [
    r"\b(shared_balance|escrow_balance|available_balance|vault_balance|"
    r"pool_balance|inventory_balance|available_inventory|usable_inventory|"
    r"remaining_capacity|shared_cap)\b\s*<\s*"
    r"\b(total_needed|total_required|aggregate_needed|aggregate_required|"
    r"aggregate_amount|total_pending|sum_\w+|total_for_\w+)\b",
    r"\b(total_needed|total_required|aggregate_needed|aggregate_required|"
    r"aggregate_amount|total_pending|sum_\w+|total_for_\w+)\b\s*>\s*"
    r"\b(shared_balance|escrow_balance|available_balance|vault_balance|"
    r"pool_balance|inventory_balance|available_inventory|usable_inventory|"
    r"remaining_capacity|shared_cap)\b",
]

_ITEM_CONTEXT_PATTERNS = [
    r"\b(execute|process|fill|settle|validate|check)_(listing|order|request|item)\b",
    r"\b(listing_id|order_id|request_id|item_id|listing_index|order_index|request_index)\b",
    r"\b(listing|order|request|item)\.(amount|qty|quantity|size|required)\b",
]

_SAFE_PATTERN = re.compile(
    r"\b(per_(listing|order|request|item)|reserved_for_(listing|order|request|item)|"
    r"reservation(s)?|request_reservations|listing_reservations|order_reservations|"
    r"reserved_balance|locked_for_(listing|order|request|item)|"
    r"held_for_(listing|order|request|item))\b",
    re.IGNORECASE | re.MULTILINE,
)

_COMPILED_GROUPS = [
    [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in _AGGREGATE_PATTERNS],
    [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in _SHARED_CAP_PATTERNS],
    [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in _GATE_PATTERNS],
    [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in _ITEM_CONTEXT_PATTERNS],
]

_STATE_WORD = (
    r"(?:pending|queue|queued|request|requests|reservation|reservations|"
    r"claim|claims|withdrawal|withdrawals|order|orders|job|jobs|task|tasks|"
    r"message|messages|registration|registrations|work|work_items)"
)

_STATE_NAME_RE = re.compile(_STATE_WORD, re.IGNORECASE | re.MULTILINE)

_GLOBAL_QUEUE_WRITE_RE = re.compile(
    r"\b(?P<target>[A-Za-z_][A-Za-z0-9_\.]*)"
    r"\s*\.\s*(?:set|insert|push|push_back|append|enqueue)\s*\(",
    re.IGNORECASE | re.MULTILINE,
)

_GLOBAL_QUEUE_LEN_GATE_RE = re.compile(
    r"\b(?P<target>[A-Za-z_][A-Za-z0-9_\.]*)"
    r"\s*\.\s*len\s*\(\s*\)(?:\s+as\s+[A-Za-z_][A-Za-z0-9_:<>]*)?"
    r"[^{};\n]{0,160}(?:>=|>|==)[^{};\n]{0,160}"
    r"(?:MAX|CAP|LIMIT|QUOTA|max|cap|limit|quota)",
    re.IGNORECASE | re.MULTILINE,
)

_GLOBAL_CONTROL_WRITE_RE = re.compile(
    r"(?:"
    r"(?:self\.)?(?:paused|pause|halted|halt|stopped|disabled|frozen|closed|"
    r"blocked|deadline|expiry|expires_at|cap|limit|max_\w+|processing_cap|"
    r"global_cap|batch_cap)\s*=\s*(?:true|false|0|0u64|0u128|caller|"
    r"user|params\.|input|requested|amount|deadline|expiry|expires_at|"
    r"cap|limit|max_|block_timestamp|timestamp|now|env\.ledger)"
    r"|"
    r"\.set\s*\([^;]*?(?:paused|pause|halted|halt|stopped|disabled|frozen|"
    r"closed|blocked|deadline|expiry|expires_at|cap|limit|max_\w+|"
    r"processing_cap|global_cap|batch_cap)[^;]*?,\s*&?(?:true|false|0|0u64|"
    r"0u128|caller|user|params\.|input|requested|amount|caller_deadline|"
    r"deadline|expiry|expires_at|caller_cap|cap|limit|max_|block_timestamp|"
    r"timestamp|now|env\.ledger)"
    r")",
    re.IGNORECASE | re.MULTILINE,
)

_GLOBAL_BLOCKING_GATE_RE = re.compile(
    r"(?:"
    r"if\s+[^{};\n]*(?:paused|pause|halted|halt|stopped|disabled|frozen|"
    r"closed|blocked)\b[^{};\n]*\{[^{}]{0,180}(?:return\s+Err|panic!|"
    r"return\s+None|return\s+false)"
    r"|"
    r"if\s+[^{};\n]*(?:now|timestamp|ledger|block_time|current_time)"
    r"[^{};\n]*(?:>|>=)\s*[^{};\n]*(?:deadline|expiry|expires_at)\b"
    r"[^{};\n]*\{[^{}]{0,180}(?:return\s+Err|panic!|return\s+None|"
    r"return\s+false)"
    r"|"
    r"if\s+[^{};\n]*(?:requested|amount|items|orders|pending|count|batch|"
    r"queue_len|len\s*\(\s*\))[^{};\n]*(?:>|>=)\s*[^{};\n]*(?:cap|limit|"
    r"max_\w+|processing_cap|global_cap|batch_cap)\b[^{};\n]*\{"
    r"[^{}]{0,180}(?:return\s+Err|panic!|return\s+None|return\s+false)"
    r")",
    re.IGNORECASE | re.MULTILINE,
)

_TIMESTAMP_DEADLINE_PASSTHROUGH_RE = re.compile(
    r"\b\w+\s*\.\s*(?:swap|exact_input|exact_output|add_liquidity|"
    r"remove_liquidity|deposit|withdraw)\s*\([^;]{0,360}?"
    r"(?:block_timestamp\s*\(\s*\)|env\.ledger\s*\(\s*\)\.timestamp\s*\(\s*\)|"
    r"env\.ledger\.timestamp\s*\(\s*\)|now\s*\(\s*\))",
    re.IGNORECASE | re.MULTILINE,
)

_CALLER_DEADLINE_RE = re.compile(
    r"\b(?:user_deadline|caller_deadline|params\.deadline|deadline\s*:|"
    r"_deadline)\b",
    re.IGNORECASE | re.MULTILINE,
)

_SAFE_GLOBAL_CAP_RE = re.compile(
    r"\b(?:require_auth|has_auth|only_owner|only_admin|admin\.require_auth|"
    r"owner\.require_auth|ensure_owner|ensure_admin|assert_owner|"
    r"assert_admin|trusted_factory|pay_fee|charge_fee|require_fee|"
    r"collect_fee|transfer_fee|required_deposit|bond_required|stake_required|"
    r"escrow_deposit|rate_limit|cooldown|throttle|requests_per_block|"
    r"per_user|per_sender|per_caller|user_quota|caller_quota|contains_key|"
    r"already_pending|dedup|unique_request|unpause|resume|reopen|"
    r"extend_deadline|increase_cap|reset_cap|clear_pause|clear_halt|"
    r"can_unblock|reconfigure)\b",
    re.IGNORECASE | re.MULTILINE,
)

_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _strip_comments(text: str) -> str:
    text = _LINE_COMMENT_RE.sub("", text)
    text = _BLOCK_COMMENT_RE.sub("", text)
    return text


def _line_for(text: str, offset: int) -> int:
    return text[:offset].count("\n") + 1


def _snippet(text: str, offset: int, length: int = 160) -> str:
    return text[offset: offset + length].replace("\n", " ").strip()


def _hit(filepath: str, code: str, anchor: re.Match[str], detail: str) -> list[dict]:
    return [{
        "severity": "high",
        "line": _line_for(code, anchor.start()),
        "col": 0,
        "snippet": _snippet(code, anchor.start()),
        "message": (
            f"{filepath}: detected {detail}. This removes or weakens an "
            f"intended global work cap and can block unrelated work "
            f"(shared dos-cap-weakening recall lift). Attack-class "
            f"suggestion: dos-cap-weakening."
        ),
    }]


def _target_aliases(target: str) -> set[str]:
    aliases = {target}
    if "." in target:
        aliases.add(target.rsplit(".", 1)[-1])
    return {alias for alias in aliases if alias}


def _has_global_queue_len_gate(code: str, target: str) -> bool:
    aliases = _target_aliases(target)
    for gate in _GLOBAL_QUEUE_LEN_GATE_RE.finditer(code):
        gate_target = gate.group("target")
        if not _STATE_NAME_RE.search(gate_target):
            continue
        if gate_target in aliases or gate_target.rsplit(".", 1)[-1] in aliases:
            return True
    return False


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")
    code = _strip_comments(text)

    if _SAFE_PATTERN.search(code):
        return hits

    if not _SAFE_GLOBAL_CAP_RE.search(code):
        for write_match in _GLOBAL_QUEUE_WRITE_RE.finditer(code):
            if not _STATE_NAME_RE.search(write_match.group("target")):
                continue
            if _has_global_queue_len_gate(code, write_match.group("target")):
                return _hit(
                    filepath,
                    code,
                    write_match,
                    "a public intake path writing caller-controlled work into a "
                    "global pending collection that is later bounded only by a "
                    "shared length or cap gate",
                )

        control_write = _GLOBAL_CONTROL_WRITE_RE.search(code)
        if control_write and _GLOBAL_BLOCKING_GATE_RE.search(code):
            return _hit(
                filepath,
                code,
                control_write,
                "caller-controlled global halt, deadline, or cap state that "
                "later acts as a processing gate",
            )

    timestamp_passthrough = _TIMESTAMP_DEADLINE_PASSTHROUGH_RE.search(code)
    if timestamp_passthrough and not _CALLER_DEADLINE_RE.search(code):
        return _hit(
            filepath,
            code,
            timestamp_passthrough,
            "a router or swap call passing the current block timestamp as the "
            "deadline, making the downstream deadline cap ineffective",
        )

    matched_groups = 0
    first_match = None
    for group in _COMPILED_GROUPS:
        for compiled in group:
            match = compiled.search(code)
            if match:
                matched_groups += 1
                if first_match is None:
                    first_match = match
                break

    if matched_groups < 3:
        return hits

    gate_match = None
    for compiled in _COMPILED_GROUPS[2]:
        gate_match = compiled.search(code)
        if gate_match:
            break

    anchor = gate_match or first_match
    if anchor is None:
        return hits

    line = code[: anchor.start()].count("\n") + 1
    snippet = code[anchor.start() : anchor.start() + 160].replace("\n", " ").strip()

    hits.append({
        "severity": "high",
        "line": line,
        "col": 0,
        "snippet": snippet,
        "message": (
            f"{filepath}: detected a single-item execute/validate path that "
            f"gates one listing/order/request on a shared aggregate total "
            f"across all pending items. One oversized sibling item can "
            f"exhaust the shared cap and DoS unrelated items "
            f"(shared-aggregate-cap-doses-independent-items). "
            f"Attack-class suggestion: dos-cap-weakening."
        ),
    })
    return hits
