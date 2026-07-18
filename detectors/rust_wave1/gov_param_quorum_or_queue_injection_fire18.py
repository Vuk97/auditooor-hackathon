"""
gov_param_quorum_or_queue_injection_fire18.py

Rust same-class recall lift for gov-param-injection misses.

This detector targets governance quorum, proposal queue, timelock schedule,
and proposal execution invariants. It deliberately requires both governance
context and a load-bearing invariant shape so generic voting vocabulary alone
does not fire.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    line_col,
    snippet_of,
    source_nocomment,
    text_of,
)


DETECTOR_ID = "rust_wave1.gov_param_quorum_or_queue_injection_fire18"

_GOV_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"governance|governor|proposal|proposal_id|quorum|vote|votes|voter|"
    r"abstain|against|for_votes|queue|queued|timelock|eta|delay|"
    r"schedule|executor|execute_proposal|action|actions"
    r")\b"
)
_QUORUM_NAME_RE = re.compile(r"(?i)(^|_)(quorum|has_?quorum|quorum_?reached|state)($|_)")
_QUEUE_NAME_RE = re.compile(r"(?i)(^|_)(queue|schedule|enqueue|propose)(_|\b)")
_EXEC_NAME_RE = re.compile(r"(?i)(^|_)(execute|execute_?proposal|execute_?action|dispatch)(_|\b)")

_AGAINST_ABSTAIN_SUM_RE = re.compile(
    r"(?is)(?:let\s+\w+\s*=\s*)?"
    r"(?:proposal\s*\.\s*)?against_votes\s*\+\s*"
    r"(?:proposal\s*\.\s*)?abstain_votes"
)
_FOR_ABSTAIN_SUM_RE = re.compile(
    r"(?is)(?:proposal\s*\.\s*)?for_votes\s*\+\s*"
    r"(?:proposal\s*\.\s*)?abstain_votes"
)
_QUORUM_COMPARE_RE = re.compile(r"(?is)(>=|<=|>|<)\s*(?:self\s*\.\s*)?quorum\s*\(|\bquorum\s*\(")

_QUADRATIC_POWER_RE = re.compile(
    r"(?is)("
    r"\bcount_votes\s*\([^)]*\)\s*(?:->\s*[A-Za-z0-9_:<>]+)?\s*\{[^{}]{0,500}"
    r"(?:integer_sqrt|\.sqrt\s*\(|sqrt\s*\()|"
    r"\b(?:integer_sqrt|sqrt_weighted|quadratic_vote|quadratic_weight)\s*\("
    r")"
)
_LINEAR_QUORUM_RE = re.compile(
    r"(?is)("
    r"total_supply\s*(?:\.\s*checked_mul\s*\(|\s*\*)[^;]{0,240}"
    r"(?:quorum_numerator|quorum_fraction|quorum_bps|quorum_percent)|"
    r"(?:quorum_numerator|quorum_fraction|quorum_bps|quorum_percent)"
    r"[^;]{0,240}(?:\*|checked_mul\s*\()[^;]{0,240}total_supply|"
    r"totalSupply\s*\(\s*\)[^;]{0,240}(?:quorumNumerator|quorum)"
    r")"
)
_QUADRATIC_QUORUM_SAFE_RE = re.compile(
    r"(?is)(sqrt_total_supply|quadratic_quorum|sqrt_weighted_quorum|quorum_sqrt)"
)

_ACTION_KEY_RE = re.compile(
    r"(?is)\b(?:let\s+)?(?P<key>action_hash|operation_hash|call_hash|tx_hash)\b"
)
_ACTION_KEY_COLLISION_RE = re.compile(
    r"(?is)"
    r"(?:contains_key\s*\(\s*&?\s*(?:action_hash|operation_hash|call_hash|tx_hash)\s*\)|"
    r"insert\s*\(\s*(?:action_hash|operation_hash|call_hash|tx_hash)\s*,)"
)
_ACTION_LIST_RE = re.compile(r"(?is)\bactions\s*:\s*Vec\s*<|\bVec\s*<\s*Action\s*>|\bfor\s+action\s+in\s+actions")
_ACTION_UNIQUENESS_SAFE_RE = re.compile(
    r"(?is)("
    r"enumerate\s*\(\s*\)|"
    r"\(\s*proposal_id\s*,\s*(?:idx|index|i)\s*(?:as\s+\w+)?\s*\)|"
    r"action_index|action_idx|nonce|ordinal|dedupe|allow_duplicate|"
    r"HashMap\s*<\s*\([^>]*(?:proposal_id|U256|u64)[^>]*(?:idx|index|u64)"
    r")"
)

_SCHEDULE_CONTEXT_RE = re.compile(r"(?i)\b(queue|queued|schedule|scheduled|timelock|eta|delay)\b")
_SCHEDULE_WRITE_RE = re.compile(r"(?is)\b(?:insert|set|push|save)\s*\([^;]{0,260}(?:eta|delay|operation|action|proposal)")
_READY_CHECK_RE = re.compile(r"(?is)(now|timestamp|block_time|current_time)[^;]{0,180}(?:>=|>|checked_sub)[^;]{0,180}(eta|ready_at|execute_after|delay)")
_TTL_SAFE_RE = re.compile(
    r"(?is)\b(ttl|expires_at|expiry|expiration|deadline|valid_until|"
    r"extend_ttl|extend_instance_ttl|cancel_after|grace_period)\b"
)

_EXTERNAL_ACTION_CALL_RE = re.compile(
    r"(?is)("
    r"\b(?:action|queued|operation|call)\s*\.\s*(?:call|execute|dispatch|invoke)\s*\(|"
    r"\b(?:execute_external|dispatch_external|call_target|invoke_target)\s*\(|"
    r"\bself\s*\.\s*(?:dispatch_action|execute_action_call|call_target)\s*\("
    r")"
)
_EXEC_GUARD_RE = re.compile(
    r"(?is)("
    r"assert_governance|require_governance|check_governance|only_governance|"
    r"ensure_governance|governance_guard|authorized_executor|"
    r"assert_authorized_executor|require_authorized_executor|"
    r"ensure_root\s*\(|ensure_origin\s*\(|\.require_auth\s*\(|"
    r"has_role\s*\([^;]*(?:governance|governor|executor|timelock)|"
    r"queued\.executed|operation\.executed|executed\s*=|"
    r"ready_at|execute_after|eta|timelock|proposal\.succeeded"
    r")"
)

_CAST_DENOM_RE = re.compile(
    r"(?is)("
    r"for_votes\s*\+\s*against_votes\s*\+\s*abstain_votes|"
    r"yes_votes\s*\+\s*no_votes\s*\+\s*abstain_votes|"
    r"total_votes_cast|votes_cast\s*\(|total_cast"
    r")"
)
_TOTAL_SUPPLY_SAFE_RE = re.compile(
    r"(?is)(total_supply|totalSupply|getPastTotalSupply|past_total_supply|snapshot_total_supply)"
)


def _signature_text(fn, source: bytes) -> str:
    return text_of(fn, source).split("{", 1)[0]


def _has_governance_context(name: str, signature: str, body: str, file_text: str) -> bool:
    joined = "\n".join([name, signature, body])
    if _GOV_CONTEXT_RE.search(joined):
        return True
    return bool(_GOV_CONTEXT_RE.search(file_text[:2000]))


def _abstain_against_mixup(name: str, signature: str, body: str) -> str | None:
    if not (_QUORUM_NAME_RE.search(name) or "quorum" in (signature + body).lower()):
        return None
    if not _AGAINST_ABSTAIN_SUM_RE.search(body):
        return None
    if _FOR_ABSTAIN_SUM_RE.search(body):
        return None
    if not _QUORUM_COMPARE_RE.search(body):
        return None
    return "quorum participation counts against + abstain instead of for + abstain"


def _cast_votes_denominator_gap(name: str, signature: str, body: str) -> str | None:
    joined = signature + "\n" + body
    if not (_QUORUM_NAME_RE.search(name) or "quorum" in joined.lower()):
        return None
    if not _CAST_DENOM_RE.search(body):
        return None
    if _TOTAL_SUPPLY_SAFE_RE.search(body):
        return None
    return "quorum denominator is cast-vote participation instead of snapshot or total supply"


def _quadratic_linear_quorum_gap(name: str, body: str, file_text: str) -> str | None:
    if not (_QUORUM_NAME_RE.search(name) or "quorum" in name.lower()):
        return None
    if not _QUADRATIC_POWER_RE.search(file_text):
        return None
    if not _LINEAR_QUORUM_RE.search(body):
        return None
    if _QUADRATIC_QUORUM_SAFE_RE.search(body):
        return None
    return "quadratic vote weights are compared against a linear total_supply quorum"


def _queued_action_key_collision(name: str, signature: str, body: str) -> str | None:
    joined = signature + "\n" + body
    if not (_QUEUE_NAME_RE.search(name) or _ACTION_LIST_RE.search(joined)):
        return None
    if not _ACTION_LIST_RE.search(joined):
        return None
    if not _ACTION_KEY_RE.search(body):
        return None
    if not _ACTION_KEY_COLLISION_RE.search(body):
        return None
    if _ACTION_UNIQUENESS_SAFE_RE.search(body):
        return None
    return "proposal action queue keys repeated actions only by action hash, not proposal and index"


def _missing_schedule_ttl(name: str, signature: str, body: str) -> str | None:
    joined = signature + "\n" + body
    if not (_QUEUE_NAME_RE.search(name) or _SCHEDULE_CONTEXT_RE.search(joined)):
        return None
    if not _SCHEDULE_WRITE_RE.search(body):
        return None
    if not _READY_CHECK_RE.search(body + "\n" + signature):
        return None
    if _TTL_SAFE_RE.search(body):
        return None
    return "governance schedule writes a ready time but no expiry, TTL, or deadline"


def _unguarded_external_execute(name: str, signature: str, body: str) -> str | None:
    if not _EXEC_NAME_RE.search(name):
        return None
    joined = signature + "\n" + body
    if not _EXTERNAL_ACTION_CALL_RE.search(body):
        return None
    if _EXEC_GUARD_RE.search(joined):
        return None
    return "proposal execution dispatches an external action without authorization or timelock guard"


def _build_hit(filepath: str, line: int, col: int, name: str, variant: str, detail: str, snippet: str) -> dict:
    return {
        "detector_id": DETECTOR_ID,
        "severity": "medium",
        "file": filepath,
        "line": line,
        "col": col,
        "fn_name": name,
        "variant": variant,
        "snippet": snippet,
        "message": (
            f"fn `{name}` matches gov-param-injection variant `{variant}`: "
            f"{detail}."
        ),
    }


def run(tree, source: bytes, filepath: str):
    hits = []
    file_text = source_nocomment(source)

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body_node = fn_body(fn)
        if body_node is None:
            continue

        name = fn_name(fn, source)
        signature = _signature_text(fn, source)
        body = body_text_nocomment(body_node, source)
        if not _has_governance_context(name, signature, body, file_text):
            continue

        line, col = line_col(fn)
        snippet = snippet_of(fn, source, 240)
        checks = [
            ("quorum-against-abstain-mixup", _abstain_against_mixup(name, signature, body)),
            ("quorum-cast-votes-denominator", _cast_votes_denominator_gap(name, signature, body)),
            ("quorum-quadratic-linear-mismatch", _quadratic_linear_quorum_gap(name, body, file_text)),
            ("queued-action-hash-collision", _queued_action_key_collision(name, signature, body)),
            ("schedule-missing-ttl", _missing_schedule_ttl(name, signature, body)),
            ("unguarded-proposal-external-call", _unguarded_external_execute(name, signature, body)),
        ]
        for variant, detail in checks:
            if detail is None:
                continue
            hits.append(_build_hit(filepath, line, col, name, variant, detail, snippet))

    return hits
