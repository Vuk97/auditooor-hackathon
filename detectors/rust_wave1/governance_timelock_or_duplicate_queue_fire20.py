"""
governance_timelock_or_duplicate_queue_fire20.py

Rust same-class recall lift for gov-param-injection misses.

This detector targets three governance and queue binding shapes:
- proposal execution dispatches queued work without a timelock readiness check
- queued action keys omit proposal or per-action uniqueness context
- HTLC or timelock commitments persist caller supplied expiry without a min delta

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
    line_col,
    snippet_of,
    source_nocomment,
    text_of,
)


DETECTOR_ID = "rust_wave1.governance_timelock_or_duplicate_queue_fire20"

_GOV_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"governance|governor|proposal|proposal_id|operation|action|actions|"
    r"queue|queued|schedule|scheduled|timelock|delay|eta|execute_after|"
    r"ready_at|htlc|expiration|expiry|deadline|unlock_time"
    r")\b"
)

_EXEC_NAME_RE = re.compile(
    r"(?i)(^|_)(execute|execute_?proposal|execute_?transaction|run|dispatch|fire|trigger)($|_)"
)
_EXEC_CONTEXT_RE = re.compile(
    r"(?i)\b(proposal|operation|action|queue|queued|governance|governor|timelock)\b"
)
_EXTERNAL_DISPATCH_RE = re.compile(
    r"(?is)("
    r"\binvoke_contract\s*\(|\btry_invoke_contract\s*\(|"
    r"\bupdate_current_contract_wasm\s*\(|"
    r"\.(?:execute|dispatch|invoke|upgrade)\s*\(|"
    r"\b(?:execute_external|dispatch_external|call_target|invoke_target)\s*\(|"
    r"\bself\s*\.\s*(?:dispatch_action|execute_action_call|call_target)\s*\("
    r")"
)
_TIME_WORD_RE = (
    r"(?:eta|ready_at|ready_ts|execute_after|exec_after|unlock_time|"
    r"timelock|delay|min_delay|expires_at|expiration|expiry|deadline)"
)
_NOW_WORD_RE = (
    r"(?:now|timestamp|block_time|current_time|block_timestamp|ledger\s*\(\s*\)\s*\.\s*timestamp\s*\(\s*\))"
)
_TIMELOCK_READY_RE = re.compile(
    rf"(?is)("
    rf"{_NOW_WORD_RE}[^;{{}}]{{0,220}}(?:>=|>|<=|<)[^;{{}}]{{0,220}}{_TIME_WORD_RE}|"
    rf"{_TIME_WORD_RE}[^;{{}}]{{0,220}}(?:>=|>|<=|<)[^;{{}}]{{0,220}}{_NOW_WORD_RE}|"
    r"assert_?(?:timelock|delay|ready)|ensure_?(?:timelock|delay|ready)|"
    r"require_?(?:timelock|delay|ready)|check_?(?:timelock|delay|ready)"
    r")"
)

_QUEUE_NAME_RE = re.compile(r"(?i)(^|_)(queue|queue_?transaction|queue_?proposal|schedule|enqueue)($|_)")
_QUEUE_CONTEXT_RE = re.compile(
    r"(?is)\b("
    r"queued_transactions|queued_actions|queued_operations|HashMap|BTreeMap|"
    r"proposal|proposal_id|action_hash|operation_hash|call_hash|tx_hash"
    r")\b"
)
_HASH_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?P<var>(?:action|operation|call|tx)_?hash)\s*=\s*(?P<expr>[^;]+);"
)
_HASH_INLINE_INSERT_RE = re.compile(
    r"(?is)\b(?:queued_transactions|queued_actions|queued_operations)\s*\(\s*\)"
    r"\s*\.\s*insert\s*\(\s*(?P<expr>hash\s*\([^;]+?)\s*(?:,|\))"
)
_QUEUE_INSERT_TEMPLATE = (
    r"(?is)(?:contains_key\s*\(\s*&?\s*{var}\s*\)|"
    r"\binsert\s*\(\s*&?\s*{var}\s*(?:,|\))|"
    r"\bset\s*\(\s*&?\s*{var}\s*(?:,|\)))"
)
_ACTION_HASH_EXPR_RE = re.compile(
    r"(?is)(?:hash\s*\(|\.hash\s*\(|keccak|sha256|blake|pedersen)"
)
_QUEUE_BINDING_RE = re.compile(
    r"(?is)\b("
    r"proposal_id|proposal\.id|operation_id|action_id|action_index|action_idx|"
    r"\bidx\b|\bindex\b|\bnonce\b|\bordinal\b|\bsalt\b"
    r")\b"
)
_QUEUE_SAFE_KEY_RE = re.compile(
    r"(?is)("
    r"let\s+(?:key|action_key|operation_key)\s*=\s*\([^;]*(?:proposal_id|proposal\.id)"
    r"[^;]*(?:idx|index|nonce|action_id|operation_id|ordinal)|"
    r"\(\s*(?:proposal_id|proposal\.id)\s*,\s*(?:idx|index|nonce|action_id|operation_id|ordinal)|"
    r"(?:proposal_id|proposal\.id)[^;]{0,160}(?:hash\s*\(|\.hash\s*\()"
    r")"
)

_TIME_PARAM_RE = re.compile(
    r"(?i)\b(timelock|expiration|expiry|expires_at|deadline|unlock_time|timeout)\b"
)
_TIME_PERSIST_RE = re.compile(
    r"(?is)("
    r"\bpersist_(?:commit|lock|htlc|timelock)\s*\([^;]*(?:timelock|expiration|expiry|deadline|unlock_time)|"
    r"\b(?:insert|save|set|put|push)\s*\([^;]*(?:timelock|expiration|expiry|deadline|unlock_time)|"
    r"\b(?:Commit|Lock|Htlc|Timelock)\s*\{[^{}]*(?:timelock|expiration|expiry|deadline|unlock_time)"
    r")"
)
_DELTA_ENFORCED_RE = re.compile(
    rf"(?is)("
    rf"(?:timelock|expiration|expiry|expires_at|deadline|unlock_time)[^;{{}}]{{0,220}}"
    rf"(?:>=|>|<=|<)[^;{{}}]{{0,220}}{_NOW_WORD_RE}[^;{{}}]{{0,120}}"
    r"(?:min_delta|min_delay|safety_delta|required_delta|MIN_|DELTA|DELAY)|"
    rf"{_NOW_WORD_RE}[^;{{}}]{{0,120}}(?:\+|checked_add|saturating_add)"
    r"[^;{}]{0,120}(?:min_delta|min_delay|safety_delta|required_delta|MIN_|DELTA|DELAY)|"
    r"assert_?(?:min_)?(?:delta|delay)|ensure_?(?:min_)?(?:delta|delay)|"
    r"require_?(?:min_)?(?:delta|delay)|check_?(?:min_)?(?:delta|delay)"
    r")"
)


def _signature_text(fn, source: bytes) -> str:
    return text_of(fn, source).split("{", 1)[0]


def _has_recall_context(name: str, signature: str, body: str, file_text: str) -> bool:
    joined = "\n".join([name, signature, body])
    if _GOV_CONTEXT_RE.search(joined):
        return True
    return bool(_GOV_CONTEXT_RE.search(file_text[:1800]))


def _execute_missing_timelock(name: str, signature: str, body: str) -> str | None:
    joined = signature + "\n" + body
    if not _EXEC_NAME_RE.search(name):
        return None
    if not _EXEC_CONTEXT_RE.search(joined):
        return None
    if not _EXTERNAL_DISPATCH_RE.search(body):
        return None
    if _TIMELOCK_READY_RE.search(body):
        return None
    return "proposal execution dispatches queued work without checking eta, ready_at, or delay"


def _duplicate_action_queue_key(name: str, signature: str, body: str) -> str | None:
    joined = signature + "\n" + body
    if not (_QUEUE_NAME_RE.search(name) or _QUEUE_CONTEXT_RE.search(joined)):
        return None
    if not _QUEUE_CONTEXT_RE.search(body):
        return None
    if _QUEUE_SAFE_KEY_RE.search(body):
        return None

    for match in _HASH_ASSIGN_RE.finditer(body):
        expr = match.group("expr")
        if not _ACTION_HASH_EXPR_RE.search(expr):
            continue
        if _QUEUE_BINDING_RE.search(expr):
            continue
        insert_re = re.compile(_QUEUE_INSERT_TEMPLATE.format(var=re.escape(match.group("var"))))
        if insert_re.search(body):
            return "queued action hash is stored without proposal id or per-action uniqueness context"

    inline = _HASH_INLINE_INSERT_RE.search(body)
    if inline and not _QUEUE_BINDING_RE.search(inline.group("expr")):
        return "queued action hash is stored without proposal id or per-action uniqueness context"

    return None


def _timelock_delta_unenforced(name: str, signature: str, body: str) -> str | None:
    joined = signature + "\n" + body
    if not _TIME_PARAM_RE.search(joined):
        return None
    if not _TIME_PERSIST_RE.search(body):
        return None
    if _DELTA_ENFORCED_RE.search(body):
        return None
    return "timelock or expiry is persisted without enforcing a minimum delta from current time"


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
        if not _has_recall_context(name, signature, body, file_text):
            continue

        checks = [
            ("execute-missing-timelock", _execute_missing_timelock(name, signature, body)),
            ("duplicate-action-queue-key", _duplicate_action_queue_key(name, signature, body)),
            ("timelock-delta-unenforced", _timelock_delta_unenforced(name, signature, body)),
        ]
        line, col = line_col(fn)
        snippet = snippet_of(fn, source, 260)
        for variant, detail in checks:
            if detail is None:
                continue
            hits.append(_build_hit(filepath, line, col, name, variant, detail, snippet))

    return hits
