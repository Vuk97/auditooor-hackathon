"""
reentrant_midstate_callback_fire34.py

Rust detector for the Fire34 reentrancy-cross-contract lift.

Flags public Rust entrypoints that write mid-operation state, transfer control
to an external callback, CPI, contract call, hook, token transfer, or receiver,
then finalize settlement or balances only after that external boundary. This
is the Rust analogue of the Fire33 ledger-settlement callback shape.

Source refs:
- reports/detector_lift_fire33_20260605/post_priorities_rust.md
- reference/patterns.dsl/reentrancy-cross-contract-stale-state-callback.yaml
- reference/patterns.dsl/callback_reentrancy_no_guard.yaml
- detectors/rust_wave1/callback_mid_state_mutation.py
- detectors/wave17/callback_ledger_settlement_fire33.py

Provenance and evidence limits:
- R37: this detector emits source-state candidate evidence only.
- R40: fixtures are detector smoke tests, not exploit PoCs.
- R76: candidate promotion must grep-verify any cited excerpt exists.
- R80: detector hits are not load-bearing exploit evidence.

Submission posture: NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re

from _util import (
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
    text_of,
)


DETECTOR_ID = "rust_wave1.reentrant_midstate_callback_fire34"

_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

_EXTERNAL_BOUNDARY_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"\benv\s*\.\s*(?:try_)?invoke_contract(?:\s*::\s*<[^>]+>)?\s*\(|"
    r"\b(?:try_)?invoke_contract\s*\(|"
    r"\bcall_contract\s*\(|"
    r"\binvoke_signed\s*\(|"
    r"\bprogram::invoke_signed\s*\(|"
    r"\binvoke\s*\(|"
    r"\bprogram::invoke\s*\(|"
    r"\banchor_spl::token::[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"\btoken::(?:transfer|transfer_checked|mint_to|burn)\s*\(|"
    r"\bcpi::[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"\bCpiContext\s*::\s*new\b|"
    r"\b(?:"
    r"[A-Za-z_][A-Za-z0-9_\.]*(?:callback|hook|receiver|recipient|"
    r"router|adapter|client|program|callee|token|vault|bridge)"
    r"[A-Za-z0-9_\.]*"
    r")\s*\.\s*(?:"
    r"before_[A-Za-z0-9_]+|after_[A-Za-z0-9_]+|on_[A-Za-z0-9_]+|"
    r"callback|hook|receive_[A-Za-z0-9_]*|handle_[A-Za-z0-9_]*|"
    r"execute_[A-Za-z0-9_]*|invoke|call|call_contract|settle[A-Za-z0-9_]*|"
    r"finali[sz]e[A-Za-z0-9_]*|safe_transfer_from|transfer_from|"
    r"transfer|send"
    r")\s*\("
    r")"
)

_STATE_TARGET_PREFIX = (
    r"(?:self|state|ledger|vault|market|position|positions|pending|"
    r"pending_withdrawals|claim|claims|balance|balances|reserve|reserves|"
    r"reward|rewards|order|orders|escrow|nonce|status|settlement|"
    r"accounting|ctx(?:\.accounts)?|account)"
)

_STATE_ASSIGN_RE = re.compile(
    rf"(?P<target>"
    rf"{_STATE_TARGET_PREFIX}[A-Za-z0-9_\.\[\]]*|"
    rf"[A-Za-z_][A-Za-z0-9_]*\."
    rf"(?:pending|claim|balance|reserve|reward|order|escrow|nonce|status|"
    rf"settlement|accounting|processed|settled|finalized|finalised|complete)"
    rf"[A-Za-z0-9_\.\[\]]*"
    rf")\s*(?:\+=|-=|\*=|/=|=)"
)

_STATE_MUT_CALL_RE = re.compile(
    rf"(?P<target>"
    rf"{_STATE_TARGET_PREFIX}[A-Za-z0-9_\.\[\]]*|"
    rf"[A-Za-z_][A-Za-z0-9_]*\."
    rf"(?:pending|claim|balance|reserve|reward|order|escrow|nonce|status|"
    rf"settlement|accounting|processed|settled|finalized|finalised|complete)"
    rf"[A-Za-z0-9_\.\[\]]*"
    rf")\s*\.\s*(?:insert|push|push_back|set|update|remove|write|save|"
    rf"replace)\s*\("
)

_STORAGE_WRITE_RE = re.compile(
    r"(?is)"
    r"(?P<target>"
    r"(?:env|e|self)?\s*\.?\s*storage\s*\(\)"
    r"[\s\S]{0,180}?"
    r"\.(?:set|update|remove)\s*\("
    r"[\s\S]{0,260}?;"
    r")"
)

_MIDSTATE_TOKEN_RE = re.compile(
    r"(?i)"
    r"(pending|in_progress|processing|started|reserved|locked|entered|"
    r"withdraw|withdrawal|redeem|redemption|claim|order|position|escrow|"
    r"balance|balances|reserve|reserves|owed|payout|settlement|status)"
)

_POST_FINAL_TOKEN_RE = re.compile(
    r"(?i)"
    r"(settled|settlement|finalized|finalised|complete|completed|processed|"
    r"status|balance|balances|ledger|nonce|paid|owed|remaining|total|"
    r"accounting)"
)

_PRE_FINAL_MARKER_RE = re.compile(
    r"(?i)"
    r"(settled|finalized|finalised|complete|completed|processed)"
)

_PENDING_MARKER_RE = re.compile(
    r"(?i)(pending|in_progress|processing|started|reserved|locked|entered)"
)

_GUARD_RE = re.compile(
    r"(?i)"
    r"(#\[\s*non_reentrant\s*\]|non_reentrant|nonReentrant|"
    r"ReentrancyGuard|reentrancy_guard|reentrancy_lock|cpi_guard|"
    r"enter_reentrancy|enter_guard|guard\.enter|lock_reentrancy|"
    r"acquire_reentrancy|check_and_set|is_entered|guard_entered|"
    r"_status\s*=\s*ENTERED|locked\s*=\s*true|entered\s*=\s*true|"
    r"in_reentrancy\s*=\s*true)"
)

_LOCAL_HELPER_CONTEXT_RE = re.compile(
    r"(?i)"
    r"\b(?:emit_event|publish_event|record_event|log_event|record_metric|"
    r"notify_only|view_only|read_only)\s*\("
)


def _mask_comments_keep_lines(text: str) -> str:
    text = _LINE_COMMENT_RE.sub(lambda match: " " * (match.end() - match.start()), text)

    def repl(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group(0))

    return _BLOCK_COMMENT_RE.sub(repl, text)


def _line_for_offset(base_line: int, text: str, offset: int) -> int:
    return base_line + text[:offset].count("\n")


def _is_declaration_assignment(text: str, match: re.Match[str]) -> bool:
    line_start = text.rfind("\n", 0, match.start()) + 1
    prefix = text[line_start:match.start()]
    return bool(re.search(r"\b(?:let|const|static)\b", prefix))


def _iter_state_writes(body_text: str):
    seen: set[tuple[int, int]] = set()
    for regex in (_STATE_ASSIGN_RE, _STATE_MUT_CALL_RE, _STORAGE_WRITE_RE):
        for match in regex.finditer(body_text):
            if regex is _STATE_ASSIGN_RE and _is_declaration_assignment(body_text, match):
                continue
            span = match.span()
            if span in seen:
                continue
            target = " ".join((match.groupdict().get("target") or match.group(0)).split())
            if not (_MIDSTATE_TOKEN_RE.search(target) or _POST_FINAL_TOKEN_RE.search(target)):
                continue
            seen.add(span)
            yield {
                "start": match.start(),
                "end": match.end(),
                "target": target[:120],
            }


def _has_pre_call_guard(header_prefix: str, body_text: str, offset: int) -> bool:
    return bool(_GUARD_RE.search(header_prefix + "\n" + body_text[:offset]))


def _has_pre_call_finalization(pre_writes: list[dict]) -> bool:
    for write in pre_writes:
        target = write["target"]
        if _PRE_FINAL_MARKER_RE.search(target) and not _PENDING_MARKER_RE.search(target):
            return True
    return False


def _first_risky_pair(body_text: str, header_prefix: str):
    writes = sorted(_iter_state_writes(body_text), key=lambda item: item["start"])
    if not writes:
        return None

    for boundary in _EXTERNAL_BOUNDARY_RE.finditer(body_text):
        boundary_text = boundary.group(0)
        if _LOCAL_HELPER_CONTEXT_RE.search(boundary_text):
            continue
        if _has_pre_call_guard(header_prefix, body_text, boundary.start()):
            continue

        pre_writes = [item for item in writes if item["end"] <= boundary.start()]
        post_writes = [item for item in writes if item["start"] >= boundary.end()]
        if not pre_writes or not post_writes:
            continue
        if _has_pre_call_finalization(pre_writes):
            continue

        pre_midstate = None
        for item in reversed(pre_writes):
            if _MIDSTATE_TOKEN_RE.search(item["target"]):
                pre_midstate = item
                break
        if pre_midstate is None:
            continue

        post_final = None
        for item in post_writes:
            if _POST_FINAL_TOKEN_RE.search(item["target"]):
                post_final = item
                break
        if post_final is None:
            continue

        return boundary, pre_midstate, post_final
    return None


def run(tree, source: bytes, filepath: str):
    hits = []
    source_text = source.decode("utf-8", errors="replace")

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        raw_body = text_of(body, source)
        body_text = _mask_comments_keep_lines(raw_body)
        if _EXTERNAL_BOUNDARY_RE.search(body_text) is None:
            continue

        header_prefix = _mask_comments_keep_lines(
            source_text[max(0, fn.start_byte - 300):fn.start_byte]
        )
        result = _first_risky_pair(body_text, header_prefix)
        if result is None:
            continue

        boundary, pre_write, post_write = result
        body_line, _ = line_col(body)
        call_line = _line_for_offset(body_line, raw_body, boundary.start())
        pre_line = _line_for_offset(body_line, raw_body, pre_write["start"])
        post_line = _line_for_offset(body_line, raw_body, post_write["start"])
        name = fn_name(fn, source)

        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "high",
                "line": call_line,
                "col": 0,
                "snippet": snippet_of(body, source),
                "message": (
                    f"fn `{name}` writes mid-operation state "
                    f"`{pre_write['target']}` at line {pre_line}, then "
                    f"transfers control externally at line {call_line} before "
                    f"settlement or balance finalization `{post_write['target']}` "
                    f"at line {post_line}. Add a shared reentrancy guard or "
                    f"finalize settlement state before the callback. "
                    f"NOT_SUBMIT_READY: validate source existence and real "
                    f"entrypoint evidence before use."
                ),
            }
        )

    return hits
