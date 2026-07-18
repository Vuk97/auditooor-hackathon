"""
callback_balance_diff_or_cross_pool_reentrancy_fire19.py

Rust same-class lift for reentrancy-cross-contract misses where callbacks,
hooks, liquidation transfers, or token receive paths happen before the state
that constrains the amount or pool is finalized.

This detector intentionally joins three R94 recall misses:
- ERC777-style balance-diff amount inference across a token callback.
- Hook-enabled liquidity paths that guard the hub but not the pool manager.
- Liquidation / debt takeover transfers that execute with no reentrancy guard.
"""

from __future__ import annotations

import re

from _util import (
    fn_body,
    fn_name,
    functions_in_contractimpl,
    is_pub,
    line_col,
    snippet_of,
    text_of,
)


DETECTOR_ID = "rust_wave1.callback_balance_diff_or_cross_pool_reentrancy_fire19"

_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

_EXTERNAL_CALL_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"\b(?:token_receive|receive_token|tokens_received|call_contract|"
    r"invoke_contract|try_invoke_contract|invoke_signed|invoke|"
    r"call_hook|execute_hook|dispatch_hook|external_call)\s*\(|"
    r"\b[A-Za-z_][A-Za-z0-9_\.]*\s*\.\s*"
    r"(?:transfer|transfer_from|safe_transfer|safe_transfer_from|send|"
    r"call|invoke|notify|callback|on_[A-Za-z0-9_]+|before_[A-Za-z0-9_]+|"
    r"after_[A-Za-z0-9_]+|receive_[A-Za-z0-9_]*|handle_[A-Za-z0-9_]*)\s*\("
    r")"
)

_HOOK_CALL_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"\b[A-Za-z_][A-Za-z0-9_\.]*\s*\.\s*"
    r"(?:before_[A-Za-z0-9_]+|after_[A-Za-z0-9_]+|on_[A-Za-z0-9_]+|"
    r"hook|callback|notify)\s*\(|"
    r"\b(?:call_hook|execute_hook|dispatch_hook)\s*\(|"
    r"\bhook_data\b"
    r")"
)

_DIRECT_POOL_RE = re.compile(
    r"(?ix)"
    r"\b(?:pool_manager|raw_pool_manager|v4_pool_manager|pool|other_pool|"
    r"target_pool)\s*\.\s*"
    r"(?:swap|unlock|modify_liquidity|add_liquidity|remove_liquidity|"
    r"borrow|repay|settle|withdraw)\s*\("
)

_GUARD_RE = re.compile(
    r"(?i)"
    r"(#\[\s*non_reentrant\s*\]|non_reentrant|nonReentrant|ReentrancyGuard|"
    r"reentrancy_guard|reentrancy_lock|enter_reentrancy_guard|"
    r"enter_hub_guard|guard_enter|guard\.enter|locked\s*=\s*true|"
    r"entered\s*=\s*true|in_reentrancy\s*=\s*true)"
)

_POOL_SCOPED_GUARD_RE = re.compile(
    r"(?i)"
    r"(cross_pool_guard|pool_manager_guard|global_reentrancy_guard|"
    r"enter_pool_manager_guard|lock_pool_manager|guard_pool_manager|"
    r"pool_scoped_guard|pool_key_guard)"
)

_BALANCE_SNAPSHOT_RE = re.compile(
    r"(?is)"
    r"\b(?:let\s+)?"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*(?:before|pre|initial|start|prev)"
    r"[A-Za-z0-9_]*|(?:before|pre|initial|start|prev)[A-Za-z0-9_]*"
    r"(?:balance|bal|amount|assets|reserve))"
    r"\s*(?::[^=;]+)?=\s*[^;]{0,160}?"
    r"(?:balance_of|token_balance|get_balance|vault_balance|balance)\s*\("
)

_BALANCE_DIFF_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"(?:balance_of|token_balance|get_balance|vault_balance|balance)\s*"
    r"\([^;]{0,160}\)\s*-\s*[A-Za-z_][A-Za-z0-9_]*|"
    r"[A-Za-z_][A-Za-z0-9_]*\s*-\s*[A-Za-z_][A-Za-z0-9_]*|"
    r"[A-Za-z_][A-Za-z0-9_]*\s*\.\s*saturating_sub\s*\("
    r"\s*[A-Za-z_][A-Za-z0-9_]*\s*\)"
    r")"
)

_AMOUNT_USE_RE = re.compile(
    r"(?i)"
    r"(received|actual_received|credited|amount_received|mint|shares|credit|"
    r"bridge|deposit|lock|supply|reserve|balance)"
)

_ACCOUNTING_EVENT_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"\b(?:self|state|ledger|vault|market|position|positions|pool|pools|"
    r"reserve|reserves|debt|debts|collateral|balance|balances|share|shares|"
    r"accounting|liquidity|status|pending|processed|settled|finalized)"
    r"[A-Za-z0-9_\.\[\]]*\s*(?:\+=|-=|=)|"
    r"\b[A-Za-z_][A-Za-z0-9_\.]*"
    r"(?:balances|reserves|positions|debts|collateral|accounting|status)"
    r"[A-Za-z0-9_\.\[\]]*\s*(?:\+=|-=|=)|"
    r"\b[A-Za-z_][A-Za-z0-9_\.]*\s*\.\s*"
    r"(?:insert|set|update|remove|save)\s*\(|"
    r"\b(?:record|finalize|finalise|settle|mark|commit|complete|update|"
    r"sync|store)_(?:deposit|receipt|accounting|balance|reserve|debt|"
    r"collateral|position|liquidation|liquidated|pool|shares|status)\s*\("
    r")"
)

_PRECOMMIT_RE = re.compile(
    r"(?i)"
    r"(pending|in_progress|processing|guard|locked|entered|liquidating|"
    r"processed|settled|finalized|finalised|complete|reserved)"
)

_LIQUIDATION_NAME_RE = re.compile(
    r"(?i)(liquidate|liquidation|take_?over_?debt|seize|close_position)"
)


def _mask_comments_keep_lines(text: str) -> str:
    text = _LINE_COMMENT_RE.sub(lambda match: " " * (match.end() - match.start()), text)

    def _block_repl(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group(0))

    return _BLOCK_COMMENT_RE.sub(_block_repl, text)


def _line_for_offset(base_line: int, text: str, offset: int) -> int:
    return base_line + text[:offset].count("\n")


def _has_guard_before(header_prefix: str, body_text: str, offset: int) -> bool:
    return bool(_GUARD_RE.search(header_prefix + "\n" + body_text[:offset]))


def _header_prefix_for(source_text: str, fn_start_byte: int) -> str:
    window_start = max(0, fn_start_byte - 240)
    window = source_text[window_start:fn_start_byte]
    split_at = window.rfind("\n\n")
    if split_at >= 0:
        return window[split_at:]
    return window


def _has_pool_scoped_guard_before(body_text: str, offset: int) -> bool:
    return bool(_POOL_SCOPED_GUARD_RE.search(body_text[:offset]))


def _iter_accounting_events(body_text: str):
    for match in _ACCOUNTING_EVENT_RE.finditer(body_text):
        line_start = body_text.rfind("\n", 0, match.start()) + 1
        prefix = body_text[line_start:match.start()]
        if re.search(r"\blet\b", prefix):
            continue
        yield {
            "start": match.start(),
            "end": match.end(),
            "target": " ".join(match.group(0).split())[:96],
        }


def _first_external_between(events, start: int, end: int):
    for event in events:
        if event.start() >= start and event.end() <= end:
            return event
    return None


def _diff_uses_snapshot(diff_text: str, snapshot_var: str) -> bool:
    if snapshot_var in diff_text:
        return True
    return bool(re.search(r"(?i)(before|pre|initial|start|prev)", diff_text))


def _emit_hit(hits: list[dict], fn, source: bytes, body, raw_body: str, offset: int, message: str) -> None:
    body_line, _ = line_col(body)
    hits.append(
        {
            "detector_id": DETECTOR_ID,
            "severity": "high",
            "line": _line_for_offset(body_line, raw_body, offset),
            "col": 0,
            "snippet": snippet_of(fn, source),
            "message": message,
        }
    )


def _try_balance_diff_hit(hits: list[dict], fn, source: bytes, body, raw_body: str, body_text: str, header_prefix: str) -> bool:
    external_calls = list(_EXTERNAL_CALL_RE.finditer(body_text))
    if not external_calls:
        return False

    snapshots = list(_BALANCE_SNAPSHOT_RE.finditer(body_text))
    if not snapshots:
        return False

    for snapshot in snapshots:
        snapshot_var = snapshot.group("var")
        for diff in _BALANCE_DIFF_RE.finditer(body_text, snapshot.end()):
            diff_text = diff.group(0)
            if not _diff_uses_snapshot(diff_text, snapshot_var):
                continue
            if not _AMOUNT_USE_RE.search(body_text[max(0, diff.start() - 120):diff.end() + 160]):
                continue
            external = _first_external_between(external_calls, snapshot.end(), diff.start())
            if external is None:
                continue
            if _has_guard_before(header_prefix, body_text, external.start()):
                continue
            name = fn_name(fn, source)
            call_line = _line_for_offset(line_col(body)[0], raw_body, external.start())
            diff_line = _line_for_offset(line_col(body)[0], raw_body, diff.start())
            _emit_hit(
                hits,
                fn,
                source,
                body,
                raw_body,
                external.start(),
                (
                    f"fn `{name}` performs balance-diff amount inference across "
                    f"an unguarded callback at line {call_line}; the diff using "
                    f"`{snapshot_var}` is finalized only at line {diff_line}."
                ),
            )
            return True
    return False


def _try_cross_pool_hook_hit(hits: list[dict], fn, source: bytes, body, raw_body: str, body_text: str) -> bool:
    hooks = list(_HOOK_CALL_RE.finditer(body_text))
    if not hooks:
        return False
    pool_calls = list(_DIRECT_POOL_RE.finditer(body_text))
    if not pool_calls:
        return False

    for hook in hooks:
        later_pool = next((pool for pool in pool_calls if pool.start() > hook.end()), None)
        if later_pool is None:
            continue
        if _has_pool_scoped_guard_before(body_text, hook.start()):
            continue
        name = fn_name(fn, source)
        hook_line = _line_for_offset(line_col(body)[0], raw_body, hook.start())
        pool_line = _line_for_offset(line_col(body)[0], raw_body, later_pool.start())
        _emit_hit(
            hits,
            fn,
            source,
            body,
            raw_body,
            hook.start(),
            (
                f"fn `{name}` invokes a caller hook at line {hook_line} before "
                f"a direct pool-manager path at line {pool_line}; no "
                f"pool-scoped reentrancy guard is visible before the hook."
            ),
        )
        return True
    return False


def _try_liquidation_guard_hit(hits: list[dict], fn, source: bytes, body, raw_body: str, body_text: str, header_prefix: str) -> bool:
    name = fn_name(fn, source)
    if not _LIQUIDATION_NAME_RE.search(name):
        return False
    for external in _EXTERNAL_CALL_RE.finditer(body_text):
        if _has_guard_before(header_prefix, body_text, external.start()):
            continue
        _emit_hit(
            hits,
            fn,
            source,
            body,
            raw_body,
            external.start(),
            (
                f"fn `{name}` executes liquidation or debt takeover external "
                f"transfer/callback logic without a visible pre-call "
                f"reentrancy guard."
            ),
        )
        return True
    return False


def _try_external_before_accounting_hit(hits: list[dict], fn, source: bytes, body, raw_body: str, body_text: str, header_prefix: str) -> bool:
    accounting_events = sorted(_iter_accounting_events(body_text), key=lambda event: event["start"])
    if not accounting_events:
        return False

    name = fn_name(fn, source)
    for external in _EXTERNAL_CALL_RE.finditer(body_text):
        if _has_guard_before(header_prefix, body_text, external.start()):
            continue
        pre_events = [event for event in accounting_events if event["end"] <= external.start()]
        if pre_events and any(_PRECOMMIT_RE.search(event["target"]) for event in pre_events):
            continue
        post_events = [event for event in accounting_events if event["start"] >= external.end()]
        if not post_events:
            continue
        if pre_events:
            continue
        post_event = post_events[0]
        call_line = _line_for_offset(line_col(body)[0], raw_body, external.start())
        post_line = _line_for_offset(line_col(body)[0], raw_body, post_event["start"])
        _emit_hit(
            hits,
            fn,
            source,
            body,
            raw_body,
            external.start(),
            (
                f"fn `{name}` transfers control externally at line "
                f"{call_line} before final accounting `{post_event['target']}` "
                f"at line {post_line}; no pre-call guard is visible."
            ),
        )
        return True
    return False


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    source_text = source.decode("utf-8", errors="replace")

    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue

        raw_body = text_of(body, source)
        body_text = _mask_comments_keep_lines(raw_body)
        header_prefix = _mask_comments_keep_lines(_header_prefix_for(source_text, fn.start_byte))

        if _try_balance_diff_hit(hits, fn, source, body, raw_body, body_text, header_prefix):
            continue
        if _try_cross_pool_hook_hit(hits, fn, source, body, raw_body, body_text):
            continue
        if _try_liquidation_guard_hit(hits, fn, source, body, raw_body, body_text, header_prefix):
            continue
        _try_external_before_accounting_hit(hits, fn, source, body, raw_body, body_text, header_prefix)

    return hits
