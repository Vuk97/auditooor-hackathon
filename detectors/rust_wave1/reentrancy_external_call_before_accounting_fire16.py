"""
reentrancy_external_call_before_accounting_fire16.py

Rust companion detector for the reentrancy-cross-contract same-class recall
gap in fire16. It joins three closely related shapes that were previously
split across narrow detectors:

  1. External callback, CPI, or contract call before critical accounting is
     finalized.
  2. Accounting-sensitive state write immediately exposed to an external
     interaction without a guard.
  3. Curve-style virtual-price oracle reads without a read-only reentrancy
     probe or lock check.

The detector stays scoped by requiring accounting-family tokens, an external
control-transfer primitive, and no pre-call reentrancy guard. Plain external
forwarding without accounting state is ignored.
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


DETECTOR_ID = "rust_wave1.reentrancy_external_call_before_accounting_fire16"

_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

_EXTERNAL_CALL_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"\benv\s*\.\s*(?:try_)?invoke_contract(?:\s*::\s*<[^>]+>)?\s*\(|"
    r"\b(?:try_)?invoke_contract\s*\(|"
    r"\bcall_contract\s*\(|"
    r"\b[A-Za-z_][A-Za-z0-9_]*Client\s*::\s*new\s*\(|"
    r"\b::Client\s*::\s*new\s*\(|"
    r"\binvoke_signed\s*\(|"
    r"\bprogram::invoke_signed\s*\(|"
    r"\binvoke\s*\(|"
    r"\bprogram::invoke\s*\(|"
    r"\banchor_spl::token::[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"\btoken::(?:transfer|transfer_checked|mint_to|burn)\s*\(|"
    r"\bcpi::[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"\bCpiContext\s*::\s*new\b|"
    r"\b(?:transfer|send|payout|refund)\s*\(|"
    r"\b[A-Za-z_][A-Za-z0-9_\.]*\s*\.\s*"
    r"(?:before_[A-Za-z0-9_]+|after_[A-Za-z0-9_]+|on_[A-Za-z0-9_]+|"
    r"callback|call_contract|invoke|notify|receive_[A-Za-z0-9_]*|"
    r"handle_[A-Za-z0-9_]*|safe_transfer_from|safeTransferFrom|"
    r"transfer_from|transfer|send|execute_[A-Za-z0-9_]*)\s*\("
    r")"
)

_STATE_ASSIGN_RE = re.compile(
    r"(?P<target>"
    r"(?:self|state|ledger|vault|market|position|positions|pending|claim|"
    r"claims|balance|balances|reserve|reserves|reward|rewards|order|orders|"
    r"escrow|nonce|status|settlement|accounting|ctx(?:\.accounts)?|account)"
    r"[A-Za-z0-9_\.\[\]]*"
    r"|[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z0-9_\.\[\]]+"
    r")"
    r"\s*(?:\+=|-=|\*=|/=|=)"
)

_STATE_MUT_CALL_RE = re.compile(
    r"(?P<target>"
    r"(?:self|state|ledger|vault|market|position|positions|pending|claim|"
    r"claims|balance|balances|reserve|reserves|reward|rewards|order|orders|"
    r"escrow|nonce|status|settlement|accounting|ctx(?:\.accounts)?|account)"
    r"[A-Za-z0-9_\.\[\]]*"
    r"|[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z0-9_\.\[\]]+"
    r")"
    r"\s*\.\s*(?:insert|push|push_back|set|update|remove|write|save)\s*\("
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

_FINALIZER_CALL_RE = re.compile(
    r"(?ix)"
    r"\b"
    r"(?P<target>"
    r"(?:finalize|finalise|settle|record|store|save|bump|increment|mark|"
    r"clear|commit|complete|open|burn|update|sync|set)"
    r"_"
    r"(?:accounting|account|accounts|reward|rewards|share|shares|balance|"
    r"balances|nonce|guard|claim|claimed|reserve|reserves|position|"
    r"positions|order|orders|supply|assets|debt|collateral|status|pending|"
    r"processed|settled|finalized|finalised|withdrawal|redemption)"
    r")"
    r"\s*\("
)

_ACCOUNTING_TOKEN_RE = re.compile(
    r"(?i)"
    r"(accounting|share|shares|balance|balances|nonce|guard|locked|entered|"
    r"in_progress|processing|claim|claimed|reserve|reserves|reward|rewards|"
    r"debt|collateral|position|positions|order|orders|supply|assets|status|"
    r"pending|processed|settled|finalized|finalised|complete|completed|"
    r"withdraw|withdrawal|redeem|redemption|escrow|liquidity|amount|value|"
    r"total)"
)

_STRONG_ACCOUNTING_TOKEN_RE = re.compile(
    r"(?i)"
    r"(accounting|share|shares|balance|balances|nonce|guard|locked|entered|"
    r"in_progress|processing|claim|claimed|reserve|reserves|reward|rewards|"
    r"debt|collateral|position|positions|order|orders|supply|assets|status|"
    r"pending|processed|settled|finalized|finalised|complete|completed|"
    r"withdraw|withdrawal|redeem|redemption|escrow|liquidity|total)"
)

_TRANSFER_OR_CALLBACK_RE = re.compile(
    r"(?i)"
    r"(transfer|send|payout|refund|withdraw|redeem|callback|hook|notify|"
    r"invoke|cpi|execute|settle|safe_transfer)"
)

_GUARD_RE = re.compile(
    r"(?i)"
    r"(#\[\s*non_reentrant\s*\]|non_reentrant|nonReentrant|ReentrancyGuard|"
    r"reentrancy_guard|reentrancy_lock|cpi_guard|check_and_set|is_entered|"
    r"guard_entered|enter_guard|guard\.enter|acquire_reentrancy|"
    r"_status\s*=\s*ENTERED|locked\s*=\s*true|entered\s*=\s*true|"
    r"in_reentrancy\s*=\s*true)"
)

_PRICE_FN_RE = re.compile(
    r"(?i)(get_price|price|latest_price|lp_price|compute_lp_value|fetch_lp_price)"
)

_VP_CALL_RE = re.compile(
    r"(?i)(get_virtual_price|getVirtualPrice|virtual_price\s*\(\s*\)|virtualPrice\s*\(\s*\))"
)

_READONLY_GUARD_RE = re.compile(
    r"(?i)"
    r"(remove_liquidity\s*\(\s*0\s*,|removeLiquidity\s*\(\s*0\s*,|"
    r"claim_admin_fees|reentrancy_check|read_only_reentrancy_guard|"
    r"readOnlyReentrancyGuard|check_curve_pool_not_entered|curve_pool_lock_state)"
)

_TOKEN_STOPWORDS = {
    "self",
    "state",
    "ctx",
    "accounts",
    "account",
    "env",
    "storage",
    "data",
    "mut",
    "let",
    "total",
}


def _mask_comments_keep_lines(text: str) -> str:
    text = _LINE_COMMENT_RE.sub(lambda match: " " * (match.end() - match.start()), text)

    def _block_repl(match: re.Match[str]) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in match.group(0))

    return _BLOCK_COMMENT_RE.sub(_block_repl, text)


def _line_for_offset(base_line: int, text: str, offset: int) -> int:
    return base_line + text[:offset].count("\n")


def _target_tokens(target: str) -> set[str]:
    tokens: set[str] = set()
    for part in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", target):
        lowered = part.lower()
        tokens.add(lowered)
        for subpart in lowered.split("_"):
            if subpart:
                tokens.add(subpart)
    return {token for token in tokens if token not in _TOKEN_STOPWORDS}


def _targets_related(left: str, right: str) -> bool:
    return bool(_target_tokens(left) & _target_tokens(right))


def _iter_accounting_events(body_text: str):
    seen: set[tuple[int, int]] = set()
    for regex in (
        _STATE_ASSIGN_RE,
        _STATE_MUT_CALL_RE,
        _STORAGE_WRITE_RE,
        _FINALIZER_CALL_RE,
    ):
        for match in regex.finditer(body_text):
            span = match.span()
            if span in seen:
                continue
            line_start = body_text.rfind("\n", 0, match.start()) + 1
            line_prefix = body_text[line_start:match.start()]
            if regex is _STATE_ASSIGN_RE and re.search(r"\blet\b", line_prefix):
                continue
            target = match.groupdict().get("target") or match.group(0)
            if not _ACCOUNTING_TOKEN_RE.search(target):
                continue
            seen.add(span)
            yield {
                "start": match.start(),
                "end": match.end(),
                "target": " ".join(target.split())[:96],
            }


def _has_guard_before(header_prefix: str, body_text: str, offset: int) -> bool:
    return bool(_GUARD_RE.search(header_prefix + "\n" + body_text[:offset]))


def _is_money_or_callback_call(call_text: str, fn_name_text: str) -> bool:
    return bool(
        _TRANSFER_OR_CALLBACK_RE.search(call_text)
        or _TRANSFER_OR_CALLBACK_RE.search(fn_name_text)
    )


def _find_related_pre_post(pre_events: list[dict], post_events: list[dict]):
    for pre_event in reversed(pre_events):
        for post_event in post_events:
            if _targets_related(pre_event["target"], post_event["target"]):
                return pre_event, post_event
    return None


def _emit_readonly_oracle_hit(hits: list[dict], fn, source: bytes, raw_body: str, body_text: str) -> bool:
    name = fn_name(fn, source)
    if not _PRICE_FN_RE.search(name):
        return False
    vp_call = _VP_CALL_RE.search(body_text)
    if vp_call is None:
        return False
    if _READONLY_GUARD_RE.search(body_text[:vp_call.start()]):
        return False

    body = fn_body(fn)
    if body is None:
        return False
    body_line, _ = line_col(body)
    call_line = _line_for_offset(body_line, raw_body, vp_call.start())
    hits.append(
        {
            "detector_id": DETECTOR_ID,
            "severity": "high",
            "line": call_line,
            "col": 0,
            "snippet": snippet_of(fn, source),
            "message": (
                f"fn `{name}` reads Curve virtual price at line {call_line} "
                f"without a read-only reentrancy probe or lock-state check."
            ),
        }
    )
    return True


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
        header_prefix = _mask_comments_keep_lines(source_text[max(0, fn.start_byte - 300):fn.start_byte])
        name = fn_name(fn, source)

        if _emit_readonly_oracle_hit(hits, fn, source, raw_body, body_text):
            continue

        external_calls = list(_EXTERNAL_CALL_RE.finditer(body_text))
        if not external_calls:
            continue

        accounting_events = sorted(
            _iter_accounting_events(body_text),
            key=lambda event: event["start"],
        )
        if not accounting_events:
            continue

        body_line, _ = line_col(body)

        for call in external_calls:
            if _has_guard_before(header_prefix, body_text, call.start()):
                continue

            call_text = call.group(0)
            if not _is_money_or_callback_call(call_text, name):
                continue

            pre_events = [event for event in accounting_events if event["end"] <= call.start()]
            post_events = [event for event in accounting_events if event["start"] >= call.end()]
            call_line = _line_for_offset(body_line, raw_body, call.start())

            related_pair = _find_related_pre_post(pre_events, post_events)
            if related_pair is not None:
                pre_event, post_event = related_pair
                post_line = _line_for_offset(body_line, raw_body, post_event["start"])
                hits.append(
                    {
                        "detector_id": DETECTOR_ID,
                        "severity": "high",
                        "line": call_line,
                        "col": 0,
                        "snippet": snippet_of(body, source),
                        "message": (
                            f"fn `{name}` exposes partially finalized "
                            f"accounting `{pre_event['target']}` across an "
                            f"external interaction at line {call_line}; related "
                            f"state `{post_event['target']}` is finalized only "
                            f"at line {post_line}."
                        ),
                    }
                )
                break

            if post_events and not pre_events:
                post_event = post_events[0]
                if not _STRONG_ACCOUNTING_TOKEN_RE.search(post_event["target"]):
                    continue
                post_line = _line_for_offset(body_line, raw_body, post_event["start"])
                hits.append(
                    {
                        "detector_id": DETECTOR_ID,
                        "severity": "high",
                        "line": call_line,
                        "col": 0,
                        "snippet": snippet_of(body, source),
                        "message": (
                            f"fn `{name}` transfers control externally at line "
                            f"{call_line} before finalizing accounting state "
                            f"`{post_event['target']}` at line {post_line}."
                        ),
                    }
                )
                break

            if pre_events and not post_events:
                pre_event = pre_events[-1]
                pre_line = _line_for_offset(body_line, raw_body, pre_event["start"])
                hits.append(
                    {
                        "detector_id": DETECTOR_ID,
                        "severity": "high",
                        "line": call_line,
                        "col": 0,
                        "snippet": snippet_of(body, source),
                        "message": (
                            f"fn `{name}` writes accounting state "
                            f"`{pre_event['target']}` at line {pre_line} before "
                            f"an unguarded external interaction at line "
                            f"{call_line}."
                        ),
                    }
                )
                break

    return hits
