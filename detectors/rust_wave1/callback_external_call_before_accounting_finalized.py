"""
callback_external_call_before_accounting_finalized.py

Flags Rust functions that perform an external callback, CPI, or contract call
before finalizing accounting-critical state such as shares, balances, nonces,
claims, reserves, or reentrancy guard state.

This is the interaction-before-final-accounting sibling of:
  - cei_violation_external_call_after_state
  - cross_contract_partial_state_finalization_reentrancy

It deliberately requires a critical state finalization after the external
interaction, so plain external forwarding is not flagged. Functions with an
active reentrancy guard before the interaction are suppressed.
"""

from __future__ import annotations

import re

from _util import function_items, fn_body, fn_name, in_test_cfg, line_col, snippet_of, text_of


DETECTOR_ID = "rust_wave1.callback_external_call_before_accounting_finalized"

_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

_EXTERNAL_CALL_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"env\s*\.\s*(?:try_)?invoke_contract(?:\s*::\s*<[^>]+>)?\s*\(|"
    r"(?:try_)?invoke_contract\s*\(|"
    r"call_contract\s*\(|"
    r"[A-Za-z_][A-Za-z0-9_]*Client\s*::\s*new\s*\(|"
    r"::Client\s*::\s*new\s*\(|"
    r"invoke_signed\s*\(|"
    r"program::invoke_signed\s*\(|"
    r"invoke\s*\(|"
    r"program::invoke\s*\(|"
    r"anchor_spl::token::[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"token::(?:transfer|transfer_checked|mint_to|burn)\s*\(|"
    r"cpi::[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"CpiContext\s*::\s*new\b|"
    r"[A-Za-z_][A-Za-z0-9_\.]*\s*\.\s*"
    r"(?:transfer|transfer_from|safe_transfer_from|safeTransferFrom|send|"
    r"receive_royalty|callback|call_contract)\s*\("
    r")"
)

_STATE_ASSIGN_RE = re.compile(
    r"(?P<target>[A-Za-z_][A-Za-z0-9_\.\[\]]*)"
    r"\s*(?:\+=|-=|\*=|/=|=)"
)

_STATE_MUT_CALL_RE = re.compile(
    r"(?P<target>[A-Za-z_][A-Za-z0-9_\.\[\]]*)"
    r"\s*\.\s*(?:insert|push|push_back|set|update|remove|write)\s*\("
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
    r"(?:update|sync|finalize|finalise|settle|record|store|save|bump|"
    r"increment|mark|clear|write)"
    r"_"
    r"(?:accounting|account|accounts|reward|rewards|share|shares|balance|"
    r"balances|nonce|guard|claim|claimed|reserve|reserves|position|"
    r"positions|order|orders|supply|assets|debt|collateral|status)"
    r"\s*\("
)

_CRITICAL_TOKEN_RE = re.compile(
    r"(?i)"
    r"(accounting|share|shares|balance|balances|nonce|guard|locked|entered|"
    r"claim|claimed|reserve|reserves|reward|rewards|debt|collateral|"
    r"position|positions|order|orders|supply|assets|status|pending|"
    r"processed|settled|finalized|finalised|total)"
)

_GUARD_RE = re.compile(
    r"(?i)"
    r"(#\[\s*non_reentrant\s*\]|non_reentrant|nonReentrant|ReentrancyGuard|"
    r"reentrancy_guard|reentrancy_lock|cpi_guard|check_and_set|is_entered|"
    r"guard_entered|enter_guard|guard\.enter|acquire_reentrancy|"
    r"_status\s*=\s*ENTERED|locked\s*=\s*true|entered\s*=\s*true|"
    r"in_reentrancy\s*=\s*true)"
)


def _mask_comments_keep_lines(text: str) -> str:
    text = _LINE_COMMENT_RE.sub(lambda match: " " * (match.end() - match.start()), text)

    def _block_repl(match: re.Match[str]) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in match.group(0))

    return _BLOCK_COMMENT_RE.sub(_block_repl, text)


def _line_for_offset(base_line: int, text: str, offset: int) -> int:
    return base_line + text[:offset].count("\n")


def _iter_finalization_events(body_text: str):
    seen: set[tuple[int, int]] = set()
    for regex in (_STATE_ASSIGN_RE, _STATE_MUT_CALL_RE, _STORAGE_WRITE_RE, _FINALIZER_CALL_RE):
        for match in regex.finditer(body_text):
            span = match.span()
            if span in seen:
                continue
            line_start = body_text.rfind("\n", 0, match.start()) + 1
            line_prefix = body_text[line_start:match.start()]
            if regex is _STATE_ASSIGN_RE and re.search(r"\blet\b", line_prefix):
                continue
            target = match.groupdict().get("target") or match.group(0)
            if not _CRITICAL_TOKEN_RE.search(target):
                continue
            seen.add(span)
            yield {
                "start": match.start(),
                "end": match.end(),
                "target": " ".join(target.split())[:96],
            }


def run(tree, source: bytes, filepath: str):
    hits = []
    source_text = source.decode("utf-8", errors="replace")

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue

        raw_body = text_of(body, source)
        body_text = _mask_comments_keep_lines(raw_body)
        header_prefix = _mask_comments_keep_lines(source_text[max(0, fn.start_byte - 300):fn.start_byte])

        external_calls = list(_EXTERNAL_CALL_RE.finditer(body_text))
        if not external_calls:
            continue

        finalizations = sorted(
            _iter_finalization_events(body_text),
            key=lambda event: event["start"],
        )
        if not finalizations:
            continue

        body_line, _ = line_col(body)
        name = fn_name(fn, source)

        for call in external_calls:
            guard_region = header_prefix + "\n" + body_text[:call.start()]
            if _GUARD_RE.search(guard_region):
                continue

            post_events = [event for event in finalizations if event["start"] >= call.end()]
            if not post_events:
                continue

            finalization = post_events[0]
            call_line = _line_for_offset(body_line, raw_body, call.start())
            finalization_line = _line_for_offset(body_line, raw_body, finalization["start"])

            hits.append(
                {
                    "detector_id": DETECTOR_ID,
                    "severity": "high",
                    "line": call_line,
                    "col": 0,
                    "snippet": snippet_of(body, source),
                    "message": (
                        f"fn `{name}` performs an external interaction at line "
                        f"{call_line} before finalizing critical accounting state "
                        f"`{finalization['target']}` at line {finalization_line}, "
                        f"with no reentrancy guard active before the call."
                    ),
                }
            )
            break

    return hits
