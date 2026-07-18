"""
callback_before_state_finalization_fire7.py

Flags Rust functions that transfer control to an external callback, CPI, hook,
or contract call before the first local write that finalizes operation state.

Fire7 source anchors:
- reference/patterns.dsl/external-call-before-state-finalization-reentrancy.yaml
- reference/patterns.dsl/callback-before-accounting-finalized-cross-contract.yaml
- audit/corpus_tags/tags/solodit-spec:62592:453fbdca57f0-453fbdca57f0.yaml
- audit/corpus_tags/tags/solodit-spec:35121:0211c976b83a-0211c976b83a.yaml

This is narrower than callback_external_call_before_accounting_finalized:
it suppresses functions that already set a critical pending, in-progress,
guard, or finalization marker before the external interaction. The detector is
for the "callback before first state finalization" shape, not generic CEI.
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


DETECTOR_ID = "rust_wave1.callback_before_state_finalization_fire7"

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
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*"
    r"(?:before_[A-Za-z0-9_]+|after_[A-Za-z0-9_]+|on_[A-Za-z0-9_]+|"
    r"callback|call_contract|invoke|notify|receive_[A-Za-z0-9_]*|"
    r"handle_[A-Za-z0-9_]*|safe_transfer_from|safeTransferFrom|"
    r"transfer_from|send|execute_[A-Za-z0-9_]*)\s*\("
    r")"
)

_CRITICAL_TOKEN_RE = re.compile(
    r"(?i)"
    r"(accounting|share|shares|balance|balances|nonce|guard|locked|entered|"
    r"in_progress|processing|claim|claimed|reserve|reserves|reward|rewards|"
    r"debt|collateral|position|positions|order|orders|supply|assets|status|"
    r"pending|processed|settled|finalized|finalised|complete|completed|"
    r"opened|burned|burnt|total|withdraw|withdrawal|redeem|redemption)"
)

_FINALIZATION_ASSIGN_RE = re.compile(
    r"(?P<target>"
    r"(?:self|state|ledger|vault|market|position|positions|pending|claim|"
    r"claims|balance|balances|reserve|reserves|reward|rewards|order|orders|"
    r"escrow|nonce|status|settlement|accounting|ctx(?:\.accounts)?|account)"
    r"[A-Za-z0-9_\.\[\]]*"
    r"|[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z0-9_\.\[\]]+"
    r")"
    r"\s*(?:\+=|-=|\*=|/=|=)"
)

_FINALIZATION_MUT_CALL_RE = re.compile(
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

_GUARD_RE = re.compile(
    r"(?i)"
    r"(#\[\s*non_reentrant\s*\]|non_reentrant|nonReentrant|ReentrancyGuard|"
    r"reentrancy_guard|reentrancy_lock|cpi_guard|check_and_set|is_entered|"
    r"guard_entered|enter_guard|guard\.enter|acquire_reentrancy|"
    r"_status\s*=\s*ENTERED|locked\s*=\s*true|entered\s*=\s*true|"
    r"in_reentrancy\s*=\s*true)"
)

_PRECOMMIT_MARKER_RE = re.compile(
    r"(?i)"
    r"(pending|in_progress|processing|entered|locked|guard|started|opened|"
    r"reserved|claimed|settled|processed|finalized|finalised|complete)"
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
    for regex in (
        _FINALIZATION_ASSIGN_RE,
        _FINALIZATION_MUT_CALL_RE,
        _STORAGE_WRITE_RE,
        _FINALIZER_CALL_RE,
    ):
        for match in regex.finditer(body_text):
            span = match.span()
            if span in seen:
                continue
            line_start = body_text.rfind("\n", 0, match.start()) + 1
            line_prefix = body_text[line_start:match.start()]
            if regex is _FINALIZATION_ASSIGN_RE and re.search(r"\blet\b", line_prefix):
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


def _has_pre_call_commit(pre_events: list[dict]) -> bool:
    if not pre_events:
        return False
    return any(_PRECOMMIT_MARKER_RE.search(event["target"]) for event in pre_events) or bool(pre_events)


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

            pre_events = [event for event in finalizations if event["end"] <= call.start()]
            if _has_pre_call_commit(pre_events):
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
                        f"fn `{name}` transfers control externally at line "
                        f"{call_line} before the first local finalization of "
                        f"critical state `{finalization['target']}` at line "
                        f"{finalization_line}; no pre-call guard or pending "
                        f"marker is visible."
                    ),
                }
            )
            break

    return hits
