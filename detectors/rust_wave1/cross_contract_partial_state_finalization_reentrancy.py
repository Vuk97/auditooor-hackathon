"""
cross_contract_partial_state_finalization_reentrancy.py

Flags functions that partially mutate callback-relevant state, then perform
an external call or CPI, and only finalize the same state family after the
interaction. This is the split-finalization sibling of the broader CEI and
callback-handler reentrancy detectors already in rust_wave1.

Heuristic:
  1. Find a callback-relevant state write before an external interaction.
  2. Find a second callback-relevant state write after that interaction.
  3. Require the pre-call and post-call writes to share a non-trivial state
     family token (for example `pending_*`, `shares`, `position`, `reserve`).
  4. Suppress hits when a reentrancy guard appears before the interaction.

Why this is narrower than generic CEI:
  - plain "write then call" is already covered by
    `cei_violation_external_call_after_state`.
  - this detector only fires when the function exposes a partially-finalized
    state family across the call boundary.
"""

from __future__ import annotations

import re

from _util import function_items, fn_body, fn_name, in_test_cfg, line_col, snippet_of, text_of


_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

_EXTERNAL_CALL_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"env\.invoke_contract(?:\s*::\s*<[^>]+>)?\s*\(|"
    r"try_invoke_contract\s*\(|"
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
    r"safe_transfer_from\s*\(|"
    r"safeTransferFrom\s*\(|"
    r"transfer_from\s*\("
    r")"
)

_STATE_ASSIGN_RE = re.compile(
    r"(?P<target>"
    r"(?:self|state|config|ledger|vault|market|position|positions|pending|"
    r"collateral|reserve|reserves|balance|balances|claims?|debt|debts|"
    r"escrow|liquidity|rewards?|ctx(?:\.accounts)?|account)"
    r"[A-Za-z0-9_\.\[\]]*"
    r"|[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z0-9_\.\[\]]+"
    r")"
    r"\s*(?:\+=|-=|=)"
)

_STATE_MUT_CALL_RE = re.compile(
    r"(?P<target>"
    r"(?:self|state|config|ledger|vault|market|position|positions|pending|"
    r"collateral|reserve|reserves|balance|balances|claims?|debt|debts|"
    r"escrow|liquidity|rewards?|ctx(?:\.accounts)?|account)"
    r"[A-Za-z0-9_\.\[\]]*"
    r"|[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z0-9_\.\[\]]+"
    r")"
    r"\s*\.\s*(?:insert|push|push_back|set|update|remove|write)\s*\("
)

_GUARD_RE = re.compile(
    r"(?i)(non_reentrant|nonReentrant|reentrancy_guard|reentrancy_lock|"
    r"mutex|cpi_guard|check_and_set|is_entered|guard_entered|"
    r"_status\s*=\s*ENTERED|locked\s*=\s*true)"
)

_CALLBACK_STATE_TOKENS = {
    "share",
    "shares",
    "balance",
    "balances",
    "collateral",
    "position",
    "positions",
    "reserve",
    "reserves",
    "pending",
    "claim",
    "claims",
    "debt",
    "debts",
    "supply",
    "locked",
    "lock",
    "escrow",
    "status",
    "liquidity",
    "nonce",
    "reward",
    "rewards",
    "withdraw",
    "withdrawal",
    "redemption",
    "market",
    "skew",
    "notional",
    "interest",
    "allowance",
    "used",
    "processed",
    "settled",
    "index",
    "owner",
    "vault",
}

_TOKEN_STOPWORDS = {
    "self",
    "state",
    "config",
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
    text = _LINE_COMMENT_RE.sub(lambda m: " " * (m.end() - m.start()), text)

    def _block_repl(match: re.Match[str]) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in match.group(0))

    return _BLOCK_COMMENT_RE.sub(_block_repl, text)


def _target_tokens(target: str) -> set[str]:
    tokens: set[str] = set()
    for part in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", target):
        lowered = part.lower()
        tokens.add(lowered)
        for subpart in lowered.split("_"):
            if subpart:
                tokens.add(subpart)
    return {token for token in tokens if token not in _TOKEN_STOPWORDS}


def _is_callback_relevant(target: str) -> bool:
    return bool(_target_tokens(target) & _CALLBACK_STATE_TOKENS)


def _targets_related(left: str, right: str) -> bool:
    return bool(_target_tokens(left) & _target_tokens(right))


def _line_for_offset(base_line: int, text: str, offset: int) -> int:
    return base_line + text[:offset].count("\n")


def _iter_state_events(body_text: str):
    seen_spans: set[tuple[int, int]] = set()
    for regex in (_STATE_ASSIGN_RE, _STATE_MUT_CALL_RE):
        for match in regex.finditer(body_text):
            span = match.span()
            if span in seen_spans:
                continue
            seen_spans.add(span)
            target = match.group("target")
            if not _is_callback_relevant(target):
                continue
            yield {
                "start": match.start(),
                "end": match.end(),
                "target": target,
            }


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue

        raw_body = text_of(body, source)
        body_text = _mask_comments_keep_lines(raw_body)

        external_calls = list(_EXTERNAL_CALL_RE.finditer(body_text))
        if not external_calls:
            continue

        state_events = sorted(_iter_state_events(body_text), key=lambda item: item["start"])
        if len(state_events) < 2:
            continue

        fn_line, _ = line_col(fn)
        name = fn_name(fn, source)

        for call in external_calls:
            guard_region = body_text[:call.start()]
            if _GUARD_RE.search(guard_region):
                continue

            pre_events = [evt for evt in state_events if evt["end"] <= call.start()]
            post_events = [evt for evt in state_events if evt["start"] >= call.end()]
            if not pre_events or not post_events:
                continue

            match_pair = None
            for pre_evt in reversed(pre_events):
                for post_evt in post_events:
                    if _targets_related(pre_evt["target"], post_evt["target"]):
                        match_pair = (pre_evt, post_evt)
                        break
                if match_pair is not None:
                    break
            if match_pair is None:
                continue

            pre_evt, post_evt = match_pair
            call_line = _line_for_offset(fn_line, raw_body, call.start())
            pre_line = _line_for_offset(fn_line, raw_body, pre_evt["start"])
            post_line = _line_for_offset(fn_line, raw_body, post_evt["start"])
            hits.append(
                {
                    "severity": "high",
                    "line": call_line,
                    "col": 0,
                    "snippet": snippet_of(body, source),
                    "message": (
                        f"fn `{name}` leaves callback-relevant state family "
                        f"`{pre_evt['target']}` partially finalized before the "
                        f"external interaction at line {call_line}, then only "
                        f"finalizes related state `{post_evt['target']}` at "
                        f"line {post_line}. Pre-call partial write is at line "
                        f"{pre_line}."
                    ),
                }
            )
            break

    return hits
