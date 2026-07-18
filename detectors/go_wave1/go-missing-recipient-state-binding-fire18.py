"""
Go missing recipient state-binding detector for Fire18.

Detects handlers, bridge daemons, keepers, relayers, and state-machine paths
that credit, forward, withdraw, or mark state using a recipient-like field from
request or event data without binding that field to an authenticated actor,
source event, chain or domain, or stored commitment.

This is detector evidence only. A hit is not a filing verdict.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-missing-recipient-state-binding-fire18"

_HANDLER_NAME_RE = re.compile(
    r"(Handle|Handler|MsgServer|Keeper|Bridge|Daemon|Relayer|Relay|Event"
    r"|Packet|Receipt|Claim|Credit|Withdraw|Withdrawal|Transfer|Forward"
    r"|Finalize|Settle|Commit|State)",
    re.IGNORECASE,
)

_STATE_CONTEXT_RE = re.compile(
    r"(bridge|daemon|relayer|relay|keeper|handler|state|account|recipient"
    r"|receiver|beneficiary|claim|withdrawal|credit|forward|settle|mark"
    r"|commitment|sourceChain|sourceDomain|eventID|eventId|chainID|chainId)",
    re.IGNORECASE,
)

_INPUT_PREFIX = (
    r"(?:req|request|msg|message|event|evt|log|payload|packet|body|claim"
    r"|withdrawal|deposit|transfer|proof|receipt)"
)
_RECIPIENT_FIELD = (
    r"(?:Recipient|Receiver|RecipientAddress|ReceiverAddress|To|ToAddress"
    r"|Destination|Beneficiary|Account|AccountID|AccountId|Address|Owner"
    r"|Sender|From|FromAddress)"
)

_INPUT_RECIPIENT_RE = re.compile(
    r"\b" + _INPUT_PREFIX + r"\." + _RECIPIENT_FIELD + r"\b"
)

_ASSIGN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?::=|=)\s*([^;\n]+)")

_VALUE_OR_STATE_SINK_RE = re.compile(
    r"\b(?P<name>Credit|CreditAccount|CreditRecipient|CreditBalance"
    r"|Forward|ForwardTo|ForwardWithdrawal|Withdraw|WithdrawTo"
    r"|Release|ReleaseTo|Send|SendCoins|SendCoinsFromModuleToAccount"
    r"|Transfer|TransferTo|MintTo|Settle|SettleTo|CompleteWithdrawal"
    r"|FinalizeWithdrawal|FinalizeTransfer|Mark|MarkClaimed|MarkProcessed"
    r"|SetClaimed|SetProcessed|SetRecipientState|RecordReceipt"
    r"|RecordClaim|StoreClaim|PutClaim|Dispatch|DispatchTo)\s*\(",
    re.IGNORECASE,
)

_MAP_OR_INDEXED_WRITE_RE = re.compile(
    r"\[[^\]\n]+\]\s*(?:=|\+=|-=|\+\+|--)"
)

_SETTER_WRITE_RE = re.compile(
    r"\.(?:Set|Put|Store|Record|Mark)[A-Za-z_]*(?:\s*\()",
    re.IGNORECASE,
)

_BINDING_HELPER_RE = re.compile(
    r"\b(?:Validate|Ensure|Assert|Check|Verify|Require|Bind)"
    r"[A-Za-z_]*(?:Recipient|Receiver|Account|Sender|Actor|Signer|Owner"
    r"|Source|Domain|Chain|Event|Commitment)"
    r"[A-Za-z_]*(?:Binding|Match|Matches|Bound|Scope|Scoped|Commitment)?"
    r"\s*\(",
    re.IGNORECASE,
)

_BINDING_CONTEXT_RE = re.compile(
    r"\b(?:authenticated|auth|actor|caller|signer|owner|principal"
    r"|expected|canonical|stored|committed|bound|commitment|source"
    r"|src|origin|domain|chain|eventID|eventId|messageID|messageId"
    r"|receiptID|receiptId)\b"
    r"|\b(?:ctx|session|identity|account|sourceEvent|storedClaim)"
    r"\.[A-Za-z_]\w*\b",
    re.IGNORECASE,
)

_COMPARISON_RE = re.compile(
    r"(?:==|!=|\.Equal\s*\(|\.Equals\s*\(|bytes\.Equal\s*\()"
)

_STRING_RE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank, src)
    return re.sub(r"/\*.*?\*/", _blank, src, flags=re.S)


def _strip_comments_and_strings(src: str) -> str:
    return _STRING_RE.sub(_blank, _strip_comments(src))


def _split_call_args(call_text: str) -> list[str]:
    start = call_text.find("(")
    end = call_text.rfind(")")
    if start < 0 or end <= start:
        return []
    args_text = call_text[start + 1 : end]
    args: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in args_text:
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth > 0:
            depth -= 1
    if current or args_text.strip():
        args.append("".join(current).strip())
    return args


def _term_pattern(term: str) -> str:
    return r"(?<![\w.])" + re.escape(term) + r"(?![\w.])"


def _mentions_any(text: str, terms: set[str]) -> bool:
    return any(re.search(_term_pattern(term), text) for term in terms)


def _is_input_recipient_expr(expr: str, aliases: set[str]) -> bool:
    return bool(_INPUT_RECIPIENT_RE.search(expr)) or _mentions_any(expr, aliases)


def _collect_input_aliases(body_text: str) -> set[str]:
    aliases: set[str] = set()
    for line in body_text.splitlines():
        assign = _ASSIGN_RE.search(line)
        if not assign:
            continue
        lhs = assign.group(1)
        rhs = assign.group(2)
        if _is_input_recipient_expr(rhs, aliases):
            aliases.add(lhs)
        else:
            aliases.discard(lhs)
    return aliases


def _recipient_terms(body_text: str, aliases: set[str]) -> set[str]:
    terms = set(aliases)
    terms.update(match.group(0) for match in _INPUT_RECIPIENT_RE.finditer(body_text))
    return terms


def _has_binding_guard(body_text: str, recipient_terms: set[str]) -> bool:
    if _BINDING_HELPER_RE.search(body_text):
        return True

    for line in body_text.splitlines():
        if not _mentions_any(line, recipient_terms):
            continue
        if not _BINDING_CONTEXT_RE.search(line):
            continue
        if _COMPARISON_RE.search(line):
            return True
    return False


def _call_uses_recipient(call_text: str, recipient_terms: set[str]) -> bool:
    if not _VALUE_OR_STATE_SINK_RE.search(call_text):
        return False
    return any(_mentions_any(arg, recipient_terms) for arg in _split_call_args(call_text))


def _sink_uses_recipient(body_text: str, recipient_terms: set[str]) -> str | None:
    sink_call: list[str] = []
    sink_depth = 0

    for line in body_text.splitlines():
        if sink_call:
            sink_call.append(line)
            sink_depth += line.count("(") - line.count(")")
            if sink_depth <= 0:
                call_text = "\n".join(sink_call)
                if _call_uses_recipient(call_text, recipient_terms):
                    return call_text.strip()
                sink_call = []
            continue

        if _VALUE_OR_STATE_SINK_RE.search(line):
            sink_call = [line]
            sink_depth = line.count("(") - line.count(")")
            if sink_depth <= 0:
                if _call_uses_recipient(line, recipient_terms):
                    return line.strip()
                sink_call = []
            continue

        if _mentions_any(line, recipient_terms) and _MAP_OR_INDEXED_WRITE_RE.search(line):
            return line.strip()
        if _mentions_any(line, recipient_terms) and _SETTER_WRITE_RE.search(line):
            return line.strip()

    return None


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue

        fn_text = engine.text(fn)
        fn_text_clean = _strip_comments_and_strings(fn_text)
        body_text = _strip_comments_and_strings(engine.text(body))

        if not (_HANDLER_NAME_RE.search(name) or _STATE_CONTEXT_RE.search(fn_text_clean)):
            continue

        aliases = _collect_input_aliases(body_text)
        recipient_terms = _recipient_terms(body_text, aliases)
        if not recipient_terms:
            continue

        sink_site = _sink_uses_recipient(body_text, recipient_terms)
        if sink_site is None:
            continue

        if _has_binding_guard(body_text, recipient_terms):
            continue

        hits.append(
            {
                "severity": "high",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": fn_text.splitlines()[0][:160],
                "message": (
                    f"`{name}` mutates value or state using a request or event "
                    f"recipient near `{sink_site}` without binding that recipient "
                    f"to the authenticated actor, source event, chain/domain, or "
                    f"stored commitment. (class: missing-recipient-validation)"
                ),
            }
        )

    return hits
