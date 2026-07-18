"""
missing_recipient_or_sender_validation_fire9.py

Flags Rust handlers that accept or decode an address-like recipient, sender,
remaining account, or bridge notification sink and then move value or credit
state before validating that sink.

This detector is intentionally shape-gated. It requires a value-moving or
state-credit sink and suppresses functions that validate the relevant term
before the first sink. It is built from the existing confirmed Rust fixtures
for missing recipient binding, unvalidated burn notification sender, and
unvalidated remaining accounts.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
)


_HANDLER_RE = re.compile(
    r"(?i)(bridge|message|packet|payload|transfer|repay|claim|settle|"
    r"withdraw|redeem|release|deposit|credit|notify|notification|recv_internal|"
    r"burn|mint|set_|update_|init|initialize|register|configure)"
)

_PRIMITIVE_FN_RE = re.compile(
    r"(?i)^(safe_transfer_from|transfer_from|safe_transfer|transfer|send|"
    r"send_to|mint_to|credit|credit_account|credit_recipient|set|insert|push)$"
)

_VALUE_OR_CREDIT_RE = re.compile(
    r"(?i)("
    r"\.\s*(?:safe_transfer_from|transfer_from|safe_transfer|transfer|send_to|"
    r"send|mint_to|credit_account|credit_recipient|credit|repay_to|repay|"
    r"settle_to|settle|release_to|release|payout_to|pay_out|withdraw_to|"
    r"deposit_to)\s*\(|"
    r"\b(?:transfer_from|transfer|send_to|mint_to|credit_account|"
    r"credit_recipient|repay_to|settle_to|release_to|payout_to|withdraw_to|"
    r"deposit_to)\s*\(|"
    r"\*\s*(?:total_supply|supply|balance|shares|credits)\s*(?:\+=|-=|=)|"
    r"\b(?:balances|balance|accounts|credits|claimed|settled_for|"
    r"total_supply|supply|rewards|shares|ledger|state)\b[^\n;]{0,80}"
    r"(?:=|\+=|-=|\.insert\s*\(|\.push\s*\(|\.set\s*\()|"
    r"(?:storage\s*\(\s*\)\s*\.\s*(?:instance|persistent|temporary)\s*\(\s*\)"
    r"\s*\.\s*(?:set|update)\s*\()|"
    r"\b(?:CpiContext::new|CpiContext::new_with_signer|invoke_signed|"
    r"invoke|cpi::|set_stake)\b"
    r")"
)

_UNTRUSTED_PARAM_RE = re.compile(
    r"(?i)^(recipient|receiver|to|to_address|beneficiary|destination|"
    r"dest|dst|sender|sender_address|from|from_address|source|payer|"
    r"account|owner|new_owner|admin|new_admin|authority|operator|"
    r"treasury|oracle|vault|minter)$"
)

_DIRECT_TERM_RE = re.compile(
    r"(?i)\b(?:payload|memo|event|evt|parsed|body|packet|message|msg|"
    r"envelope|proof|order|claim|request|req|notification|notify)\."
    r"(?:recipient|receiver|to|to_address|beneficiary|destination|sender|"
    r"sender_address|from|from_address|source|payer|account|owner|admin|"
    r"authority|operator|treasury|oracle|vault|minter)\b"
)

_ASSIGN_RE = re.compile(
    r"\b(?:let\s+(?:mut\s+)?|)([A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?::[^=;\n]+)?=\s*([^;\n]+)"
)

_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_REMAINING_USE_RE = re.compile(
    r"remaining_accounts\s*\.\s*(?:iter|get|into_iter|as_slice|first|last)|"
    r"remaining_accounts\s*\[\s*\d+\s*\]|"
    r"CpiContext::new(?:_with_signer)?\s*\([^)]*remaining_accounts|"
    r"\bcpi::[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*remaining_accounts"
)

_REMAINING_VALIDATION_RE = re.compile(
    r"remaining_accounts\.len\s*\(\)\s*(?:==|>=|<=|>|<)|"
    r"remaining_accounts\[[^\]]*\]\.(?:key\s*\(\)|owner|is_signer|mint)\s*(?:==|!=)|"
    r"validate_remaining_accounts|check_remaining_accounts|"
    r"require!?\s*\([^)]*remaining_accounts|"
    r"assert!?\s*\([^)]*remaining_accounts|"
    r"ensure!?\s*\([^)]*remaining_accounts"
)

_NOTIFICATION_RE = re.compile(r"(?i)(burn_notification|mint_notification|notification_op)")
_SENDER_TERM_RE = re.compile(r"(?i)\b(sender_address|sender|from_address|from)\b")
_SENDER_VALIDATION_RE = re.compile(
    r"(?i)("
    r"(?:require|assert|ensure|throw_unless)!?\s*\([^)]*"
    r"(?:sender_address|sender|from_address|from)[^)]*(?:==|!=|expected|master|"
    r"minter|owner|authorized|allowed)|"
    r"(?:sender_address|sender|from_address|from)\s*(?:==|!=)\s*"
    r"(?:expected|.*master|.*minter|.*owner|authorized|allowed)|"
    r"(?:sender_address|sender|from_address|from)\.require_auth\s*\(|"
    r"validate_.*(?:sender|from)|check_.*(?:sender|from)|ensure_.*(?:sender|from)"
    r")"
)

_TERM_VALIDATION_WORD_RE = re.compile(
    r"(?i)(require|assert|ensure|throw_unless|return\s+Err|panic|"
    r"validate|check|bind|allow|allowed|authorized|expected|require_auth|"
    r"assert_eq)"
)

_IDENTITY_TYPE_RE = re.compile(
    r"(?i)\b(?:Address|AccountId|Pubkey|PublicKey|H160|H256|AccountInfo)\b"
)

_IDENTITY_NAME_RE = re.compile(
    r"(?i)(recipient|receiver|to|beneficiary|destination|dest|dst|sender|"
    r"from|source|payer|account|owner|admin|authority|operator|treasury|"
    r"oracle|vault|minter)"
)

_ZERO_OR_DEFAULT_RE = re.compile(
    r"(?i)(Address::default\s*\(|Pubkey::default\s*\(|Default::default\s*\(|"
    r"ZERO_ADDRESS|zero_address|is_zero\s*\(|\.is_zero\s*\(|"
    r"\b(?:0x0|0_u64|0u64|0)\b)"
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_strings(text: str) -> str:
    return _STRING_RE.sub(_blank, text)


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


def _param_names(fn_text: str) -> set[str]:
    head = fn_text.split("{", 1)[0]
    match = re.search(r"\bfn\s+\w+\s*\((?P<params>.*?)\)", head, re.S)
    if not match:
        return set()

    names: set[str] = set()
    for param in _split_call_args("(" + match.group("params") + ")"):
        param = param.strip()
        if not param or param in {"self", "&self", "&mut self"}:
            continue
        name_match = re.match(r"(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:", param)
        if name_match and _UNTRUSTED_PARAM_RE.match(name_match.group(1)):
            names.add(name_match.group(1))
    return names


def _identity_params(fn_text: str) -> set[str]:
    head = fn_text.split("{", 1)[0]
    match = re.search(r"\bfn\s+\w+\s*\((?P<params>.*?)\)", head, re.S)
    if not match:
        return set()

    names: set[str] = set()
    for param in _split_call_args("(" + match.group("params") + ")"):
        param = param.strip()
        if not param or param in {"self", "&self", "&mut self"}:
            continue
        name_match = re.match(r"(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:", param)
        if not name_match:
            continue
        name = name_match.group(1)
        if _UNTRUSTED_PARAM_RE.match(name):
            names.add(name)
            continue
        if _IDENTITY_NAME_RE.search(name) and _IDENTITY_TYPE_RE.search(param):
            names.add(name)
    return names


def _term_pattern(term: str) -> str:
    return r"(?<![\w.])" + re.escape(term) + r"(?![\w.])"


def _mentions_term(text: str, term: str) -> bool:
    return re.search(_term_pattern(term), text) is not None


def _mentions_term_or_method(text: str, term: str) -> bool:
    if _mentions_term(text, term):
        return True
    return re.search(r"(?<![\w.])" + re.escape(term) + r"\s*\.", text) is not None


def _collect_terms(body_text: str, param_terms: set[str]) -> set[str]:
    terms = set(param_terms)
    terms.update(match.group(0) for match in _DIRECT_TERM_RE.finditer(body_text))

    changed = True
    while changed:
        changed = False
        for line in body_text.splitlines():
            assign = _ASSIGN_RE.search(line)
            if not assign:
                continue
            lhs = assign.group(1)
            if lhs == "_":
                continue
            rhs = assign.group(2)
            if lhs in terms:
                continue
            if any(_mentions_term(rhs, term) for term in terms):
                terms.add(lhs)
                changed = True
    return terms


def _first_value_sink_index(body_text: str) -> int | None:
    match = _VALUE_OR_CREDIT_RE.search(body_text)
    if not match:
        return None
    return match.start()


def _value_sink_chunks(body_text: str) -> list[str]:
    chunks: list[str] = []
    current: list[str] = []
    depth = 0

    for line in body_text.splitlines():
        if current:
            current.append(line)
            depth += line.count("(") - line.count(")")
            if depth <= 0 or ";" in line:
                chunks.append("\n".join(current))
                current = []
            continue

        if not _VALUE_OR_CREDIT_RE.search(line):
            continue
        current = [line]
        depth = line.count("(") - line.count(")")
        if depth <= 0 or ";" in line:
            chunks.append(line)
            current = []

    if current:
        chunks.append("\n".join(current))
    return chunks


def _term_used_in_value_sink(body_text: str, term: str) -> bool:
    return any(
        _mentions_term(chunk, term) and _VALUE_OR_CREDIT_RE.search(chunk)
        for chunk in _value_sink_chunks(body_text)
    )


def _term_has_validation(before_sink: str, term: str) -> bool:
    terms = {term}
    changed = True
    while changed:
        changed = False
        for line in before_sink.splitlines():
            assign = _ASSIGN_RE.search(line)
            if not assign:
                continue
            lhs = assign.group(1)
            if lhs == "_":
                continue
            rhs = assign.group(2)
            if lhs in terms:
                continue
            if any(_mentions_term(rhs, known) for known in terms):
                terms.add(lhs)
                changed = True

    for line in before_sink.splitlines():
        if not any(_mentions_term_or_method(line, candidate) for candidate in terms):
            continue
        if _TERM_VALIDATION_WORD_RE.search(line):
            return True
        for candidate in terms:
            if re.search(_term_pattern(candidate) + r"\s*(?:==|!=)\s*", line):
                return True
            if re.search(r"\s*(?:==|!=)\s*" + _term_pattern(candidate), line):
                return True
            if re.search(_term_pattern(candidate) + r"\.require_auth\s*\(", line):
                return True
            if _ZERO_OR_DEFAULT_RE.search(line):
                return True
    return False


def _has_unvalidated_remaining_accounts(body_text: str) -> bool:
    if "remaining_accounts" not in body_text:
        return False
    sink_index = _first_value_sink_index(body_text)
    if sink_index is None:
        return False
    before_sink = body_text[:sink_index]
    if _REMAINING_VALIDATION_RE.search(before_sink):
        return False
    return _REMAINING_USE_RE.search(body_text) is not None


def _has_unvalidated_notification_sender(body_text: str, fn_text: str) -> bool:
    if not _NOTIFICATION_RE.search(body_text):
        return False
    sender_params = {
        term for term in _identity_params(fn_text)
        if re.search(r"(?i)(sender|from|source)", term)
    }
    if not (_SENDER_TERM_RE.search(body_text) or sender_params):
        return False
    sink_index = _first_value_sink_index(body_text)
    if sink_index is None:
        return False
    before_sink = body_text[:sink_index]
    return _SENDER_VALIDATION_RE.search(before_sink) is None


def _unvalidated_address_terms(body_text: str, fn_text: str) -> list[str]:
    sink_index = _first_value_sink_index(body_text)
    if sink_index is None:
        return []
    before_sink = body_text[:sink_index]
    terms = _collect_terms(body_text, _identity_params(fn_text))
    bad: list[str] = []
    for term in sorted(terms):
        first = body_text.find(term)
        if first < 0:
            continue
        if first > sink_index and not _term_used_in_value_sink(body_text, term):
            continue
        if _term_has_validation(before_sink, term):
            continue
        bad.append(term)
    return bad


def run(tree, source: bytes, filepath: str, *, engine=None):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        if _PRIMITIVE_FN_RE.match(name):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        fn_text = source[fn.start_byte:fn.end_byte].decode("utf-8", errors="replace")
        if not (_HANDLER_RE.search(name) or _HANDLER_RE.search(fn_text)):
            continue

        body_nc = _strip_strings(body_text_nocomment(body, source))
        if _first_value_sink_index(body_nc) is None:
            continue

        issues: list[str] = []
        if _has_unvalidated_remaining_accounts(body_nc):
            issues.append("remaining_accounts")
        if _has_unvalidated_notification_sender(body_nc, fn_text):
            issues.append("notification sender")
        issues.extend(_unvalidated_address_terms(body_nc, fn_text))

        if not issues:
            continue

        line, col = line_col(fn)
        seen = sorted(set(issues))
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` moves value or credits state using "
                    f"unvalidated recipient/sender sink(s): {', '.join(seen)}. "
                    f"Validate or bind those sinks before token movement, CPI, "
                    f"supply mutation, or state credit. "
                    f"(class: missing-recipient-validation)"
                ),
            }
        )

    return hits
