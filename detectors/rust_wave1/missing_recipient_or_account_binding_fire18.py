"""
missing_recipient_or_account_binding_fire18.py

Same-class Rust detector for missing-recipient-validation.

Flags public handlers that credit, debit, wrap, forward, or CPI through an
untrusted recipient, sender, coin type, remaining account, owner, beneficiary,
or callback-provided account before validating the binding.

The detector is intentionally effect-gated. Address/account words alone are not
enough; a hit needs a transfer-like, wrapper, CPI, bridge, accounting, or
callback effect that consumes the untrusted identity before a validation guard.
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
    r"(?i)(bridge|callback|claim|configure|credit|deposit|forward|init|"
    r"initialize|mint|notify|packet|"
    r"payout|receive|redeem|release|repay|settle|transfer|withdraw|wrap|"
    r"create_wrapped|register|register_wrapped|remaining_accounts|"
    r"recv_internal|set_|update_|cpi|beneficiary)"
)

_PRIMITIVE_FN_RE = re.compile(
    r"(?i)^(transfer|transfer_from|safe_transfer|safe_transfer_from|send|"
    r"mint_to|credit|insert|push|set)$"
)

_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_ASSIGN_RE = re.compile(
    r"\b(?:let\s+(?:mut\s+)?|)([A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?::[^=;\n]+)?=\s*([^;\n]+)"
)

_IDENTITY_PARAM_NAME_RE = re.compile(
    r"(?i)^(recipient|receiver|to|to_address|beneficiary|destination|dest|"
    r"dst|sender|sender_address|from|from_address|source|payer|account|"
    r"token_account|callback_account|owner|new_owner|authority|operator|"
    r"wallet|vault|escrow|treasury|minter|beneficiary_account)$"
)

_IDENTITY_NAME_RE = re.compile(
    r"(?i)(recipient|receiver|beneficiary|destination|sender|from|payer|"
    r"account|owner|authority|operator|wallet|vault|escrow|treasury|minter)"
)

_IDENTITY_TYPE_RE = re.compile(
    r"(?i)\b(Address|AccountId|Pubkey|PublicKey|AccountInfo|Account|H160|"
    r"H256|Key|Principal)\b"
)

_DIRECT_FIELD_RE = re.compile(
    r"(?i)\b(?:payload|memo|event|evt|parsed|body|packet|message|msg|"
    r"envelope|proof|order|claim|request|req|notification|notify|callback|"
    r"hook|reply)\."
    r"(?:recipient|receiver|to|to_address|beneficiary|destination|sender|"
    r"sender_address|from|from_address|source|payer|account|token_account|"
    r"callback_account|owner|authority|operator|wallet|vault|escrow|treasury|"
    r"minter)\b"
)

_EFFECT_RE = re.compile(
    r"(?i)("
    r"\.\s*(?:safe_transfer_from|transfer_from|safe_transfer|transfer|send|"
    r"send_to|mint_to|credit_account|credit_recipient|credit|repay_to|repay|"
    r"settle_to|settle|release_to|release|payout_to|pay_out|withdraw_to|"
    r"deposit_to|forward_to|bridge_to)\s*\(|"
    r"\b(?:safe_transfer_from|transfer_from|safe_transfer|transfer|send|"
    r"send_to|mint_to|credit_account|credit_recipient|credit|repay_to|repay|"
    r"settle_to|settle|release_to|release|payout_to|pay_out|withdraw_to|"
    r"deposit_to|forward_to|bridge_to)\s*\(|"
    r"\b(?:balances|balance|accounts|credits|ledger|state|escrow|claims|"
    r"settled_for|rewards|shares|positions|beneficiaries|owners)\b[^\n;]{0,120}"
    r"(?:=|\+=|-=|\.insert\s*\(|\.push\s*\(|\.set\s*\(|\.entry\s*\()|"
    r"(?:storage\s*\(\s*\)\s*\.\s*(?:instance|persistent|temporary)\s*\(\s*\)"
    r"\s*\.\s*(?:set|update)\s*\()|"
    r"\b(?:CpiContext::new|CpiContext::new_with_signer|invoke_signed|invoke|"
    r"cpi::|spl_[A-Za-z0-9_]+::cpi|anchor_spl::|set_stake)\b"
    r")"
)

_COINTYPE_SOURCE_RE = re.compile(
    r"(?i)\b(?:vaa|payload|message|attestation|proof|packet)\."
    r"(?:origin_chain|origin_address|cointype|coin_type|token_address)\b|"
    r"\b(?:origin_chain|origin_address|cointype|coin_type|wrapped_asset)\b"
)

_WRAP_EFFECT_RE = re.compile(
    r"(?i)\b(?:derive_wrapped|deploy|register_wrapped|create_wrapped|"
    r"mint_wrapped|wrapped_assets?\.insert|asset_registry\.insert|"
    r"TokenManager::deploy|WrappedAsset)\b"
)

_COINTYPE_VALIDATION_RE = re.compile(
    r"(?i)(?:require|assert|ensure|check|validate|registry|whitelist|"
    r"allow_list|allowed|contains|registered_cointypes|is_allowed)"
    r"[^\n;]{0,120}(?:cointype|coin_type|origin_chain|origin_address|"
    r"wrapped_asset)|"
    r"(?:cointype|coin_type|origin_chain|origin_address|wrapped_asset)"
    r"[^\n;]{0,120}(?:require|assert|ensure|check|validate|registry|"
    r"whitelist|allow_list|allowed|contains|registered_cointypes|is_allowed)"
)

_REMAINING_USE_RE = re.compile(
    r"remaining_accounts\s*\.\s*(?:iter|get|into_iter|as_slice|first|last)|"
    r"remaining_accounts\s*\[\s*\d+\s*\]|"
    r"CpiContext::new(?:_with_signer)?\s*\([^)]*remaining_accounts|"
    r"\bcpi::[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*remaining_accounts|"
    r"\binvoke(?:_signed)?\s*\([^)]*remaining_accounts"
)

_REMAINING_EFFECT_RE = re.compile(
    r"(?i)(?:CpiContext::new|CpiContext::new_with_signer|invoke_signed|invoke|"
    r"cpi::|spl_[A-Za-z0-9_]+::cpi|anchor_spl::|set_stake|transfer|mint_to|"
    r"credit|deposit|withdraw)"
)

_REMAINING_VALIDATION_RE = re.compile(
    r"remaining_accounts\.len\s*\(\)\s*(?:==|>=|<=|>|<)|"
    r"remaining_accounts\[[^\]]*\]\.(?:key\s*\(\)|owner|is_signer|mint)\s*(?:==|!=)|"
    r"validate_remaining_accounts|check_remaining_accounts|bind_remaining_accounts|"
    r"require!?\s*\([^)]*remaining_accounts|"
    r"assert!?\s*\([^)]*remaining_accounts|"
    r"ensure!?\s*\([^)]*remaining_accounts"
)

_NOTIFICATION_RE = re.compile(
    r"(?i)(burn_notification|mint_notification|notification_op|recv_internal|"
    r"callback|hook|reply)"
)

_SUPPLY_EFFECT_RE = re.compile(
    r"(?i)(?:\*\s*)?(?:total_supply|supply|shares|credits|balance)\s*"
    r"(?:\+=|-=|=)|"
    r"\b(?:total_supply|supply|shares|credits|balance)\b[^\n;]{0,80}"
    r"(?:\+=|-=|=|\.set\s*\(|\.update\s*\()"
)

_VALIDATION_WORD_RE = re.compile(
    r"(?i)(require|assert|ensure|throw_unless|return\s+Err|panic|validate|"
    r"check|bind|allow|allowed|authorized|expected|require_auth|assert_eq|"
    r"owner|has_one|constraint|seeds|contains)"
)

_ZERO_OR_DEFAULT_RE = re.compile(
    r"(?i)(Address::default\s*\(|Pubkey::default\s*\(|Default::default\s*\(|"
    r"ZERO_ADDRESS|zero_address|is_zero\s*\(|\.is_zero\s*\(|\b0x0\b)"
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


def _term_pattern(term: str) -> str:
    return r"(?<![\w.])" + re.escape(term) + r"(?![\w.])"


def _mentions_term(text: str, term: str) -> bool:
    return re.search(_term_pattern(term), text) is not None


def _mentions_term_or_method(text: str, term: str) -> bool:
    return _mentions_term(text, term) or re.search(
        r"(?<![\w.])" + re.escape(term) + r"\s*\.",
        text,
    ) is not None


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
        if _IDENTITY_PARAM_NAME_RE.match(name):
            names.add(name)
            continue
        if _IDENTITY_NAME_RE.search(name) and _IDENTITY_TYPE_RE.search(param):
            names.add(name)
    return names


def _collect_terms(body_text: str, param_terms: set[str]) -> set[str]:
    terms = set(param_terms)
    terms.update(match.group(0) for match in _DIRECT_FIELD_RE.finditer(body_text))

    changed = True
    while changed:
        changed = False
        for line in body_text.splitlines():
            assign = _ASSIGN_RE.search(line)
            if not assign:
                continue
            lhs = assign.group(1)
            if lhs == "_" or lhs in terms:
                continue
            rhs = assign.group(2)
            if any(_mentions_term(rhs, term) for term in terms):
                terms.add(lhs)
                changed = True
    return terms


def _first_match_index(pattern: re.Pattern[str], text: str) -> int | None:
    match = pattern.search(text)
    return match.start() if match else None


def _effect_chunks(body_text: str) -> list[str]:
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

        if not _EFFECT_RE.search(line):
            continue
        current = [line]
        depth = line.count("(") - line.count(")")
        if depth <= 0 or ";" in line:
            chunks.append(line)
            current = []

    if current:
        chunks.append("\n".join(current))
    return chunks


def _term_used_in_effect(body_text: str, term: str) -> bool:
    return any(
        _mentions_term(chunk, term) and _EFFECT_RE.search(chunk)
        for chunk in _effect_chunks(body_text)
    )


def _has_validation(before_effect: str, term: str) -> bool:
    terms = {term}
    changed = True
    while changed:
        changed = False
        for line in before_effect.splitlines():
            assign = _ASSIGN_RE.search(line)
            if not assign:
                continue
            lhs = assign.group(1)
            if lhs == "_" or lhs in terms:
                continue
            rhs = assign.group(2)
            if any(_mentions_term(rhs, known) for known in terms):
                terms.add(lhs)
                changed = True

    for line in before_effect.splitlines():
        if not any(_mentions_term_or_method(line, candidate) for candidate in terms):
            continue
        if _VALIDATION_WORD_RE.search(line):
            return True
        if _ZERO_OR_DEFAULT_RE.search(line):
            return True
        for candidate in terms:
            if re.search(_term_pattern(candidate) + r"\s*(?:==|!=)\s*", line):
                return True
            if re.search(r"\s*(?:==|!=)\s*" + _term_pattern(candidate), line):
                return True
            if re.search(_term_pattern(candidate) + r"\.require_auth\s*\(", line):
                return True
    return False


def _direct_unvalidated_terms(body_text: str, fn_text: str) -> list[str]:
    effect_index = _first_match_index(_EFFECT_RE, body_text)
    if effect_index is None:
        return []

    before_effect = body_text[:effect_index]
    terms = _collect_terms(body_text, _identity_params(fn_text))
    bad: list[str] = []
    for term in sorted(terms):
        first = body_text.find(term)
        if first < 0:
            continue
        if first > effect_index and not _term_used_in_effect(body_text, term):
            continue
        if not _term_used_in_effect(body_text, term):
            continue
        if _has_validation(before_effect, term):
            continue
        bad.append(term)
    return bad


def _has_unvalidated_remaining_accounts(body_text: str) -> bool:
    if "remaining_accounts" not in body_text:
        return False
    effect_index = _first_match_index(_REMAINING_EFFECT_RE, body_text)
    if effect_index is None:
        return False
    before_effect = body_text[:effect_index]
    if _REMAINING_VALIDATION_RE.search(before_effect):
        return False
    return _REMAINING_USE_RE.search(body_text) is not None


def _has_unvalidated_cointype_wrap(body_text: str, fn_text: str) -> bool:
    if not _COINTYPE_SOURCE_RE.search(body_text):
        return False
    if not (_WRAP_EFFECT_RE.search(body_text) or re.search(r"(?i)wrap", fn_text)):
        return False
    effect_index = _first_match_index(_WRAP_EFFECT_RE, body_text)
    if effect_index is None:
        effect_index = _first_match_index(_EFFECT_RE, body_text)
    if effect_index is None:
        return False
    before_effect = body_text[:effect_index]
    return _COINTYPE_VALIDATION_RE.search(before_effect) is None


def _unvalidated_notification_sender_terms(body_text: str, fn_text: str) -> list[str]:
    if not _NOTIFICATION_RE.search(body_text):
        return []
    effect_index = _first_match_index(_SUPPLY_EFFECT_RE, body_text)
    if effect_index is None:
        return []

    before_effect = body_text[:effect_index]
    sender_terms = [
        term for term in sorted(_identity_params(fn_text))
        if re.search(r"(?i)(sender|from|source)", term)
    ]
    return [
        term for term in sender_terms
        if not _has_validation(before_effect, term)
    ]


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
        body_nc = _strip_strings(body_text_nocomment(body, source))
        if not (_HANDLER_RE.search(name) or _HANDLER_RE.search(body_nc)):
            continue

        issues: list[str] = []
        if _has_unvalidated_remaining_accounts(body_nc):
            issues.append("remaining_accounts")
        if _has_unvalidated_cointype_wrap(body_nc, fn_text):
            issues.append("coin type or origin asset")
        issues.extend(_direct_unvalidated_terms(body_nc, fn_text))
        issues.extend(_unvalidated_notification_sender_terms(body_nc, fn_text))

        if not issues:
            continue

        line, col = line_col(fn)
        seen = sorted(set(issues))
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:240],
                "message": (
                    f"pub fn `{name}` reaches a value, wrapper, CPI, bridge, "
                    f"or accounting effect before validating account binding: "
                    f"{', '.join(seen)}. Bind recipient/sender/remaining "
                    f"account/coin-type inputs before the effect. "
                    f"(class: missing-recipient-validation)"
                ),
            }
        )

    return hits
