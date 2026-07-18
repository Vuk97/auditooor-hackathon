"""
rust_transfer_to_repay_missing_recipient_validation.py

Detects Rust transfer, repayment, claim, and bridge settlement handlers where
an explicit recipient from a payload, memo, event, or parameter is present but
the final value-moving edge is routed to a different borrower, debtor, owner,
caller, or canonical sink without binding the two recipients.

This is intentionally narrow. It is not a generic "has a recipient parameter"
rule. It requires:
1. A transfer, repay, claim, bridge, settlement, release, or credit handler.
2. A supplied recipient term.
3. A different canonical or hardcoded sink term.
4. A value or state sink call using either the supplied term without equality
   binding, or the canonical term while the supplied term is ignored.
5. No equality guard, named binding helper, or proof/domain hash that includes
   the supplied recipient.
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


_HANDLER_NAME_RE = re.compile(
    r"(?i)("
    r"bridge|message|packet|payload|transfer|repay|repayment|claim|"
    r"settle|settlement|release|withdraw|redeem|finalize|fulfill|credit"
    r")"
)

_BODY_CONTEXT_RE = re.compile(
    r"(?i)("
    r"recipient|receiver|beneficiary|payload|memo|event|message|packet|"
    r"borrower|debtor|repay|repayment|settle|settlement|transfer|credit"
    r")"
)

_RECIPIENT_NAME_RE = re.compile(
    r"(?i)^(recipient|receiver|to|to_address|beneficiary|destination|"
    r"account|payout_sink|refund_to)$"
)

_SUPPLIED_RECIPIENT_RE = re.compile(
    r"(?i)\b(?:payload|memo|event|evt|parsed|body|packet|message|"
    r"envelope|proof|order|claim)\."
    r"(?:recipient|receiver|to|to_address|beneficiary|destination|account)\b"
)

_CANONICAL_RECIPIENT_RE = re.compile(
    r"(?i)\b(?:msg|request|req|route|canonical|sink|settlement|"
    r"transfer|claim|deposit|order|expected|repayment|loan|position)\."
    r"(?:recipient|receiver|to|to_address|beneficiary|destination|account|"
    r"borrower|debtor|owner|maker|payer|sender)\b"
    r"|\b(?:canonical_recipient|expected_recipient|sink_recipient|"
    r"settlement_recipient|canonical_receiver|expected_receiver|sink_receiver|"
    r"canonical_sink|expected_sink|borrower_sink|debtor_sink|owner_sink)\b"
)

_CANONICAL_PARAM_RE = re.compile(
    r"(?i)^(borrower|debtor|owner|maker|payer|sender|caller|account)$"
)

_ASSIGN_RE = re.compile(
    r"\b(?:let\s+(?:mut\s+)?|)([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=;\n]+)?=\s*([^;\n]+)"
)

_SINK_CALL_PREFIX_RE = re.compile(
    r"(?i)(?:\.|::|\b)(?P<name>"
    r"safe_transfer_from|transfer_from|safe_transfer|transfer|send_to|send|"
    r"credit_account|credit_recipient|credit|repay_to|repay|settle_to|"
    r"settle|release_to|release|mint_to|payout_to|pay_out|withdraw_to|"
    r"deposit_to|insert|entry"
    r")\s*\("
)

_RECIPIENT_ARG_INDEXES = {
    "safe_transfer_from": (1,),
    "transfer_from": (1,),
    "safe_transfer": (0,),
    "transfer": (0, 1),
    "send_to": (0,),
    "send": (0, 1),
    "credit_account": (0,),
    "credit_recipient": (0,),
    "credit": (0, 1),
    "repay_to": (0,),
    "repay": (0, 1),
    "settle_to": (0,),
    "settle": (0, 1),
    "release_to": (0,),
    "release": (0, 1),
    "mint_to": (0,),
    "payout_to": (0,),
    "pay_out": (0, 1),
    "withdraw_to": (0,),
    "deposit_to": (0,),
    "insert": (0,),
    "entry": (0,),
}

_BINDING_HELPER_RE = re.compile(
    r"(?i)(validate_.*recipient.*(binding|match|matches)|"
    r"ensure_.*recipient.*matches|assert_.*recipient.*matches|"
    r"recipient_matches|equal_recipient|bind_.*recipient)"
)

_DOMAIN_BINDING_CALL_RE = re.compile(
    r"(?i)(hash|digest|verify|proof|domain|leaf|commit|commitment|bind)\s*\("
)

_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


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


def _mentions_any(text: str, terms: set[str]) -> bool:
    return any(re.search(_term_pattern(term), text) for term in terms)


def _param_names(fn_text: str, name_re: re.Pattern[str]) -> set[str]:
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
        if name_match and name_re.match(name_match.group(1)):
            names.add(name_match.group(1))
    return names


def _is_supplied_expr(expr: str, aliases: set[str], params: set[str]) -> bool:
    if _SUPPLIED_RECIPIENT_RE.search(expr):
        return True
    return _mentions_any(expr, aliases | params)


def _is_canonical_expr(expr: str, aliases: set[str], params: set[str]) -> bool:
    if _CANONICAL_RECIPIENT_RE.search(expr):
        return True
    return _mentions_any(expr, aliases | params)


def _collect_aliases(
    body_text: str,
    supplied_params: set[str],
    canonical_params: set[str],
) -> tuple[set[str], set[str]]:
    supplied_aliases: set[str] = set()
    canonical_aliases: set[str] = set()

    for line in body_text.splitlines():
        assign = _ASSIGN_RE.search(line)
        if not assign:
            continue
        lhs = assign.group(1)
        rhs = assign.group(2)
        if _is_supplied_expr(rhs, supplied_aliases, supplied_params):
            supplied_aliases.add(lhs)
            canonical_aliases.discard(lhs)
        elif _is_canonical_expr(rhs, canonical_aliases, canonical_params):
            canonical_aliases.add(lhs)
            supplied_aliases.discard(lhs)
        else:
            supplied_aliases.discard(lhs)
            canonical_aliases.discard(lhs)

    return supplied_aliases, canonical_aliases


def _terms_for(
    body_text: str,
    aliases: set[str],
    direct_re: re.Pattern[str],
    params: set[str],
) -> set[str]:
    terms = set(aliases) | set(params)
    terms.update(match.group(0) for match in direct_re.finditer(body_text))
    return terms


def _has_binding_guard(
    body_text: str,
    supplied_terms: set[str],
    canonical_terms: set[str],
) -> bool:
    if _BINDING_HELPER_RE.search(body_text):
        return True

    for supplied in supplied_terms:
        supplied_pat = _term_pattern(supplied)
        for canonical in canonical_terms:
            canonical_pat = _term_pattern(canonical)
            comparators = (
                r"\s*(?:!=|==)\s*",
                r"\.eq\s*\(\s*&?",
            )
            for comp in comparators:
                if re.search(supplied_pat + comp + canonical_pat, body_text, re.S):
                    return True
                if re.search(canonical_pat + comp + supplied_pat, body_text, re.S):
                    return True
            if re.search(r"assert_eq!\s*\([^)]*" + supplied_pat + r"[^)]*" + canonical_pat, body_text, re.S):
                return True
            if re.search(r"assert_eq!\s*\([^)]*" + canonical_pat + r"[^)]*" + supplied_pat, body_text, re.S):
                return True
    return False


def _has_domain_binding(body_text: str, supplied_terms: set[str]) -> bool:
    sink_call: list[str] = []
    depth = 0
    for line in body_text.splitlines():
        if sink_call:
            sink_call.append(line)
            depth += line.count("(") - line.count(")")
            if depth <= 0:
                call_text = "\n".join(sink_call)
                if _DOMAIN_BINDING_CALL_RE.search(call_text) and _mentions_any(call_text, supplied_terms):
                    return True
                sink_call = []
            continue

        if not _DOMAIN_BINDING_CALL_RE.search(line):
            continue
        sink_call = [line]
        depth = line.count("(") - line.count(")")
        if depth <= 0:
            if _mentions_any(line, supplied_terms):
                return True
            sink_call = []
    return False


def _sink_calls(body_text: str) -> list[str]:
    calls: list[str] = []
    current: list[str] = []
    depth = 0

    for line in body_text.splitlines():
        if current:
            current.append(line)
            depth += line.count("(") - line.count(")")
            if depth <= 0:
                calls.append("\n".join(current))
                current = []
            continue

        if not _SINK_CALL_PREFIX_RE.search(line):
            continue
        current = [line]
        depth = line.count("(") - line.count(")")
        if depth <= 0:
            calls.append(line)
            current = []
    return calls


def _call_routes_to_terms(call_text: str, terms: set[str]) -> bool:
    match = _SINK_CALL_PREFIX_RE.search(call_text)
    if not match:
        return False
    indexes = _RECIPIENT_ARG_INDEXES.get(match.group("name").lower(), ())
    args = _split_call_args(call_text)
    return any(idx < len(args) and _mentions_any(args[idx], terms) for idx in indexes)


def run(tree, source: bytes, filepath: str, *, engine=None):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue

        fn_text = source[fn.start_byte:fn.end_byte].decode("utf-8", errors="replace")
        if not (_HANDLER_NAME_RE.search(name) or _BODY_CONTEXT_RE.search(fn_text)):
            continue

        body_nc = _strip_strings(body_text_nocomment(body, source))
        supplied_params = _param_names(fn_text, _RECIPIENT_NAME_RE)
        canonical_params = _param_names(fn_text, _CANONICAL_PARAM_RE)
        supplied_aliases, canonical_aliases = _collect_aliases(
            body_nc,
            supplied_params,
            canonical_params,
        )
        supplied_terms = _terms_for(
            body_nc,
            supplied_aliases,
            _SUPPLIED_RECIPIENT_RE,
            supplied_params,
        )
        canonical_terms = _terms_for(
            body_nc,
            canonical_aliases,
            _CANONICAL_RECIPIENT_RE,
            canonical_params,
        )

        if not supplied_terms or not canonical_terms:
            continue
        if _has_binding_guard(body_nc, supplied_terms, canonical_terms):
            continue
        if _has_domain_binding(body_nc, supplied_terms):
            continue

        calls = _sink_calls(body_nc)
        pays_supplied = any(_call_routes_to_terms(call, supplied_terms) for call in calls)
        pays_canonical = any(_call_routes_to_terms(call, canonical_terms) for call in calls)

        if not (pays_canonical or pays_supplied):
            continue
        if pays_supplied and pays_canonical:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` has an explicit supplied recipient but "
                    f"routes transfer, repayment, credit, or settlement to a "
                    f"different sink without an equality guard or proof/domain "
                    f"binding. Bind the final recipient before moving value. "
                    f"(class: missing-recipient-validation)"
                ),
            }
        )

    return hits
