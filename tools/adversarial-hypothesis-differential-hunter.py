#!/usr/bin/env python3
"""Standalone Adversarial-Hypothesis Differential Hunter.

Given Solidity source files/directories or a JSON function manifest, emit a
bounded set of per-function adversarial hypotheses. Each hypothesis is framed
as a differential test idea: compare the normal path against a manipulated
adversarial path and assert the invariant that must continue to hold.

The tool is deliberately deterministic and stdlib-only. It is advisory: it
does not prove exploitability and it does not re-triage old NOT-A-BUG rows.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.adversarial_hypothesis_differential_hunter.v1"
DEFAULT_MAX_FUNCTIONS = 80
DEFAULT_MAX_HYPOTHESES_PER_FUNCTION = 3
DEFAULT_MAX_SOURCE_BYTES = 1_000_000

# r36-rebuttal: bugfix-inventory-claude-20260610
SKIP_DIRS = {
    ".git",
    "artifacts",
    "broadcast",
    "cache",
    "certora",
    "halmos",
    "kontrol",
    "lib",
    "mock",
    "mocks",
    "node_modules",
    "out",
    "spec",
    "specs",
    "test",
    "tests",
}

VISIBILITY_RE = re.compile(r"\b(public|external|internal|private)\b")
MUTABILITY_RE = re.compile(r"\b(payable|view|pure)\b")
RETURNS_RE = re.compile(r"\breturns\s*\(", re.IGNORECASE)
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

AUTH_MODIFIER_TERMS = (
    "owner",
    "admin",
    "auth",
    "role",
    "govern",
    "operator",
    "guardian",
    "manager",
    "keeper",
)
VALUE_CALL_TERMS = (".call", ".transfer", ".send")
LOW_LEVEL_CALL_TERMS = (".call", ".delegatecall", ".staticcall")
KNOWN_CALL_TARGETS = {
    "abi",
    "assert",
    "block",
    "console",
    "keccak256",
    "msg",
    "require",
    "revert",
    "string",
    "super",
    "this",
    "tx",
    "type",
    "vm",
}
KNOWN_MEMBER_FUNCS = {"add", "concat", "div", "length", "mul", "pop", "push", "sub"}
KEYWORDS = {
    "address",
    "bool",
    "break",
    "bytes",
    "calldata",
    "continue",
    "delete",
    "else",
    "emit",
    "false",
    "for",
    "if",
    "int",
    "memory",
    "new",
    "payable",
    "return",
    "returns",
    "revert",
    "storage",
    "string",
    "true",
    "uint",
    "while",
}


@dataclass(frozen=True)
class Param:
    name: str
    type: str


@dataclass(frozen=True)
class FunctionRecord:
    file_path: str
    contract_name: str
    contract_kind: str
    function_name: str
    function_signature: str
    visibility: str
    state_mutability: str
    line_start: int
    line_end: int
    modifiers: tuple[str, ...]
    params: tuple[Param, ...]
    return_types: tuple[str, ...]
    body: str
    state_vars: tuple[str, ...]
    state_writes: tuple[str, ...]
    external_calls: tuple[str, ...]
    guards_detected: tuple[str, ...]


@dataclass(frozen=True)
class FunctionDraft:
    start: int
    end: int
    body_start: int
    body_end: int
    has_body: bool
    function_name: str
    signature: str
    visibility: str
    state_mutability: str
    modifiers: tuple[str, ...]
    params: tuple[Param, ...]
    return_types: tuple[str, ...]


def _collapse_ws(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _line_at(text: str, pos: int) -> int:
    return text.count("\n", 0, max(0, pos)) + 1


def _mask_comments_and_strings(text: str) -> str:
    """Replace comments and strings with spaces while preserving offsets."""
    out: list[str] = []
    i = 0
    n = len(text)
    mode = "code"
    quote = ""
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if mode == "line":
            if ch == "\n":
                mode = "code"
                out.append(ch)
            else:
                out.append(" ")
            i += 1
            continue
        if mode == "block":
            if ch == "*" and nxt == "/":
                out.extend("  ")
                i += 2
                mode = "code"
                continue
            out.append("\n" if ch == "\n" else " ")
            i += 1
            continue
        if mode == "string":
            if ch == "\\" and i + 1 < n:
                out.extend("  ")
                i += 2
                continue
            out.append("\n" if ch == "\n" else " ")
            if ch == quote:
                mode = "code"
                quote = ""
            i += 1
            continue

        if ch == "/" and nxt == "/":
            out.extend("  ")
            i += 2
            mode = "line"
            continue
        if ch == "/" and nxt == "*":
            out.extend("  ")
            i += 2
            mode = "block"
            continue
        if ch in {"'", '"'}:
            out.append(" ")
            quote = ch
            mode = "string"
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _find_matching_pair(text: str, open_pos: int, open_ch: str, close_ch: str, limit: int | None = None) -> int:
    depth = 0
    end = len(text) if limit is None else min(limit, len(text))
    for idx in range(open_pos, end):
        ch = text[idx]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _find_signature_terminator(masked: str, start: int, limit: int) -> int:
    paren = 0
    bracket = 0
    brace = 0
    for idx in range(start, limit):
        ch = masked[idx]
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(0, bracket - 1)
        elif ch == "{":
            if paren == 0 and bracket == 0 and brace == 0:
                return idx
            brace += 1
        elif ch == "}":
            brace = max(0, brace - 1)
        elif ch == ";" and paren == 0 and bracket == 0 and brace == 0:
            return idx
    return -1


def _split_top_level(value: str, sep: str = ",") -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    paren = 0
    bracket = 0
    angle = 0
    for ch in value:
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(0, bracket - 1)
        elif ch == "<":
            angle += 1
        elif ch == ">":
            angle = max(0, angle - 1)
        if ch == sep and paren == 0 and bracket == 0 and angle == 0:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return parts


def _normalize_solidity_type(value: str) -> str:
    value = _collapse_ws(value)
    value = re.sub(r"\b(memory|calldata|storage)\b", "", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def parse_params(params_text: str) -> tuple[Param, ...]:
    out: list[Param] = []
    for raw in _split_top_level(params_text):
        part = _collapse_ws(raw)
        if not part:
            continue
        part = re.sub(r"\b(indexed|memory|calldata|storage)\b", "", part)
        part = _collapse_ws(part)
        tokens = part.split()
        if not tokens:
            continue
        if len(tokens) == 1:
            out.append(Param(name="", type=_normalize_solidity_type(tokens[0])))
            continue
        maybe_name = tokens[-1]
        if IDENT_RE.fullmatch(maybe_name) and maybe_name not in KEYWORDS:
            out.append(Param(name=maybe_name, type=_normalize_solidity_type(" ".join(tokens[:-1]))))
        else:
            out.append(Param(name="", type=_normalize_solidity_type(part)))
    return tuple(out)


def _extract_return_types(signature: str) -> tuple[str, ...]:
    match = RETURNS_RE.search(signature)
    if not match:
        return ()
    open_pos = signature.find("(", match.end() - 1)
    if open_pos == -1:
        return ()
    close_pos = _find_matching_pair(signature, open_pos, "(", ")")
    if close_pos == -1:
        return ()
    values: list[str] = []
    for part in _split_top_level(signature[open_pos + 1:close_pos]):
        tokens = _collapse_ws(part).split()
        if not tokens:
            continue
        if len(tokens) >= 2 and IDENT_RE.fullmatch(tokens[-1]) and tokens[-1] not in KEYWORDS:
            values.append(_normalize_solidity_type(" ".join(tokens[:-1])))
        else:
            values.append(_normalize_solidity_type(" ".join(tokens)))
    return tuple(v for v in values if v)


def _extract_modifiers(signature: str, params_close: int) -> tuple[str, ...]:
    tail = signature[params_close + 1:]
    returns = RETURNS_RE.search(tail)
    if returns:
        tail = tail[:returns.start()]
    for token in ("public", "external", "internal", "private", "payable", "view", "pure", "virtual", "override"):
        tail = re.sub(rf"\b{token}\b(?:\s*\([^)]*\))?", " ", tail)
    mods: list[str] = []
    seen: set[str] = set()
    for match in IDENT_RE.finditer(tail):
        mod = match.group(0)
        if mod in KEYWORDS or mod in seen:
            continue
        seen.add(mod)
        mods.append(mod)
    return tuple(mods)


def _visibility_from_signature(signature: str, default: str = "internal") -> str:
    match = VISIBILITY_RE.search(signature)
    return match.group(1) if match else default


def _mutability_from_signature(signature: str) -> str:
    match = MUTABILITY_RE.search(signature)
    return match.group(1) if match else "nonpayable"


def _parse_function_drafts(text: str, masked: str, body_start: int, body_end: int) -> list[FunctionDraft]:
    fn_re = re.compile(
        r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("
        r"|\bconstructor\s*\("
        r"|\breceive\s*\("
        r"|\bfallback\s*\(",
        re.MULTILINE,
    )
    drafts: list[FunctionDraft] = []
    for match in fn_re.finditer(masked, body_start, body_end):
        start = match.start()
        open_pos = masked.find("(", start, body_end)
        if open_pos == -1:
            continue
        close_pos = _find_matching_pair(masked, open_pos, "(", ")", body_end)
        if close_pos == -1:
            continue
        term = _find_signature_terminator(masked, close_pos + 1, body_end)
        if term == -1:
            continue
        has_body = masked[term] == "{"
        fn_body_end = term
        if has_body:
            match_brace = _find_matching_pair(masked, term, "{", "}", body_end)
            if match_brace == -1:
                continue
            fn_body_end = match_brace
        raw_sig = _collapse_ws(text[start:term])
        params = parse_params(text[open_pos + 1:close_pos])
        name = match.group(1) or ""
        if not name:
            head = masked[start:open_pos].strip()
            if head.startswith("constructor"):
                name = "<constructor>"
            elif head.startswith("receive"):
                name = "<receive>"
            else:
                name = "<fallback>"
        signature_for_mods = text[start:term]
        params_close_in_sig = signature_for_mods.find(")", signature_for_mods.find("("))
        modifiers = _extract_modifiers(signature_for_mods, params_close_in_sig) if params_close_in_sig != -1 else ()
        default_visibility = "public" if name == "<constructor>" else "external" if name in {"<receive>", "<fallback>"} else "internal"
        drafts.append(
            FunctionDraft(
                start=start,
                end=fn_body_end + 1 if has_body else term + 1,
                body_start=term,
                body_end=fn_body_end,
                has_body=has_body,
                function_name=name,
                signature=raw_sig,
                visibility=_visibility_from_signature(signature_for_mods, default=default_visibility),
                state_mutability=_mutability_from_signature(signature_for_mods),
                modifiers=modifiers,
                params=params,
                return_types=_extract_return_types(signature_for_mods),
            )
        )
    return drafts


def _blank_spans_preserve_newlines(text: str, spans: Iterable[tuple[int, int]]) -> str:
    chars = list(text)
    for start, end in spans:
        for idx in range(max(0, start), min(len(chars), end)):
            if chars[idx] != "\n":
                chars[idx] = " "
    return "".join(chars)


def _parse_state_vars(masked_contract_body: str) -> tuple[str, ...]:
    var_re = re.compile(
        r"(?m)^\s*"
        r"(?!(?:function|modifier|event|error|using|struct|enum|return|if|for|while)\b)"
        r"(?P<type>mapping\s*\([^;]+?\)|[A-Za-z_][A-Za-z0-9_.]*(?:\s+payable)?(?:\s*\[[^\]]*\])*)"
        r"\s+"
        r"(?:(?:public|private|internal|constant|immutable|override|transient)\s+)*"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
        r"\s*(?:=|;)",
    )
    out: list[str] = []
    seen: set[str] = set()
    for match in var_re.finditer(masked_contract_body):
        name = match.group("name")
        if name in KEYWORDS or name in seen:
            continue
        seen.add(name)
        out.append(name)
    return tuple(out)


def _detect_state_writes(body: str, state_vars: tuple[str, ...], params: tuple[Param, ...]) -> tuple[str, ...]:
    clean = _mask_comments_and_strings(body)
    candidates: list[str] = []
    if state_vars:
        for name in state_vars:
            escaped = re.escape(name)
            patterns = (
                rf"\b{escaped}\s*(?:\[[^\]]+\]\s*)?(?:=|\+=|-=|\*=|/=|%=|\+\+|--)",
                rf"\bdelete\s+{escaped}\b",
                rf"\b{escaped}\s*\.\s*(?:push|pop)\s*\(",
            )
            if any(re.search(pattern, clean) for pattern in patterns):
                candidates.append(name)
    else:
        param_names = {p.name for p in params if p.name}
        generic_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]+\]\s*)?(?:=|\+=|-=|\*=|/=|%=|\+\+|--)")
        for match in generic_re.finditer(clean):
            name = match.group(1)
            if name in KEYWORDS or name in param_names:
                continue
            candidates.append(name)
    seen: set[str] = set()
    out: list[str] = []
    for name in candidates:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return tuple(out[:10])


def _detect_external_calls(body: str) -> tuple[str, ...]:
    clean = _mask_comments_and_strings(body)
    calls: list[str] = []
    seen: set[str] = set()

    for match in re.finditer(r"\.\s*(call|delegatecall|staticcall|transfer|send)\s*(?:\{[^{}]*\})?\s*\(", clean):
        label = "." + match.group(1)
        if label not in seen:
            seen.add(label)
            calls.append(label)

    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", clean):
        target, func = match.group(1), match.group(2)
        if target in KNOWN_CALL_TARGETS or func in KNOWN_MEMBER_FUNCS:
            continue
        label = f"{target}.{func}"
        if label not in seen:
            seen.add(label)
            calls.append(label)
        if len(calls) >= 16:
            break
    return tuple(calls)


def _detect_guards(modifiers: tuple[str, ...], body: str) -> tuple[str, ...]:
    clean = _mask_comments_and_strings(body)
    lower = clean.lower()
    out: list[str] = []
    seen: set[str] = set()

    def add(label: str) -> None:
        if label not in seen:
            seen.add(label)
            out.append(label)

    for mod in modifiers:
        low = mod.lower()
        if any(term in low for term in AUTH_MODIFIER_TERMS):
            add("authority-check")
        if "reentrant" in low:
            add("reentrancy-guard")
        if "pause" in low:
            add("pause-guard")
    if re.search(r"\b(hasrole|_checkowner|ownableunauthorizedaccount)\s*\(", lower):
        add("authority-check")
    if re.search(r"\brequire\s*\([^;]*(msg\.sender|_msgsender\s*\()", lower):
        add("require-sender")
    if re.search(r"\bif\s*\([^;]*(msg\.sender|_msgsender\s*\()[^;]*(?:!=|==)", lower):
        add("require-sender")
    if "nonreentrant" in lower:
        add("reentrancy-guard")
    if "whennotpaused" in lower or re.search(r"\brequire\s*\(\s*!?\s*paused\s*\(", lower):
        add("pause-guard")
    return tuple(out)


def parse_solidity_source(text: str, file_path: str = "<memory>") -> list[FunctionRecord]:
    """Best-effort Solidity parser used by tests and the CLI."""
    masked = _mask_comments_and_strings(text)
    contract_re = re.compile(
        r"\b(?:(abstract)\s+)?(contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)[^{;]*\{",
        re.MULTILINE,
    )
    records: list[FunctionRecord] = []
    last_contract_end = -1
    for match in contract_re.finditer(masked):
        if match.start() < last_contract_end:
            continue
        kind = match.group(2)
        contract_name = match.group(3)
        contract_open = masked.find("{", match.start(), match.end())
        if contract_open == -1:
            continue
        contract_close = _find_matching_pair(masked, contract_open, "{", "}")
        if contract_close == -1:
            continue
        last_contract_end = contract_close
        body_start = contract_open + 1
        body_end = contract_close
        drafts = _parse_function_drafts(text, masked, body_start, body_end)
        body_mask = masked[body_start:body_end]
        relative_spans = ((d.start - body_start, d.end - body_start) for d in drafts)
        state_mask = _blank_spans_preserve_newlines(body_mask, relative_spans)
        state_vars = _parse_state_vars(state_mask)

        for draft in drafts:
            body = text[draft.body_start:draft.body_end + 1] if draft.has_body else ""
            state_writes = _detect_state_writes(body, state_vars, draft.params)
            external_calls = _detect_external_calls(body)
            guards = _detect_guards(draft.modifiers, body)
            records.append(
                FunctionRecord(
                    file_path=file_path,
                    contract_name=contract_name,
                    contract_kind=kind,
                    function_name=draft.function_name,
                    function_signature=draft.signature,
                    visibility=draft.visibility,
                    state_mutability=draft.state_mutability,
                    line_start=_line_at(text, draft.start),
                    line_end=_line_at(text, draft.end),
                    modifiers=draft.modifiers,
                    params=draft.params,
                    return_types=draft.return_types,
                    body=body,
                    state_vars=state_vars,
                    state_writes=state_writes,
                    external_calls=external_calls,
                    guards_detected=guards,
                )
            )
    return records


def _function_selector(fn: FunctionRecord) -> str:
    if fn.function_name.startswith("<"):
        return fn.function_name.strip("<>")
    arg_types = ",".join(_abi_type(p.type) for p in fn.params)
    return f"{fn.function_name}({arg_types})"


def _abi_type(sol_type: str) -> str:
    value = _normalize_solidity_type(sol_type)
    value = value.replace(" payable", "")
    value = re.sub(r"\b(contract|interface)\s+", "", value)
    return value or "uint256"


def _zero_expr(sol_type: str) -> str:
    value = _abi_type(sol_type)
    if value.startswith(("uint", "int")):
        return f"{value}(0)" if value != "uint" else "uint256(0)"
    if value == "address":
        return "address(0xCAFE)"
    if value == "bool":
        return "false"
    if value.startswith("bytes") and value != "bytes":
        return f"{value}(0)"
    if value == "bytes":
        return 'bytes("")'
    if value == "string":
        return '""'
    if value.endswith("[]"):
        return f"new {value}(0)"
    return "0"


def _signals(fn: FunctionRecord) -> dict[str, Any]:
    surface = f"{fn.function_name} {fn.function_signature} {fn.body}".lower()
    return {
        "reachable": fn.visibility in {"public", "external"} or fn.function_name in {"<receive>", "<fallback>"},
        "mutating": fn.state_mutability not in {"view", "pure"},
        "payable": fn.state_mutability == "payable" or " payable" in fn.function_signature.lower(),
        "state_write_count": len(fn.state_writes),
        "external_call_count": len(fn.external_calls),
        "has_authority_guard": any(g in {"authority-check", "require-sender"} for g in fn.guards_detected),
        "has_reentrancy_guard": "reentrancy-guard" in fn.guards_detected,
        "has_value_call": any(term in surface for term in VALUE_CALL_TERMS),
        "has_low_level_call": any(term in surface for term in LOW_LEVEL_CALL_TERMS),
        "has_division": "/" in fn.body or "muldiv" in surface,
        "has_oracle_terms": any(term in surface for term in ("oracle", "price", "twap", "reserve", "slot0", "latestrounddata")),
        "has_signature_terms": any(term in surface for term in ("signature", "permit", "ecrecover", "eip712", "nonce")),
        "has_share_terms": any(term in surface for term in ("share", "shares", "asset", "assets", "totalsupply", "balanceof", "deposit", "redeem")),
    }


def _names_surface(fn: FunctionRecord) -> str:
    bits = [
        fn.function_name,
        fn.function_signature,
        " ".join(fn.state_vars),
        " ".join(fn.state_writes),
        " ".join(fn.external_calls),
    ]
    return " ".join(bits).lower()


def _manipulated_state(fn: FunctionRecord, fallback: str) -> str:
    if fn.state_writes:
        return ", ".join(fn.state_writes[:4])
    if fn.state_vars:
        return ", ".join(fn.state_vars[:4])
    return fallback


def _score_cap(value: int) -> int:
    return max(1, min(100, value))


def _candidate_hypotheses(fn: FunctionRecord) -> list[dict[str, Any]]:
    sig = _signals(fn)
    surface = _names_surface(fn)
    body_surface = fn.body.lower()
    candidates: list[dict[str, Any]] = []

    def add(
        attack_class: str,
        score: int,
        attacker_goal: str,
        manipulated_state: str,
        violated_invariant: str,
        required_preconditions: list[str],
        differentiator: str,
        signals: list[str],
    ) -> None:
        candidates.append(
            {
                "attack_class": attack_class,
                "score": _score_cap(score),
                "attacker_goal": attacker_goal,
                "manipulated_state": manipulated_state,
                "violated_invariant": violated_invariant,
                "required_preconditions": required_preconditions[:6],
                "differentiator_against_normal_path": differentiator,
                "signals": signals[:10],
            }
        )

    suspicious_mutator = bool(re.search(r"\b(set|update|mint|burn|withdraw|sweep|rescue|emergency|upgrade|execute|grant|revoke)", surface))
    if sig["reachable"] and sig["mutating"] and not sig["has_authority_guard"] and (fn.state_writes or suspicious_mutator):
        score = 62 + (12 if suspicious_mutator else 0) + min(10, len(fn.state_writes) * 3)
        add(
            "access-control-bypass",
            score,
            "Reach a privileged state transition from an unprivileged caller.",
            _manipulated_state(fn, "privileged configuration or accounting state"),
            "Only authorized actors may mutate privileged or user-owned state.",
            [
                "Function is externally reachable.",
                "No owner/role/sender gate blocks the attacker path.",
                "Target state has value, permissions, or accounting impact.",
            ],
            "Normal path uses the intended privileged actor; adversarial path repeats the same call from attacker and expects identical state reachability to fail.",
            ["external-or-public", "mutating", "no-authority-guard"],
        )

    if sig["reachable"] and sig["mutating"] and fn.external_calls:
        score = 56 + (14 if not sig["has_reentrancy_guard"] else -10) + (10 if fn.state_writes else 0)
        if re.search(r"\b(withdraw|claim|redeem|refund|payout|sweep)", surface):
            score += 8
        if sig["has_value_call"] or sig["has_low_level_call"]:
            score += 8
        add(
            "reentrancy-state-differential",
            score,
            "Re-enter or callback during the external interaction to observe a different state transition than the single-call path.",
            _manipulated_state(fn, "post-call accounting and contract balance"),
            "Accounting effects must be identical whether the callee is passive or adversarially reentrant.",
            [
                "Attacker controls or can route through the external callee/recipient.",
                "The call target can execute code before the function has fully settled state.",
                "A balance, debt, share, or claim value is reusable across the callback boundary.",
            ],
            "Normal path uses a passive recipient/callee; adversarial path uses a recipient/callee that calls back before final accounting settles.",
            ["external-call", "mutating", "callback-capable"],
        )

    if sig["has_share_terms"] or sig["has_division"]:
        score = 46 + (12 if sig["has_division"] else 0) + (8 if sig["mutating"] else 0)
        if re.search(r"\b(deposit|withdraw|mint|redeem|convert|preview)", surface):
            score += 8
        add(
            "precision-rounding-accounting",
            score,
            "Choose asset/share amounts and sequencing that make rounding favor the attacker over the protocol or other users.",
            _manipulated_state(fn, "share price, total supply, balances, and rounding residue"),
            "Equivalent economic positions should not mint, burn, or redeem more value through rounding or donation sequencing.",
            [
                "Function converts between shares/assets or divides proportional accounting state.",
                "Attacker can pre-position balances, donations, or tiny amounts near a rounding boundary.",
                "A normal-sized control path and boundary-sized adversarial path can be compared.",
            ],
            "Normal path uses representative non-boundary amounts; adversarial path uses dust, donation, or supply-skewed amounts around division boundaries.",
            ["share-or-asset-terms", "division-or-conversion"],
        )

    if sig["has_oracle_terms"]:
        score = 52 + (8 if sig["mutating"] else 0)
        add(
            "oracle-manipulation",
            score,
            "Move or stale the price input so the function accepts an economically invalid state transition.",
            "oracle price, reserve snapshot, TWAP window, or freshness marker",
            "Price-dependent state transitions must use bounded, fresh, manipulation-resistant prices.",
            [
                "Function consumes a spot, TWAP, reserve, or oracle price.",
                "Attacker can trade, delay, or select a stale price source before the call.",
                "The downstream state change depends on the manipulated price.",
            ],
            "Normal path uses an honest/fresh price; adversarial path perturbs the price source first and compares collateralization, payout, or mint result.",
            ["oracle-or-price-terms"],
        )

    if sig["has_signature_terms"]:
        writes_nonce = any("nonce" in w.lower() for w in fn.state_writes)
        score = 58 + (10 if not writes_nonce else 0)
        add(
            "signature-replay-or-domain-drift",
            score,
            "Replay, transplant, or malleate an authorization so the function accepts a signature outside its intended domain or nonce epoch.",
            "nonce, signer authorization, domain separator, and consumed signature marker",
            "Each signed authorization must be single-use and bound to the intended chain, contract, signer, and action.",
            [
                "Function verifies signatures, permits, nonces, or EIP-712-style payloads.",
                "Attacker can obtain one valid authorization or replay material.",
                "A distinct domain, caller, nonce, deadline, or calldata path exists for comparison.",
            ],
            "Normal path consumes a fresh signature once; adversarial path reuses or cross-domains the same signature and asserts the second acceptance fails.",
            ["signature-or-nonce-terms"],
        )

    if sig["has_low_level_call"] or ("delegatecall" in body_surface):
        has_target_data = any(
            p.type.startswith(("address", "bytes")) or p.name.lower() in {"target", "to", "data", "calldata"}
            for p in fn.params
        )
        score = 58 + (14 if has_target_data else 0) + (8 if not sig["has_authority_guard"] else 0)
        add(
            "arbitrary-call-surface",
            score,
            "Steer target, calldata, or value so the function performs an unintended external action.",
            "call target, calldata payload, forwarded value, and authorization context",
            "User-controlled call surfaces must not escape allowlists, selector checks, or value bounds.",
            [
                "Function performs low-level call/delegatecall/staticcall or forwards arbitrary calldata.",
                "Attacker controls target, payload, value, or an adapter-selected route.",
                "A benign allowlisted target and adversarial target can be executed side by side.",
            ],
            "Normal path targets an expected integration; adversarial path swaps target/calldata/value to a capability the normal route should never reach.",
            ["low-level-call", "target-or-data-surface"],
        )

    if re.search(r"\b(executeoperation|flash|callback|onerc|ontransfer|hook|uniswapv\d+call|receive|fallback)", surface):
        score = 54 + (8 if sig["mutating"] else 0) + (8 if fn.external_calls else 0)
        add(
            "callback-origin-differential",
            score,
            "Invoke the callback from an unexpected origin or phase to make callback-only logic run outside its intended transaction envelope.",
            _manipulated_state(fn, "callback phase state and transient balances"),
            "Callback handlers must be bound to the expected initiator, asset, and active operation.",
            [
                "Function is a callback, hook, fallback, or flash-loan-style entrypoint.",
                "Attacker can call the callback directly or through a spoofed integration.",
                "The normal flow has an expected initiator/phase that can be compared.",
            ],
            "Normal path enters through the intended upstream protocol; adversarial path directly invokes or spoofs the callback origin and checks state parity.",
            ["callback-or-hook-name"],
        )

    if re.search(r"\b(bridge|crosschain|cross_chain|message|merkle|proof|root|withdraw|mint)", surface) and (
        "proof" in surface or "message" in surface or "bridge" in surface or "merkle" in surface
    ):
        score = 50 + (10 if sig["mutating"] else 0)
        add(
            "bridge-message-validation",
            score,
            "Craft a message/proof shape that passes local validation but represents a different source-domain action.",
            "processed-message marker, source domain, recipient, amount, and minted/released supply",
            "A bridge action must be unique, source-bound, and equivalent to the verified remote state transition.",
            [
                "Function validates messages, proofs, roots, or cross-domain withdrawal/mint data.",
                "Attacker can vary source chain, nonce, recipient, token, or proof encoding.",
                "Normal and adversarial messages can share surface fields while differing in binding fields.",
            ],
            "Normal path uses a canonical message; adversarial path mutates one binding field and expects validation or replay marking to diverge safely.",
            ["bridge-message-or-proof-terms"],
        )

    if re.search(r"\b(vote|proposal|quorum|timelock|execute|veto|delegate)", surface):
        score = 48 + (10 if sig["mutating"] else 0)
        add(
            "governance-timing-bypass",
            score,
            "Manipulate proposal timing, vote weight, delegation, or execution ordering to bypass the intended governance state machine.",
            "proposal status, vote weight snapshot, quorum, and timelock readiness",
            "Governance execution must require the same quorum, delay, and snapshot constraints on every path.",
            [
                "Function touches proposal, vote, quorum, delegation, or timelock state.",
                "Attacker can choose block timing, delegation state, or execution ordering.",
                "A normal proposal lifecycle can be compared against a skipped or reordered lifecycle.",
            ],
            "Normal path follows create-vote-queue-execute; adversarial path reorders timing/delegation and asserts execution state remains blocked.",
            ["governance-terms"],
        )

    if re.search(r"\b(liquidat|collateral|debt|borrow|health|solvenc|margin)", surface):
        score = 48 + (10 if sig["mutating"] else 0)
        add(
            "liquidation-solvency-differential",
            score,
            "Manipulate debt, collateral, or price sequencing so an insolvent or healthy position is handled as the opposite state.",
            "collateral balance, debt index, health factor, and liquidation payout",
            "Liquidation eligibility and payout must match the protocol solvency model under equivalent economic states.",
            [
                "Function uses debt/collateral/health or liquidation terms.",
                "Attacker can change price, interest index, repayment, or collateral ordering.",
                "A control account and adversarially sequenced account can be compared.",
            ],
            "Normal path liquidates or rejects a canonical account; adversarial path sequences price/index/collateral changes and checks the eligibility/payout differential.",
            ["debt-collateral-terms"],
        )

    if re.search(r"\b(initializ|upgrade|implementation|proxy|beacon|diamondcut)", surface):
        score = 56 + (10 if not sig["has_authority_guard"] else 0)
        add(
            "initialization-upgrade-takeover",
            score,
            "Reach an initialization or upgrade transition from the wrong actor or lifecycle phase.",
            "implementation pointer, initialized flag, owner/admin slot, or facet set",
            "Initialization and upgrade state may only change once and only through the intended authority.",
            [
                "Function initializes, upgrades, or changes implementation/facet/admin state.",
                "Attacker can call before/after the intended lifecycle transition or through a proxy surface.",
                "The normal deployment/upgrade actor is distinct from the adversarial actor.",
            ],
            "Normal path performs the deployment/upgrade sequence once; adversarial path repeats, front-runs, or calls through another surface and asserts ownership/implementation is unchanged.",
            ["upgrade-or-initializer-terms"],
        )

    if not candidates:
        if sig["mutating"]:
            add(
                "state-transition-differential",
                28 + (8 if sig["reachable"] else 0),
                "Find a call sequence where this function mutates different state than the documented happy path.",
                _manipulated_state(fn, "function-local state dependencies"),
                "Equivalent pre-state and inputs should lead to equivalent post-state except for expected actor-specific fields.",
                [
                    "Establish a normal pre-state for the function.",
                    "Vary actor, ordering, boundary inputs, or dependent state before the adversarial call.",
                    "Compare post-state against the normal-path invariant.",
                ],
                "Normal path uses the intended actor and ordinary values; adversarial path perturbs actor/order/boundary values and compares state deltas.",
                ["fallback-generic-mutating"],
            )
        else:
            add(
                "read-path-differential",
                20,
                "Identify whether view/helper output diverges under adversarially prepared state.",
                _manipulated_state(fn, "read dependencies and cached state"),
                "Read-only outputs should report the same value for economically equivalent state.",
                [
                    "Prepare two economically equivalent states.",
                    "Manipulate cached, rounded, stale, or boundary state before the adversarial read.",
                    "Compare the view result against the normal reference result.",
                ],
                "Normal path reads from a canonical state; adversarial path reads after boundary or stale-state preparation and asserts output parity.",
                ["fallback-generic-read"],
            )

    candidates.sort(key=lambda row: (-int(row["score"]), str(row["attack_class"])))
    return candidates


def _hypothesis_id(fn: FunctionRecord, attack_class: str) -> str:
    raw = "|".join([fn.file_path, fn.contract_name, fn.function_name, fn.function_signature, attack_class])
    return "AHDH-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def foundry_test_skeleton(fn: FunctionRecord, hypothesis: dict[str, Any]) -> str:
    class_slug = _slug(f"{fn.contract_name}_{fn.function_name}_{hypothesis['attack_class']}")[:70]
    test_slug = _slug(f"{fn.function_name}_{hypothesis['attack_class']}")[:80]
    selector = _function_selector(fn)
    args = ", ".join(_zero_expr(p.type) for p in fn.params)
    encoded = f'abi.encodeWithSignature("{selector}"{", " + args if args else ""})'
    preconditions = "; ".join(hypothesis.get("required_preconditions") or [])[:260]
    manipulated = str(hypothesis.get("manipulated_state") or "target state")[:180]
    invariant = str(hypothesis.get("violated_invariant") or "target invariant")[:220]
    return "\n".join(
        [
            "// SPDX-License-Identifier: UNLICENSED",
            "pragma solidity ^0.8.20;",
            "",
            'import "forge-std/Test.sol";',
            "",
            f"contract AHDH_{class_slug}Test is Test {{",
            "    address internal target = address(0xBEEF);",
            "    address internal attacker = address(0xA11CE);",
            "    address internal normalUser = address(0xB0B);",
            "",
            f"    function test_AHDH_{test_slug}() public {{",
            f"        bytes memory normalCall = {encoded};",
            "        vm.prank(normalUser);",
            "        (bool normalOk, ) = target.call(normalCall);",
            "        normalOk;",
            "",
            f"        // TODO: prepare adversarial preconditions: {preconditions}",
            f"        // TODO: manipulate state surface: {manipulated}",
            "        bytes memory adversarialCall = normalCall;",
            "        vm.startPrank(attacker);",
            "        (bool adversarialOk, ) = target.call(adversarialCall);",
            "        vm.stopPrank();",
            "        adversarialOk;",
            "",
            f"        // Differential assertion: adversarial path must not violate: {invariant}",
            "        // TODO: assertEq(normalInvariant, adversarialInvariant);",
            "    }",
            "}",
        ]
    )


def _slug(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_]+", "_", value.replace("<", "").replace(">", ""))
    value = re.sub(r"_+", "_", value).strip("_")
    if not value:
        return "hypothesis"
    if value[0].isdigit():
        value = "_" + value
    return value


def build_hypotheses_for_function(
    fn: FunctionRecord,
    *,
    max_hypotheses: int = DEFAULT_MAX_HYPOTHESES_PER_FUNCTION,
    emit_foundry_skeleton: bool = False,
) -> list[dict[str, Any]]:
    rows = _candidate_hypotheses(fn)[: max(1, max_hypotheses)]
    out: list[dict[str, Any]] = []
    for idx, row in enumerate(rows, start=1):
        hyp = dict(row)
        hyp["id"] = _hypothesis_id(fn, str(row["attack_class"]))
        hyp["rank"] = idx
        hyp["source_ref"] = f"{fn.file_path}:{fn.line_start}"
        hyp["function"] = {
            "file_path": fn.file_path,
            "contract_name": fn.contract_name,
            "function_name": fn.function_name,
            "function_signature": fn.function_signature,
        }
        if emit_foundry_skeleton:
            hyp["foundry_test_skeleton"] = foundry_test_skeleton(fn, hyp)
        out.append(hyp)
    return out


def _function_to_dict(fn: FunctionRecord, hypotheses: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "file_path": fn.file_path,
        "contract_name": fn.contract_name,
        "contract_kind": fn.contract_kind,
        "function_name": fn.function_name,
        "function_signature": fn.function_signature,
        "visibility": fn.visibility,
        "state_mutability": fn.state_mutability,
        "line_start": fn.line_start,
        "line_end": fn.line_end,
        "modifiers": list(fn.modifiers),
        "params": [{"name": p.name, "type": p.type} for p in fn.params],
        "return_types": list(fn.return_types),
        "state_vars": list(fn.state_vars[:20]),
        "state_writes": list(fn.state_writes),
        "external_calls": list(fn.external_calls),
        "guards_detected": list(fn.guards_detected),
        "signals": _signals(fn),
        "hypotheses": hypotheses,
    }


def _iter_solidity_sources(paths: Iterable[Path], warnings: list[str]) -> list[Path]:
    out: list[Path] = []
    seen: set[Path] = set()
    for raw in paths:
        path = Path(raw)
        if not path.exists():
            warnings.append(f"source path not found: {path}")
            continue
        if path.is_dir():
            for child in sorted(path.rglob("*.sol")):
                rel_parts = set(child.relative_to(path).parts[:-1])
                if rel_parts & SKIP_DIRS:
                    continue
                if child.name.endswith((".t.sol", ".s.sol")):
                    continue
                resolved = child.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    out.append(child)
            continue
        if path.suffix != ".sol":
            warnings.append(f"skipping non-Solidity source: {path}")
            continue
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            out.append(path)
    return sorted(out, key=lambda p: str(p))


def _read_source(path: Path, max_source_bytes: int, warnings: list[str]) -> str | None:
    try:
        data = path.read_bytes()
    except OSError as exc:
        warnings.append(f"could not read {path}: {exc}")
        return None
    if len(data) > max_source_bytes:
        warnings.append(f"truncated {path} to {max_source_bytes} bytes for bounded parsing")
        data = data[:max_source_bytes]
    return data.decode("utf-8", errors="replace")


def _records_from_sources(paths: Iterable[Path], *, max_source_bytes: int, warnings: list[str]) -> list[FunctionRecord]:
    records: list[FunctionRecord] = []
    for path in _iter_solidity_sources(paths, warnings):
        text = _read_source(path, max_source_bytes, warnings)
        if text is None:
            continue
        parsed = parse_solidity_source(text, str(path))
        if not parsed:
            warnings.append(f"no Solidity functions parsed from {path}")
        records.extend(parsed)
    return records


def _load_manifest_records(path: Path, warnings: list[str]) -> list[FunctionRecord]:
    if not path.exists():
        warnings.append(f"manifest not found: {path}")
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        warnings.append(f"could not read manifest {path}: {exc}")
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        warnings.append(f"manifest is not valid JSON: {path}: {exc}")
        return []
    if isinstance(data, dict):
        raw_rows = data.get("functions") or data.get("records") or data.get("items") or []
        manifest_state = data.get("state_vars") or data.get("state_variables") or []
    elif isinstance(data, list):
        raw_rows = data
        manifest_state = []
    else:
        warnings.append(f"manifest root must be object or list: {path}")
        return []
    if not isinstance(raw_rows, list):
        warnings.append(f"manifest functions/records/items must be a list: {path}")
        return []

    records: list[FunctionRecord] = []
    for idx, raw in enumerate(raw_rows):
        if not isinstance(raw, dict):
            warnings.append(f"manifest row {idx} is not an object")
            continue
        records.append(_record_from_manifest_row(raw, path, idx, manifest_state))
    return records


def _manifest_list(value: Any) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(v) for v in value if str(v))
    if isinstance(value, str) and value.strip():
        return tuple(part.strip() for part in value.split(",") if part.strip())
    return ()


def _manifest_params(value: Any, signature: str) -> tuple[Param, ...]:
    if isinstance(value, list):
        params: list[Param] = []
        for row in value:
            if isinstance(row, dict):
                params.append(Param(name=str(row.get("name") or ""), type=str(row.get("type") or "")))
            elif isinstance(row, str):
                parsed = parse_params(row)
                params.extend(parsed)
        if params:
            return tuple(params)
    open_pos = signature.find("(")
    close_pos = _find_matching_pair(signature, open_pos, "(", ")") if open_pos != -1 else -1
    if open_pos != -1 and close_pos != -1:
        return parse_params(signature[open_pos + 1:close_pos])
    return ()


def _record_from_manifest_row(raw: dict[str, Any], manifest_path: Path, idx: int, manifest_state: Any) -> FunctionRecord:
    signature = str(raw.get("function_signature") or raw.get("signature") or "")
    name = str(raw.get("function_name") or raw.get("name") or "")
    if not name and signature:
        match = re.search(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", signature)
        if match:
            name = match.group(1)
    if not signature and name:
        signature = f"function {name}(...)"
    params = _manifest_params(raw.get("params") or raw.get("parameters"), signature)
    body = str(raw.get("body") or raw.get("function_body") or "")
    state_vars = _manifest_list(raw.get("state_vars") or raw.get("state_variables") or manifest_state)
    modifiers = _manifest_list(raw.get("modifiers"))
    external_calls = _manifest_list(raw.get("external_calls") or raw.get("calls_made"))
    guards = _manifest_list(raw.get("guards_detected") or raw.get("guards"))
    state_writes = _manifest_list(raw.get("state_writes") or raw.get("writes"))
    if not state_writes:
        state_writes = _detect_state_writes(body, state_vars, params)
    if not external_calls and body:
        external_calls = _detect_external_calls(body)
    if not guards:
        guards = _detect_guards(modifiers, body)
    return FunctionRecord(
        file_path=str(raw.get("file_path") or raw.get("path") or manifest_path),
        contract_name=str(raw.get("contract_name") or raw.get("contract") or ""),
        contract_kind=str(raw.get("contract_kind") or "contract"),
        function_name=name or f"manifest_row_{idx}",
        function_signature=signature,
        visibility=str(raw.get("visibility") or _visibility_from_signature(signature, default="unknown")),
        state_mutability=str(raw.get("state_mutability") or _mutability_from_signature(signature)),
        line_start=int(raw.get("line_start") or raw.get("line") or 0),
        line_end=int(raw.get("line_end") or raw.get("line") or 0),
        modifiers=modifiers,
        params=params,
        return_types=_manifest_list(raw.get("return_types") or raw.get("returns")) or _extract_return_types(signature),
        body=body,
        state_vars=state_vars,
        state_writes=state_writes,
        external_calls=external_calls,
        guards_detected=guards,
    )


def build_payload(
    source_paths: Iterable[str | Path] | None = None,
    *,
    manifest_path: str | Path | None = None,
    emit_foundry_skeleton: bool = False,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_hypotheses_per_function: int = DEFAULT_MAX_HYPOTHESES_PER_FUNCTION,
    max_source_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
) -> dict[str, Any]:
    warnings: list[str] = []
    paths = [Path(p) for p in (source_paths or [])]
    records: list[FunctionRecord] = []
    if manifest_path:
        records.extend(_load_manifest_records(Path(manifest_path), warnings))
    records.extend(_records_from_sources(paths, max_source_bytes=max_source_bytes, warnings=warnings))

    if not records and not paths and not manifest_path:
        warnings.append("no Solidity source paths or JSON function manifest provided")

    records.sort(key=lambda fn: (fn.file_path, fn.line_start, fn.contract_name, fn.function_name, fn.function_signature))
    truncated = False
    max_functions = max(0, max_functions)
    if max_functions and len(records) > max_functions:
        records = records[:max_functions]
        truncated = True
        warnings.append(f"function output truncated to {max_functions} records")

    functions: list[dict[str, Any]] = []
    flat_hypotheses: list[dict[str, Any]] = []
    for fn in records:
        hypotheses = build_hypotheses_for_function(
            fn,
            max_hypotheses=max_hypotheses_per_function,
            emit_foundry_skeleton=emit_foundry_skeleton,
        )
        functions.append(_function_to_dict(fn, hypotheses))
        flat_hypotheses.extend(hypotheses)

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "advisory_only": True,
        "claim_scope": "hypothesis_generation_only",
        "inputs": {
            "sources": [str(p) for p in paths],
            "manifest": str(manifest_path) if manifest_path else "",
            "emit_foundry_skeleton": bool(emit_foundry_skeleton),
            "max_functions": max_functions,
            "max_hypotheses_per_function": max_hypotheses_per_function,
            "max_source_bytes": max_source_bytes,
        },
        "summary": {
            "function_count": len(functions),
            "hypotheses_count": len(flat_hypotheses),
            "warnings_count": len(warnings),
            "truncated": truncated,
        },
        "warnings": warnings,
        "functions": functions,
        "hypotheses": flat_hypotheses,
        "limitations": [
            "Regex parser is best-effort and does not replace solc or a full AST.",
            "Hypotheses are deterministic attack ideas, not exploitability verdicts.",
            "Foundry skeletons are starting points; target deployment and invariant assertions remain TODOs.",
        ],
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    payload["context_pack_hash"] = digest
    payload["context_pack_id"] = f"{SCHEMA}:{digest[:16]}"
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", nargs="*", help="Solidity source file(s) or directories")
    parser.add_argument("--manifest", type=Path, help="JSON function manifest with functions/records/items")
    parser.add_argument("--out", type=Path, help="Write JSON payload to this path instead of stdout")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    parser.add_argument("--emit-foundry-skeleton", action="store_true", help="Include a Foundry differential test skeleton per hypothesis")
    parser.add_argument("--max-functions", type=int, default=DEFAULT_MAX_FUNCTIONS, help="Maximum functions to emit")
    parser.add_argument(
        "--max-hypotheses-per-function",
        type=int,
        default=DEFAULT_MAX_HYPOTHESES_PER_FUNCTION,
        help="Maximum ranked hypotheses per function",
    )
    parser.add_argument("--max-source-bytes", type=int, default=DEFAULT_MAX_SOURCE_BYTES, help="Maximum bytes read from each Solidity source")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = build_payload(
        args.sources,
        manifest_path=args.manifest,
        emit_foundry_skeleton=args.emit_foundry_skeleton,
        max_functions=args.max_functions,
        max_hypotheses_per_function=args.max_hypotheses_per_function,
        max_source_bytes=args.max_source_bytes,
    )
    text = json.dumps(payload, indent=2 if args.pretty else None, sort_keys=bool(args.pretty))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
