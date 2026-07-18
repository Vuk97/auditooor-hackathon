"""
paymaster-sender-validation-tocu-fire30

Regex API detector for account abstraction, paymaster, and router paths that
validate one sender, owner, or account before a state-changing boundary, then
charge, sponsor, or mutate a different actor.

Source refs:
- reports/detector_lift_fire29_20260605/post_priorities_solidity.md
- reference/patterns.dsl/state-change-between-check-and-use-token-delta-boundary.yaml
- reference/patterns.dsl/erc4337-paymaster-no-sender-validation.yaml
- reference/patterns.dsl/state-check-before-token-or-sender-mutation.yaml

This is candidate evidence only. It requires AA, paymaster, sponsorship, or
router vocabulary, an actor validation check, a later effect boundary, and an
actor-keyed charge or mutation that is not keyed to any actor validated by the
pre-boundary check.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "paymaster-sender-validation-tocu-fire30"
DETECTOR_SEVERITY_DEFAULT = "Medium"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


@dataclass
class FunctionSlice:
    name: str
    header: str
    body: str
    line: int


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CALLABLE_RE = re.compile(r"\b(?:external|public)\b")
_SURFACE_RE = re.compile(
    r"(?is)\b("
    r"UserOperation|PackedUserOperation|validatePaymasterUserOp|postOp|"
    r"paymaster|EntryPoint|sponsor|sponsored|sponsorship|account abstraction|"
    r"executeBatch|batchExecute|delegatecall|router|accountOwner"
    r")\b"
)
_VALIDATION_NAME_RE = re.compile(
    r"(?i)^(?:_?validatePaymasterUserOp|_?validate[A-Za-z0-9_]*(?:UserOp|Account|Sender|Owner|Sponsor|Route))$"
)
_POSTOP_OR_CHARGE_NAME_RE = re.compile(
    r"(?i)^(?:_?postOp|_?charge[A-Za-z0-9_]*|_?debit[A-Za-z0-9_]*|"
    r"_?consume[A-Za-z0-9_]*|_?spend[A-Za-z0-9_]*|_?record[A-Za-z0-9_]*)$"
)
_CHECK_RE = re.compile(r"(?is)\b(?P<kind>require|assert|if)\s*\((?P<expr>[^;{}]*)\)")
_CHECK_POLICY_RE = re.compile(
    r"(?i)\b("
    r"allow|allowed|whitelist|whiteList|approved|authorized|eligible|owner|"
    r"sender|account|wallet|user|sponsor|sponsored|quota|budget|limit|"
    r"policy|permission|class|tier|balance|deposit|valid"
    r")\b"
)
_ACTOR_NAME_RE = re.compile(
    r"(?i)^(?:"
    r"sender|owner|account|wallet|user|userAccount|payer|sponsor|beneficiary|"
    r"receiver|recipient|relayer|executor|operator|signer|validatedSender|"
    r"validatedOwner|checkedSender|checkedOwner|checkedAccount|actualSender|"
    r"actualOwner|from|payerAccount"
    r")$"
)
_ACTOR_FRAGMENT_RE = re.compile(
    r"(?i)(sender|owner|account|wallet|user|payer|sponsor|beneficiary|receiver|"
    r"recipient|relayer|executor|operator|signer)"
)
_DOTTED_ACTOR_RE = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*"
    r"(?:sender|owner|account|wallet|user|payer|sponsor|from)\b",
    re.IGNORECASE,
)
_ADDRESS_PARAM_RE = re.compile(
    r"\baddress(?:\s+payable)?\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_BRACKET_KEY_RE = re.compile(r"\[\s*(?P<key>[^\]\n;]{1,120})\s*\]")
_BOUNDARY_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*"
    r"(?:call|delegatecall|functionCall|execute[A-Za-z0-9_]*|route[A-Za-z0-9_]*|"
    r"swap[A-Za-z0-9_]*|sponsor[A-Za-z0-9_]*|before[A-Za-z0-9_]*|"
    r"after[A-Za-z0-9_]*|validate[A-Za-z0-9_]*)\s*\(|"
    r"\b(?:call|delegatecall|functionCall|safeTransferFrom|transferFrom|"
    r"safeTransfer|transfer|execute|executeBatch|batchExecute|route|"
    r"routeCall|sponsor|sponsorFor)\s*\("
    r")"
)
_STATE_NAME_RE = (
    r"(?:"
    r"[A-Za-z_][A-Za-z0-9_]*(?:Debt|debt|Charge|charge|Charged|charged|"
    r"Quota|quota|Budget|budget|Sponsor|sponsor|Sponsored|sponsored|"
    r"Balance|balance|Spent|spent|Gas|gas|Deposit|deposit|Usage|usage|"
    r"Used|used|Nonce|nonce|Mutation|mutation|Allowance|allowance)"
    r"[A-Za-z0-9_]*|"
    r"debt|charged|quota|budget|sponsored|spent|gasUsed|deposit|usage|used"
    r")"
)
_MAPPING_MUTATION_RE = re.compile(
    rf"(?is)\b(?P<state>{_STATE_NAME_RE})\s*"
    r"\[\s*(?P<actor>[^\]\n;]{1,120})\s*\]\s*"
    r"(?:=|\+=|-=|\+\+|--)"
)
_CALL_MUTATION_RE = re.compile(
    r"(?is)\b(?P<name>"
    r"charge|debit|credit|sponsor|sponsorFor|consume|spend|record|bill|"
    r"settle|mutate|markSponsored|recordGas|chargeGas"
    r")[A-Za-z0-9_]*\s*\((?P<args>[^;{}]*)\)"
)
_SUCCESS_RE = re.compile(
    r"(?is)\b(SIG_VALIDATION_SUCCESS|validationData|return\s*\([^;]*(?:0|bytes32\s*\(\s*0\s*\)))"
)
_ABI_ENCODE_RE = re.compile(r"(?is)\babi\.encode(?:Packed)?\s*\((?P<args>[^;{}]*)\)")
_ABI_DECODE_ADDRESS_RE = re.compile(
    r"(?is)\babi\.decode\s*\([^;{}]*context[^;{}]*,\s*\([^)]*\baddress\b"
)
_POST_BOUNDARY_REVALIDATION_RE = re.compile(
    r"(?i)\b(revalidate|validateAfter|senderAfter|ownerAfter|accountAfter|"
    r"policyAfter|quotaAfter|freshSender|freshOwner|freshAccount)\b"
)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    if open_brace < 0 or open_brace >= len(source) or source[open_brace] != "{":
        return None, open_brace
    depth = 1
    i = open_brace + 1
    while i < len(source) and depth > 0:
        char = source[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        i += 1
    if depth != 0:
        return None, open_brace
    return source[open_brace + 1:i - 1], i


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        i = match.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            char = source[i]
            if char == "(":
                depth_paren += 1
            elif char == ")":
                depth_paren -= 1
            i += 1

        body_start = -1
        j = i
        while j < len(source):
            if source[j] == ";":
                break
            if source[j] == "{":
                body_start = j
                break
            j += 1
        if body_start < 0:
            pos = max(j, i)
            continue

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        line = source.count("\n", 0, match.start()) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, line=line))
        pos = end_pos
    return out


def _line_for_body_match(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.line + fn.body.count("\n", 0, match.start())


def _normalise_expr(expr: str) -> str:
    out = re.sub(r"\s+", "", expr or "")
    out = re.sub(r"^(?:address|payable)\((.*)\)$", r"\1", out)
    return out


def _expr_regex(expr: str) -> str:
    return r"\s*\.\s*".join(re.escape(part) for part in _normalise_expr(expr).split("."))


def _identity_re(identity: str) -> re.Pattern[str]:
    norm = _normalise_expr(identity)
    if "." in norm:
        return re.compile(_expr_regex(norm))
    return re.compile(rf"\b{re.escape(norm)}\b")


def _contains_identity(text: str, identities: list[str]) -> bool:
    return any(_identity_re(identity).search(text) for identity in identities)


def _split_args(args: str) -> list[str]:
    out: list[str] = []
    start = 0
    depth = 0
    for idx, char in enumerate(args or ""):
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth > 0:
            depth -= 1
        elif char == "," and depth == 0:
            out.append(args[start:idx].strip())
            start = idx + 1
    tail = args[start:].strip()
    if tail:
        out.append(tail)
    return out


def _header_actor_params(header: str) -> list[str]:
    params: list[str] = []
    for match in _ADDRESS_PARAM_RE.finditer(header):
        name = match.group("name")
        if _ACTOR_NAME_RE.search(name) or _ACTOR_FRAGMENT_RE.search(name):
            if name not in params:
                params.append(name)
    return params


def _actorish_identifier(token: str) -> bool:
    token = token.strip()
    return bool(_ACTOR_NAME_RE.search(token) or _ACTOR_FRAGMENT_RE.search(token))


def _clean_actor_expr(expr: str) -> str:
    actor = _normalise_expr(expr)
    actor = re.sub(r"^(?:address|payable)\((.*)\)$", r"\1", actor)
    actor = actor.strip()
    return actor


def _is_simple_actor_expr(expr: str) -> bool:
    actor = _clean_actor_expr(expr)
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?", actor))


def _checked_identities(fn: FunctionSlice, expr: str) -> list[str]:
    identities: list[str] = []
    ignored_idents: set[str] = set()

    def add(identity: str) -> None:
        identity = _clean_actor_expr(identity)
        if not identity or not _is_simple_actor_expr(identity):
            return
        if identity in {"address", "this", "block.timestamp", "block.number"}:
            return
        if identity not in identities:
            identities.append(identity)

    for match in _DOTTED_ACTOR_RE.finditer(expr):
        dotted = match.group(0)
        add(dotted)
        ignored_idents.update(part.strip() for part in dotted.split("."))

    for map_match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\[", expr):
        ignored_idents.add(map_match.group(1))

    for match in _BRACKET_KEY_RE.finditer(expr):
        key = match.group("key").strip()
        if _is_simple_actor_expr(key) and _actorish_identifier(key.split(".")[-1]):
            add(key)
            if "." in key:
                ignored_idents.update(part.strip() for part in key.split("."))

    for param in _header_actor_params(fn.header):
        if _identity_re(param).search(expr):
            add(param)

    for ident in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expr):
        if ident in ignored_idents:
            continue
        if _actorish_identifier(ident):
            add(ident)

    return identities


def _check_matches_actor_policy(fn: FunctionSlice, match: re.Match[str]) -> list[str]:
    expr = match.group("expr")
    tail = fn.body[match.end():match.end() + 180]
    if not _CHECK_POLICY_RE.search(expr + tail):
        return []
    return _checked_identities(fn, expr)


def _context_binds_checked_actor(fn: FunctionSlice, checked: list[str]) -> bool:
    for match in _ABI_ENCODE_RE.finditer(fn.body):
        if _contains_identity(match.group("args"), checked):
            return True
    return False


def _actor_is_ignored_protocol_sink(actor: str) -> bool:
    actor = _clean_actor_expr(actor)
    return actor in {
        "address(this)",
        "this",
        "entryPoint",
        "ENTRY_POINT",
        "paymaster",
        "feeReceiver",
        "treasury",
    }


def _different_actor(actor: str, checked: list[str]) -> bool:
    actor = _clean_actor_expr(actor)
    if not _is_simple_actor_expr(actor):
        return False
    if _actor_is_ignored_protocol_sink(actor):
        return False
    checked_norm = {_clean_actor_expr(identity) for identity in checked}
    if actor in checked_norm:
        return False
    if any(_identity_re(actor).search(identity) for identity in checked_norm):
        return False
    if actor in {"msg.sender", "tx.origin"}:
        return True
    leaf = actor.split(".")[-1]
    return _actorish_identifier(leaf) or _actorish_identifier(actor)


def _mutation_candidates(text: str) -> list[tuple[re.Match[str], str, str]]:
    out: list[tuple[re.Match[str], str, str]] = []
    for match in _MAPPING_MUTATION_RE.finditer(text):
        out.append((match, match.group("actor"), f"{match.group('state')}[{match.group('actor').strip()}]"))
    for match in _CALL_MUTATION_RE.finditer(text):
        args = _split_args(match.group("args"))
        if not args:
            continue
        actor = args[0]
        out.append((match, actor, f"{match.group('name')}({actor.strip()}, ...)"))
    return sorted(out, key=lambda item: item[0].start())


def _first_wrong_actor_mutation(text: str, checked: list[str]) -> tuple[re.Match[str], str, str] | None:
    for match, actor, detail in _mutation_candidates(text):
        if _different_actor(actor, checked):
            return match, _clean_actor_expr(actor), detail
    return None


def _has_post_boundary_revalidation(segment: str, checked: list[str]) -> bool:
    if _POST_BOUNDARY_REVALIDATION_RE.search(segment):
        return True
    for match in _CHECK_RE.finditer(segment):
        expr = match.group("expr")
        if _contains_identity(expr, checked):
            return True
    return False


def _match_same_function(fn: FunctionSlice) -> tuple[int, str] | None:
    if not _CALLABLE_RE.search(fn.header):
        return None

    for check in _CHECK_RE.finditer(fn.body):
        checked = _check_matches_actor_policy(fn, check)
        if not checked:
            continue
        boundary = _BOUNDARY_RE.search(fn.body, check.end())
        if boundary is None:
            continue
        after_boundary = fn.body[boundary.end():]
        wrong = _first_wrong_actor_mutation(after_boundary, checked)
        if wrong is None:
            continue
        mutation_match, actor, detail = wrong
        before_mutation = after_boundary[:mutation_match.start()]
        if _has_post_boundary_revalidation(before_mutation, checked):
            continue
        line = _line_for_body_match(fn, check)
        return (
            line,
            "checked "
            + ", ".join(checked)
            + " before an AA, paymaster, or router effect boundary, then mutated "
            + detail
            + f" keyed to different actor {actor}",
        )
    return None


def _validation_checks(fn: FunctionSlice) -> list[tuple[re.Match[str], list[str]]]:
    checks: list[tuple[re.Match[str], list[str]]] = []
    if not _CALLABLE_RE.search(fn.header):
        return checks
    if not _VALIDATION_NAME_RE.search(fn.name):
        return checks
    for check in _CHECK_RE.finditer(fn.body):
        checked = _check_matches_actor_policy(fn, check)
        if checked:
            checks.append((check, checked))
    return checks


def _postop_decodes_address_and_uses_sender(fn: FunctionSlice) -> bool:
    if not _ABI_DECODE_ADDRESS_RE.search(fn.body):
        return False
    sender_like = ["sender", "owner", "account", "wallet", "user", "payer"]
    return any(_contains_identity(detail, sender_like) for _, _, detail in _mutation_candidates(fn.body))


def _postop_wrong_actor_detail(fn: FunctionSlice, checked: list[str]) -> tuple[str, str] | None:
    if _postop_decodes_address_and_uses_sender(fn):
        return None
    wrong = _first_wrong_actor_mutation(fn.body, checked)
    if wrong is None:
        return None
    _, actor, detail = wrong
    return actor, detail


def _match_validation_to_postop(
    fn: FunctionSlice,
    post_ops: list[FunctionSlice],
) -> tuple[int, str] | None:
    for check, checked in _validation_checks(fn):
        if _context_binds_checked_actor(fn, checked):
            continue
        if _SUCCESS_RE.search(fn.body) is None:
            continue
        for post_op in post_ops:
            detail = _postop_wrong_actor_detail(post_op, checked)
            if detail is None:
                continue
            actor, mutation = detail
            line = _line_for_body_match(fn, check)
            return (
                line,
                "checked "
                + ", ".join(checked)
                + " during paymaster validation, but returned context without that actor "
                + f"while later `{post_op.name}` mutates {mutation} keyed to {actor}",
            )
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    findings: list[Finding] = []
    if not _SURFACE_RE.search(source or ""):
        return findings

    clean_source = _strip_comments_and_strings(source)
    if not _SURFACE_RE.search(clean_source):
        return findings

    functions = _split_functions(clean_source)
    post_ops = [fn for fn in functions if _POSTOP_OR_CHARGE_NAME_RE.search(fn.name)]
    seen: set[tuple[str, int, str]] = set()

    for fn in functions:
        matches = [_match_same_function(fn), _match_validation_to_postop(fn, post_ops)]
        for matched in matches:
            if matched is None:
                continue
            line, reason = matched
            key = (fn.name, line, reason)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` has a sender validation check-use boundary: "
                        f"{reason}. Carry the checked actor through the effect "
                        "boundary and key charge, sponsorship, and mutation state "
                        "to that same actor."
                    ),
                )
            )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
