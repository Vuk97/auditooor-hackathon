"""
oracle-cached-baseline-mutation-fire29

Regex detector for Solidity oracle paths where deviation, stale, or threshold
checks compare the current oracle value against a cache-like baseline that the
same public or external transaction path can reset or overwrite.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:1fbd7a4998da1f42
- context_pack_hash: 1fbd7a4998da1f424cce0858c69a5dd246edb458f1cb9f1927dd25e36d73cb98
- source ref: reference/patterns.dsl.zellic_k2_mined/oracle-config-changes-do-not-invalidate-cached-prices.yaml
- source ref: reference/patterns.dsl.zellic_k2_mined/stale-price-cache-bypasses-oracle-config-changes.yaml
- source ref: reference/patterns.dsl.zellic_k2_mined/cached-oracle-prices-ignore-per-asset-freshness-limits.yaml
- attack_class: oracle-price-manipulation

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "oracle-cached-baseline-mutation-fire29"
DETECTOR_SEVERITY_DEFAULT = "High"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_ENTRY_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_PURE_OR_VIEW_RE = re.compile(r"\b(?:pure|view)\b")
_ORACLE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:oracle|price|feed|aggregator|chainlink|pyth|redstone|twap|"
    r"deviation|stale|fresh|heartbeat|threshold|maxAge|maxStale|cache|cached|"
    r"baseline|reference|snapshot|lastGood|liquidat|borrow|collateral|debt|"
    r"solvency|health|quote|swap|mint|redeem)\w*\b"
)
_VALIDATION_CONTEXT_RE = re.compile(
    r"(?is)(?:deviat\w*|stale\w*|fresh\w*|maxAge|maxStale|heartbeat|"
    r"threshold\w*|tolerance\w*|limit\w*|bound\w*|\bmax\b|\bmin\b|"
    r"bps\b|basis|absDiff|absDelta|delta|updatedAt|lastUpdate|lastUpdated|"
    r"cachedAt|priceStaleness|priceDeviation|block\s*\.\s*timestamp|"
    r"withinDeviation|validate\w*|ensure\w*|sanity)"
)
_COMPARE_OR_VALIDATE_RE = re.compile(
    r"(?is)(?:<=|>=|<|>|==|!=|\b_?within\w*\s*\(|\b_?validate\w*\s*\(|"
    r"\b_?ensure\w*\s*\(|\b_?isFresh\s*\(|\b_check\w*\s*\()"
)
_VALIDATION_EXPR_RE = re.compile(
    r"(?is)\b(?:require|if)\s*\((?P<expr>[^;{}]{0,700})\)"
)
_ACCESS_CONTROL_RE = re.compile(
    r"(?is)\b(?:onlyOwner|onlyAdmin|onlyGovernor|onlyGovernance|onlyKeeper|"
    r"onlyOracle|onlyUpdater|onlyRole|requiresRole|auth|authorized|"
    r"permissioned|trustedUpdater|_checkOwner|_checkRole)\b|"
    r"\brequire\s*\(\s*(?:msg\s*\.\s*sender|_msgSender\s*\(\s*\))\s*==\s*"
    r"(?:owner|admin|governor|governance|keeper|oracle|trusted|updater)\b"
)
_STATE_DECL_RE = re.compile(
    r"(?im)^\s*(?P<type>mapping\s*\([^;]+?\)|u?int\d*|bytes32)\s+"
    r"(?P<mods>(?:(?:public|private|internal|external|constant|immutable|override)\s+)*)"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:;|=)"
)
_CACHE_NAME_RE = re.compile(
    r"(?i)(?:cache|cached|last|baseline|reference|anchor|snapshot|stored|"
    r"previous|stale).*?(?:price|rate|value|answer|round|timestamp|updated|"
    r"time|age|heartbeat|threshold|deviation)|"
    r"(?:price|rate|value|answer|timestamp|updated|time|age|heartbeat|"
    r"threshold|deviation).*?(?:cache|cached|last|baseline|reference|anchor|"
    r"snapshot|stored|previous|stale)|"
    r"cachedAt|lastUpdate|lastUpdated|lastGoodPrice"
)
_HELPER_NAME_RE = re.compile(r"(?i)^_*(?:refresh|reset|prime|seed|sync|roll|update|store|cache|set)\w*")


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _split_functions(source: str) -> list[tuple[str, str, str, int, int]]:
    out: list[tuple[str, str, str, int, int]] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        i = match.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            if source[i] == "(":
                depth_paren += 1
            elif source[i] == ")":
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
            pos = max(i, j)
            continue

        depth = 1
        k = body_start + 1
        while k < len(source) and depth > 0:
            if source[k] == "{":
                depth += 1
            elif source[k] == "}":
                depth -= 1
            k += 1

        header = source[match.start():body_start]
        body = source[body_start + 1:k - 1]
        function_line = source.count("\n", 0, match.start()) + 1
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append((name, header, body, function_line, body_line))
        pos = k
    return out


def _line_for(body: str, body_line: int, match_start: int) -> int:
    return body_line + body.count("\n", 0, max(match_start, 0))


def _cache_state_vars(source: str) -> set[str]:
    out: set[str] = set()
    depth = 0
    for line in source.splitlines():
        match = _STATE_DECL_RE.match(line) if depth == 1 else None
        depth += line.count("{") - line.count("}")
        if match is None:
            continue
        mods = match.group("mods") or ""
        if re.search(r"\b(?:constant|immutable)\b", mods):
            continue
        name = match.group("name")
        if _CACHE_NAME_RE.search(name):
            out.add(name)
    return out


def _var_ref_re(var_name: str) -> re.Pattern[str]:
    return re.compile(rf"\b{re.escape(var_name)}\b\s*(?:\[[^\]]+\]\s*){{0,3}}")


def _var_write_re(var_name: str) -> re.Pattern[str]:
    return re.compile(
        rf"(?is)(?:\bdelete\s+)?\b{re.escape(var_name)}\b\s*"
        rf"(?:\[[^\]]+\]\s*){{0,3}}(?:\+\+|--|\+=|-=|=(?!=))"
    )


def _writes_to_var(body: str, var_name: str) -> list[int]:
    return [match.start() for match in _var_write_re(var_name).finditer(body)]


def _aliases_for_var(body: str, var_name: str) -> set[str]:
    aliases: set[str] = set()
    ref = _var_ref_re(var_name)
    for match in re.finditer(
        r"(?im)\b(?:uint\d*|int\d*|bytes32|bool|address|PriceData|OraclePrice|"
        r"Snapshot|CacheEntry)?\s*(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;\n]*;",
        body,
    ):
        statement = match.group(0)
        alias = match.group("alias")
        if alias == var_name:
            continue
        if ref.search(statement):
            aliases.add(alias)
    return aliases


def _expr_mentions_var_or_alias(expr: str, var_name: str, aliases: set[str]) -> bool:
    if _var_ref_re(var_name).search(expr):
        return True
    return any(re.search(rf"\b{re.escape(alias)}\b", expr) for alias in aliases)


def _validation_refs(body: str, var_name: str) -> list[int]:
    aliases = _aliases_for_var(body, var_name)
    offsets: list[int] = []
    for match in _VALIDATION_EXPR_RE.finditer(body):
        expr = match.group("expr")
        if not _expr_mentions_var_or_alias(expr, var_name, aliases):
            continue
        if not _VALIDATION_CONTEXT_RE.search(expr):
            continue
        if not _COMPARE_OR_VALIDATE_RE.search(expr):
            continue
        offsets.append(match.start())
    return offsets


def _is_untrusted_entry(name: str, header: str, body: str) -> bool:
    text = f"{header}\n{body[:500]}"
    if not _ENTRY_HEADER_RE.search(header):
        return False
    if _PURE_OR_VIEW_RE.search(header):
        return False
    if _ACCESS_CONTROL_RE.search(text):
        return False
    return bool(_ORACLE_CONTEXT_RE.search(name) or _ORACLE_CONTEXT_RE.search(body))


def _helper_mutators(
    functions: list[tuple[str, str, str, int, int]],
    cache_vars: set[str],
) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for name, header, body, _function_line, _body_line in functions:
        if _ACCESS_CONTROL_RE.search(f"{header}\n{body[:500]}"):
            continue
        if not _HELPER_NAME_RE.search(name):
            continue
        mutated = {var for var in cache_vars if _writes_to_var(body, var)}
        if mutated:
            out[name] = mutated
    return out


def _direct_mutation_kind(writes: list[int], validations: list[int]) -> tuple[int, str] | None:
    if not writes or not validations:
        return None
    first_write = min(writes)
    first_validation = min(validations)
    if first_write <= first_validation:
        return first_write, "same-entrypoint-cache-reset-before-check"
    return first_validation, "same-entrypoint-cache-overwrite-after-check"


def _helper_call_kind(
    body: str,
    helper_mutators: dict[str, set[str]],
    var_name: str,
    validations: list[int],
) -> tuple[int, str] | None:
    if not validations:
        return None
    for helper_name, mutated_vars in helper_mutators.items():
        if var_name not in mutated_vars:
            continue
        call_re = re.compile(rf"\b{re.escape(helper_name)}\s*\(")
        for call in call_re.finditer(body):
            if call.start() <= max(validations):
                return call.start(), "same-transaction-helper-baseline-reset-before-check"
    return None


def _finding(file_path: str, line: int, function: str, var_name: str, kind: str) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            f"{kind}: oracle deviation, stale, or threshold validation uses mutable "
            f"cached baseline `{var_name}` while the same caller-controlled path can "
            "reset or overwrite that baseline. NOT_SUBMIT_READY: detector fixture "
            "smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    cache_vars = _cache_state_vars(stripped)
    if not cache_vars:
        return []

    functions = _split_functions(stripped)
    helper_mutators = _helper_mutators(functions, cache_vars)
    findings: list[Finding] = []
    emitted: set[tuple[str, str, str]] = set()

    for name, header, body, function_line, body_line in functions:
        if not _is_untrusted_entry(name, header, body):
            continue
        for var_name in sorted(cache_vars):
            validations = _validation_refs(body, var_name)
            if not validations:
                continue

            direct = _direct_mutation_kind(_writes_to_var(body, var_name), validations)
            helper = _helper_call_kind(body, helper_mutators, var_name, validations)
            for classified in (direct, helper):
                if classified is None:
                    continue
                offset, kind = classified
                key = (name, var_name, kind)
                if key in emitted:
                    continue
                emitted.add(key)
                line = _line_for(body, body_line, offset) if offset >= 0 else function_line
                findings.append(_finding(file_path, line, name, var_name, kind))

    return findings


__all__ = [
    "scan",
    "Finding",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "SUBMISSION_POSTURE",
]
