"""
go-oracle-rate-provider-identity-or-freshness-guard-missing.py

Detects Go liquidation/accounting paths that consume oracle or exchange-rate
provider output without validating the provider identity and/or the returned
value freshness/deviation before the value feeds critical math.

The detector is intentionally conservative:

1. The function must look like liquidation/accounting/collateral/debt logic.
2. The function must assign a price/rate/EMA-like value from an oracle or
   rate-provider call.
3. The assigned value must later feed arithmetic or a liquidation-style
   comparison.
4. The function is flagged only when:
   - a provider/source/feed argument is present but no visible allowlist or
     provider-validation guard exists, or
   - no visible freshness/deviation guard exists before the value is used.

This keeps the lift narrow to the requested cross-language stale/manipulated
oracle class instead of broadening into generic pricing helpers.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-oracle-rate-provider-identity-or-freshness-guard-missing"

_CRITICAL_NAME_RE = re.compile(
    r"(?i)(liquidat|health|margin|equity|account|collateral|debt|"
    r"settle|payout|nav|borrow|seize|value|quote)"
)
_CRITICAL_BODY_RE = re.compile(
    r"(?i)(liquidat|health|margin|equity|account|collateral|debt|"
    r"settle|payout|borrow|seize|ltv|insolven|balance)"
)

_SOURCE_ASSIGN_RE = re.compile(
    r"(?m)^\s*(?P<lhs>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*){0,4})\s*(?::=|=)\s*"
    r"(?P<rhs>[^\n;]*("
    r"(?:[A-Za-z_]\w*\.)?(?:Get|Fetch|Query|Read|Latest)[A-Za-z_0-9]*"
    r"(?:Price|Rate|ExchangeRate|EMA|EMAPrice|TWAP|Twap)"
    r"|(?:[A-Za-z_]\w*\.)?(?:Price|Rate|ExchangeRate|LatestRoundData)"
    r")[^\n;]*)$"
)
_VALUE_VAR_RE = re.compile(r"(?i)(price|rate|ema|mark|value)")

_PROVIDER_ARG_RE = re.compile(
    r"(?i)\([^)]*\b("
    r"(?:msg|req|request|params)\.Provider|"
    r"provider(?:ID|Id)?|source(?:ID|Id)?|feed(?:ID|Id)?|oracle(?:ID|Id)?"
    r")\b"
)
_PROVIDER_GUARD_RE = re.compile(
    r"(?is)("
    r"validate[A-Za-z_0-9]*Provider|"
    r"check[A-Za-z_0-9]*Provider|"
    r"isAllowedProvider|"
    r"isTrustedProvider|"
    r"providerAllowlist|providerWhitelist|providerRegistry|"
    r"allowedProviders?\s*\[|"
    r"knownProviders?\s*\[|"
    r"supportedProviders?\s*\[|"
    r"allowlistedProviders?\s*\[|"
    r"whitelistedProviders?\s*\[|"
    r"switch\s+[A-Za-z_][A-Za-z_0-9]*Provider|"
    r"switch\s+provider(?:ID|Id)?|"
    r"switch\s+(?:msg|req|request|params)\.Provider"
    r")"
)

_FRESHNESS_OR_DEVIATION_GUARD_RE = re.compile(
    r"(?is)("
    r"validate[A-Za-z_0-9]*(?:Price|Rate|Fresh|Stale|Deviation)|"
    r"check[A-Za-z_0-9]*(?:Price|Rate|Fresh|Stale|Deviation)|"
    r"withinDeviation|"
    r"circuitBreaker|"
    r"heartbeat|"
    r"maxStaleness|maxAge|maxDeviation|deviationBps|"
    r"time\.Now\s*\(\s*\)\.Unix\s*\(\s*\)\s*-\s*[A-Za-z_][A-Za-z_0-9]*"
    r"(?:UpdatedAt|Timestamp|PublishTime|Time)\s*[<>!=]=?\s*[A-Za-z_0-9().+\-*/ ]+|"
    r"(?:UpdatedAt|Timestamp|PublishTime|Time)\s*[<>!=]=?\s*"
    r"time\.Now\s*\(\s*\)\.Unix\s*\(\s*\)\s*-\s*[A-Za-z_0-9().+\-*/ ]+|"
    r"diff\s*[*\/+\-<>=]|delta\s*[*\/+\-<>=]|deviation\s*[*\/+\-<>=]|"
    r"spotPrice|referenceRate|secondaryPrice|fallbackPrice|crossCheck"
    r")"
)


def _blank_comment(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank_comment, src)
    return re.sub(r"/\*.*?\*/", _blank_comment, src, flags=re.S)


def _pick_value_var(lhs_text: str) -> str:
    parts = [part.strip() for part in lhs_text.split(",")]
    for part in parts:
        if _VALUE_VAR_RE.search(part):
            return part
    return parts[0]


def _value_used_in_critical_math(body_text: str, value_var: str) -> bool:
    value_re = re.compile(rf"\b{re.escape(value_var)}\b")
    for line in body_text.splitlines():
        if not value_re.search(line):
            continue
        if not re.search(r"[+\-*/]|[<>]=?|==|!=", line):
            continue
        if _CRITICAL_BODY_RE.search(line) or _CRITICAL_NAME_RE.search(line):
            return True
    return False


def _hit(engine, fn, name: str, why: str):
    return {
        "severity": "high",
        "line": engine.line(fn),
        "col": engine.col(fn),
        "snippet": engine.text(fn).splitlines()[0][:160],
        "message": (
            f"`{name}` uses oracle/rate-provider output in liquidation or "
            f"accounting math without {why}. Validate provider identity and "
            f"enforce freshness/deviation bounds before using returned "
            f"prices or rates. (class: stale-or-manipulated-oracle)"
        ),
    }


def run(engine, filepath: str):  # noqa: ARG001
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue

        body_text = engine.text(body)
        body_nc = _strip_comments(body_text)
        if not (_CRITICAL_NAME_RE.search(name) or _CRITICAL_BODY_RE.search(body_nc)):
            continue

        for match in _SOURCE_ASSIGN_RE.finditer(body_nc):
            rhs = match.group("rhs")
            value_var = _pick_value_var(match.group("lhs"))
            if not _value_used_in_critical_math(body_nc, value_var):
                continue

            has_provider_arg = bool(_PROVIDER_ARG_RE.search(rhs))
            has_provider_guard = bool(_PROVIDER_GUARD_RE.search(body_nc))
            has_freshness_guard = bool(_FRESHNESS_OR_DEVIATION_GUARD_RE.search(body_nc))

            if has_provider_arg and not has_provider_guard:
                hits.append(_hit(engine, fn, name, "any visible provider allowlist/identity guard"))
                break

            if not has_freshness_guard:
                hits.append(_hit(engine, fn, name, "any visible freshness/deviation guard"))
                break

    return hits
