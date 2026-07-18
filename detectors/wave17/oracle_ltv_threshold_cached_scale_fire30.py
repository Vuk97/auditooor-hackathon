"""
oracle-ltv-threshold-cached-scale-fire30

Solidity regex detector for lending valuation paths where LTV,
liquidation-threshold, oracle-config, or decimal-scale changes do not
invalidate cached price or scale state that is later consumed by collateral
valuation math.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:7d4cd518d841bbb0
- context_pack_hash: 7d4cd518d841bbb0abef5ff4d39a17902e7d232a2304aeea41f8bee5239aee4d
- source ref: reports/detector_lift_fire29_20260605/post_priorities_solidity.md
- source ref: reference/patterns.dsl/erc4626-share-price-used-as-collateral-oracle.yaml
- source ref: reference/patterns.dsl.zellic_k2_mined/oracle-config-changes-do-not-invalidate-cached-prices.yaml
- source ref: reference/patterns.dsl.r74_mined_cs/asymmetrical-norm-in-price-update-threshold.yaml
- attack_class: oracle-price-manipulation

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "oracle-ltv-threshold-cached-scale-fire30"
DETECTOR_SEVERITY_DEFAULT = "High"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"


try:
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
except Exception:  # pragma: no cover - regex scan remains usable without Slither.
    class AbstractDetector:  # type: ignore[no-redef]
        pass

    class DetectorClassification:  # type: ignore[no-redef]
        HIGH = "High"
        MEDIUM = "Medium"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None
    setter: Optional[str] = None
    cache_var: Optional[str] = None
    config_var: Optional[str] = None


@dataclass(frozen=True)
class FunctionSlice:
    name: str
    header: str
    body: str
    function_line: int
    body_line: int


@dataclass(frozen=True)
class UnsafeConfigSetter:
    name: str
    line: int
    config_var: str


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_VISIBILITY_RE = re.compile(r"\b(?:external|public|internal)\b")
_EXTERNAL_OR_PUBLIC_RE = re.compile(r"\b(?:external|public)\b")
_STATE_DECL_RE = re.compile(
    r"^\s*(?:mapping\s*\([^;]+?\)|[A-Za-z_][A-Za-z0-9_]*(?:\[\])?|"
    r"u?int\d*|address|bytes32|bool)\s+"
    r"(?:(?:public|private|internal|constant|immutable|override)\s+)*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:;|=)"
)
_CACHE_VAR_RE = re.compile(
    r"(?i)(?:cache|cached|last|stored|snapshot|baseline|reference).*?"
    r"(?:price|scale|decimal|precision|rate|value|answer)|"
    r"(?:price|scale|decimal|precision|rate|value|answer).*?"
    r"(?:cache|cached|last|stored|snapshot|baseline|reference)|"
    r"cachedAt|lastPrice|lastScale|priceScale|oracleScale|assetScale"
)
_CONFIG_VAR_RE = re.compile(
    r"(?i)(?:risk|assetConfig|oracleConfig|config|feed|oracle|ltv|loanToValue|"
    r"collateralFactor|borrowFactor|liquidationThreshold|healthFactor|"
    r"threshold|decimals|precision|priceScale|oracleScale)"
)
_RISK_FIELD_RE = re.compile(
    r"(?i)\b(?:ltv|ltvBps|maxLtv|maxLtvBps|loanToValue|loanToValueBps|"
    r"collateralFactor|collateralFactorBps|borrowFactor|borrowFactorBps|"
    r"liquidationThreshold|liquidationThresholdBps|healthFactorThreshold|"
    r"thresholdBps|risk|riskParams|assetConfig|oracleConfig|feedDecimals|"
    r"priceDecimals|oracleDecimals)\b"
)
_SETTER_NAME_RE = re.compile(
    r"(?i)^(?:set|update|configure|replace|change|enable|disable|register|"
    r"setAsset|setOracle|setRisk|setCollateral|setLtv|setLiquidation)"
)
_VALUATION_CONTEXT_RE = re.compile(
    r"(?is)\b(?:collateral|collateralValue|accountLiquidity|liquidity|"
    r"borrow|borrowLimit|borrowable|maxBorrow|debt|health|healthFactor|"
    r"solvency|ltv|loanToValue|liquidat|liquidation|threshold|"
    r"isHealthy|isLiquidatable|valuation|valueOf|assetValue)\w*\b"
)
_VALUE_MATH_RE = re.compile(r"(?:\*|/|mulDiv|wadMul|wadDiv|rayMul|rayDiv)")
_COLLATERAL_VALUE_RE = re.compile(
    r"(?is)\b(?:collateral|value|borrow|debt|health|ltv|liquidat|threshold)\w*\b"
)
_SAFE_REFRESH_RE = re.compile(
    r"(?is)\b(?:fresh|refresh|sync|recompute|normalize|normalise|scaleTo|"
    r"scalePrice|scaleTo18|priceToWad|getFresh|latestRoundData|decimals)\s*\(|"
    r"\b(?:cacheVersion|configVersion|oracleVersion)\b"
)
_CACHE_INVALIDATE_CALL_RE = re.compile(
    r"(?is)\b(?:invalidate|clear|reset|refresh|recompute|sync)\w*"
    r"(?:Cache|Price|Scale|Oracle|Valuation|Config)\s*\("
)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _find_matching_delimiter(source: str, open_pos: int, open_char: str, close_char: str) -> int:
    if open_pos < 0 or open_pos >= len(source) or source[open_pos] != open_char:
        return -1
    depth = 1
    index = open_pos + 1
    while index < len(source) and depth > 0:
        if source[index] == open_char:
            depth += 1
        elif source[index] == close_char:
            depth -= 1
        index += 1
    return index - 1 if depth == 0 else -1


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        open_paren = source.find("(", match.end() - 1)
        close_paren = _find_matching_delimiter(source, open_paren, "(", ")")
        if close_paren < 0:
            pos = match.end()
            continue

        body_start = -1
        scan = close_paren + 1
        while scan < len(source):
            if source[scan] == ";":
                break
            if source[scan] == "{":
                body_start = scan
                break
            scan += 1
        if body_start < 0:
            pos = max(scan, close_paren + 1)
            continue

        body_end = _find_matching_delimiter(source, body_start, "{", "}")
        if body_end < 0:
            pos = body_start + 1
            continue

        out.append(
            FunctionSlice(
                name=name,
                header=source[match.start():body_start],
                body=source[body_start + 1:body_end],
                function_line=source.count("\n", 0, match.start()) + 1,
                body_line=source.count("\n", 0, body_start + 1) + 1,
            )
        )
        pos = body_end + 1
    return out


def _state_vars(source: str) -> set[str]:
    out: set[str] = set()
    depth = 0
    for line in source.splitlines():
        if depth == 1:
            match = _STATE_DECL_RE.match(line)
            if match:
                out.add(match.group("name"))
        depth += line.count("{") - line.count("}")
    return out


def _line_for_body(fn: FunctionSlice, offset: int) -> int:
    return fn.body_line + fn.body.count("\n", 0, max(offset, 0))


def _var_ref_re(var_name: str) -> re.Pattern[str]:
    return re.compile(
        rf"\b{re.escape(var_name)}\b\s*(?:\[[^\]]+\]\s*){{0,4}}"
        rf"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
    )


def _var_write_re(var_name: str) -> re.Pattern[str]:
    return re.compile(
        rf"(?is)(?:\bdelete\s+)?\b{re.escape(var_name)}\b\s*"
        rf"(?:\[[^\]]+\]\s*){{0,4}}(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
        rf"\s*(?:\+\+|--|\+=|-=|\*=|/=|=(?!=))"
    )


def _writes_var(body: str, var_name: str) -> bool:
    return bool(_var_write_re(var_name).search(body))


def _reads_var(body: str, var_name: str) -> bool:
    return bool(_var_ref_re(var_name).search(body))


def _invalidates_cache(body: str, cache_vars: set[str]) -> bool:
    if _CACHE_INVALIDATE_CALL_RE.search(body):
        return True
    for var_name in cache_vars:
        escaped = re.escape(var_name)
        patterns = (
            rf"(?is)\bdelete\s+{escaped}\b",
            rf"(?is)\b{escaped}\b\s*(?:\[[^\]]+\]\s*){{0,4}}\s*=\s*0\b",
            rf"(?is)\b{escaped}\b\s*(?:\[[^\]]+\]\s*){{0,4}}\s*="
            rf"\s*(?:_?fresh|_?refresh|_?scale|_?normalize|_?normalise)",
        )
        if any(re.search(pattern, body) for pattern in patterns):
            return True
    return False


def _unsafe_setters(
    functions: list[FunctionSlice],
    config_vars: set[str],
    cache_vars: set[str],
) -> list[UnsafeConfigSetter]:
    out: list[UnsafeConfigSetter] = []
    for fn in functions:
        if not _EXTERNAL_OR_PUBLIC_RE.search(fn.header):
            continue
        if not (_SETTER_NAME_RE.search(fn.name) or _RISK_FIELD_RE.search(fn.body)):
            continue
        if _invalidates_cache(fn.body, cache_vars):
            continue
        mutated = sorted(var_name for var_name in config_vars if _writes_var(fn.body, var_name))
        for var_name in mutated:
            out.append(UnsafeConfigSetter(name=fn.name, line=fn.function_line, config_var=var_name))
    return out


def _first_read(body: str, vars_to_check: set[str]) -> str:
    matches: list[tuple[int, str]] = []
    for var_name in vars_to_check:
        match = _var_ref_re(var_name).search(body)
        if match:
            matches.append((match.start(), var_name))
    if not matches:
        return ""
    return min(matches, key=lambda item: item[0])[1]


def _valuation_reads_cache_and_risk(
    fn: FunctionSlice,
    cache_vars: set[str],
    config_vars: set[str],
) -> tuple[str, str] | None:
    if not _VISIBILITY_RE.search(fn.header):
        return None
    context = f"{fn.name}\n{fn.body}"
    if not _VALUATION_CONTEXT_RE.search(context):
        return None
    if not (_VALUE_MATH_RE.search(fn.body) and _COLLATERAL_VALUE_RE.search(fn.body)):
        return None
    if _SAFE_REFRESH_RE.search(fn.body):
        return None

    cache_read = _first_read(fn.body, cache_vars)
    if not cache_read:
        return None

    config_read = _first_read(fn.body, config_vars)
    if not config_read and _RISK_FIELD_RE.search(fn.body):
        config_read = "risk-config-field"
    if not config_read:
        return None
    return cache_read, config_read


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    """Regex scanner used by tests and recall tooling."""
    text = _strip_comments_and_strings(source)
    functions = _split_functions(text)
    state_vars = _state_vars(text)
    cache_vars = {name for name in state_vars if _CACHE_VAR_RE.search(name)}
    config_vars = {name for name in state_vars if _CONFIG_VAR_RE.search(name)} - cache_vars
    if not cache_vars or not config_vars:
        return []

    setters = _unsafe_setters(functions, config_vars, cache_vars)
    if not setters:
        return []

    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for fn in functions:
        valuation = _valuation_reads_cache_and_risk(fn, cache_vars, config_vars)
        if valuation is None:
            continue
        cache_var, config_var = valuation
        for setter in setters:
            key = (setter.name, fn.name, cache_var)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=setter.line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    setter=setter.name,
                    cache_var=cache_var,
                    config_var=setter.config_var if setter.config_var != "risk-config-field" else config_var,
                    message=(
                        f"{DETECTOR_NAME}: config-change-without-cache-invalidation "
                        f"in `{setter.name}` updates `{setter.config_var}` without clearing "
                        f"cached price or scale `{cache_var}`; `{fn.name}` later combines "
                        f"that cache with `{config_var}` in collateral, LTV, or "
                        "liquidation-threshold valuation math. NOT_SUBMIT_READY: "
                        "detector fixture smoke evidence only."
                    ),
                )
            )
    return findings


def _source_text(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _source_file(obj) -> str:
    try:
        filename = obj.source_mapping.filename
        for attr in ("absolute", "relative", "short"):
            value = getattr(filename, attr, None)
            if value:
                return str(value)
    except Exception:
        pass
    return "<unknown>"


class OracleLtvThresholdCachedScaleFire30(AbstractDetector):
    ARGUMENT = DETECTOR_NAME
    HELP = (
        "Oracle, LTV, liquidation-threshold, or decimal-scale config changes "
        "do not invalidate cached price or scale state used by collateral "
        "valuation math."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Oracle risk-parameter changes leave stale cached valuation scale"
    WIKI_DESCRIPTION = (
        "Lending protocols frequently cache oracle prices, feed scales, or "
        "normalized collateral values. If an admin path changes the oracle, "
        "feed decimals, LTV, liquidation threshold, or collateral factor "
        "without invalidating that cache, later health-factor or borrowing "
        "math can combine new risk parameters with stale precision."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "Governance changes an asset from an 8-decimal feed to an 18-decimal "
        "feed and adjusts LTV. The cache still stores the old normalized "
        "scale. Borrow and liquidation checks read the new threshold but use "
        "the old cached scale, mis-valuing collateral."
    )
    WIKI_RECOMMENDATION = (
        "On every oracle, decimals, LTV, collateral-factor, or liquidation "
        "threshold update, clear the cached price and scale, bump a cache "
        "version, or force the next valuation path to read and normalize a "
        "fresh oracle sample before accepting collateral math."
    )

    SUBMISSION_POSTURE = SUBMISSION_POSTURE
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self):
        results = []
        for contract in getattr(self, "contracts", []):
            contract_source = _source_text(contract)
            if not contract_source:
                continue
            functions_by_name = {
                str(getattr(function, "name", "") or ""): function
                for function in getattr(contract, "functions_and_modifiers_declared", [])
            }
            for finding in scan(contract_source, _source_file(contract)):
                anchor = functions_by_name.get(finding.function or "") or contract
                info = [anchor, f" - {finding.message} (line {finding.line})"]
                results.append(self.generate_result(info))
        return results


__all__ = [
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "Finding",
    "OracleLtvThresholdCachedScaleFire30",
    "scan",
]
