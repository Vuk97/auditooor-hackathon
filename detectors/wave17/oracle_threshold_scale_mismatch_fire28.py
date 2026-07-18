"""
oracle-threshold-scale-mismatch-fire28

Regex detector for Solidity oracle, health factor, and liquidation checks that
compare feed values or safety thresholds across incompatible decimal scales.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:86c2076101171056
- context_pack_hash: 86c2076101171056d88e0073a7354a1cf2324d92f13627249a1c5ece0c70b722
- source ref: reference/patterns.dsl.r75_mined/firms_zellic_ottersec_nethermind/maxmin-raw-comparison-across-different-decimals.yaml
- source ref: reference/patterns.dsl.r75_mined/firms_zellic_ottersec_nethermind/scaled-vs-unscaled-threshold-comparison.yaml
- source ref: reference/patterns.dsl.r94_solodit_oracle/incorrect-handling-of-pricefeed-decimals-only-works-for-8-dec-feeds.yaml
- attack_class: oracle-price-manipulation

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "oracle-threshold-scale-mismatch-fire28"
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
_VISIBILITY_RE = re.compile(r"\b(?:external|public|internal)\b")
_PURE_RE = re.compile(r"\bpure\b")
_LEAF_HELPER_RE = re.compile(
    r"(?i)^_?(?:min|max|median|bound|clamp|scale|normalize|normalise|toWad|toRay|mulDiv)$"
)

_ORACLE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:oracle|price|feed|aggregator|chainlink|pyth|redstone|latestRoundData|"
    r"latestAnswer|health\w*|ltv\w*|loanToValue\w*|liquidat\w*|"
    r"collateral\w*|debt\w*|borrow\w*|solvency\w*)\b"
)
_RISK_CONTEXT_RE = re.compile(
    r"(?is)\b(?:health\w*|ltv\w*|loanToValue\w*|liquidat\w*|"
    r"collateral\w*|borrow\w*|debt\w*|solvency\w*|threshold\w*|"
    r"factor\w*|min\w*|max\w*|bound\w*|ratio\w*|require)\b"
)
_SAFE_SCALE_RE = re.compile(
    r"(?is)"
    r"\.decimals\s*\(|"
    r"\b(?:feed|price|oracle|token|asset|base|quote|collateral|debt)Decimals\b|"
    r"\b(?:normalize|normalise|scaleTo|scalePrice|scaleFeed|toWad|toRay|toBase|"
    r"convertDecimals|convertToDecimals|adjustDecimals|fromFeedDecimals|"
    r"priceToWad|amountToUsd|toUsdValue|to18Decimals|scaleTo18)\b|"
    r"\b(?:mulDiv|FullMath|wadMul|wadDiv|rayMul|rayDiv)\b|"
    r"10\s*\*\*\s*\([^)]*(?:decimals|Decimals)[^)]*\)"
)
_FEED_READ_RE = re.compile(
    r"(?is)\b(?:latestRoundData|latestAnswer|getPrice|getAssetPrice|peekPrice|readPrice)\s*\("
)
_HARD_CODED_8_RE = re.compile(r"(?is)\b(?:1e8|100000000|10\s*\*\*\s*8)\b")
_FIXED_8_DECIMALS_RE = re.compile(
    r"(?is)\b(?:FEED|PRICE|ORACLE|CHAINLINK)?_?DECIMALS\b\s*=\s*8\b|"
    r"\buint8\s+(?:public\s+|internal\s+|private\s+)?(?:constant\s+)?"
    r"(?:feed|price|oracle|chainlink)?Decimals\s*=\s*8\b"
)
_RAW_VAR_RE = re.compile(
    r"(?i)\b(?:raw\w*Price|oraclePrice|feedPrice|price|answer|roundAnswer|latestPrice|"
    r"collateralPrice|debtPrice|healthFactor|ltv|loanToValue|collateralRatio|"
    r"systemRatio|currentRatio)\b"
)
_THRESHOLD_VAR_RE = re.compile(
    r"(?i)\b(?:MIN[A-Z0-9_]*|MAX[A-Z0-9_]*|minimum\w+|maximum\w+|min\w+|max\w+|"
    r".*threshold\w*|.*factor\w*|.*ltv\w*|.*bound\w*|.*limit\w*)\b"
)
_COMPARE_RE = re.compile(
    r"(?is)(?:require|if)\s*\((?P<expr>[^;{}]{0,360}?(?:<=|>=|<|>)[^;{}]{0,360}?)\)"
)
_SCALE_MARKER_RE = re.compile(r"(?is)\b(?:BPS|BASE|SCALE|WAD|RAY|1e18|1e4|10000)\b")
_SMALL_CONSTANT_RE = re.compile(
    r"(?is)\b(?P<name>(?:MINIMUM|MIN|MAX|LIQUIDATION|LTV|HEALTH|COLLATERAL|"
    r"COLLATERALIZATION|SOLVENCY)[A-Z0-9_]*(?:RATIO|FACTOR|THRESHOLD|LTV|HEALTH|BOUND|LIMIT)?)"
    r"\s*=\s*(?P<value>[1-9][0-9]{0,2})\b"
)
_MAXMIN_CALL_RE = re.compile(
    r"(?is)\b(?:Math\s*\.\s*)?(?P<callee>max|min)\s*\((?P<args>[^;{}]{0,260})\)"
)

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


def _is_candidate_function(name: str, header: str, body: str) -> bool:
    if not _VISIBILITY_RE.search(header):
        return False
    if _PURE_RE.search(header):
        return False
    if _LEAF_HELPER_RE.search(name):
        return False
    return bool(_ORACLE_CONTEXT_RE.search(name) or _ORACLE_CONTEXT_RE.search(body))


def _line_for(body: str, body_line: int, match_start: int) -> int:
    return body_line + body.count("\n", 0, max(match_start, 0))


def _safe_scale_present(text: str) -> bool:
    return bool(_SAFE_SCALE_RE.search(text))


def _expr_has_raw_threshold_cross(expr: str) -> bool:
    if not _RAW_VAR_RE.search(expr):
        return False
    if not _THRESHOLD_VAR_RE.search(expr):
        return False
    return True


def _is_hardcoded_8_feed_path(body: str) -> tuple[int, str] | None:
    if not _FEED_READ_RE.search(body):
        return None
    if re.search(r"(?is)\.decimals\s*\(", body):
        return None
    match = _HARD_CODED_8_RE.search(body) or _FIXED_8_DECIMALS_RE.search(body)
    if not match:
        return None
    return match.start(), "hardcoded-8-decimal-feed-assumption"


def _is_raw_oracle_threshold_compare(body: str) -> tuple[int, str] | None:
    if _safe_scale_present(body):
        return None
    if not (_FEED_READ_RE.search(body) or re.search(r"(?is)\boracle\w*Price\b|\braw\w*Price\b", body)):
        return None
    for match in _COMPARE_RE.finditer(body):
        expr = match.group("expr")
        if _expr_has_raw_threshold_cross(expr):
            return match.start(), "raw-oracle-threshold-scale-mismatch"
    return None


def _small_threshold_constants(source: str) -> set[str]:
    constants: set[str] = set()
    for match in _SMALL_CONSTANT_RE.finditer(source):
        try:
            value = int(match.group("value"))
        except ValueError:
            continue
        if value <= 500:
            constants.add(match.group("name"))
    return constants


def _is_scaled_unscaled_threshold(body: str, constants: set[str]) -> tuple[int, str] | None:
    if _safe_scale_present(body):
        return None
    if not constants:
        return None
    if not _SCALE_MARKER_RE.search(body):
        return None
    for match in _COMPARE_RE.finditer(body):
        expr = match.group("expr")
        if not re.search(r"(?is)\b(?:health|ratio|collateral|ltv|factor|threshold)\w*\b", expr):
            continue
        if any(re.search(rf"\b{re.escape(name)}\b", expr) for name in constants):
            return match.start(), "scaled-runtime-value-vs-unscaled-threshold"
    return None


def _top_level_args(args: str) -> list[str]:
    out: list[str] = []
    start = 0
    depth = 0
    for i, ch in enumerate(args):
        if ch == "(":
            depth += 1
        elif ch == ")" and depth > 0:
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(args[start:i].strip())
            start = i + 1
    out.append(args[start:].strip())
    return [arg for arg in out if arg]


def _has_distinct_decimal_hints(args: list[str]) -> bool:
    joined = " ".join(args)

    def has(name: str) -> bool:
        return bool(re.search(rf"(?i)\b{re.escape(name)}\w*\b", joined))

    if has("token0") and has("token1"):
        return True
    if (has("wbtc") or has("btc")) and (has("weth") or has("eth")):
        return True
    if has("usdc") and (has("weth") or has("eth")):
        return True
    if has("usdc") and (has("wbtc") or has("btc")):
        return True
    if has("asset0") and has("asset1"):
        return True
    if has("feedA") and has("feedB"):
        return True
    if has("priceA") and has("priceB"):
        return True
    if has("collateral") and has("debt"):
        return True
    if has("borrow") and has("supply"):
        return True
    return False


def _is_raw_maxmin_cross_scale(body: str) -> tuple[int, str] | None:
    if _safe_scale_present(body):
        return None
    if not _RISK_CONTEXT_RE.search(body):
        return None
    for match in _MAXMIN_CALL_RE.finditer(body):
        args = _top_level_args(match.group("args"))
        if len(args) < 2:
            continue
        call_text = match.group(0)
        if _FEED_READ_RE.search(body) or _has_distinct_decimal_hints(args) or _has_distinct_decimal_hints([body]):
            if re.search(r"(?is)(?:price|amount|requirement|collateral|debt|feed|answer)", call_text):
                return match.start(), "raw-minmax-across-different-decimal-domains"
    return None


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    constants = _small_threshold_constants(stripped)
    findings: list[Finding] = []

    for name, header, body, function_line, body_line in _split_functions(stripped):
        if not _is_candidate_function(name, header, body):
            continue
        text = f"{header}\n{body}"
        checks = [
            _is_hardcoded_8_feed_path(body),
            _is_raw_oracle_threshold_compare(body),
            _is_scaled_unscaled_threshold(body, constants),
            _is_raw_maxmin_cross_scale(body),
        ]
        emitted: set[str] = set()
        for check in checks:
            if check is None:
                continue
            offset, kind = check
            if kind in emitted:
                continue
            emitted.add(kind)
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(body, body_line, offset) if offset >= 0 else function_line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    message=(
                        f"{kind}: oracle, health, liquidation, or threshold comparison "
                        "appears to mix raw feed values or unscaled thresholds without "
                        "feed-specific decimal normalization."
                    ),
                    function=name,
                )
            )

    return findings
