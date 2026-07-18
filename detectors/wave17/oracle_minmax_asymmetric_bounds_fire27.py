"""
oracle-minmax-asymmetric-bounds-fire27

Solidity recall-lift detector for oracle price paths that choose min, max,
clamp, or bound values across asymmetric venues, sides, or stale/fresh feeds.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:5a4dc5fcabec4193
- context_pack_hash: 5a4dc5fcabec419385f40cc3f83d3a24f63a01e0d5c301ab1ef08763094a3fe5
- source ref: reference/patterns.dsl/can-oracle-min-both-sides-asymmetric-arb.yaml
- source ref: reference/patterns.dsl/a-multiplication-over-low-allows-an-attacker-to-block-the-tally.yaml
- source ref: reference/patterns.dsl/certora-aave-ltv-bounded-by-liquidation-threshold.yaml
- attack_class: oracle-price-manipulation

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "oracle-minmax-asymmetric-bounds-fire27"
DETECTOR_SEVERITY_DEFAULT = "High"


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
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_PURE_HEADER_RE = re.compile(r"\bpure\b")
_LEAF_HELPER_RE = re.compile(r"(?i)^_?(min|max|median|bound|clamp|abs|sort|scale|normalize)")

_ORACLE_VOCAB_RE = re.compile(
    r"(?is)(?:oracle|price|feed|reserve|twap|spot|bound|bounds|"
    r"aggregator|chainlink|pyth|redstone|fallback|primary|secondary)"
)
_MIN_CALL_RE = re.compile(r"(?is)\b(?:Math\s*\.\s*)?min\s*\(|\b_min\s*\(")
_MAX_CALL_RE = re.compile(r"(?is)\b(?:Math\s*\.\s*)?max\s*\(|\b_max\s*\(")
_CLAMP_CALL_START_RE = re.compile(
    r"(?is)(?P<callee>"
    r"(?:Math\s*\.\s*)?(?:min|max)|"
    r"_?(?:min|max|clamp|bound)(?:Price)?|"
    r"(?:clamp|bound)(?:Price)?"
    r")\s*\("
)
_COLLATERAL_SIDE_RE = re.compile(r"(?is)\b(?:collateral|supply|deposit|asset)\w*\b")
_DEBT_SIDE_RE = re.compile(r"(?is)\b(?:debt|borrow|liability|repay|loan)\w*\b")
_RISKY_ENTRY_RE = re.compile(
    r"(?is)\b(?:borrow|withdraw|redeem|repay|liquidat|health|solvency|"
    r"account|quote|swap|mint|burn|reserve|collateral|debt|liability)\w*\b"
)
_SAFE_ASYMMETRIC_RE = re.compile(
    r"(?is)"
    r"collateral\w*price\s*=\s*[^;]*(?:Math\s*\.\s*)?min\s*\([^;]*;"
    r"[\s\S]{0,900}"
    r"(?:debt|borrow|liability|repay)\w*price\s*=\s*[^;]*(?:Math\s*\.\s*)?max\s*\("
)
_SAFE_ASYMMETRIC_ALT_RE = re.compile(
    r"(?is)"
    r"(?:debt|borrow|liability|repay)\w*price\s*=\s*[^;]*(?:Math\s*\.\s*)?max\s*\([^;]*;"
    r"[\s\S]{0,900}"
    r"collateral\w*price\s*=\s*[^;]*(?:Math\s*\.\s*)?min\s*\("
)
_DEVIATION_OR_MEDIAN_GUARD_RE = re.compile(
    r"(?is)\b(?:median|weightedMedian|ensureFresh|validateFresh|checkFresh|"
    r"updatedAt|answeredInRound|heartbeat|maxStale|MAX_STALE|deviation|"
    r"MAX_DEVIATION|spread|absDiff|absDelta|staleness)\b"
)
_SOURCE_PAIR_PATTERNS = [
    ("spot-vs-twap", re.compile(r"(?is)\bspot\w*[\s\S]{0,260}\btwap\w*|\btwap\w*[\s\S]{0,260}\bspot\w*")),
    ("primary-vs-fallback", re.compile(r"(?is)\bprimary\w*[\s\S]{0,260}\b(?:secondary|fallback)\w*|\b(?:secondary|fallback)\w*[\s\S]{0,260}\bprimary\w*")),
    ("chainlink-vs-alt-feed", re.compile(r"(?is)\bchainlink\w*[\s\S]{0,260}\b(?:pyth|redstone|uniswap|curve|twap|spot|fallback)\w*|\b(?:pyth|redstone|uniswap|curve|twap|spot|fallback)\w*[\s\S]{0,260}\bchainlink\w*")),
    ("fresh-vs-cached", re.compile(r"(?is)\bfresh\w*[\s\S]{0,260}\b(?:stale|cached|last)\w*|\b(?:stale|cached|last)\w*[\s\S]{0,260}\bfresh\w*")),
    ("venue-a-vs-b", re.compile(r"(?is)\b(?:venue|dex|feed|oracle|source)[A-Z]?\w*A\b[\s\S]{0,260}\b(?:venue|dex|feed|oracle|source)[A-Z]?\w*B\b")),
]


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _split_functions(source: str) -> list[tuple[str, str, str, int]]:
    out: list[tuple[str, str, str, int]] = []
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
        line = source.count("\n", 0, match.start()) + 1
        out.append((name, header, body, line))
        pos = k
    return out


def _is_candidate_entry(name: str, header: str) -> bool:
    if not _PUBLIC_HEADER_RE.search(header):
        return False
    if _PURE_HEADER_RE.search(header):
        return False
    return not _LEAF_HELPER_RE.search(name)


def _find_matching_paren(text: str, open_index: int) -> int:
    depth = 1
    i = open_index + 1
    while i < len(text) and depth > 0:
        if text[i] == "(":
            depth += 1
        elif text[i] == ")" and depth > 0:
            depth -= 1
        i += 1
    return i - 1 if depth == 0 else -1


def _split_top_level_args(args: str) -> list[str]:
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


def _clamp_calls(body: str) -> list[tuple[str, list[str], str]]:
    out: list[tuple[str, list[str], str]] = []
    for match in _CLAMP_CALL_START_RE.finditer(body):
        open_index = match.end() - 1
        close_index = _find_matching_paren(body, open_index)
        if close_index < 0:
            continue
        callee = re.sub(r"\s+", "", match.group("callee")).lower()
        if "min" in callee:
            kind = "min"
        elif "max" in callee:
            kind = "max"
        else:
            kind = "clamp"
        args_text = body[open_index + 1:close_index]
        out.append((kind, _split_top_level_args(args_text), body[match.start():close_index + 1]))
    return out


def _source_pair_labels(text: str) -> list[str]:
    labels = [label for label, pattern in _SOURCE_PAIR_PATTERNS if pattern.search(text)]
    if re.search(r"(?is)\bpriceA\b[\s\S]{0,260}\bpriceB\b|\bpriceB\b[\s\S]{0,260}\bpriceA\b", text):
        labels.append("price-a-vs-b")
    return labels


def _has_oracle_clamp_context(body: str, calls: list[tuple[str, list[str], str]]) -> bool:
    if not _ORACLE_VOCAB_RE.search(body):
        return False
    return bool(calls)


def _has_safe_asymmetric_rule(body: str) -> bool:
    return bool(_SAFE_ASYMMETRIC_RE.search(body) or _SAFE_ASYMMETRIC_ALT_RE.search(body))


def _has_median_or_deviation_guard(body: str) -> bool:
    return bool(_DEVIATION_OR_MEDIAN_GUARD_RE.search(body))


def _side_symmetric_gap(body: str, calls: list[tuple[str, list[str], str]]) -> tuple[str, str] | None:
    if _has_safe_asymmetric_rule(body) or _has_median_or_deviation_guard(body):
        return None
    if not (_COLLATERAL_SIDE_RE.search(body) and _DEBT_SIDE_RE.search(body)):
        return None
    source_labels = _source_pair_labels(body)
    if not source_labels:
        for _kind, args, text in calls:
            source_labels.extend(_source_pair_labels(" ".join(args) + " " + text))
    if not source_labels:
        return None
    kinds = {kind for kind, _args, _text in calls if kind in {"min", "max"}}
    if kinds == {"min"}:
        return "symmetric-min-both-sides", ", ".join(sorted(set(source_labels)))
    if kinds == {"max"}:
        return "symmetric-max-both-sides", ", ".join(sorted(set(source_labels)))
    return None


def _source_choice_gap(body: str, calls: list[tuple[str, list[str], str]]) -> tuple[str, str] | None:
    if _has_safe_asymmetric_rule(body) or _has_median_or_deviation_guard(body):
        return None
    if not _RISKY_ENTRY_RE.search(body):
        return None
    for kind, args, text in calls:
        labels = _source_pair_labels(" ".join(args) + " " + text)
        if labels:
            return f"asymmetric-source-{kind}-choice", ", ".join(sorted(set(labels)))
    return None


def _classify_gap(header: str, body: str) -> tuple[str, str] | None:
    text = f"{header}\n{body}"
    calls = _clamp_calls(body)
    if not _has_oracle_clamp_context(text, calls):
        return None
    side_gap = _side_symmetric_gap(text, calls)
    if side_gap is not None:
        return side_gap
    return _source_choice_gap(text, calls)


def _finding(file_path: str, line: int, function: str, branch: str, source_pair: str) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function,
        message=(
            f"{branch} across {source_pair}: oracle price path chooses min, max, "
            "clamp, or bound across asymmetric sources or sides without a safe "
            "min-collateral plus max-debt rule, median path, or deviation/freshness "
            "guard. NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for name, header, body, line in _split_functions(code):
        if not _is_candidate_entry(name, header):
            continue
        classified = _classify_gap(header, body)
        if classified is None:
            continue
        branch, source_pair = classified
        findings.append(_finding(file_path, line, name, branch, source_pair))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
