#!/usr/bin/env python3
"""Rule 23 comparative-baseline filing completeness preflight.

HIGH/CRITICAL claims that rely on comparative language, performance deltas,
bounded degradation, weakened parameters, or regression framing must include
all three pieces of filing evidence:

  1. a concrete baseline/comparator,
  2. the measurement method used for the same workload, and
  3. the pass/fail threshold that turns the comparison into impact.

Override marker:
  <!-- r23-rebuttal: <bounded reason> -->

Exit codes:
  0 - pass, out-of-scope, or accepted rebuttal
  1 - Rule 23 violation
  2 - input error
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.comparative_baseline_check.v1"
GATE = "R23-COMPARATIVE-BASELINE-REQUIRED"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

TRIGGER_RE = re.compile(
    r"\b(?:"
    r"compar(?:e|ed|ison|ative)|same[- ]workload|side[- ]by[- ]side|"
    r"baseline|upstream|regress(?:ion|ed)?|previous(?: version)?|prior version|"
    r"weaken(?:ed|s|ing)?|loosen(?:ed|s|ing)?|lower(?:ed)?|higher|"
    r"cap(?:acity)?|threshold|default|parameter|limit|"
    r"degrad(?:e|es|ed|ation)|slow(?:er|down)|latency|throughput|tps|qps|"
    r"slo|p95|p99|gas|runtime|duration|"
    r"\d+(?:\.\d+)?\s*(?:x|%|ms|s|sec|seconds|minutes|hours|h|gas|tps|qps)\b|"
    r"[+-]\s*\d+(?:\.\d+)?\s*%"
    r")\b|"
    r"\b(?:vs\.?|versus)\b|"
    r"\b(?:from|cap|threshold|limit|default)\s*=\s*[A-Za-z0-9_.:-]+\s*(?:to|vs\.?|versus)\s*"
    r"[A-Za-z0-9_.:-]+",
    re.IGNORECASE,
)

COMPARATOR_RE = re.compile(
    r"\b(?:"
    r"baseline|comparator|control|upstream|previous(?: version)?|prior version|"
    r"before|after|target|patched|unpatched|cap\s*=\s*[^,\n]+?\s*(?:vs\.?|versus)\s*cap\s*=|"
    r"threshold\s*=\s*[^,\n]+?\s*(?:vs\.?|versus)\s*threshold\s*=|"
    r"same[- ]workload|side[- ]by[- ]side"
    r")\b",
    re.IGNORECASE,
)

MEASUREMENT_RE = re.compile(
    r"\b(?:"
    r"method|measurement|measured|benchmark|microbench|load test|replay|harness|"
    r"test command|command|script|fixture|workload|dataset|seed|sample|n\s*=|"
    r"poc|forge test|go test|cargo test|pytest|trace|profile|metric"
    r")\b",
    re.IGNORECASE,
)

THRESHOLD_RE = re.compile(
    r"\b(?:"
    r"threshold|pass/fail|fail(?:s|ed)? if|passes? if|acceptance|slo|budget|"
    r"must remain|must stay|must be|violation if|impact if|"
    r">=\s*\d|<=\s*\d|>\s*\d|<\s*\d|at least\s+\d|no more than\s+\d|"
    r"exceeds?\s+\d|below\s+\d|above\s+\d"
    r")",
    re.IGNORECASE,
)

NEGATIVE_SCOPE_RE = re.compile(
    r"\b(?:not[_ -]?claimed|no claim|does not claim|not alleged|not demonstrated|"
    r"not relying on|not comparative|no regression)\b",
    re.IGNORECASE,
)

REBUTTAL_RE = re.compile(r"<!--\s*r23-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override and override.lower() != "auto":
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    for pattern, source in (
        (r"(?im)^\s*\**\s*Severity\s*:\**\s*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*severity_implied\s*:\s*(Critical|High|Medium|Low)\b", "program-impact-mapping"),
        (r"(?im)^\s*severity_tier\s*:\s*(Critical|High|Medium|Low)\b", "impact-contract"),
        (r"(?im)^\s*selected_severity\s*:\s*(Critical|High|Medium|Low)\b", "selected-severity"),
    ):
        match = re.search(pattern, text)
        if match:
            return match.group(1).lower(), source
    name = path.name.lower()
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", name):
            return severity, "filename"
    return None, "missing"


def _line_hits(text: str, pattern: re.Pattern[str], *, ignore_negative: bool = False, limit: int = 16) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if ignore_negative and NEGATIVE_SCOPE_RE.search(line):
            continue
        match = pattern.search(line)
        if match:
            hits.append({"line": idx, "token": match.group(0), "text": line.strip()[:240]})
            if len(hits) >= limit:
                break
    return hits


def _rebuttal(text: str) -> str | None:
    match = REBUTTAL_RE.search(text)
    if not match:
        return None
    return " ".join(match.group(1).split())


def run(
    draft: Path,
    *,
    severity_override: str | None = None,
    strict: bool = False,
) -> tuple[int, dict[str, Any]]:
    try:
        text = _read_text(draft)
    except Exception as exc:
        return 2, {
            "schema_version": SCHEMA_VERSION,
            "gate": GATE,
            "file": str(draft),
            "verdict": "error",
            "error": f"cannot read draft: {exc}",
        }

    severity, severity_source = _severity(text, draft, severity_override)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "file": str(draft),
        "severity": severity,
        "severity_source": severity_source,
        "strict": strict,
        "evidence": {},
        "required_items": ["concrete_comparator", "measurement_method", "pass_fail_threshold"],
        "remediation_options": [
            "Add a same-workload baseline/comparator, e.g. cap=X vs cap=Y or upstream vs target.",
            "Name the measurement method: command, harness, workload, seed, replay, or benchmark setup.",
            "State the pass/fail threshold that makes the comparative result filing-relevant.",
            "Use <!-- r23-rebuttal: reason --> only for a bounded, source-backed exception.",
        ],
    }

    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH or missing"
        return 0, payload

    trigger_hits = _line_hits(text, TRIGGER_RE, ignore_negative=True)
    if not trigger_hits:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "no comparative/regression/degradation trigger"
        return 0, payload

    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= 240:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        payload["evidence"] = {"trigger_hits": trigger_hits}
        return 0, payload

    comparator_hits = _line_hits(text, COMPARATOR_RE)
    method_hits = _line_hits(text, MEASUREMENT_RE)
    threshold_hits = _line_hits(text, THRESHOLD_RE)
    missing: list[str] = []
    if not comparator_hits:
        missing.append("concrete_comparator")
    if not method_hits:
        missing.append("measurement_method")
    if not threshold_hits:
        missing.append("pass_fail_threshold")

    payload["evidence"] = {
        "trigger_hits": trigger_hits,
        "comparator_hits": comparator_hits,
        "measurement_method_hits": method_hits,
        "pass_fail_threshold_hits": threshold_hits,
    }
    payload["missing"] = missing

    if not missing:
        payload["verdict"] = "pass-comparative-baseline-complete"
        payload["reason"] = "comparative claim includes comparator, method, and threshold"
        return 0, payload

    payload["verdict"] = "fail-comparative-baseline-incomplete"
    payload["reason"] = "HIGH/CRITICAL comparative claim lacks required baseline filing evidence"
    return 1, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--severity", default="auto")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    rc, payload = run(args.draft, severity_override=args.severity, strict=args.strict)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
