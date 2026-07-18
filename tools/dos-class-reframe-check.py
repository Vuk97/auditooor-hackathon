#!/usr/bin/env python3
"""Rule 35 DoS-class-reframe preflight.

# Rule 35: this tool emits no corpus record.

GENERAL RULE - applies to ANY bounty platform, not just dYdX. Every major
bounty platform (Cantina, Immunefi, Sherlock, Code4rena, private engagements)
down-ranks or closes out-of-scope a HIGH+ finding whose actual demonstrated
impact is generic denial of service, rate-limit pressure, liveness
degradation, or resource exhaustion. Before filing, such a finding must be
reframed to and prove a separate non-DoS production impact: direct fund loss,
insurance-fund draw, protocol insolvency, permanent freeze, unauthorized
state transition, or a measurable settlement / matching-engine failure.

The gate fires only on severity HIGH and above. It first resolves the
workspace SEVERITY.md (walking up from the draft path). If SEVERITY.md lists
a DoS / RPC-crash / liveness / validator-halt impact row verbatim as
in-scope, the program accepts DoS and the gate skips. Otherwise it scans the
draft's selected_impact / impact prose for DoS-class language; if found, it
requires a separately proven non-DoS impact.

Exit codes:
  0 - pass, out-of-scope, DoS-in-scope, reframed, or accepted rebuttal
  1 - Rule 35 violation (with --strict)
  2 - input error
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.rebuttal_util import apply_rebuttal_gate  # noqa: E402


SCHEMA_VERSION = "auditooor.r35_dos_class_reframe.v1"
GATE = "R35-DOS-CLASS-REFRAME"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# DoS-class language in the draft's selected_impact / impact prose.
DEFAULT_DOS_KEYWORDS = [
    r"denial of service",
    r"\bDoS\b",
    r"rate.?limit",
    r"liveness",
    r"unavailab",
    r"degradation",
    r"resource exhaustion",
    r"griefing",
    r"block stuffing",
    r"gas griefing",
    r"mempool pressure",
    r"\bspam\b",
]

# A separately proven non-DoS production impact.
DEFAULT_NONDOS_IMPACT_KEYWORDS = [
    r"\btheft\b",
    r"loss of funds",
    r"insolvency",
    r"permanent freez",
    r"unauthorized (?:state|withdraw|transfer|mint)",
    r"insurance fund",
    r"settlement failure",
    r"matching-engine",
    r"matching engine",
    r"direct loss",
    r"fund drain",
    # A DoS/halt that LOCKS funds is a valid in-scope impact - permit the reframe to
    # the freezing/governance/yield rows, not only theft/insolvency. (NUVA 2026-06-30:
    # halt -> temporary/permanent freezing of funds is a real Immunefi row.)
    r"temporar(?:y|ily) freez",
    r"freezing of funds",
    r"frozen",
    r"governance(?:[- ]vote)? manipulat",
    r"vote manipulat",
    r"governance takeover",
    r"voting result",
    r"unclaimed.{0,12}yield",
    r"yield (?:theft|redistribut|diversion)",
]

# SEVERITY.md rows that show the program accepts DoS as an in-scope impact.
SEVERITY_DOS_INSCOPE_RE = re.compile(
    r"denial of service|\bDoS\b|rpc (?:api )?crash|rpc[- ]api crash|"
    r"liveness (?:failure|degradation)|validator (?:halt|crash)|"
    r"chain halt|node crash|block production (?:halt|stall)|"
    r"network[- ]level (?:liveness|downtime)|service (?:disruption|unavailab)",
    re.IGNORECASE,
)

REBUTTAL_HTML_RE = re.compile(r"<!--\s*r35-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)
REBUTTAL_LINE_RE = re.compile(r"(?im)^\s*(?:[-*]\s*)?r35[-_ ]rebuttal\s*:\s*(.+?)\s*$")

SEVERITY_FILE_NAMES = ("SEVERITY.md", "severity.md", "Severity.md")


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override:
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
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", path.name.lower()):
            return severity, "filename"
    return None, "missing"


def _workspace_root(draft: Path) -> Path:
    cur = draft.resolve().parent
    for parent in [cur, *cur.parents]:
        if (parent / "poc-tests").is_dir() or (parent / "submissions").is_dir():
            return parent
        for name in SEVERITY_FILE_NAMES:
            if (parent / name).is_file():
                return parent
    return draft.resolve().parent


def _find_severity_md(draft: Path) -> Path | None:
    cur = draft.resolve().parent
    for parent in [cur, *cur.parents]:
        for name in SEVERITY_FILE_NAMES:
            candidate = parent / name
            if candidate.is_file():
                return candidate
    return None


def _env_patterns(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return []
    return [item.strip() for item in raw.splitlines() if item.strip()]


def _compile_union(patterns: list[str]) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{pattern})" for pattern in patterns), re.IGNORECASE)


def _line_hits(text: str, pattern: re.Pattern[str], limit: int = 12) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        match = pattern.search(line)
        if match:
            hits.append({"line": idx, "token": match.group(0)[:80], "text": line.strip()[:240]})
            if len(hits) >= limit:
                break
    return hits


def _rebuttal(text: str) -> str | None:
    match = REBUTTAL_LINE_RE.search(text)
    if not match:
        match = REBUTTAL_HTML_RE.search(text)
    if not match:
        return None
    return " ".join(match.group(1).split())


def run(
    draft: Path,
    *,
    severity_override: str | None = None,
    poc_dir: list[str] | None = None,
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
        "general_rule": "Rule 35 is general - every bounty platform down-ranks generic DoS.",
        "evidence": {},
        "remediation_options": [
            "Reframe the finding to a proven non-DoS production impact: direct fund loss, insurance-fund draw, protocol insolvency, permanent freeze, unauthorized state transition, or a measurable settlement / matching-engine failure.",
            "If SEVERITY.md lists a DoS / RPC-crash / liveness / validator-halt impact row verbatim as in-scope, cite it in the draft so the gate resolves it.",
            "Walk severity below HIGH if only generic DoS / rate-limit / liveness-degradation impact is provable.",
            "Override: visible line 'r35-rebuttal: <reason>' (<=200 chars) or <!-- r35-rebuttal: <reason> -->.",
        ],
    }

    # Below HIGH: out of scope.
    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH or missing"
        return 0, payload

    # SEVERITY.md DoS-in-scope check: if the program lists a DoS / RPC-crash /
    # liveness / validator-halt impact row verbatim as in-scope, DoS is
    # acceptable and the gate skips.
    severity_md = _find_severity_md(draft)
    if severity_md is not None:
        try:
            sev_text = _read_text(severity_md)
        except Exception:
            sev_text = ""
        sev_hits = _line_hits(sev_text, SEVERITY_DOS_INSCOPE_RE)
        if sev_hits:
            payload["verdict"] = "pass-dos-in-scope"
            payload["reason"] = "workspace SEVERITY.md lists a DoS / RPC-crash / liveness / validator-halt impact row verbatim as in-scope"
            payload["severity_md"] = str(severity_md)
            payload["evidence"] = {"severity_md_dos_rows": sev_hits}
            return 0, payload
        payload["severity_md"] = str(severity_md)

    rebuttal = _rebuttal(text)
    if apply_rebuttal_gate(payload, rebuttal):
        return 0, payload

    dos_re = _compile_union(DEFAULT_DOS_KEYWORDS + _env_patterns("AUDITOOOR_R35_DOS_KEYWORDS"))
    nondos_re = _compile_union(
        DEFAULT_NONDOS_IMPACT_KEYWORDS + _env_patterns("AUDITOOOR_R35_NONDOS_IMPACT_KEYWORDS")
    )

    dos_hits = _line_hits(text, dos_re)
    nondos_hits = _line_hits(text, nondos_re)

    payload["evidence"] = {
        "dos_class_hits": dos_hits,
        "nondos_impact_hits": nondos_hits,
    }

    if not dos_hits:
        payload["verdict"] = "pass-not-dos-class"
        payload["reason"] = "no DoS-class language in the draft's selected_impact / impact prose"
        return 0, payload

    if nondos_hits:
        payload["verdict"] = "pass-dos-reframed-to-nondos"
        payload["reason"] = "DoS-class language present but the draft separately proves a non-DoS production impact"
        return 0, payload

    payload["verdict"] = "fail-dos-class-not-reframed"
    payload["reason"] = (
        "draft impact is generic DoS-class (denial of service / rate-limit / liveness "
        "degradation / resource exhaustion) with no separately proven non-DoS production impact; "
        "every bounty platform closes this out-of-scope at HIGH+"
    )
    return (1 if strict else 0), payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument(
        "--severity",
        choices=["auto", "Critical", "High", "Medium", "Low",
                 "critical", "high", "medium", "low"],
        default="auto",
    )
    parser.add_argument("--poc-dir", action="append", default=[])
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    override = None if args.severity == "auto" else args.severity
    rc, payload = run(
        args.draft,
        severity_override=override,
        poc_dir=args.poc_dir,
        strict=args.strict,
    )
    # Sibling tools always emit a clean JSON dict to stdout.
    print(json.dumps(payload, indent=2, sort_keys=True))
    if not args.json:
        sys.stderr.write(
            f"[{GATE}] {payload.get('verdict')}: {payload.get('reason', payload.get('error', ''))}\n"
        )
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
