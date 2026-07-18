#!/usr/bin/env python3
"""Rule 21 permanent-impact five-ask template preflight.

HIGH/CRITICAL filings claiming permanent-class impact must answer the five
triager asks in a top-of-response ask-coverage section:

  1. who is affected
  2. what exact asset/state is frozen
  3. why recovery/admin/governance/restart cannot clear it
  4. duration/permanence
  5. source/runtime proof

Exit codes:
  0 - pass, out-of-scope, below severity threshold, honest walkback, or rebuttal
  1 - Rule 21 violation
  2 - input error
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.permanent_impact_five_ask_template_check.v1"
GATE = "R21-PERMANENT-IMPACT-5-ASK-TEMPLATE"

REBUTTAL_RE = re.compile(r"<!--\s*r21-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)

SEVERITY_RE = re.compile(
    r"(?im)^\s*(?:severity|impact|risk)\s*:\s*(critical|crit(?:ical)?[- ]?[12]|high|medium|low|informational|info)\b|"
    r"\b(CRITICAL|CRIT[- ]?[12]|HIGH|MEDIUM|LOW|INFORMATIONAL|INFO)\b"
)

PERMANENT_TRIGGER_RE = re.compile(
    r"\b(?:"
    r"permanent(?:ly)?\s+(?:freez(?:e|es|ing)|lock(?:ed|s|ing)|stuck|bricked|lost|unrecoverable|impact|degradation)|"
    r"permanent[- ]class\s+impact|"
    r"permanent\s+freezing|"
    r"(?:funds?|assets?|collateral|balances?|withdrawals?|exits?|state|position|account|vault|market|chain)\s+"
    r"(?:are|is|become|becomes|remain|remains)\s+(?:permanently\s+)?(?:frozen|locked|stuck|bricked|unrecoverable)|"
    r"(?:requires|needs)\s+(?:a\s+)?(?:hardfork|governance\s+intervention|admin\s+intervention)|"
    r"(?:hardfork|required\s+hardfork|governance-required|admin-required)|"
    r"(?:chain|network|protocol)\s+halt|block\s+production\s+halt|"
    r"(?:24\s*h(?:ours?)?\+|24\+\s*h(?:ours?)?|more\s+than\s+24\s*h(?:ours?)?)\s+(?:degradation|downtime|halt|outage)|"
    r"CRIT[- ]?[12]"
    r")\b",
    re.IGNORECASE,
)

NEGATIVE_SCOPE_RE = re.compile(
    r"\b(?:"
    r"not[_ -]?proven(?:_\w+)?|not claimed|does not claim|do not claim|no claim|"
    r"not in scope|out of scope|not part of this report|not alleged|not demonstrated|"
    r"no match|why not|non[- ]permanent|not permanent|does not cause permanent|"
    r"no permanent impact|no permanent freezing|temporary only|transient only"
    r")\b",
    re.IGNORECASE,
)

HONEST_WALKBACK_RE = re.compile(
    r"\b(?:"
    r"honest\s+walkback|walk(?:ed)?\s+back|"
    r"(?:severity|impact)\s+(?:is\s+)?(?:walked\s+)?back\s+to\s+(?:medium|low)|"
    r"not\s+(?:a\s+)?permanent[- ]class\s+impact|"
    r"not\s+permanent(?:ly)?\b|"
    r"(?:admin|governance|operator|restart|recovery|manual intervention)\s+"
    r"(?:can|could|does|will)\s+(?:clear|recover|restore|unfreeze|unlock|restart|resolve)|"
    r"(?:clears|recovers|restores|unfreezes|unlocks|resolves)\s+(?:after|with|via)\s+"
    r"(?:admin|governance|operator|restart|recovery|manual intervention)"
    r")\b",
    re.IGNORECASE,
)

ASK_SECTION_RE = re.compile(
    r"(?im)^[^\S\n]{0,3}(?:#{1,6}\s*)?(?:r21\s+)?(?:five[- ]ask|5[- ]ask|ask[- ]coverage|ask coverage|triager asks)\b"
)

ASK_PATTERNS: dict[str, re.Pattern[str]] = {
    "who_affected": re.compile(
        r"\b(?:who\s+is\s+affected|affected\s+(?:users?|parties|accounts?|validators?|nodes?|operators?)|"
        r"victims?|impacted\s+(?:users?|parties|accounts?))\b",
        re.IGNORECASE,
    ),
    "asset_or_state_frozen": re.compile(
        r"\b(?:what\s+exact\s+(?:asset|state)|asset/state|asset\s+or\s+state|"
        r"(?:asset|state|funds?|collateral|balance|withdrawal|exit|position|account|vault|market)\s+"
        r"(?:is|are|gets?|becomes?)\s+(?:frozen|locked|stuck|bricked|unrecoverable))\b",
        re.IGNORECASE,
    ),
    "cannot_clear": re.compile(
        r"\b(?:why\s+(?:recovery|admin|governance|restart)|"
        r"(?:recovery|admin|governance|restart|operator|manual intervention)\s+"
        r"(?:cannot|can't|can not|does not|won't|will not|fails to)\s+"
        r"(?:clear|recover|restore|unfreeze|unlock|resolve)|"
        r"cannot\s+be\s+(?:cleared|recovered|restored|unfrozen|unlocked|resolved))\b",
        re.IGNORECASE,
    ),
    "duration_permanence": re.compile(
        r"\b(?:duration|permanence|permanent\s+duration|"
        r"(?:for|lasts|persists|continues)\s+(?:forever|indefinitely|until\s+(?:hardfork|governance|admin)|"
        r"more\s+than\s+24\s*h(?:ours?)?|24\s*h(?:ours?)?\+)|"
        r"\bindefinite(?:ly)?\b|\bpermanent(?:ly)?\b)\b",
        re.IGNORECASE,
    ),
    "source_runtime_proof": re.compile(
        r"\b(?:source/runtime\s+proof|runtime\s+proof|source\s+proof|source\s+and\s+runtime|"
        r"(?:source|code)\s+(?:anchor|evidence|reference)|"
        r"(?:runtime|test|harness|poc|transcript|trace)\s+(?:proof|evidence|reproduction|repro|shows|demonstrates))\b",
        re.IGNORECASE,
    ),
}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _line_hits(text: str, pattern: re.Pattern[str], limit: int = 12) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            hits.append({"line": idx, "text": line.strip()[:240]})
            if len(hits) >= limit:
                break
    return hits


def _is_negative_context(line: str) -> bool:
    if NEGATIVE_SCOPE_RE.search(line):
        return True
    trigger = PERMANENT_TRIGGER_RE.search(line)
    negative = NEGATIVE_SCOPE_RE.search(line[max(0, (trigger.start() if trigger else 0) - 80) :]) if trigger else None
    return bool(negative)


def _trigger_hits(text: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if PERMANENT_TRIGGER_RE.search(line) and not _is_negative_context(line):
            hits.append({"line": idx, "text": line.strip()[:240]})
            if len(hits) >= 12:
                break
    return hits


def _severity(text: str) -> tuple[str | None, bool]:
    for match in SEVERITY_RE.finditer(text):
        raw = next((group for group in match.groups() if group), "")
        normalized = raw.upper().replace(" ", "-")
        if normalized in {"CRITICAL", "CRIT-1", "CRIT-2", "HIGH"}:
            return normalized, True
        if normalized.startswith("CRIT"):
            return normalized, True
        return normalized, False
    return None, False


def _rebuttal(text: str) -> str | None:
    match = REBUTTAL_RE.search(text)
    if not match:
        return None
    return " ".join(match.group(1).split())


def _ask_section(text: str) -> tuple[str, int | None]:
    match = ASK_SECTION_RE.search(text[:5000])
    if not match:
        return text[:3200], None
    start = match.start()
    section = text[start : start + 3500]
    after_first_line = section.find("\n")
    if after_first_line != -1:
        next_heading = re.search(r"(?m)^\s{0,3}#{1,6}\s+\S", section[after_first_line + 1 :])
        if next_heading:
            section = section[: after_first_line + 1 + next_heading.start()]
    return section, text[:start].count("\n") + 1


def _ask_coverage(text: str) -> tuple[dict[str, bool], int | None]:
    section, line = _ask_section(text)
    coverage = {name: bool(pattern.search(section)) for name, pattern in ASK_PATTERNS.items()}
    return coverage, line


def run(draft: Path, *, strict: bool = False) -> tuple[int, dict[str, Any]]:
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

    severity, severity_in_scope = _severity(text)
    trigger_hits = _trigger_hits(text)
    raw_trigger_hits = _line_hits(text, PERMANENT_TRIGGER_RE)
    coverage, ask_section_line = _ask_coverage(text)
    missing = [name for name, present in coverage.items() if not present]
    honest_hits = _line_hits(text, HONEST_WALKBACK_RE)

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "file": str(draft),
        "strict": strict,
        "severity": severity,
        "severity_in_scope": severity_in_scope,
        "evidence": {
            "trigger_hits": trigger_hits,
            "honest_walkback_hits": honest_hits,
            "ask_section_line": ask_section_line,
            "ask_coverage": coverage,
            "missing_asks": missing,
        },
        "remediation_options": [
            "Add a top-of-response ask-coverage section answering all five R21 asks.",
            "Walk back the permanent-class impact if admin/governance/restart/recovery can clear it.",
            "Use <!-- r21-rebuttal: reason --> only for a bounded, source-backed exception.",
        ],
    }

    if not trigger_hits:
        if raw_trigger_hits and honest_hits:
            payload["verdict"] = "pass-honest-walkback"
            payload["reason"] = "draft walks back permanent-class impact"
            return 0, payload
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "no in-scope permanent-impact trigger"
        return 0, payload

    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= 240:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload

    if honest_hits:
        payload["verdict"] = "pass-honest-walkback"
        payload["reason"] = "draft walks back permanent-class impact"
        return 0, payload

    if not severity_in_scope and not strict:
        payload["verdict"] = "pass-below-severity-threshold"
        payload["reason"] = "permanent-impact trigger is not paired with HIGH/CRITICAL severity"
        return 0, payload

    if all(coverage.values()):
        payload["verdict"] = "pass-five-ask-covered"
        payload["reason"] = "all five R21 asks are covered near the top of the draft"
        return 0, payload

    payload["verdict"] = "fail-missing-five-ask-coverage"
    payload["reason"] = "HIGH/CRITICAL permanent-impact claim lacks complete R21 ask coverage"
    return 1, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--strict", action="store_true", help="enforce R21 even when severity is absent/below threshold")
    parser.add_argument("--json", action="store_true", help="accepted for pre-submit consistency; output is always JSON")
    args = parser.parse_args(argv)

    rc, payload = run(args.draft, strict=args.strict)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
