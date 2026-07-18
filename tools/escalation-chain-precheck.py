#!/usr/bin/env python3
"""Advisory precheck for escalation/chaining evidence in markdown findings.

This helper checks whether a finding/workpack records the minimum structured
evidence needed before spending more runtime on a chain/escalation lane:

1. named primitive(s),
2. attempted stronger impact,
3. material distinction from the base issue,
4. why the escalation holds or fails.

It is evidence-only. It does not claim exploitability, submission readiness,
or severity correctness.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.escalation_chain_precheck.v1"

HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*$")

CHECKS = (
    {
        "name": "named_primitives",
        "label": "named primitive(s)",
        "guidance": "add `primitive:` / `primitives:` evidence naming the starting issue(s)",
        "inline_patterns": (
            re.compile(r"(?im)^(?:[-*]\s*)?(?:named\s+)?primitives?\s*:\s*(.+\S.*)$"),
            re.compile(r"(?im)^(?:[-*]\s*)?(?:base|root)\s+primitives?\s*:\s*(.+\S.*)$"),
        ),
        "section_patterns": (
            re.compile(r"\b(?:named\s+)?primitives?\b", re.IGNORECASE),
            re.compile(r"\b(?:base|root)\s+primitives?\b", re.IGNORECASE),
        ),
    },
    {
        "name": "attempted_stronger_impact",
        "label": "attempted stronger impact",
        "guidance": "add `attempted stronger impact:` / `escalation target:` evidence",
        "inline_patterns": (
            re.compile(r"(?im)^(?:[-*]\s*)?attempted\s+stronger\s+impact\s*:\s*(.+\S.*)$"),
            re.compile(r"(?im)^(?:[-*]\s*)?(?:stronger\s+impact|escalation\s+target|chaining\s+target)\s*:\s*(.+\S.*)$"),
        ),
        "section_patterns": (
            re.compile(r"\battempted\s+stronger\s+impact\b", re.IGNORECASE),
            re.compile(r"\b(?:stronger\s+impact|escalation\s+target|chaining\s+target)\b", re.IGNORECASE),
        ),
    },
    {
        "name": "material_distinction",
        "label": "material distinction from base issue",
        "guidance": "add `material distinction:` or `distinct from base issue:` evidence",
        "inline_patterns": (
            re.compile(r"(?im)^(?:[-*]\s*)?material\s+distinction\s*:\s*(.+\S.*)$"),
            re.compile(r"(?im)^(?:[-*]\s*)?(?:distinct(?:ion)?\s+from\s+base\s+issue|delta\s+vs\.?\s+base\s+issue)\s*:\s*(.+\S.*)$"),
            re.compile(r"(?im)^(?:[-*]\s*)?not\s+duplicate\s+because\s*:\s*(.+\S.*)$"),
        ),
        "section_patterns": (
            re.compile(r"\bmaterial\s+distinction\b", re.IGNORECASE),
            re.compile(r"\bdistinct(?:ion)?\s+from\s+base\s+issue\b", re.IGNORECASE),
            re.compile(r"\bdelta\s+vs\.?\s+base\s+issue\b", re.IGNORECASE),
        ),
    },
    {
        "name": "escalation_rationale",
        "label": "why escalation holds or fails",
        "guidance": "add `escalation result:` / `holds because:` / `fails because:` evidence",
        "inline_patterns": (
            re.compile(r"(?im)^(?:[-*]\s*)?escalation\s+result\s*:\s*(.+\S.*)$"),
            re.compile(r"(?im)^(?:[-*]\s*)?(?:holds|fails)\s+because\s*:\s*(.+\S.*)$"),
            re.compile(r"(?im)^(?:[-*]\s*)?why\s+escalation\s+(?:holds|fails)\s*:\s*(.+\S.*)$"),
            re.compile(r"(?im)^(?:[-*]\s*)?escalation\s+blocker\s*:\s*(.+\S.*)$"),
        ),
        "section_patterns": (
            re.compile(r"\bescalation\s+result\b", re.IGNORECASE),
            re.compile(r"\bwhy\s+escalation\s+(?:holds|fails)\b", re.IGNORECASE),
            re.compile(r"\bescalation\s+blocker\b", re.IGNORECASE),
        ),
    },
)


def _clean_snippet(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())


def _extract_sections(lines: list[str]) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line_no, line in enumerate(lines, start=1):
        heading = HEADING_RE.match(line)
        if heading:
            if current is not None:
                current["text"] = "\n".join(current["body"]).strip()
                sections.append(current)
            current = {
                "heading": heading.group(1).strip(),
                "line": line_no,
                "body": [],
            }
            continue
        if current is not None:
            current["body"].append(line)
    if current is not None:
        current["text"] = "\n".join(current["body"]).strip()
        sections.append(current)
    return sections


def _collect_inline_hits(lines: list[str], patterns: tuple[re.Pattern[str], ...]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for line_no, line in enumerate(lines, start=1):
        for pattern in patterns:
            match = pattern.search(line)
            if not match:
                continue
            snippet = _clean_snippet(match.group(0))
            if not snippet:
                continue
            hits.append({"line": line_no, "text": snippet, "source": "inline"})
            break
    return hits


def _collect_section_hits(
    sections: list[dict[str, Any]],
    patterns: tuple[re.Pattern[str], ...],
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for section in sections:
        heading = str(section.get("heading") or "")
        text = str(section.get("text") or "")
        if not text:
            continue
        if not any(pattern.search(heading) for pattern in patterns):
            continue
        first_line = text.splitlines()[0].strip()
        snippet = _clean_snippet(first_line)
        if not snippet:
            continue
        hits.append(
            {
                "line": int(section["line"]),
                "text": snippet,
                "source": "section",
            }
        )
    return hits


def _dedupe_hits(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for hit in hits:
        key = (int(hit["line"]), str(hit["text"]))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(hit)
    return deduped


def evaluate_markdown(text: str, path: Path) -> dict[str, Any]:
    lines = text.splitlines()
    sections = _extract_sections(lines)
    checks: list[dict[str, Any]] = []
    missing: list[str] = []
    guidance: list[str] = []

    for check in CHECKS:
        hits = _collect_inline_hits(lines, check["inline_patterns"])
        hits.extend(_collect_section_hits(sections, check["section_patterns"]))
        evidence = _dedupe_hits(hits)
        present = bool(evidence)
        checks.append(
            {
                "name": check["name"],
                "label": check["label"],
                "present": present,
                "evidence": evidence,
            }
        )
        if not present:
            missing.append(check["label"])
            guidance.append(check["guidance"])

    status = "ok" if not missing else "blocked_missing_evidence"
    return {
        "schema_version": SCHEMA_VERSION,
        "path": str(path),
        "advisory_only": True,
        "does_not_claim_exploitability": True,
        "submission_posture": "NOT_SUBMIT_READY",
        "status": status,
        "passes_precheck": not missing,
        "checks": checks,
        "missing_checks": missing,
        "guidance": guidance,
        "summary": (
            "Evidence-only escalation/chaining precheck. "
            "This does not prove exploitability."
        ),
    }


def inspect_file(path: Path) -> dict[str, Any]:
    return evaluate_markdown(path.read_text(encoding="utf-8"), path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("markdown", type=Path, help="finding/workpack markdown file")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="return non-zero when escalation/chaining evidence is incomplete",
    )
    args = parser.parse_args(argv)

    path = args.markdown.expanduser()
    if not path.exists():
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "path": str(path),
                    "status": "error_missing_file",
                    "advisory_only": True,
                    "does_not_claim_exploitability": True,
                    "error": "markdown file not found",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    payload = inspect_file(path)
    print(json.dumps(payload, indent=2, sort_keys=True))
    if args.strict and payload.get("status") == "blocked_missing_evidence":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
