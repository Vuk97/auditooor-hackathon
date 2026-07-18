#!/usr/bin/env python3
"""impact-contract-validator.py — internal-consistency checks for filled
impact-contract specs (operator-filled or auto-filled drafts).

Companion to:
  tools/impact-contract-scaffolder.py — emits the skeleton.
  tools/impact-contract-auto-fill.py  — emits a draft fill (dry-run by
      default).

This validator does NOT prove the spec is correct. It only catches a set
of internal-consistency mistakes that operators (and the auto-fill draft)
have historically made:

  V1  any `<TODO_OPERATOR>` marker still present in non-skeleton sections.
  V2  empty Production-precondition list for a row whose harness family
      indicates a stateful invariant.
  V3  empty Borrowed-asset list for a row whose harness family indicates
      borrowing / leveraged-capital strategies.
  V4  Adversarial-control surface that contradicts the modifier
      constraints (e.g. EOA + role-gated modifier without operator-
      reviewed override).
  V5  Severity tier set to High/Critical without a verbatim listed-impact
      sentence.
  V6  Auto-fill output (\"_autofilled.md\") with `overall_confidence: low`
      and an empty `<TODO_OPERATOR>` field — operator must fill this row,
      not promote.
  V7  Title does not match the T-02 schema (`<Class> in <component>
      leads to|allows|causes|results in|enables|permits <Impact>`).

Usage:
  python3 tools/impact-contract-validator.py <spec.md>
  python3 tools/impact-contract-validator.py <spec.md> --strict --json-out report.json

Exit codes:
  0  all checks PASS (or warnings only)
  1  --strict and at least one check FAILED
  2  bad input
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"

TODO_MARKER = "<TODO_OPERATOR>"
TITLE_VERBS = (
    "leads to",
    "allows",
    "causes",
    "results in",
    "enables",
    "permits",
)
BORROWING_FAMILY_TOKENS = (
    "borrow",
    "leverage",
    "flash_loan",
    "flash-loan",
    "flashloan",
    "lending",
    "swap_router",
    "zap",
    "lp_share",
)
STATEFUL_INVARIANT_TOKENS = (
    "stateful",
    "invariant",
    "liveness",
    "balance",
    "supply",
    "share",
    "reserve",
    "accounting",
    "state_root",
    "rate",
    "oracle",
)


@dataclass
class CheckResult:
    rule: str
    status: str
    message: str
    extra: dict = field(default_factory=dict)


# ============================================================================
# Section parsers
# ============================================================================


def _section(text: str, heading: str) -> str:
    """Return the content of the first markdown section whose heading
    matches `heading` (case-insensitive). Returns empty string if not found.
    """
    pat = re.compile(
        rf"^##\s*{re.escape(heading)}\s*$",
        re.IGNORECASE | re.MULTILINE,
    )
    m = pat.search(text)
    if not m:
        return ""
    start = m.end()
    next_h = re.search(r"^##\s+", text[start:], re.MULTILINE)
    end = start + (next_h.start() if next_h else len(text) - start)
    return text[start:end]


def _list_items(section_body: str) -> List[str]:
    items: List[str] = []
    for line in section_body.splitlines():
        s = line.strip()
        if s.startswith("- "):
            items.append(s[2:].strip())
    return items


def _identity_table(text: str) -> dict:
    """Parse the Identity table (Markdown). Best-effort."""
    out: dict = {}
    in_table = False
    for line in text.splitlines():
        if line.strip().lower().startswith("## identity"):
            in_table = True
            continue
        if in_table and line.strip().startswith("##") and "identity" not in line.lower():
            break
        if not in_table:
            continue
        m = re.match(r"^\|\s*([^|]+?)\s*\|\s*`?([^|`]+?)`?\s*\|\s*$", line)
        if m:
            key = m.group(1).strip().lower()
            val = m.group(2).strip()
            if key in ("field", "---"):
                continue
            out[key] = val
    return out


def _title_line(text: str) -> str:
    m = re.search(r"\*\*Proposed title.*?\*\*\s*\n+\s*>\s*(.+?)\s*$", text, re.MULTILINE)
    if m:
        return m.group(1).strip()
    # also accept a "Title:" line for operator-customized layouts
    m2 = re.search(r"^Title:\s*(.+?)\s*$", text, re.MULTILINE)
    if m2:
        return m2.group(1).strip()
    return ""


def _severity_tier(text: str) -> str:
    m = re.search(r"\*\*Severity tier:\*\*\s*`?(Critical|High|Medium|Low)`?", text, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _listed_impact_sentence(text: str) -> str:
    m = re.search(
        r"\*\*Listed-impact sentence \(verbatim from SEVERITY\.md\):\*\*\s*\n+\s*>\s*(.+?)\s*$",
        text,
        re.MULTILINE,
    )
    if not m:
        return ""
    val = m.group(1).strip()
    return val


def _is_autofilled_file(path: Path, text: str) -> bool:
    if path.name.endswith("_autofilled.md"):
        return True
    if "auto-filled" in text.lower() or "auto_filled" in text.lower():
        return True
    return False


def _overall_confidence(text: str) -> str:
    m = re.search(r"overall[_-]?confidence\s*[:=]\s*['\"]?(high|medium|low)['\"]?", text, re.IGNORECASE)
    return m.group(1).lower() if m else ""


# ============================================================================
# Rules
# ============================================================================


def check_v1_no_todos(text: str, is_skeleton_only: bool) -> CheckResult:
    if is_skeleton_only:
        return CheckResult(
            "V1_no_todos",
            PASS,
            "Skeleton-only file: TODO markers expected — skipped",
        )
    n = text.count(TODO_MARKER)
    if n == 0:
        return CheckResult("V1_no_todos", PASS, "No TODO markers remain")
    return CheckResult(
        "V1_no_todos",
        FAIL,
        f"{n} `<TODO_OPERATOR>` marker(s) still present",
        {"count": n},
    )


def check_v2_production_precondition(text: str, identity: dict) -> CheckResult:
    body = _section(text, "Production-precondition")
    items = [
        i for i in _list_items(body)
        if i and not i.startswith(TODO_MARKER)
    ]
    fam = (identity.get("source invariant family") or "").lower()
    is_stateful = any(t in fam for t in STATEFUL_INVARIANT_TOKENS)
    if not items:
        if is_stateful:
            return CheckResult(
                "V2_production_precondition",
                FAIL,
                "Empty Production-precondition list for stateful "
                f"invariant family {fam!r}",
                {"invariant_family": fam},
            )
        return CheckResult(
            "V2_production_precondition",
            WARN,
            "Empty Production-precondition list",
        )
    return CheckResult(
        "V2_production_precondition",
        PASS,
        f"{len(items)} precondition(s) declared",
    )


def check_v3_borrowed_assets(text: str, identity: dict) -> CheckResult:
    body = _section(text, "Borrowed-asset list")
    items = [
        i for i in _list_items(body)
        if i and not i.startswith(TODO_MARKER)
    ]
    fam = (identity.get("harness family") or "").lower()
    is_borrowing = any(t in fam for t in BORROWING_FAMILY_TOKENS)
    if not items:
        if is_borrowing:
            return CheckResult(
                "V3_borrowed_assets",
                FAIL,
                "Empty Borrowed-asset list for borrowing/leveraged "
                f"harness family {fam!r}",
                {"harness_family": fam},
            )
        return CheckResult(
            "V3_borrowed_assets",
            WARN,
            "Empty Borrowed-asset list",
        )
    return CheckResult(
        "V3_borrowed_assets",
        PASS,
        f"{len(items)} borrowed-asset row(s) declared",
    )


def check_v4_adversarial_consistency(text: str) -> CheckResult:
    body = _section(text, "Adversarial-control")
    if not body.strip():
        return CheckResult(
            "V4_adversarial_consistency",
            WARN,
            "Adversarial-control section missing or empty",
        )
    eoa_hint = re.search(r"attacker\s+EOA", body, re.IGNORECASE)
    role_gated_modifier = re.search(
        r"only(Owner|Admin|Role|Authorized)|onlyRole", body, re.IGNORECASE
    )
    operator_reviewed = re.search(
        r"operator[- ]reviewed|override|in[- ]scope role", body, re.IGNORECASE
    )
    if eoa_hint and role_gated_modifier and not operator_reviewed:
        return CheckResult(
            "V4_adversarial_consistency",
            FAIL,
            "Adversarial surface claims EOA control but lists a "
            "role-gated modifier without operator-reviewed override",
        )
    return CheckResult(
        "V4_adversarial_consistency",
        PASS,
        "Adversarial-control surface internally consistent",
    )


def check_v5_severity_supports_listed_impact(text: str) -> CheckResult:
    tier = _severity_tier(text)
    listed = _listed_impact_sentence(text)
    if tier in ("High", "Critical"):
        if not listed or listed.strip() in (TODO_MARKER, ""):
            return CheckResult(
                "V5_severity_supports_listed_impact",
                FAIL,
                f"Severity tier {tier} declared but listed-impact "
                "sentence is empty or TODO",
            )
        return CheckResult(
            "V5_severity_supports_listed_impact",
            PASS,
            f"Severity tier {tier} backed by listed-impact sentence",
        )
    return CheckResult(
        "V5_severity_supports_listed_impact",
        PASS,
        f"Severity tier {tier or '(none)'} does not require strict listed-impact backing",
    )


def check_v6_autofill_low_confidence(text: str, is_autofill: bool) -> CheckResult:
    if not is_autofill:
        return CheckResult(
            "V6_autofill_low_confidence",
            PASS,
            "Not an autofill artifact",
        )
    conf = _overall_confidence(text)
    if conf == "low":
        if TODO_MARKER not in text:
            return CheckResult(
                "V6_autofill_low_confidence",
                WARN,
                "Autofill marked overall_confidence=low but no "
                "<TODO_OPERATOR> markers — operator should sanity-check",
            )
        return CheckResult(
            "V6_autofill_low_confidence",
            PASS,
            "Autofill is overall_confidence=low and contains "
            "<TODO_OPERATOR> markers (expected; operator must fill)",
        )
    return CheckResult(
        "V6_autofill_low_confidence",
        PASS,
        f"Autofill overall_confidence={conf or '(unset)'}",
    )


def check_v7_title_schema(text: str) -> CheckResult:
    title = _title_line(text)
    if not title:
        return CheckResult(
            "V7_title_schema",
            WARN,
            "Title line not found",
        )
    if TODO_MARKER in title:
        return CheckResult(
            "V7_title_schema",
            WARN,
            "Title still contains TODO marker (skeleton or partial fill)",
        )
    low = title.lower()
    if " in " not in low:
        return CheckResult(
            "V7_title_schema",
            FAIL,
            f"Title missing ' in <component>' segment: {title!r}",
        )
    if not any(verb in low for verb in TITLE_VERBS):
        return CheckResult(
            "V7_title_schema",
            FAIL,
            f"Title missing required verb (one of: {', '.join(TITLE_VERBS)}): {title!r}",
        )
    return CheckResult(
        "V7_title_schema",
        PASS,
        "Title matches T-02 schema",
    )


# ============================================================================
# Driver
# ============================================================================


def validate(path: Path) -> List[CheckResult]:
    text = path.read_text(encoding="utf-8")
    identity = _identity_table(text)
    is_autofill = _is_autofilled_file(path, text)
    # Skeleton-only files: TODO markers are expected, skip V1 fail.
    is_skeleton_only = (
        not is_autofill
        and "Auto-generated by `tools/impact-contract-scaffolder.py`" in text
        and TODO_MARKER in text
    )

    results: List[CheckResult] = []
    results.append(check_v1_no_todos(text, is_skeleton_only=is_skeleton_only))
    results.append(check_v2_production_precondition(text, identity))
    results.append(check_v3_borrowed_assets(text, identity))
    results.append(check_v4_adversarial_consistency(text))
    results.append(check_v5_severity_supports_listed_impact(text))
    results.append(check_v6_autofill_low_confidence(text, is_autofill))
    results.append(check_v7_title_schema(text))
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("spec", help="path to filled or auto-filled impact-contract spec")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any check FAILed")
    ap.add_argument("--json-out", default=None, help="optional JSON report path")
    args = ap.parse_args(argv)

    path = Path(args.spec)
    if not path.is_file():
        print(f"spec not found: {path}", file=sys.stderr)
        return 2

    results = validate(path)
    fails = [r for r in results if r.status == FAIL]
    warns = [r for r in results if r.status == WARN]
    passes = [r for r in results if r.status == PASS]

    print(f"[impact-contract-validator] {path}")
    print(f"  rules: {len(results)} ({len(passes)} PASS, {len(warns)} WARN, {len(fails)} FAIL)")
    print()
    for r in results:
        marker = {"PASS": "OK", "WARN": "WARN", "FAIL": "FAIL"}[r.status]
        print(f"  [{marker}] {r.rule}: {r.status}")
        if r.status != PASS:
            print(f"     -> {r.message}")
            if r.extra:
                for k, v in r.extra.items():
                    print(f"        {k}: {v}")

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                {
                    "schema": "auditooor.impact_contract_validator.v1",
                    "spec": str(path),
                    "results": [
                        {
                            "rule": r.rule,
                            "status": r.status,
                            "message": r.message,
                            "extra": r.extra,
                        }
                        for r in results
                    ],
                    "fail_count": len(fails),
                    "warn_count": len(warns),
                    "pass_count": len(passes),
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    if args.strict and fails:
        print("\n  STRICT MODE: failing due to FAIL rules above.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
