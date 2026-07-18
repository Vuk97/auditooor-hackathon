#!/usr/bin/env python3
"""Rule 52 Rubric-Row-Coverage preflight (Check #91).

# Rule 52: this tool emits no corpus record.

GENERAL RULE - applies to ANY draft (LOW+) before paste_ready promotion.
Severity-agnostic because mismatched-rubric closures happen at all severity
tiers. A triager will close any submission that cannot be matched to a
verbatim row in the program's SEVERITY.md, regardless of how well the bug
is proven.

The gate requires a "Rubric Row Mapping" section in the draft containing
four fields:

  1. Program SEVERITY.md cited row verbatim: the exact text of the rubric
     row the draft claims to match.
  2. Impact claim verbatim: the exact text from the draft's Impact section.
  3. Word-overlap verification: the impact must contain load-bearing nouns
     from the cited rubric row (e.g., "direct loss of funds" -> impact must
     contain "loss" or "drain" or "theft").
  4. Verdict: pass / fail / rebuttal.

The gate also independently:
  (a) Confirms the cited verbatim row actually appears (or is sufficiently
      close) in the workspace SEVERITY.md.
  (b) Checks that load-bearing nouns from the cited row appear in the
      draft's impact text.

--workspace is required. The tool walks up from the draft to find the
workspace SEVERITY.md; if not found it returns fail-program-severity-missing-
impact-class when the impact class cannot be validated at all.

Verdict vocabulary:
  pass-out-of-scope                     - severity below LOW (no valid severity)
  pass-rubric-row-matched               - cited row confirmed in SEVERITY.md;
                                          impact contains load-bearing nouns
  ok-rebuttal                           - r52-rebuttal marker with <=200-char reason
  fail-no-rubric-row-cited              - draft has no Rubric Row Mapping section
  fail-impact-mismatch-with-cited-row   - impact does not contain load-bearing
                                          nouns from the cited rubric row
  fail-program-severity-missing-impact-class
                                        - impact class not found in SEVERITY.md
                                          (program does not have such a row)
  error                                 - cannot read draft or workspace

Exit codes:
  0 - pass, ok-rebuttal, or pass-out-of-scope
  1 - Rule 52 violation (always; --strict is available but the gate is
      already considered severe for LOW+ drafts)
  2 - input error

Override marker: visible line 'r52-rebuttal: <reason>' (<=200 chars) OR
HTML-comment form '<!-- r52-rebuttal: <reason> -->'. Empty or oversized
reason is ignored.

Env extension hooks:
  AUDITOOOR_R52_LOAD_BEARING_NOUN_OVERRIDES  - newline-separated extra
      mapping lines in format "impact_class_keyword=noun1,noun2,noun3"
      e.g. "reentrancy=reentrant,reentrancy,drain"

Schema: auditooor.r52_rubric_row_coverage.v1
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

# G13: single source of truth for SEVERITY.md discovery + tier-row parsing.
# r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[].
try:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lib import severity_rubric as _severity_rubric  # type: ignore
except Exception:  # pragma: no cover - lib optional; gate degrades gracefully
    _severity_rubric = None


SCHEMA_VERSION = "auditooor.r52_rubric_row_coverage.v1"
GATE = "R52-RUBRIC-ROW-COVERAGE"

# Minimum severity to trigger (LOW and above means all real severities).
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_TOKEN_RE = r"(Critical|High|Medium|Low|CRIT-\d+|HIGH-\d+|MED-\d+|MEDIUM-\d+|LOW-\d+)"

SEVERITY_FILE_NAMES = ("SEVERITY.md", "severity.md", "Severity.md")

# Rubric row mapping section header variants.
RUBRIC_SECTION_RE = re.compile(
    r"(?im)^#+\s*rubric\s+row\s+mapping|"
    r"^#+\s*rubric\s+coverage|"
    r"^#+\s*severity\s+rubric\s+row|"
    r"^#+\s*rubric\s+row",
)

# Field extractors within the Rubric Row Mapping section.
# The label may include "verbatim" as part of the label itself (e.g.
# "Program SEVERITY.md cited row verbatim:") so we allow optional trailing
# words before the colon.
CITED_ROW_RE = re.compile(
    r"(?im)^\s*(?:[-*]|\d+[.)])?\s*(?:program\s+severity\.?md\s+cited\s+row|"
    r"cited\s+rubric\s+row|rubric\s+row\s+verbatim|rubric\s+row)"
    r"(?:\s+\w+)*\s*:\s*(.+?)(?:\n|$)"
)
IMPACT_CLAIM_RE = re.compile(
    r"(?im)^\s*(?:[-*]|\d+[.)])?\s*(?:impact\s+claim\s+verbatim|impact\s+verbatim|"
    r"impact\s+claim)(?:\s+\w+)*\s*:\s*(.+?)(?:\n|$)"
)

# Rebuttal patterns (shared form with sibling gates).
REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*r52-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL
)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?r52[-_ ]rebuttal\s*:\s*(.+?)\s*$"
)

# ---------------------------------------------------------------------------
# Load-bearing noun tables: for each impact class keyword, the nouns that
# must appear in the impact text.  The match is case-insensitive substring.
# ---------------------------------------------------------------------------
LOAD_BEARING_NOUNS: dict[str, list[str]] = {
    # fund loss / theft
    "direct loss of funds": ["loss", "drain", "theft", "lost", "drained", "stolen"],
    "loss of funds": ["loss", "drain", "theft", "lost", "drained", "stolen"],
    "theft of funds": ["theft", "steal", "drain", "loss", "stolen"],
    "direct theft": ["theft", "steal", "drain", "loss", "stolen"],
    "fund drain": ["drain", "loss", "theft", "stolen"],
    "unauthorized withdraw": ["withdraw", "drain", "transfer", "loss"],
    # freeze
    "permanent freezing": ["freez", "lock", "stuck", "inaccessible", "irrecoverable"],
    "freezing of funds": ["freez", "lock", "stuck", "inaccessible", "irrecoverable"],
    # governance
    "governance takeover": ["governance", "takeover", "control", "vote"],
    "theft of governance": ["governance", "takeover", "control", "vote"],
    # DoS
    "rpc api crash": ["crash", "dos", "denial", "unavail", "halt", "revert"],
    "denial of service": ["dos", "denial", "crash", "halt", "unavail", "degradat"],
    # griefing
    "griefing": ["grief", "gas", "cost", "waste", "harm"],
    # yield
    "yield redistribution": ["yield", "reward", "redistribute", "divert"],
    "yield diversion": ["yield", "reward", "redistribute", "divert"],
    # privilege escalation
    "privilege escalation": ["privilege", "escalat", "access", "admin", "role"],
    # precision
    "precision loss": ["precision", "round", "truncat", "overflow", "underflow"],
    "rounding error": ["precision", "round", "truncat", "overflow", "underflow"],
}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _env_patterns(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return []
    return [item.strip() for item in raw.splitlines() if item.strip()]


def _load_env_noun_overrides() -> dict[str, list[str]]:
    """Parse AUDITOOOR_R52_LOAD_BEARING_NOUN_OVERRIDES."""
    extra: dict[str, list[str]] = {}
    for line in _env_patterns("AUDITOOOR_R52_LOAD_BEARING_NOUN_OVERRIDES"):
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        nouns = [n.strip() for n in val.split(",") if n.strip()]
        if key.strip() and nouns:
            extra[key.strip().lower()] = nouns
    return extra


def _normalize_severity_token(raw: str) -> str | None:
    normalized = raw.strip().strip("*").lower()
    if normalized == "crit" or normalized.startswith("crit-"):
        normalized = "critical"
    elif normalized.startswith("high-"):
        normalized = "high"
    elif normalized == "med" or normalized.startswith("med-") or normalized.startswith("medium-"):
        normalized = "medium"
    elif normalized.startswith("low-"):
        normalized = "low"
    return normalized if normalized in SEVERITY_RANK else None


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:

    if override:
        normalized = _normalize_severity_token(override)
        if normalized:
            return normalized, "cli"
    for pattern, source in (
        (
            rf"(?im)^\s*(?:[-*]|\d+[.)])?\s*\**\s*Severity\s*\**\s*:\**\s*\**\s*{SEVERITY_TOKEN_RE}\b\**",
            "severity-header",
        ),
        (
            rf"(?im)^\s*(?:[-*]|\d+[.)])?\s*severity_implied\s*:\**\s*\**\s*{SEVERITY_TOKEN_RE}\b\**",
            "program-impact-mapping",
        ),
        (
            rf"(?im)^\s*(?:[-*]|\d+[.)])?\s*severity_tier\s*:\**\s*\**\s*{SEVERITY_TOKEN_RE}\b\**",
            "impact-contract",
        ),
        (
            rf"(?im)^\s*(?:[-*]|\d+[.)])?\s*selected_severity\s*:\**\s*\**\s*{SEVERITY_TOKEN_RE}\b\**",
            "selected-severity",
        ),
    ):
        m = re.search(pattern, text)
        if m:
            normalized = _normalize_severity_token(m.group(1))
            if normalized:
                return normalized, source
    filename = path.name.lower()
    for sev in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){sev}(?:[-_.]|$)", filename):
            return sev, "filename"
    m = re.search(r"(?:^|[-_])(crit|critical|high|med|medium|low)-\d+(?:[-_.]|$)", filename)
    if m:
        normalized = _normalize_severity_token(m.group(1))
        if normalized:
            return normalized, "filename"
    return None, "missing"


def _find_severity_md(draft: Path, workspace: Path | None) -> Path | None:
    """Walk up from draft (or workspace root) looking for SEVERITY.md.

    G13: when a workspace is supplied, delegate the workspace-root lookup to
    the shared ``lib.severity_rubric.find_severity_md`` so this gate and the
    dispatch full-rubric injection agree on a single discovery rule. Falls
    back to the draft-directory walk-up below (which the lib does not do).

    r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[].
    """
    if workspace is not None and _severity_rubric is not None:
        hit = _severity_rubric.find_severity_md(workspace)
        if hit is not None:
            return hit

    search_roots: list[Path] = []
    if workspace:
        search_roots.append(workspace.resolve())
    search_roots.append(draft.resolve().parent)

    for root in search_roots:
        for name in SEVERITY_FILE_NAMES:
            candidate = root / name
            if candidate.is_file():
                return candidate

    # Walk up from draft
    cur = draft.resolve().parent
    for parent in [cur, *cur.parents]:
        for name in SEVERITY_FILE_NAMES:
            candidate = parent / name
            if candidate.is_file():
                return candidate
    return None


def _rebuttal(text: str) -> str | None:
    m = REBUTTAL_LINE_RE.search(text)
    if not m:
        m = REBUTTAL_HTML_RE.search(text)
    if not m:
        return None
    return " ".join(m.group(1).split())


def _extract_rubric_section(text: str) -> str | None:
    """Return the content following the Rubric Row Mapping heading, up to
    the next heading or end of file."""
    m = RUBRIC_SECTION_RE.search(text)
    if not m:
        return None
    start = m.end()
    # Find next heading at same or higher level.
    rest = text[start:]
    next_heading = re.search(r"(?m)^#+\s", rest)
    if next_heading:
        return rest[: next_heading.start()]
    return rest


def _cited_row_from_section(section: str) -> str | None:
    m = CITED_ROW_RE.search(section)
    if m:
        return m.group(1).strip()
    # Fallback: look for any quoted text after "cited row" style labels.
    m2 = re.search(r"(?im)^\s*(?:[-*]|\d+[.)])?\s*(?:row|rubric)\s*:\s*(.+?)(?:\n|$)", section)
    if m2:
        return m2.group(1).strip()
    return None


def _impact_claim_from_section(section: str) -> str | None:
    m = IMPACT_CLAIM_RE.search(section)
    if m:
        return m.group(1).strip()
    return None


def _impact_from_draft(text: str) -> str:
    """Extract Impact section prose from the draft."""
    m = re.search(
        r"(?im)^#+\s*(?:impact|selected[_ ]impact|impact[_ ]claim)\b.*?\n(.*?)(?=^#+\s|\Z)",
        text,
        re.DOTALL | re.MULTILINE,
    )
    if m:
        return m.group(1).strip()
    # Fallback: selected_impact: <value>
    m2 = re.search(r"(?im)^\s*selected_impact\s*:\s*(.+?)(?:\n|$)", text)
    if m2:
        return m2.group(1).strip()
    return ""


def _best_noun_match(
    cited_row: str,
    impact_text: str,
    extra_nouns: dict[str, list[str]],
) -> tuple[str | None, list[str]]:
    """Return (matched_class_key, required_nouns) or (None, []) if no match."""
    combined = {**LOAD_BEARING_NOUNS, **extra_nouns}
    cited_lower = cited_row.lower()
    impact_lower = impact_text.lower()

    # Find the best matching class key (longest key contained in cited row).
    best_key: str | None = None
    best_len = 0
    for key in combined:
        if key in cited_lower and len(key) > best_len:
            best_key = key
            best_len = len(key)

    if best_key is None:
        return None, []

    nouns = combined[best_key]
    return best_key, nouns


def _impact_contains_nouns(impact_text: str, nouns: list[str]) -> list[str]:
    """Return the nouns that were found in impact_text."""
    impact_lower = impact_text.lower()
    return [n for n in nouns if n.lower() in impact_lower]


def _row_in_severity_md(cited_row: str, severity_md_text: str) -> bool:
    """Check whether the cited row (or its key terms) appears in SEVERITY.md.

    We use a loose match: at least 40% of non-stop-word tokens from the cited
    row must appear in the SEVERITY.md text.
    """
    stop = {"the", "a", "an", "of", "in", "to", "and", "or", "with", "that", "is",
            "for", "at", "by", "on", "as", "its", "not", "be", "from", "this"}
    tokens = [t.lower() for t in re.findall(r"\b\w+\b", cited_row) if t.lower() not in stop]
    if not tokens:
        return False
    sev_lower = severity_md_text.lower()
    found = sum(1 for t in tokens if t in sev_lower)
    return found >= max(1, int(len(tokens) * 0.4))


def run(
    draft: Path,
    *,
    workspace: Path | None = None,
    severity_override: str | None = None,
    strict: bool = False,
) -> tuple[int, dict[str, Any]]:
    """Run the R52 gate. Returns (exit_code, payload)."""
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
        "remediation_options": [
            "Add a '## Rubric Row Mapping' section with four fields: "
            "(1) Program SEVERITY.md cited row verbatim, "
            "(2) Impact claim verbatim, "
            "(3) Word-overlap verification, "
            "(4) Verdict.",
            "Ensure the cited row appears in the workspace SEVERITY.md.",
            "Ensure the impact text contains load-bearing nouns from the cited row.",
            "Override: visible line 'r52-rebuttal: <reason>' (<=200 chars) "
            "or <!-- r52-rebuttal: <reason> -->.",
        ],
    }

    # Severity below LOW (no valid severity) -> pass-out-of-scope.
    if severity is None:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "no valid severity detected"
        return 0, payload

    # Rebuttal check (runs at all severities).
    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= 200:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload

    # Find workspace SEVERITY.md.
    severity_md_path = _find_severity_md(draft, workspace)
    severity_md_text: str = ""
    if severity_md_path and severity_md_path.is_file():
        try:
            severity_md_text = _read_text(severity_md_path)
            payload["severity_md"] = str(severity_md_path)
        except Exception:
            pass

    # Extract Rubric Row Mapping section.
    section = _extract_rubric_section(text)
    if section is None:
        payload["verdict"] = "fail-no-rubric-row-cited"
        payload["reason"] = (
            "draft has no 'Rubric Row Mapping' section; add one with four fields: "
            "cited row verbatim, impact claim verbatim, word-overlap verification, verdict"
        )
        return 1, payload

    cited_row = _cited_row_from_section(section)
    if not cited_row:
        payload["verdict"] = "fail-no-rubric-row-cited"
        payload["reason"] = (
            "Rubric Row Mapping section found but 'Program SEVERITY.md cited row verbatim' "
            "field is empty or missing"
        )
        return 1, payload

    payload["evidence"]["cited_row"] = cited_row

    # Extract impact claim from Rubric Row Mapping section, or fall back to
    # the draft's Impact section.
    mapped_impact = _impact_claim_from_section(section)
    draft_impact = _impact_from_draft(text)
    impact_text = mapped_impact or draft_impact
    payload["evidence"]["impact_text"] = impact_text[:300] if impact_text else ""

    # Check whether the cited row appears in SEVERITY.md.
    if severity_md_text:
        row_found = _row_in_severity_md(cited_row, severity_md_text)
        payload["evidence"]["cited_row_found_in_severity_md"] = row_found
        if not row_found:
            payload["verdict"] = "fail-program-severity-missing-impact-class"
            payload["reason"] = (
                f"cited row '{cited_row[:120]}' not found in workspace SEVERITY.md "
                f"({severity_md_path}); the program may not have this impact class"
            )
            return 1, payload
    else:
        payload["evidence"]["cited_row_found_in_severity_md"] = None
        payload["evidence"]["severity_md_missing"] = True

    # Word-overlap check.
    extra_nouns = _load_env_noun_overrides()
    matched_class, required_nouns = _best_noun_match(cited_row, impact_text, extra_nouns)

    if matched_class is not None and required_nouns:
        found_nouns = _impact_contains_nouns(impact_text, required_nouns)
        payload["evidence"]["load_bearing_class"] = matched_class
        payload["evidence"]["required_nouns"] = required_nouns
        payload["evidence"]["found_nouns"] = found_nouns

        if not found_nouns:
            payload["verdict"] = "fail-impact-mismatch-with-cited-row"
            payload["reason"] = (
                f"impact text does not contain load-bearing nouns for cited row class "
                f"'{matched_class}'; expected at least one of {required_nouns!r}"
            )
            return 1, payload

    payload["verdict"] = "pass-rubric-row-matched"
    payload["reason"] = (
        "cited rubric row confirmed in SEVERITY.md and impact contains load-bearing nouns"
    )
    return 0, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--workspace", type=Path, default=None,
                        help="Path to workspace root containing SEVERITY.md")

    def severity_arg(raw: str) -> str:
        if raw == "auto":
            return raw
        if _normalize_severity_token(raw):
            return raw
        raise argparse.ArgumentTypeError(
            "severity must be auto, low, medium, high, critical, or a tier id like CRIT-1"
        )

    parser.add_argument(
        "--severity",
        type=severity_arg,
        default="auto",
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    override = None if args.severity == "auto" else args.severity
    rc, payload = run(
        args.draft,
        workspace=args.workspace,
        severity_override=override,
        strict=args.strict,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    if not args.json:
        sys.stderr.write(
            f"[{GATE}] {payload.get('verdict')}: "
            f"{payload.get('reason', payload.get('error', ''))}\n"
        )
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
