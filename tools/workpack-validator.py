#!/usr/bin/env python3
"""workpack-validator.py — H-02 (extension of dispatch-brief.sh).

Per PR603 § Gate 2 acceptance #4 plus the memory-use gate: workpacks MUST
require all 7 fields:

  1. changed files / artifact paths
  2. commands run
  3. pass/fail output expected
  4. candidate disposition (SUBMIT/KILL/HOLD)
  5. known-limitation update
  6. next blocker if not complete
  7. memory context used

Validates a workpack markdown against this schema. Exits rc=0 on PASS,
rc=1 on missing required field, rc=2 on bad input.

This complements `tools/dispatch-brief.sh` (which generates the brief
template) by enforcing that completed workpacks contain every required
field BEFORE they are accepted as evidence.

Usage:
  python3 tools/workpack-validator.py <workpack.md>
  python3 tools/workpack-validator.py --json-out report.json <workpack.md>

Required header markers (case-insensitive, fuzzy):

  ## Changed files          OR  ### Files changed         OR  Artifacts:
  ## Commands               OR  ## Commands run            OR  Run:
  ## Output                 OR  ## Pass/Fail               OR  Expected output:
  ## Disposition            OR  Candidate state:           OR  Final action:
  ## Known limitation       OR  KNOWN_LIMITATIONS update:  OR  Limitations:
  ## Next blocker           OR  Next blocker:              OR  If not complete:
  ## Memory context         OR  Memory used:               OR  MCP context:

Conditional handoff checks:
  A workpack whose disposition is SUBMIT must also show the canonical audit
  chain: `make audit WS=...` and either `make audit-deep WS=...` (prefer
  `DEEP_PROFILE=all`) or an explicit audit-deep waiver/blocker. SUBMIT
  workpacks must include concrete MCP memory context (`context_pack_id`,
  `context_pack_hash`, and source refs / Memory used evidence), explicit
  chain/escalation attempt evidence, platform selector evidence (`Impact(s)`
  or severity/likelihood/impact selector language), and must not contain
  `NOT_SUBMIT_READY`, `EXECUTION_BLOCKED`, or `listed_impact_proven=false`.

  A workpack that mentions final paste or HM submission/handoff posture must
  either inline `context_pack_id`, `context_pack_hash`, and `source_refs`, or
  include the strict `memory-context-load.py --check --strict --require-proof`
  receipt command.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


REQUIRED_FIELDS = [
    {
        "name": "changed_files_or_artifacts",
        "label": "Changed files / artifact paths",
        "patterns": [
            r"^#{1,3}\s*(changed\s+files|files\s+changed|artifacts?|changed\s+artifacts?)\b",
            r"^artifacts?\s*:",
            r"^changed\s+files?\s*:",
        ],
    },
    {
        "name": "commands_run",
        "label": "Commands run",
        "patterns": [
            r"^#{1,3}\s*(commands?|commands?\s+run|how\s+to\s+run|reproduction\s+commands?)\b",
            r"^commands?\s*:",
            r"^run\s*:",
            r"^reproduction\s*:",
        ],
    },
    {
        "name": "expected_output",
        "label": "Pass/fail output expected",
        "patterns": [
            r"^#{1,3}\s*(output|expected\s+output|pass[/\s-]*fail|expected|observed\s+output|expected\s+result)\b",
            r"^expected\s+output\s*:",
            r"^pass[/\s-]*fail\s*:",
            r"^observed\s+output\s*:",
        ],
    },
    {
        "name": "candidate_disposition",
        "label": "Candidate disposition (SUBMIT/KILL/HOLD)",
        "patterns": [
            r"^#{1,3}\s*(disposition|candidate\s+disposition|final\s+action|candidate\s+state)\b",
            r"^disposition\s*:",
            r"^final\s+action\s*:",
            r"^(submit|kill|hold)\s*:",
            r"\b(SUBMIT|KILL|HOLD)\b",  # If ALL CAPS bare token appears anywhere, count as covered
        ],
    },
    {
        "name": "known_limitation_update",
        "label": "Known-limitation update",
        "patterns": [
            r"^#{1,3}\s*(known.limitation|limitations?\s+update|new\s+limitation)\b",
            r"^known.limitation\s+update\s*:",
            r"^limitations?\s*:",
            r"^new\s+limitation\s*:",
            r"\b(KNOWN_LIMITATIONS\.md|known_limitations_burndown_map\.json)\b",
        ],
    },
    {
        "name": "next_blocker_if_incomplete",
        "label": "Next blocker if not complete",
        "patterns": [
            r"^#{1,3}\s*(next\s+blocker|blockers?|if\s+not\s+complete|next\s+command)\b",
            r"^next\s+blocker\s*:",
            r"^blockers?\s*:",
            r"^next\s+command\s*:",
            r"^if\s+not\s+complete\s*:",
        ],
    },
    {
        "name": "memory_context_used",
        "label": "Memory context used",
        "patterns": [
            r"^#{1,3}\s*(memory\s+context|memory\s+used|mcp\s+context|vault\s+mcp\s+context)\b",
            r"^memory[_\s]*(context|used)\s*:",
            r"^mcp[_\s]*context\s*:",
            r"\b(context_pack_id|context_pack_hash|vault_resume_context|vault_exploit_context|vault_harness_context|vault_knowledge_gap_context)\b",
        ],
    },
]

_COMPLETE_WORKPACK_MARKER_RE = re.compile(
    r"(?im)^(?:#{1,3}\s*)?"
    r"(?:disposition|candidate\s+disposition|final\s+action|candidate\s+state|status|result)"
    r"\b[^\n]*\b(?:complete|completed|finished|finalized|closed|done)\b|"
    r"^#{1,3}\s*complete\s+workpack\b"
)
_NEGATED_COMPLETE_WORKPACK_RE = re.compile(
    r"\bnot\s+(?:yet\s+)?(?:complete|completed|finished|finalized|closed|done)\b",
    re.IGNORECASE,
)
_CHANGED_FILES_SECTION_PATTERNS = [
    re.compile(r"^#{1,3}\s*(changed\s+files|files\s+changed|artifacts?|changed\s+artifacts?)\b", re.IGNORECASE),
    re.compile(r"^artifacts?\s*:", re.IGNORECASE),
    re.compile(r"^changed\s+files?\s*:", re.IGNORECASE),
]
_COMMANDS_SECTION_PATTERNS = [
    re.compile(r"^#{1,3}\s*(commands?|commands?\s+run|reproduction\s+commands?)\b", re.IGNORECASE),
    re.compile(r"^commands?\s*:", re.IGNORECASE),
    re.compile(r"^run\s*:", re.IGNORECASE),
    re.compile(r"^reproduction\s*:", re.IGNORECASE),
]
_NO_ARTIFACT_REASON_HEADER_PATTERNS = [
    re.compile(r"^#{1,3}\s*no[_\s-]*artifact[_\s-]*reason\b", re.IGNORECASE),
    re.compile(r"^no[_\s-]*artifact[_\s-]*reason\s*:", re.IGNORECASE),
    re.compile(r"^#{1,3}\s*NO_ARTIFACT\b", re.IGNORECASE),
    re.compile(r"^NO_ARTIFACT\s*:", re.IGNORECASE),
]
_NO_ARTIFACT_REASON_INLINE_RE = re.compile(r"^\s*NO_ARTIFACT\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_TEST_OR_LOG_REFERENCE_RE = re.compile(
    r"(?im)\b(?:"
    r"pytest|go\s+test|cargo\s+test|forge\s+test|halmos|medusa|make\s+test|npm\s+test|pnpm\s+test|yarn\s+test|"
    r"agent_outputs/|\.log\b|/tmp/.*\.(?:log|txt|out|stderr|stdout)"
    r")\b"
)
_HEADING_RE = re.compile(r"^\s*#{1,6}\s+\S")

_SUBMIT_DISPOSITION_RE = re.compile(
    r"(?im)^(?:#{1,3}\s*)?"
    r"(?:disposition|candidate\s+disposition|final\s+action|candidate\s+state)"
    r"\b[^\n]*\bSUBMIT\b|^SUBMIT\b"
)
_MAKE_AUDIT_RE = re.compile(r"\bmake\s+audit\s+WS\s*=", re.IGNORECASE)
_MAKE_AUDIT_DEEP_RE = re.compile(
    r"\bmake\s+audit-deep\s+WS\s*=|\bDEEP_PROFILE\s*=\s*\w+\s+make\s+audit-deep\b",
    re.IGNORECASE,
)
_AUDIT_DEEP_WAIVER_RE = re.compile(
    r"\baudit[-_ ]deep\b[^\n]*(?:waiv|skip|not\s+run|blocked|inapplicable|budget)",
    re.IGNORECASE,
)
_E2E_WORKFLOW_COMPLETION_CLAIM_RE = re.compile(
    r"\b(?:"
    r"(?:end[-\s]*to[-\s]*end|e2e|full|canonical)\s+"
    r"(?:audit\s+)?(?:workflow|pipeline|audit)\s+"
    r"(?:complete|completed|completion|finished|finalized|closed)|"
    r"(?:workflow|pipeline|audit)\s+"
    r"(?:complete|completed|completion|finished|finalized|closed)\s+"
    r"(?:end[-\s]*to[-\s]*end|e2e)"
    r")\b",
    re.IGNORECASE,
)
_WORKFLOW_BLOCKER_ARTIFACT_RE = re.compile(
    r"(?im)^(?:[-*]\s*)?"
    r"(?:explicit\s+)?(?:workflow\s+)?(?:audit[-_\s]*(?:deep\s+)?)?"
    r"blocker[_\s-]*(?:artifact|record|report)\s*:\s*\S+"
)
_PLACEHOLDER_VALUES = {
    "",
    "-",
    "n/a",
    "na",
    "none",
    "null",
    "tbd",
    "todo",
    "unknown",
}
_CONTEXT_PACK_ID_RE = re.compile(
    r"\bcontext_pack_id\s*:\s*([^\s`]+)",
    re.IGNORECASE,
)
_CONTEXT_PACK_HASH_RE = re.compile(
    r"\bcontext_pack_hash\s*:\s*([^\s`]+)",
    re.IGNORECASE,
)
_SOURCE_REFS_RE = re.compile(r"\bsource[_\s-]*refs?\s*:\s*(.*)$", re.IGNORECASE)
_MCP_MEMORY_SOURCE_EVIDENCE_RE = re.compile(
    r"\bsource[_\s-]*refs?\s*:",
    re.IGNORECASE,
)
_MCP_WORKFLOW_CLAIM_RE = re.compile(
    r"\b(?:"
    r"mcp[-_\s]+backed|"
    r"mcp[-_\s]+workflow|"
    r"mcp[-_\s]+resume[-_\s]+context|"
    r"vault[-_\s]+mcp[-_\s]+context|"
    r"vault_(?:resume|exploit|harness|knowledge_gap)_context"
    r")\b|--call\s+vault_(?:resume|exploit|harness|knowledge_gap)_context\b",
    re.IGNORECASE,
)
_FINAL_PASTE_OR_HM_HANDOFF_RE = re.compile(
    r"\b(?:"
    r"final\s+paste|"
    r"final[_\s-]*cantina[_\s-]*paste|"
    r"hm\s+(?:submission|handoff)|"
    r"history[-\s]*mining\s+(?:submission|handoff)"
    r")\b",
    re.IGNORECASE,
)
_CHAIN_ESCALATION_EVIDENCE_RE = re.compile(
    r"\b(?:"
    r"chain(?:ing)?\s*/\s*escalation\s+attempt|"
    r"recorded\s+chain\s*/\s*escalation\s+attempt|"
    r"escalation\s*/\s*chaining\s+attempt\s+notes?|"
    r"escalation\s+attempt(?:\s+notes?)?|"
    r"chaining\s+attempt(?:\s+notes?)?|"
    r"attempt(?:ed)?\s+to\s+chain|"
    r"attempt(?:ed)?\s+to\s+escalate"
    r")\b",
    re.IGNORECASE,
)
_PLATFORM_SELECTOR_EVIDENCE_RE = re.compile(
    r"\bImpact\(s\)\b|"
    r"\bselected_impact\s*:|"
    r"\blisted-impact sentence\b|"
    r"\b(?:platform\s+)?impact\s+selector\b|"
    r"\b(?:platform\s+)?severity\s+selector\b|"
    r"\bLikelihood\s*[xX\xb7\u00d7]\s*Impact\b[^\n]*\bseverity\s+selector\b",
    re.IGNORECASE,
)
_SEVERITY_SELECTOR_FIELD_RE = re.compile(
    r"(?im)^(?:[-*]\s*)?(?:exact\s+platform\s+)?severity\s*:"
)
_LIKELIHOOD_SELECTOR_FIELD_RE = re.compile(
    r"(?im)^(?:[-*]\s*)?(?:exact\s+platform\s+)?likelihood\s*:"
)
_IMPACT_SELECTOR_FIELD_RE = re.compile(
    r"(?im)^(?:[-*]\s*)?(?:exact\s+platform\s+)?impact(?:\(s\))?\s*:"
)
_BLOCKED_SUBMIT_RE = re.compile(
    r"\b(?:NOT_SUBMIT_READY|EXECUTION_BLOCKED)\b|"
    r"\blisted_impact_proven\s*=\s*false\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Severity-rubric verbatim grep (L19 rubric-discipline gate)
# ---------------------------------------------------------------------------
#
# Codifies the L17/L18 lessons (CLAUDE.md L17 rubric-match-verbatim-or-drop
# discipline + L18 trigger-vs-attack-vector M14-trap). The gate fires on
# finding-shaped staging drafts (those that carry `Severity:` AND `Target:`
# markers) and validates:
#   1. Engagement detection: parse Target: line, resolve to <audits>/<eng>/SEVERITY.md
#   2. Severity tier: parse claimed `Severity:` row (Critical/High/Medium/Low/Info)
#   3. Verbatim grep: workpack body must contain at least one verbatim
#      listed-impact sentence from the rubric for the claimed severity tier.
#   4. Trigger-vs-attack-vector OOS check: workpack body must NOT contain an
#      explicit admission that the bug's trigger is OOS (e.g. honest-SO-crash,
#      OOS-DOS, malicious-SO trigger). If such an admission is present, the
#      gate fails per the L18 AAF M14-trap lesson.
#   5. Explicit not-fileable admissions (DROPPED, NOT FILEABLE, rubric mismatch
#      admitted in body) also fail the gate.
#
# The gate is conservative on engagement detection: if no engagement marker is
# resolvable, the rubric path is unavailable, or the rubric file is missing,
# the check is skipped (advisory) rather than failing closed — to avoid
# generating false-positives on non-engagement workpacks.
_TARGET_LINE_RE = re.compile(
    r"(?im)^(?:[-*]\s*)?target\s*:\s*[`*]*([^`\n*]+)",
)
_SEVERITY_LINE_RE = re.compile(
    r"(?im)^(?:[-*]\s*)?severity\s*:\s*\*{0,2}([A-Za-z][A-Za-z0-9 _/-]*)",
)
_RUBRIC_DISCIPLINE_FAIL_ADMISSION_RE = re.compile(
    r"\b(?:"
    r"NOT\s+FILEABLE|"
    r"not\s+submission[-_\s]*ready|"
    r"rubric\s+mismatch|"
    r"severity[-_\s]*rubric\s+verbatim\s+grep\s*[—-]+\s*FAIL|"
    r"no\s+verbatim\s+listed[-_\s]*impact\s+sentence|"
    r"no\s+matching\s+(?:rubric\s+)?row"
    r")\b",
    re.IGNORECASE,
)
# L18 trigger-vs-attack-vector M14-trap — explicit textual admissions that
# the bug's trigger is OOS or not an attack vector. Codified from the
# LEAD-COMMIT-RESUME staging draft.
_TRIGGER_OOS_ADMISSION_RE = re.compile(
    r"\b(?:"
    r"trigger[-_\s]*vs[-_\s]*attack[-_\s]*vector\s+M14[-_\s]*trap|"
    r"attacker[-_\s]*induced\s+trigger\s+NOT\s+identified|"
    r"honest[-_\s]*SO[-_\s]*crash[-_\s]*via[-_\s]*natural[-_\s]*causes|"
    r"trigger\s+is\s+honest[-_\s]*SO[-_\s]*crash|"
    r"bug'?s?\s+TRIGGER\s+is\s+(?:an?\s+)?honest\s+SO\s+crash|"
    r"trigger\s+(?:lives\s+)?in\s+OOS"
    r")\b",
    re.IGNORECASE,
)
# Default mapping of repo-host markers in `Target:` lines to local engagement
# directories under ~/audits/<engagement>. Extend by editing this dict.
_DEFAULT_ENGAGEMENT_MAP = {
    "github.com/buildonspark/spark": "spark",
    "buildonspark/spark": "spark",
}


def _resolve_engagement(text: str, engagement_map: dict[str, str] | None = None) -> str | None:
    if engagement_map is None:
        engagement_map = _DEFAULT_ENGAGEMENT_MAP
    match = _TARGET_LINE_RE.search(text)
    if not match:
        return None
    target = match.group(1).strip().lower()
    for marker, engagement in engagement_map.items():
        if marker.lower() in target:
            return engagement
    return None


def _extract_severity_claim(text: str) -> str | None:
    match = _SEVERITY_LINE_RE.search(text)
    if not match:
        return None
    raw = match.group(1).strip().rstrip(":").strip()
    raw = raw.split()[0] if raw else raw
    if not raw:
        return None
    canonical = raw.lower()
    aliases = {
        "critical": "Critical",
        "crit": "Critical",
        "high": "High",
        "medium": "Medium",
        "med": "Medium",
        "low": "Low",
        "informational": "Informational",
        "info": "Informational",
    }
    return aliases.get(canonical, raw.title())


def _extract_listed_impact_sentences(rubric_text: str) -> dict[str, list[str]]:
    """Parse SEVERITY.md to produce {tier: [verbatim sentence, ...]}.

    The expected rubric format is:

        ### Critical (...)
        | ID | Listed-impact sentence (verbatim) | Reward |
        |---|---|---|
        | CRIT-1 | <verbatim sentence> | <reward> |
        ...

        Listed-impact sentences (verbatim, bullet form for rubric grounding):

        - <verbatim sentence>
        - <verbatim sentence>

    Both the table rows and the bullet form are accepted. Bullet form is
    preferred because it is the canonical bootstrap representation.
    """
    tiers: dict[str, list[str]] = {}
    current_tier: str | None = None
    in_bullet_block = False
    tier_header_re = re.compile(r"^#{2,4}\s*(Critical|High|Medium|Low|Informational)\b", re.IGNORECASE)
    bullet_re = re.compile(r"^\s*-\s+(.+?)\s*$")
    table_row_re = re.compile(r"^\|\s*[A-Z]+-\d+\s*\|\s*([^|]+?)\s*\|")
    for line in rubric_text.splitlines():
        header = tier_header_re.match(line)
        if header:
            current_tier = header.group(1).title()
            tiers.setdefault(current_tier, [])
            in_bullet_block = False
            continue
        if "Listed-impact sentences" in line and current_tier:
            in_bullet_block = True
            continue
        if in_bullet_block and current_tier:
            bullet = bullet_re.match(line)
            if bullet:
                sentence = bullet.group(1).strip().strip("`").strip('"').strip()
                if sentence and sentence not in tiers[current_tier]:
                    tiers[current_tier].append(sentence)
                continue
            if line.startswith("#"):
                in_bullet_block = False
        if current_tier and line.startswith("|"):
            row = table_row_re.match(line)
            if row:
                sentence = row.group(1).strip().strip("`").strip('"').strip()
                if sentence and sentence not in tiers[current_tier]:
                    tiers[current_tier].append(sentence)
    return tiers


def _verbatim_listed_impact_present(text: str, sentences: list[str]) -> str | None:
    for sentence in sentences:
        if not sentence:
            continue
        if sentence in text:
            return sentence
    return None


def _severity_rubric_verbatim_grep_check(
    text: str,
    rubric_root: Path | None = None,
    engagement_map: dict[str, str] | None = None,
) -> dict | None:
    """L19 rubric-discipline gate (codifies CLAUDE.md L17 + L18 lessons).

    Returns a check-result dict or None if the gate is not applicable
    (advisory skip when engagement is unresolvable or rubric file missing).
    """
    if rubric_root is None:
        rubric_root = Path.home() / "audits"

    has_target = bool(_TARGET_LINE_RE.search(text))
    if not has_target:
        # Not a finding-shaped draft; skip.
        return None

    engagement = _resolve_engagement(text, engagement_map=engagement_map)
    if engagement is None:
        return None

    severity_claim = _extract_severity_claim(text)
    fail_admission = _RUBRIC_DISCIPLINE_FAIL_ADMISSION_RE.search(text)
    trigger_oos_admission = _TRIGGER_OOS_ADMISSION_RE.search(text)

    # Gate is applicable when the draft is finding-shaped (engagement match)
    # AND either claims a severity OR admits the rubric/trigger mismatch.
    # Drafts with neither are out-of-scope for this gate (e.g. brief notes
    # that mention `Target:` but are not severity-claim staging drafts).
    if severity_claim is None and not (fail_admission or trigger_oos_admission):
        return None

    rubric_path = rubric_root / engagement / "SEVERITY.md"
    rubric_text: str | None = None
    if rubric_path.exists():
        try:
            rubric_text = rubric_path.read_text(encoding="utf-8")
        except OSError:
            rubric_text = None

    listed_impacts: dict[str, list[str]] = {}
    sentences_for_tier: list[str] = []
    matched_sentence: str | None = None
    if rubric_text is not None:
        listed_impacts = _extract_listed_impact_sentences(rubric_text)
        if severity_claim is not None:
            sentences_for_tier = listed_impacts.get(severity_claim, [])
            matched_sentence = _verbatim_listed_impact_present(
                text, sentences_for_tier
            )

    failure_reasons: list[str] = []
    if fail_admission:
        failure_reasons.append(
            "rubric-discipline: workpack body admits no rubric row matches "
            "(per CLAUDE.md L17 valid outcomes are build-evidence-or-drop); "
            f"matched marker: {fail_admission.group(0)!r}"
        )
    if trigger_oos_admission:
        failure_reasons.append(
            "trigger-vs-attack-vector M14-trap: workpack body admits the bug's "
            "trigger is OOS / not an attack vector (per L18 AAF lesson, "
            f"consequence != attack); matched marker: {trigger_oos_admission.group(0)!r}"
        )
    if (
        severity_claim is not None
        and rubric_text is not None
        and not matched_sentence
        and sentences_for_tier
    ):
        failure_reasons.append(
            f"rubric-mismatch: claimed Severity={severity_claim} for "
            f"engagement={engagement} but no verbatim listed-impact sentence "
            f"from {rubric_path} appears in the workpack body. "
            "Per CLAUDE.md L17, valid outcomes are build-evidence-or-drop. "
            f"Expected one of: {sentences_for_tier!r}"
        )
    # If the rubric file is missing, surface that as a soft skip rather than
    # a failure — engagements not yet onboarded to the gate should not break.
    if rubric_text is None and not failure_reasons:
        return None

    present = not failure_reasons
    return {
        "name": "severity_rubric_verbatim_grep",
        "label": (
            "Severity claim verbatim-matches engagement rubric and trigger is "
            "in-scope attack vector (codifies CLAUDE.md L17 rubric-discipline "
            "+ L18 trigger-vs-attack-vector M14-trap)"
        ),
        "present": present,
        "matched_pattern": (
            f"engagement={engagement} severity={severity_claim} "
            f"rubric={rubric_path} matched_sentence={matched_sentence!r}"
        ),
        "failure_reasons": failure_reasons,
    }


def find_field(text: str, field: dict) -> tuple[bool, str | None]:
    """Returns (found, matched_pattern)."""
    for pat in field["patterns"]:
        if re.search(pat, text, re.MULTILINE | re.IGNORECASE):
            return True, pat
    return False, None


def _has_strict_memory_receipt_command(text: str) -> bool:
    for line in text.splitlines():
        lower = line.lower()
        if "python3 tools/memory-context-load.py" not in lower:
            continue
        if (
            "--check" in lower
            and "--strict" in lower
            and "--require-proof" in lower
        ):
            return True
    return False


def _is_placeholder_value(value: str | None) -> bool:
    if value is None:
        return True
    stripped = value.strip().strip("`").strip()
    if stripped.startswith("- "):
        stripped = stripped[2:].strip().strip("`").strip()
    return stripped.lower() in _PLACEHOLDER_VALUES


def _has_context_pack_id(text: str) -> bool:
    return any(
        not _is_placeholder_value(match.group(1))
        for match in _CONTEXT_PACK_ID_RE.finditer(text)
    )


def _has_context_pack_hash(text: str) -> bool:
    return any(
        not _is_placeholder_value(match.group(1))
        for match in _CONTEXT_PACK_HASH_RE.finditer(text)
    )


def _has_source_refs(text: str) -> bool:
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        match = _SOURCE_REFS_RE.search(line)
        if not match:
            continue
        candidates = [match.group(1)]
        for next_line in lines[idx + 1 : idx + 8]:
            stripped = next_line.strip()
            if not stripped:
                break
            if stripped.startswith("#"):
                break
            if re.match(r"^[A-Za-z0-9_ -]+\s*:", stripped) and not stripped.startswith(
                "-"
            ):
                break
            candidates.append(stripped)
        if any(not _is_placeholder_value(candidate) for candidate in candidates):
            return True
    return False


def _has_context_pack_trace(text: str) -> bool:
    return (
        _has_context_pack_id(text)
        and _has_context_pack_hash(text)
        and _has_source_refs(text)
    )


def _extract_section_lines(text: str, header_patterns: list[re.Pattern]) -> list[str]:
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if not any(pattern.search(line) for pattern in header_patterns):
            continue

        section: list[str] = []
        if not _HEADING_RE.match(line) and ":" in line:
            rhs = line.split(":", 1)[1].strip()
            if rhs:
                section.extend(_split_inline_values(rhs))

        for next_line in lines[idx + 1 :]:
            if _HEADING_RE.match(next_line):
                break
            section.append(next_line)
        return section
    return []


def _split_inline_values(raw: str) -> list[str]:
    return [value.strip() for value in re.split(r",|;", raw) if value.strip()]


def _normalize_list_value(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        return ""
    if normalized.startswith("- "):
        normalized = normalized[2:]
    elif normalized.startswith("* "):
        normalized = normalized[2:]
    elif normalized.startswith("+ "):
        normalized = normalized[2:]
    return normalized.strip().strip("`").strip("'\"")


def _is_complete_workpack_marked(text: str) -> bool:
    for line in text.splitlines():
        if not _COMPLETE_WORKPACK_MARKER_RE.search(line):
            continue
        if _NEGATED_COMPLETE_WORKPACK_RE.search(line):
            continue
        return True
    return False


def _artifact_lines(text: str) -> list[str]:
    return [
        _normalize_list_value(line)
        for line in _extract_section_lines(text, _CHANGED_FILES_SECTION_PATTERNS)
    ]


def _command_lines(text: str) -> list[str]:
    return [
        _normalize_list_value(line)
        for line in _extract_section_lines(text, _COMMANDS_SECTION_PATTERNS)
    ]


def _extract_no_artifact_reason_lines(text: str) -> list[str]:
    lines = _extract_section_lines(text, _NO_ARTIFACT_REASON_HEADER_PATTERNS)
    if lines:
        return [_normalize_list_value(line) for line in lines]
    reasons: list[str] = []
    for match in _NO_ARTIFACT_REASON_INLINE_RE.finditer(text):
        reasons.append(match.group(1).strip())
    return reasons


def _looks_like_artifact_path(value: str) -> bool:
    cleaned = value.strip()
    if not cleaned or _is_placeholder_value(cleaned):
        return False
    if " " in cleaned:
        return False
    if "/" in cleaned or "\\" in cleaned:
        return True
    lowered = cleaned.lower()
    return lowered.endswith(
        (
            ".md",
            ".json",
            ".jsonl",
            ".yaml",
            ".yml",
            ".toml",
            ".py",
            ".go",
            ".rs",
            ".sol",
            ".ts",
            ".js",
            ".sh",
            ".log",
        )
    )


def _complete_workpack_artifact_or_no_artifact_present(text: str) -> bool:
    for line in _artifact_lines(text):
        if _looks_like_artifact_path(line):
            return True
    for reason in _extract_no_artifact_reason_lines(text):
        if reason and not _is_placeholder_value(reason):
            return True
    return False


def _complete_workpack_tests_or_logs_present(text: str) -> bool:
    for line in _command_lines(text):
        if not line or _is_placeholder_value(line):
            continue
        if _TEST_OR_LOG_REFERENCE_RE.search(line):
            return True
    return bool(_TEST_OR_LOG_REFERENCE_RE.search(text))


def _conditional_results(
    text: str,
    rubric_root: Path | None = None,
    engagement_map: dict[str, str] | None = None,
) -> list[dict]:
    """Return conditional checks that apply to submission or handoff posture."""
    checks: list[dict] = []
    if _is_complete_workpack_marked(text):
        checks.append(
            {
                "name": "complete_workpack_artifact_or_no_artifact_reason",
                "label": "Complete workpack declares artifact paths or explicit NO_ARTIFACT reason",
                "present": _complete_workpack_artifact_or_no_artifact_present(text),
                "matched_pattern": (
                    f"{_CHANGED_FILES_SECTION_PATTERNS[0].pattern} OR "
                    f"{_NO_ARTIFACT_REASON_INLINE_RE.pattern} OR "
                    f"{_NO_ARTIFACT_REASON_HEADER_PATTERNS[0].pattern}"
                ),
            }
        )
        checks.append(
            {
                "name": "complete_workpack_tests_or_logs_reference",
                "label": "Complete workpack includes test command evidence or log references",
                "present": _complete_workpack_tests_or_logs_present(text),
                "matched_pattern": _TEST_OR_LOG_REFERENCE_RE.pattern,
            }
        )
        checks.append(
            {
                "name": "complete_workpack_has_mcp_context_trace_or_receipt_check",
                "label": (
                    "Complete workpack includes MCP memory/context evidence via "
                    "`context_pack_id`, `context_pack_hash`, and `source_refs`, "
                    "or the strict "
                    "`memory-context-load.py --check --strict --require-proof` command"
                ),
                "present": _has_context_pack_trace(text)
                or _has_strict_memory_receipt_command(text),
                "matched_pattern": (
                    f"{_CONTEXT_PACK_ID_RE.pattern} + "
                    f"{_CONTEXT_PACK_HASH_RE.pattern} + "
                    f"{_SOURCE_REFS_RE.pattern} OR "
                    "python3 tools/memory-context-load.py ... "
                    "--check --strict --require-proof"
                ),
            }
        )

    if _MCP_WORKFLOW_CLAIM_RE.search(text):
        checks.append(
            {
                "name": "mcp_claim_has_context_pack_source_evidence",
                "label": (
                    "MCP-backed workflow claim includes `context_pack_id`, "
                    "`context_pack_hash`, and `source_refs` evidence"
                ),
                "present": _has_context_pack_trace(text),
                "matched_pattern": (
                    f"{_MCP_WORKFLOW_CLAIM_RE.pattern} requires "
                    f"{_CONTEXT_PACK_ID_RE.pattern} + "
                    f"{_CONTEXT_PACK_HASH_RE.pattern} + "
                    f"{_SOURCE_REFS_RE.pattern}"
                ),
            }
        )

    if _E2E_WORKFLOW_COMPLETION_CLAIM_RE.search(text):
        checks.append(
            {
                "name": "workflow_completion_has_audit_deep_evidence_or_blocker_artifact",
                "label": (
                    "End-to-end workflow completion claim includes both "
                    "`make audit WS=...` and `make audit-deep WS=...` evidence, "
                    "or an explicit blocker artifact"
                ),
                "present": bool(
                    (
                        _MAKE_AUDIT_RE.search(text)
                        and _MAKE_AUDIT_DEEP_RE.search(text)
                    )
                    or _WORKFLOW_BLOCKER_ARTIFACT_RE.search(text)
                ),
                "matched_pattern": (
                    f"{_E2E_WORKFLOW_COMPLETION_CLAIM_RE.pattern} requires "
                    f"({_MAKE_AUDIT_RE.pattern} + {_MAKE_AUDIT_DEEP_RE.pattern}) "
                    f"OR {_WORKFLOW_BLOCKER_ARTIFACT_RE.pattern}"
                ),
            }
        )

    if _SUBMIT_DISPOSITION_RE.search(text):
        has_platform_selector_evidence = bool(
            _PLATFORM_SELECTOR_EVIDENCE_RE.search(text)
            or (
                _SEVERITY_SELECTOR_FIELD_RE.search(text)
                and _LIKELIHOOD_SELECTOR_FIELD_RE.search(text)
                and _IMPACT_SELECTOR_FIELD_RE.search(text)
            )
        )

        # SUBMIT is paste-ready posture, so a generic memory-context header is not
        # enough; require the concrete MCP context pack and traceable source evidence.
        checks.extend(
            [
                {
                    "name": "submit_has_context_pack_id",
                    "label": "SUBMIT workpack includes `context_pack_id: ...` MCP memory context",
                    "present": _has_context_pack_id(text),
                    "matched_pattern": _CONTEXT_PACK_ID_RE.pattern,
                },
                {
                    "name": "submit_has_context_pack_hash",
                    "label": (
                        "SUBMIT workpack includes `context_pack_hash: ...` MCP memory context"
                    ),
                    "present": _has_context_pack_hash(text),
                    "matched_pattern": _CONTEXT_PACK_HASH_RE.pattern,
                },
                {
                    "name": "submit_has_mcp_memory_source_evidence",
                    "label": (
                        "SUBMIT workpack includes source_refs evidence for MCP memory context"
                    ),
                    "present": _has_source_refs(text),
                    "matched_pattern": _MCP_MEMORY_SOURCE_EVIDENCE_RE.pattern,
                },
                {
                    "name": "submit_has_chain_or_escalation_attempt_evidence",
                    "label": (
                        "SUBMIT workpack includes explicit chain/escalation attempt evidence"
                    ),
                    "present": bool(_CHAIN_ESCALATION_EVIDENCE_RE.search(text)),
                    "matched_pattern": _CHAIN_ESCALATION_EVIDENCE_RE.pattern,
                },
                {
                    "name": "submit_has_platform_selector_evidence",
                    "label": (
                        "SUBMIT workpack includes platform selector evidence "
                        "(`Impact(s)` or severity/likelihood/impact selector language)"
                    ),
                    "present": has_platform_selector_evidence,
                    "matched_pattern": (
                        f"{_PLATFORM_SELECTOR_EVIDENCE_RE.pattern} OR "
                        f"{_SEVERITY_SELECTOR_FIELD_RE.pattern} + "
                        f"{_LIKELIHOOD_SELECTOR_FIELD_RE.pattern} + "
                        f"{_IMPACT_SELECTOR_FIELD_RE.pattern}"
                    ),
                },
                {
                    "name": "submit_has_make_audit",
                    "label": "SUBMIT workpack includes `make audit WS=...` evidence",
                    "present": bool(_MAKE_AUDIT_RE.search(text)),
                    "matched_pattern": _MAKE_AUDIT_RE.pattern,
                },
                {
                    "name": "submit_has_audit_deep_or_waiver",
                    "label": (
                        "SUBMIT workpack includes `make audit-deep WS=...` evidence "
                        "or an explicit audit-deep waiver/blocker"
                    ),
                    "present": bool(
                        _MAKE_AUDIT_DEEP_RE.search(text)
                        or _AUDIT_DEEP_WAIVER_RE.search(text)
                    ),
                    "matched_pattern": (
                        f"{_MAKE_AUDIT_DEEP_RE.pattern} OR {_AUDIT_DEEP_WAIVER_RE.pattern}"
                    ),
                },
                {
                    "name": "submit_has_no_blocked_readiness_markers",
                    "label": (
                        "SUBMIT workpack has no NOT_SUBMIT_READY / EXECUTION_BLOCKED / "
                        "listed_impact_proven=false marker"
                    ),
                    "present": not bool(_BLOCKED_SUBMIT_RE.search(text)),
                    "matched_pattern": _BLOCKED_SUBMIT_RE.pattern,
                },
            ]
        )

    rubric_check = _severity_rubric_verbatim_grep_check(
        text,
        rubric_root=rubric_root,
        engagement_map=engagement_map,
    )
    if rubric_check is not None:
        checks.append(rubric_check)

    if _FINAL_PASTE_OR_HM_HANDOFF_RE.search(text):
        checks.append(
            {
                "name": "handoff_has_memory_trace_or_receipt_check",
                "label": (
                    "Final paste/HM handoff workpack includes `context_pack_id`, "
                    "`context_pack_hash`, and `source_refs`, or the strict "
                    "`memory-context-load.py --check --strict --require-proof` command"
                ),
                "present": _has_context_pack_trace(text)
                or _has_strict_memory_receipt_command(text),
                "matched_pattern": (
                    f"{_CONTEXT_PACK_ID_RE.pattern} + "
                    f"{_CONTEXT_PACK_HASH_RE.pattern} + "
                    f"{_SOURCE_REFS_RE.pattern} OR "
                    "python3 tools/memory-context-load.py ... "
                    "--check --strict --require-proof"
                ),
            }
        )
    return checks


def validate_workpack(
    path: Path,
    rubric_root: Path | None = None,
    engagement_map: dict[str, str] | None = None,
) -> dict:
    text = path.read_text(encoding="utf-8")
    results = []
    for field in REQUIRED_FIELDS:
        ok, pattern = find_field(text, field)
        results.append({
            "name": field["name"],
            "label": field["label"],
            "present": ok,
            "matched_pattern": pattern,
        })
    conditional_results = _conditional_results(
        text,
        rubric_root=rubric_root,
        engagement_map=engagement_map,
    )
    missing = [r for r in results if not r["present"]]
    conditional_failures = [r for r in conditional_results if not r["present"]]
    return {
        "schema": "auditooor.workpack_validator.v1",
        "workpack": str(path),
        "field_count": len(REQUIRED_FIELDS),
        "present_count": sum(1 for r in results if r["present"]),
        "missing_count": len(missing),
        "conditional_count": len(conditional_results),
        "conditional_failure_count": len(conditional_failures),
        "results": results,
        "conditional_results": conditional_results,
        "passes": len(missing) == 0 and len(conditional_failures) == 0,
        "missing_fields": [r["label"] for r in missing + conditional_failures],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("workpack")
    ap.add_argument("--json-out", default=None)
    ap.add_argument(
        "--rubric-root",
        default=None,
        help=(
            "Override the engagement rubric root (default ~/audits). The "
            "severity-rubric verbatim grep gate looks for "
            "<rubric-root>/<engagement>/SEVERITY.md when an engagement marker "
            "is found in the workpack's `Target:` line."
        ),
    )
    args = ap.parse_args()
    path = Path(args.workpack)
    if not path.exists():
        print(f"workpack not found: {path}", file=sys.stderr)
        return 2
    rubric_root = Path(args.rubric_root) if args.rubric_root else None
    summary = validate_workpack(path, rubric_root=rubric_root)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(summary, indent=2))
    print(f"[workpack-validator] {path}")
    print(f"  required fields: {summary['field_count']}")
    print(f"  present:         {summary['present_count']}")
    print(f"  missing:         {summary['missing_count']}")
    if summary.get("conditional_count"):
        print(f"  conditional:     {summary['conditional_count']}")
        print(f"  conditional fail:{summary['conditional_failure_count']}")
    if summary["missing_count"] or summary.get("conditional_failure_count", 0):
        print()
        print("  missing fields:")
        for label in summary["missing_fields"]:
            print(f"    ❌ {label}")
        print()
        print("  Workpack does not meet PR603 § Gate 2 acceptance #4 schema.")
        return 1
    print("  ✅ all required fields present (PR603 § Gate 2 acceptance #4 satisfied)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
