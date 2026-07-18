#!/usr/bin/env python3
"""Rule 53 prior-audit-finding-supersede-check (Check #99).

# Rule 53: this tool emits no corpus record.

Generalizes L31 (dupe-preflight) from in-workspace dashboard-grep to in-tree
prior_audits/* corpus deep-scan. L31 catches workspace-local dupes (other
findings filed by this engagement). R53 catches EXTERNAL prior-audit
acknowledgements - findings in published audit reports under
<workspace>/prior_audits/* (PDF extracts or markdown audit-report extracts)
that supersede the current finding.

Trigger: HIGH+ drafts before paste_ready promotion.

Required section: "Prior-Audit Supersede Scan" with 4 sub-fields:
  1. Workspace prior_audits/ inventory: list every audit-report file scanned
  2. Matched prior finding: if a prior finding covers the same root cause /
     file:line, cite the audit report + section + verbatim quote
  3. Extension-distinct evidence: if matched, does the new finding break the
     prior mitigation in a new way OR exploit a downstream surface not covered?
  4. Verdict

Verdicts:
  pass-out-of-scope                - severity below HIGH, or no draft provided
  pass-no-prior-audits-corpus      - no prior_audits/ dir or no readable files
  pass-no-matching-prior-finding   - scan performed, no root-cause overlap found
  pass-no-matching-corpus-prior-finding - in-ws clean AND no cross-workspace
                                     corpus prior-audit/solodit match either
  pass-extension-distinct-from-prior - prior finding found but new finding is distinct
  ok-rebuttal                      - valid r53-rebuttal marker present
  fail-superseded-by-prior-audit   - prior finding covers the same root cause,
                                     no extension-distinct evidence
  fail-superseded-by-corpus-prior-audit - a cross-workspace corpus prior-audit /
                                     solodit record covers the same root cause
                                     (shared file-ref AND >=2 shared root-cause
                                     tokens), no extension-distinct evidence
  fail-no-supersede-scan           - HIGH+ draft is missing the required
                                     "Prior-Audit Supersede Scan" section
  error

Cross-workspace corpus dedup (default ON):
  R53 + L31 historically read ONLY the current workspace's prior_audits/ dir,
  so a finding already covered by a prior-audit / solodit record in the corpus
  (any OTHER workspace) sailed through clean. The corpus prior-audit + solodit
  records under audit/corpus_tags/tags/**/*.{json,yaml,yml} are now consumed for
  cross-workspace dedup. To keep noise down against a huge corpus, the corpus
  scan is GATED: it requires BOTH a shared file-ref AND >=2 shared root-cause
  tokens (the stronger file:line co-occurrence) before declaring a supersede.
  Toggle with --corpus-scan / --no-corpus-scan; fixture root via
  AUDITOOOR_R53_CORPUS_ROOT.

CLI: <draft.md> [--workspace <ws>] [--severity {auto,LOW,MEDIUM,HIGH,CRITICAL}]
     [--corpus-scan | --no-corpus-scan] [--strict] [--json]

Override marker: r53-rebuttal: <reason> <=200 chars
             OR <!-- r53-rebuttal: <reason> -->

Schema: auditooor.r53_prior_audit_supersede.v1

Exit codes:
  0 - pass / ok-rebuttal / out-of-scope
  1 - Rule 53 violation (fail-* verdict)
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "auditooor.r53_prior_audit_supersede.v1"
GATE = "R53-PRIOR-AUDIT-FINDING-SUPERSEDE"
REBUTTAL_MAX_CHARS = 200

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# ---------------------------------------------------------------------------
# Prior-audit overlap signals
# ---------------------------------------------------------------------------

# Patterns that indicate a prior-audit finding covers fund loss / freeze /
# the same broad root-cause class as common HIGH+ findings.
DEFAULT_PRIOR_FINDING_PATTERNS: list[str] = [
    r"\bloss\s+of\s+funds?\b",
    r"\bfund\s+(?:drain|loss|theft|freeze|stolen)\b",
    r"\bunauthorized\s+(?:withdraw|transfer|mint|access)\b",
    r"\bpermanent(?:ly)?\s+(?:frozen?|locked?|stuck)\b",
    r"\breentrancy\b",
    r"\binteger\s+(?:overflow|underflow)\b",
    r"\bprecision\s+(?:loss|error)\b",
    r"\border\s+manipulation\b",
    r"\bprice\s+manipulation\b",
    r"\boracle\s+manipulation\b",
    r"\baccess\s+control\b",
    r"\bprivilege\s+escalation\b",
    r"\bfront.?run(?:ning)?\b",
    r"\bsandwich\s+attack\b",
    r"\bflash\s+loan\b",
    r"\bslippage\b",
    r"\bliquidation\s+(?:underflow|manipulation|bypass)\b",
    r"\bvalidation\s+(?:missing|absent|skipped|bypassed)\b",
    r"\bmissing\s+(?:check|guard|validation|revert)\b",
    r"\bbypass(?:ed|ing)?\b",
    r"\b3\.2\.[0-9]+\b",   # prior audit section numbering style (e.g. Cantina 3.2.5)
    r"\b[HMC]-[0-9]+\b",   # finding ID styles e.g. H-01, M-03, C-01
    r"\bfinding\s+[0-9]+\b",
    r"\bissue\s+[0-9]+\b",
    r"\bhigh\s+severity\b",
    r"\bcritical\s+severity\b",
]

# Phrases that indicate the prior finding was risk-accepted / acknowledged
# (strengthens the supersede signal).
ACKNOWLEDGED_IN_PRIOR_RE = re.compile(
    r"\backnowledged\b|\baccepted[- ]risk\b|\bwont[- ]fix\b|\bwon['']t\s+fix\b"
    r"|\bby[- ]design\b|\bintentional(?:ly)?\b|\brisk[- ]accepted\b"
    r"|\bno[- ](?:fix|patch|mitigation)\s+(?:planned|required|needed)\b"
    r"|\barchitectural(?:ly)?\s+(?:by[- ]design|intentional)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Section detection: "Prior-Audit Supersede Scan"
# ---------------------------------------------------------------------------

SECTION_RE = re.compile(
    r"(?im)^#{1,4}\s*Prior[- ]Audit\s+Supersede\s+Scan"
    r"|^Prior[- ]Audit\s+Supersede\s+Scan\s*:?\s*$",
)

# Sub-field 1: inventory declaration
INVENTORY_RE = re.compile(
    r"(?im)(?:(?:prior[- ]audits?/?|workspace)\s+(?:inventory|corpus|files?)"
    r"|files?\s+scanned|audit[- ]report\s+files?|inventory\s*:)",
)

# Sub-field 2: matched-prior-finding
MATCHED_RE = re.compile(
    r"(?im)(?:matched\s+prior\s+finding"
    r"|prior\s+(?:finding|issue|report)\s+(?:found|matched|covers?)"
    r"|(?:no\s+)?match(?:ing)?\s+prior\s+find"
    r"|prior\s+audit\s+match)",
)

# Sub-field 3: extension-distinct
EXTENSION_RE = re.compile(
    r"(?im)(?:extension[- ]distinct"
    r"|distinct\s+(?:from|extension|evidence|surface)"
    r"|new\s+(?:variant|bypass|surface|attack|exploit|call\s*site)"
    r"|breaks?\s+(?:the\s+)?(?:prior|mitigation|existing)"
    r"|downstream\s+surface\s+not\s+covered"
    r"|not\s+(?:covered|addressed)\s+(?:by|in)\s+(?:the\s+)?prior)",
)

# Sub-field 4: verdict declaration
VERDICT_FIELD_RE = re.compile(
    r"(?im)verdict\s*:\s*(?:pass|fail|no[- ]prior|no[- ]match|extension[- ]distinct"
    r"|superseded|no[- ]acknowledgement|distinct|not[- ]superseded|n/?a|none)",
)

# ---------------------------------------------------------------------------
# Rebuttal detection
# ---------------------------------------------------------------------------

REBUTTAL_RE = re.compile(
    r"r53[- ]rebuttal\s*:\s*(.{1," + str(REBUTTAL_MAX_CHARS) + r"}?)(?:\s*-->|\s*$)",
    re.IGNORECASE | re.DOTALL,
)

REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*r53[- ]rebuttal\s*:\s*(.{1," + str(REBUTTAL_MAX_CHARS) + r"}?)-->",
    re.IGNORECASE | re.DOTALL,
)

# ---------------------------------------------------------------------------
# Severity parsing (matches other rule tools)
# ---------------------------------------------------------------------------

SEVERITY_HEADER_RE = re.compile(
    r"(?im)^[-*]?\s*severity\s*:?\s*(critical|high|medium|low|informational|info)",
)


def _parse_severity(text: str, cli_severity: str) -> str:
    if cli_severity and cli_severity.lower() != "auto":
        return cli_severity.lower()
    m = SEVERITY_HEADER_RE.search(text)
    if m:
        return m.group(1).lower()
    return "unknown"


def _severity_gte_high(sev: str) -> bool:
    return SEVERITY_RANK.get(sev.lower(), 0) >= SEVERITY_RANK["high"]


# ---------------------------------------------------------------------------
# Prior-audits corpus loading
# ---------------------------------------------------------------------------

PRIOR_AUDITS_SUBDIR = "prior_audits"
READABLE_SUFFIXES = {".txt", ".md", ".rst", ".json"}


def _load_prior_audits(workspace: Path) -> dict[str, str]:
    """Return {filename: text} for every readable file under prior_audits/."""
    pa_dir = workspace / PRIOR_AUDITS_SUBDIR
    if not pa_dir.is_dir():
        return {}
    corpus: dict[str, str] = {}
    for f in sorted(pa_dir.rglob("*")):
        if not f.is_file():
            continue
        if f.suffix.lower() not in READABLE_SUFFIXES:
            continue
        try:
            corpus[str(f.relative_to(workspace))] = f.read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            pass
    return corpus


# ---------------------------------------------------------------------------
# Cross-workspace corpus prior-audit / solodit loading (R53 corpus dedup)
# ---------------------------------------------------------------------------

# Corpus layout, relative to repo root: audit/corpus_tags/tags/**/*.{yaml,yml,json}
CORPUS_TAGS_RELDIR = Path("audit") / "corpus_tags" / "tags"
CORPUS_SUFFIXES = {".yaml", ".yml", ".json"}

# Only finding-bearing record families carry a prior-published-finding root
# cause: prior-audit:* extracts and solodit:* extracts. dsl_pattern_*, evm_*,
# SUMMARY.json, etc. are not per-finding records and would inject noise.
CORPUS_RECORD_PREFIXES = ("prior-audit-", "solodit")

# record_id line in a hackerman record (yaml or json).
_CORPUS_RECORD_ID_RE = re.compile(
    r'(?im)^\s*["\']?record_id["\']?\s*[:=]\s*["\']?([^"\'\n]+?)["\']?\s*,?\s*$'
)


def _find_repo_root(start: Path) -> Path | None:
    """Walk upward from *start* to find the repo root holding the corpus dir.

    The repo root is the first ancestor containing audit/corpus_tags/tags/.
    Returns None if no such ancestor exists.
    """
    cur = start.resolve()
    for cand in (cur, *cur.parents):
        if (cand / CORPUS_TAGS_RELDIR).is_dir():
            return cand
    return None


def _corpus_record_text(raw: str, fallback_id: str) -> tuple[str, str]:
    """Return (record_id, text) for a corpus record file's raw contents.

    We do NOT full-parse YAML/JSON (the corpus is ~70k finding records); the
    overlap logic only needs the raw text body for token + file-ref extraction,
    which the existing _extract_root_cause_tokens / _extract_file_refs operate
    on directly. record_id is sniffed via a cheap line regex.
    """
    m = _CORPUS_RECORD_ID_RE.search(raw)
    rid = m.group(1).strip() if m else fallback_id
    return rid, raw


def _load_corpus_prior_audits(repo_root: Path) -> dict[str, str]:
    """Return {record_id -> raw text} for corpus prior-audit + solodit records.

    Walks audit/corpus_tags/tags/**/*.{yaml,yml,json}, restricted to the
    finding-bearing record families (prior-audit-*, solodit*) by filename. The
    text is the raw file body (target_component / attacker_action_sequence /
    required_preconditions / fix_pattern / source_audit_ref / shape_tags all
    live inline), reused by the same overlap extractors as the in-ws scan.
    """
    tags_dir = repo_root / CORPUS_TAGS_RELDIR
    if not tags_dir.is_dir():
        return {}
    corpus: dict[str, str] = {}
    for f in tags_dir.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix.lower() not in CORPUS_SUFFIXES:
            continue
        name = f.name
        if not name.startswith(CORPUS_RECORD_PREFIXES):
            continue
        try:
            raw = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rid, text = _corpus_record_text(raw, fallback_id=str(f.name))
        # last-writer-wins on a duplicate record_id is fine (same finding).
        corpus[rid] = text
    return corpus


# ---------------------------------------------------------------------------
# Root-cause token extraction (shared between draft and prior-audit texts)
# ---------------------------------------------------------------------------

# Patterns we compile from the environment override.
_ENV_PRIOR_PATTERNS_RAW = os.environ.get(
    "AUDITOOOR_R53_PRIOR_FINDING_PATTERNS", ""
).splitlines()

_PRIOR_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in DEFAULT_PRIOR_FINDING_PATTERNS
    if p
] + [
    re.compile(p, re.IGNORECASE) for p in _ENV_PRIOR_PATTERNS_RAW
    if p.strip()
]


def _extract_root_cause_tokens(text: str) -> set[str]:
    """Return set of lower-cased keyword tokens matched in text."""
    tokens: set[str] = set()
    for pat in _PRIOR_PATTERNS:
        for m in pat.finditer(text):
            tokens.add(m.group(0).lower().strip())
    return tokens


# File:line reference pattern to compare specific code references.
FILE_LINE_RE = re.compile(r"[a-zA-Z_][\w/.-]{2,60}\.(?:sol|go|rs|py|ts|js)(?::[0-9]+)?")


def _extract_file_refs(text: str) -> set[str]:
    """Return set of file (optionally :line) references."""
    refs = {m.group(0).lower() for m in FILE_LINE_RE.finditer(text)}
    return refs


# Minimum shared root-cause tokens for a CORPUS supersede (stronger bar than the
# in-ws scan, which fires on any single shared token, because the corpus is huge).
CORPUS_MIN_SHARED_TOKENS = 2


def _scan_corpus_overlap(
    corpus: dict[str, str],
    draft_tokens: set[str],
    draft_file_refs: set[str],
) -> list[dict[str, Any]]:
    """Return GATED cross-workspace corpus overlaps.

    A corpus record only counts as superseding when it shares BOTH:
      - at least one file-ref with the draft (file:line co-occurrence), AND
      - at least CORPUS_MIN_SHARED_TOKENS root-cause tokens.
    The shared file-ref requirement makes the match cite a concrete code site,
    not just generic vocabulary, keeping FP noise down against ~70k records.

    Cheap pre-filter: a record is only token/file-ref-extracted when its raw
    body contains at least one draft file-ref substring; without a shared
    file-ref the gate can never fire, so skipping is safe and avoids running the
    regex extractors over the whole corpus.
    """
    if not draft_file_refs or len(draft_tokens) < CORPUS_MIN_SHARED_TOKENS:
        # Gate can never fire: no file-ref to co-locate, or too few draft tokens.
        return []
    overlapping: list[dict[str, Any]] = []
    for rid, text in corpus.items():
        low = text.lower()
        # Pre-filter: must contain at least one draft file-ref as a substring.
        if not any(ref in low for ref in draft_file_refs):
            continue
        rec_file_refs = _extract_file_refs(text)
        common_files = draft_file_refs & rec_file_refs
        if not common_files:
            continue
        rec_tokens = _extract_root_cause_tokens(text)
        common_tokens = draft_tokens & rec_tokens
        if len(common_tokens) < CORPUS_MIN_SHARED_TOKENS:
            continue
        overlapping.append(
            {
                "record_id": rid,
                "common_tokens": sorted(common_tokens),
                "common_file_refs": sorted(common_files),
                "acknowledged_in_prior": bool(ACKNOWLEDGED_IN_PRIOR_RE.search(text)),
            }
        )
    return overlapping


# ---------------------------------------------------------------------------
# Main check logic
# ---------------------------------------------------------------------------

def check(
    draft_path: Path,
    workspace: Path,
    severity_cli: str = "auto",
    strict: bool = False,
    corpus_scan: bool = True,
    corpus_root: Path | None = None,
) -> dict[str, Any]:
    """Return result dict with verdict + supporting fields."""

    # --- read draft -------------------------------------------------------
    try:
        draft_text = draft_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return _error(f"cannot read draft: {exc}")

    severity = _parse_severity(draft_text, severity_cli)

    # --- out of scope: below HIGH -----------------------------------------
    if not _severity_gte_high(severity):
        return _result(
            verdict="pass-out-of-scope",
            reason=f"severity={severity!r} is below HIGH; R53 skipped",
            severity=severity,
        )

    # --- rebuttal? --------------------------------------------------------
    rebuttal = _find_rebuttal(draft_text)
    if rebuttal is not None:
        if rebuttal:
            return _result(
                verdict="ok-rebuttal",
                reason=f"r53-rebuttal accepted: {rebuttal[:80]}",
                severity=severity,
                rebuttal=rebuttal,
            )
        # empty rebuttal - ignore, continue checking

    # --- extract root-cause tokens from draft for cross-matching ----------
    draft_tokens = _extract_root_cause_tokens(draft_text)
    draft_file_refs = _extract_file_refs(draft_text)

    # --- cross-workspace corpus dedup helper ------------------------------
    # Reused both when there is no in-ws prior_audits/ at all AND when the in-ws
    # scan finds no overlap. Runs the SAME overlap extractors against the corpus
    # prior-audit + solodit records, GATED on shared file-ref + >=2 tokens.
    def _corpus_branch(scanned: list[str], in_ws_dir: bool) -> dict[str, Any]:
        if not corpus_scan:
            if not in_ws_dir:
                return _result(
                    verdict="pass-no-prior-audits-corpus",
                    reason=(
                        "no prior_audits/ corpus found; R53 in-ws scan skipped; "
                        "corpus scan disabled (--no-corpus-scan)"
                    ),
                    severity=severity,
                    prior_audits_scanned=scanned,
                )
            return _result(
                verdict="pass-no-matching-prior-finding",
                reason=(
                    "no in-workspace prior-audit overlap; corpus scan disabled "
                    "(--no-corpus-scan)"
                ),
                severity=severity,
                prior_audits_scanned=scanned,
            )
        root = corpus_root or _find_repo_root(Path(__file__).resolve().parent)
        if root is None:
            return _result(
                verdict="pass-no-matching-corpus-prior-finding",
                reason=(
                    "no in-workspace prior-audit overlap; corpus root not found "
                    "(audit/corpus_tags/tags/ absent)"
                ),
                severity=severity,
                prior_audits_scanned=scanned,
            )
        corpus = _load_corpus_prior_audits(root)
        corpus_overlap = _scan_corpus_overlap(corpus, draft_tokens, draft_file_refs)
        if not corpus_overlap:
            return _result(
                verdict="pass-no-matching-corpus-prior-finding",
                reason=(
                    "no in-workspace prior-audit overlap and no cross-workspace "
                    f"corpus prior-audit/solodit record (scanned {len(corpus)}) "
                    "shares a file-ref + >=2 root-cause tokens"
                ),
                severity=severity,
                prior_audits_scanned=scanned,
                corpus_records_scanned=len(corpus),
            )
        # Corpus supersede: require extension-distinct evidence (same as in-ws).
        has_section = bool(SECTION_RE.search(draft_text))
        section_text = _extract_section_text(draft_text)
        has_extension = bool(EXTENSION_RE.search(section_text or draft_text))
        has_inventory = bool(INVENTORY_RE.search(section_text or draft_text))
        has_matched = bool(MATCHED_RE.search(section_text or draft_text))
        has_verdict = bool(VERDICT_FIELD_RE.search(section_text or draft_text))
        all_fields = has_section and has_inventory and has_matched and has_extension and has_verdict
        if all_fields:
            return _result(
                verdict="pass-extension-distinct-from-prior",
                reason=(
                    "cross-workspace corpus prior-finding overlap, but draft "
                    "documents extension-distinct evidence"
                ),
                severity=severity,
                prior_audits_scanned=scanned,
                corpus_records_scanned=len(corpus),
                overlapping_corpus_prior_audits=corpus_overlap,
            )
        top = corpus_overlap[0]
        return _result(
            verdict="fail-superseded-by-corpus-prior-audit",
            reason=(
                f"cross-workspace corpus record {top['record_id']!r} covers the "
                f"same root cause: shared file-ref {top['common_file_refs']} + "
                f"tokens {top['common_tokens'][:3]}. "
                "Document extension-distinct evidence in a 'Prior-Audit Supersede "
                "Scan' section, or override: r53-rebuttal: <reason up to 200 chars>."
            ),
            severity=severity,
            prior_audits_scanned=scanned,
            corpus_records_scanned=len(corpus),
            overlapping_corpus_prior_audits=corpus_overlap,
        )

    # --- load prior audits corpus -----------------------------------------
    prior_corpus = _load_prior_audits(workspace)
    if not prior_corpus:
        # No in-ws prior_audits/ - still run the cross-workspace corpus scan.
        return _corpus_branch(scanned=[], in_ws_dir=False)

    # --- scan prior audits for overlap (do this BEFORE section check) -----
    overlapping: list[dict[str, Any]] = []
    for pa_file, pa_text in prior_corpus.items():
        pa_tokens = _extract_root_cause_tokens(pa_text)
        pa_file_refs = _extract_file_refs(pa_text)

        common_tokens = draft_tokens & pa_tokens
        common_files = draft_file_refs & pa_file_refs
        acknowledged = bool(ACKNOWLEDGED_IN_PRIOR_RE.search(pa_text))

        if common_tokens:
            overlapping.append(
                {
                    "file": pa_file,
                    "common_tokens": sorted(common_tokens),
                    "common_file_refs": sorted(common_files),
                    "acknowledged_in_prior": acknowledged,
                }
            )

    # No in-ws overlap -> fall through to cross-workspace corpus scan.
    if not overlapping:
        return _corpus_branch(scanned=list(prior_corpus.keys()), in_ws_dir=True)

    # --- overlap found: now require the section ---------------------------
    has_section = bool(SECTION_RE.search(draft_text))
    if not has_section:
        return _result(
            verdict="fail-no-supersede-scan",
            reason=(
                "HIGH+ draft has prior-audit root-cause overlap but is missing a "
                "'Prior-Audit Supersede Scan' section. "
                "Add the section with all 4 sub-fields (inventory, matched prior "
                "finding, extension-distinct evidence, verdict). "
                "Override: r53-rebuttal: <reason up to 200 chars>."
            ),
            severity=severity,
            prior_audits_scanned=list(prior_corpus.keys()),
            overlapping_prior_audits=overlapping,
            hints=[
                "Required section header: '## Prior-Audit Supersede Scan'",
                "Required sub-fields: inventory, matched prior finding, "
                "extension-distinct evidence, verdict",
            ],
        )

    # --- check sub-field completeness inside the section ------------------
    section_text = _extract_section_text(draft_text)
    missing_fields = _check_section_fields(section_text)

    # --- overlap found: check for extension-distinct evidence in draft ----
    has_extension = bool(EXTENSION_RE.search(section_text or draft_text))
    has_inventory = bool(INVENTORY_RE.search(section_text or draft_text))
    has_matched = bool(MATCHED_RE.search(section_text or draft_text))
    has_verdict = bool(VERDICT_FIELD_RE.search(section_text or draft_text))

    all_fields_present = has_inventory and has_matched and has_extension and has_verdict

    if has_extension and all_fields_present and not missing_fields:
        return _result(
            verdict="pass-extension-distinct-from-prior",
            reason=(
                "prior-audit overlap found but draft documents extension-distinct "
                "evidence breaking prior mitigation or exploiting uncovered surface"
            ),
            severity=severity,
            prior_audits_scanned=list(prior_corpus.keys()),
            overlapping_prior_audits=overlapping,
        )

    # --- superseded: no extension or missing fields -----------------------
    hint_lines: list[str] = []
    if not has_inventory:
        hint_lines.append("sub-field 1 (inventory) not found in Prior-Audit Supersede Scan section")
    if not has_matched:
        hint_lines.append("sub-field 2 (matched prior finding) not found in section")
    if not has_extension:
        hint_lines.append(
            "sub-field 3 (extension-distinct evidence) not found in section - "
            "required when prior-audit overlap exists"
        )
    if not has_verdict:
        hint_lines.append("sub-field 4 (verdict) not found in section")

    top_overlap = overlapping[0]
    return _result(
        verdict="fail-superseded-by-prior-audit",
        reason=(
            f"prior-audit file {top_overlap['file']!r} overlaps on root-cause "
            f"tokens {top_overlap['common_tokens'][:3]}. "
            "Draft must document extension-distinct evidence (new bypass, new "
            "call site, downstream surface not covered by prior mitigation). "
            "Override: r53-rebuttal: <reason up to 200 chars>."
        ),
        severity=severity,
        prior_audits_scanned=list(prior_corpus.keys()),
        overlapping_prior_audits=overlapping,
        hints=hint_lines,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_rebuttal(text: str) -> str | None:
    """Return rebuttal reason string if a valid non-empty r53-rebuttal marker exists, else None.

    Returns None if no marker present or if the reason is empty (empty rebuttal is ignored).
    Returns the reason string (non-empty) when a valid marker is found.

    HTML-comment form is checked FIRST so the inline regex does not accidentally
    capture the --> delimiter as the reason text.
    """
    # HTML comment form: <!-- r53-rebuttal: <reason> -->
    m = REBUTTAL_HTML_RE.search(text)
    if m:
        reason = m.group(1).strip()
        if not reason:
            return None  # empty -> ignored
        if len(reason) <= REBUTTAL_MAX_CHARS:
            return reason

    # Inline form: r53-rebuttal: <reason> (end of line or end of string)
    # Strip HTML comment closer from the capture to avoid false positives.
    m = REBUTTAL_RE.search(text)
    if m:
        reason = m.group(1).strip().rstrip("-").rstrip(">").strip()
        if not reason:
            return None  # empty -> ignored
        if len(reason) <= REBUTTAL_MAX_CHARS:
            return reason

    return None


def _extract_section_text(draft_text: str) -> str:
    """Return the text of the 'Prior-Audit Supersede Scan' section (up to next ##)."""
    m = SECTION_RE.search(draft_text)
    if not m:
        return ""
    start = m.end()
    # Find next section header at same or higher level
    rest = draft_text[start:]
    next_sec = re.search(r"(?m)^##+ ", rest)
    if next_sec:
        return rest[: next_sec.start()]
    return rest


def _check_section_fields(section_text: str) -> list[str]:
    """Return list of missing sub-field names."""
    missing: list[str] = []
    if not INVENTORY_RE.search(section_text):
        missing.append("inventory")
    if not MATCHED_RE.search(section_text):
        missing.append("matched-prior-finding")
    if not EXTENSION_RE.search(section_text):
        missing.append("extension-distinct-evidence")
    if not VERDICT_FIELD_RE.search(section_text):
        missing.append("verdict")
    return missing


def _result(verdict: str, reason: str, **extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "gate": GATE,
        "verdict": verdict,
        "reason": reason,
    }
    base.update(extra)
    return base


def _error(msg: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA_VERSION,
        "gate": GATE,
        "verdict": "error",
        "reason": msg,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _exit_code(verdict: str) -> int:
    if verdict in ("error",):
        return 2
    if verdict.startswith("fail-"):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="R53 prior-audit-finding-supersede-check (Check #99)",
    )
    parser.add_argument("draft", nargs="?", help="path to draft .md file")
    parser.add_argument("--workspace", "--ws", default=".", help="workspace root (default: .)")
    parser.add_argument(
        "--severity",
        default="auto",
        choices=["auto", "LOW", "MEDIUM", "HIGH", "CRITICAL",
                 "low", "medium", "high", "critical"],
        help="override severity (default: auto-detect from draft)",
    )
    parser.add_argument("--strict", action="store_true", help="exit 1 on close-fail verdicts")
    parser.add_argument(
        "--corpus-scan",
        dest="corpus_scan",
        action="store_true",
        default=True,
        help="scan the cross-workspace corpus prior-audit/solodit records (default ON)",
    )
    parser.add_argument(
        "--no-corpus-scan",
        dest="corpus_scan",
        action="store_false",
        help="disable the cross-workspace corpus scan (in-workspace prior_audits/ only)",
    )
    parser.add_argument("--json", action="store_true", dest="json_out", help="emit JSON")
    args = parser.parse_args(argv)

    if not args.draft:
        parser.print_help()
        return 2

    draft_path = Path(args.draft)
    if not draft_path.exists():
        sys.stderr.write(f"error: draft not found: {args.draft}\n")
        return 2

    workspace = Path(args.workspace).resolve()

    corpus_root_env = os.environ.get("AUDITOOOR_R53_CORPUS_ROOT", "").strip()
    corpus_root = Path(corpus_root_env).resolve() if corpus_root_env else None

    result = check(
        draft_path=draft_path,
        workspace=workspace,
        severity_cli=args.severity,
        strict=args.strict,
        corpus_scan=args.corpus_scan,
        corpus_root=corpus_root,
    )

    if args.json_out:
        print(json.dumps(result, indent=2))
    else:
        verdict = result["verdict"]
        reason = result.get("reason", "")
        print(f"{verdict}: {reason}")
        for hint in result.get("hints", []):
            print(f"  hint: {hint}")

    return _exit_code(result["verdict"])


if __name__ == "__main__":
    sys.exit(main())
