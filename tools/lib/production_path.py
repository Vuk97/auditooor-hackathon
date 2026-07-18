"""production_path.py — V4 Phase P1 (Workstream A1) helpers.

Shared production-path section parsing, mock-trigger detection, prose-trigger
detection, and structured field extraction. Used by:

  * ``tools/pre-submit-check.sh`` Check #27 (production-path gate)
  * ``tools/submission-packager.py`` (manifest enrichment, A2)
  * ``tools/tests/test_production_path_gate.py``

Why a single library:
  ``pre-submit-check.sh`` already runs Python heredocs for its harder gates
  (Check #21 live-proof, #26 mock-poc-contamination). Putting the section
  parser, trigger detectors, and field extractor in one importable module
  lets the packager build a manifest from the same parser the gate uses,
  guaranteeing the manifest's ``mock_components`` / ``oos_clauses_checked``
  reflect exactly what the hard gate sees. Drift between gate and manifest
  was a known risk in V4 §2 A2.

Stdlib-only (re, dataclasses, pathlib). No third-party deps.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Section markers
# ---------------------------------------------------------------------------

# Recognises "## Production Path", "### Production Path", and bold-emoji
# variants (e.g. "## **Production Path**"). Also tolerates a trailing
# parenthesised suffix such as "## Production Path (Rule 40)" so a rule-tag
# on the heading does not silently drop the whole section.
PRODUCTION_PATH_HEADING_RE = re.compile(
    r"^[#]{1,6}\s+\**\s*Production\s+Path\s*\**\s*(?:\([^)]*\)\s*)?$",
    re.IGNORECASE,
)

# A heading at any depth (used to find the *next* heading after the section).
ANY_HEADING_RE = re.compile(r"^[#]{1,6}\s+", re.MULTILINE)

# Numbered-item line. Accepts:
#   1. In-scope asset:
#   1) In-scope asset -
#   1.  In-scope asset:
#   - 1. In-scope asset:
NUMBERED_ITEM_RE = re.compile(
    r"^\s*(?:[-*]\s*)?(\d+)\s*[.)]\s*(.+?)\s*$",
    re.MULTILINE,
)

# 10 canonical item labels. Order matters — index in this list is item number.
CANONICAL_ITEMS: List[str] = [
    "In-scope asset",
    "Affected contract / function",
    "Reachability",
    "Attacker-controlled inputs",
    "Non-attacker preconditions",
    "Privileged roles involved",
    "Mock components used in PoC",
    "Real component replacement for each mock",
    "OOS clauses checked",
    "Final in-scope impact",
]


# ---------------------------------------------------------------------------
# Mock-component & prose triggers (V4 §2 A1)
# ---------------------------------------------------------------------------

# Suspicious mocks that REQUIRE item 8 to be non-empty when present anywhere
# in the draft body or the cited PoC text.
MOCK_TRIGGER_TOKENS: List[str] = [
    "MockVerifier",
    "MockOracle",
    "MockPortal",
    "MockRegistry",
    "MockProof",
    "MockSignature",
]

# Hardcoded `returns true` verifier shortcut. Match patterns of the form:
#   function verify(...) ... returns (bool) { return true; }
HARDCODED_RETURNS_TRUE_RE = re.compile(
    r"function\s+\w*verif\w*\s*\([^)]*\)[^{]*returns\s*\([^)]*\)[^{]*\{\s*return\s+true\s*;\s*\}",
    re.IGNORECASE | re.DOTALL,
)
# Looser secondary detector: any "return true;" inside a contract whose name
# contains "verif"/"verifier".
LOOSE_VERIFIER_RETURNS_TRUE_RE = re.compile(
    r"contract\s+\w*[Vv]erif\w*[^}]*?return\s+true\s*;",
    re.DOTALL,
)


# Prose triggers that REQUIRE item 9 (OOS clauses checked) to cite an exact
# program clause. Case-insensitive substring matches.
PROSE_TRIGGERS: List[str] = [
    "forged proof",
    "invalid TEE",
    "invalid ZK",
    "operator does not",
    "Base does not",
    "guardian does not",
    "project does not",
    "will not blacklist",
]


# Branch/state-precondition phrasing that previously let branch-invariant PoCs
# look submission-ready even when the precondition was only reachable through
# admin action, project inaction, or proof-system compromise.
BRANCH_PRECONDITION_TRIGGERS: List[str] = [
    "CHALLENGER_WINS",
    "DEFENDER_WINS",
    "parentGameStatus",
    "parent-loss",
    "parent loss",
    "blacklistDisputeGame",
    "blacklisted parent",
    "retired parent",
    "status ==",
    "status() ==",
]

# Tolerate a trailing bold close and/or a parenthesised suffix
# (e.g. "## Precondition-Reachability (Rule 40)") for the same reason as
# PRODUCTION_PATH_HEADING_RE above.
PRECONDITION_HEADING_RE = re.compile(
    r"^[#]{1,6}\s+\**\s*Precondition[-\s]+Reachability\s*\**\s*(?:\([^)]*\)\s*)?$",
    re.IGNORECASE,
)

EXTERNAL_REACHABLE_RE = re.compile(
    r"\b(permissionless|external(?:ly)?|non[-\s]?privileged|ordinary\s+user|"
    r"attacker\s+can|anyone\s+can|publicly\s+callable|no\s+access\s+control)\b",
    re.IGNORECASE,
)

IN_SCOPE_RE = re.compile(r"\b(in[-\s]?scope|scope\s+verdict\s*:\s*in)\b", re.IGNORECASE)

OOS_ONLY_RE = re.compile(
    r"\b(admin|guardian|owner|governance|multisig|blacklist|retire|retirement|"
    r"compromis(?:e|ed)|invalid\s+TEE|invalid\s+ZK|ZK\s+soundness|TEE\s+proof|"
    r"prover\s+compromise|key\s+compromise|project\s+inaction|will\s+not\s+blacklist|"
    r"Base\s+does\s+not|operator\s+does\s+not)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

SEVERITY_LINE_RE = re.compile(
    r"^[\s>*_-]*\**\s*Severity\s*\**\s*[:=]\s*\**\s*"
    r"(critical|high|medium|low|informational|info)\b",
    re.IGNORECASE | re.MULTILINE,
)


def detect_severity(text: str) -> str:
    """Return canonical severity tier (uppercase) or "" when not present."""
    match = SEVERITY_LINE_RE.search(text)
    if not match:
        return ""
    raw = match.group(1).lower()
    if raw == "info":
        raw = "informational"
    return raw.upper()


def is_high_or_critical(severity: str) -> bool:
    return severity.upper() in {"HIGH", "CRITICAL"}


def is_medium(severity: str) -> bool:
    return severity.upper() == "MEDIUM"


# ---------------------------------------------------------------------------
# Section extraction
# ---------------------------------------------------------------------------

@dataclass
class ProductionPathSection:
    """Parsed `## Production Path` section.

    Attributes:
      present:        True iff a `## Production Path` heading exists.
      raw:            Verbatim section body (between the heading and the
                      next heading), excluding the heading itself.
      items:          Dict mapping integer item number (1..10) -> the value
                      portion of the line (the text AFTER the colon). Items
                      whose value is empty/whitespace-only are stored as "".
                      Items not present in the section are absent from the
                      dict.
      missing_items:  Sorted list of item numbers (1..10) that are absent
                      from the dict OR whose value is empty.
    """

    present: bool = False
    raw: str = ""
    items: dict = field(default_factory=dict)

    @property
    def missing_items(self) -> List[int]:
        out = []
        for n in range(1, 11):
            value = (self.items.get(n) or "").strip()
            if not value:
                out.append(n)
        return out

    def item(self, n: int) -> str:
        return (self.items.get(n) or "").strip()


def extract_production_path_section(text: str) -> ProductionPathSection:
    """Locate the `## Production Path` heading and parse its 10 items.

    The parser is forgiving: it accepts numbered items in any order (so
    long as the number is 1..10), tolerates surrounding bullet markers,
    and treats any line of the form "<n>. <label>: <value>" as item <n>
    with <value> as the right-hand side. The label is not validated
    against ``CANONICAL_ITEMS`` here — drafts that paraphrase the label
    still pass section-presence detection. The hard gate decides whether
    a missing/empty value blocks the submission.
    """
    section = ProductionPathSection()
    lines = text.splitlines()
    heading_idx: Optional[int] = None
    for idx, line in enumerate(lines):
        if PRODUCTION_PATH_HEADING_RE.match(line):
            heading_idx = idx
            break
    if heading_idx is None:
        return section

    section.present = True

    # Walk forward to the next heading (or EOF).
    next_heading_idx = len(lines)
    heading_simple_re = re.compile(r"^[#]{1,6}\s+")
    for j in range(heading_idx + 1, len(lines)):
        if heading_simple_re.match(lines[j]):
            next_heading_idx = j
            break
    section_lines = lines[heading_idx + 1 : next_heading_idx]
    section.raw = "\n".join(section_lines)

    # Parse numbered items. Strip everything before the first colon.
    for line in section_lines:
        m = NUMBERED_ITEM_RE.match(line)
        if not m:
            continue
        n = int(m.group(1))
        if n < 1 or n > 10:
            continue
        rest = m.group(2)
        # Split on first colon — the LHS is the label, the RHS is the value.
        # If no colon, treat the rest as label-only with empty value.
        if ":" in rest:
            _, value = rest.split(":", 1)
            section.items[n] = value.strip()
        else:
            section.items[n] = ""
    return section


# ---------------------------------------------------------------------------
# Trigger detection
# ---------------------------------------------------------------------------

def detect_mock_triggers(text: str) -> List[str]:
    """Return the suspicious-mock tokens present anywhere in `text`.

    Token matching is case-insensitive. The list is de-duplicated and
    preserves the order from ``MOCK_TRIGGER_TOKENS``. The "hardcoded
    `returns true` verifier" pseudo-token is appended when matched.
    """
    hits: List[str] = []
    lower = text.lower()
    for token in MOCK_TRIGGER_TOKENS:
        if token.lower() in lower and token not in hits:
            hits.append(token)
    if HARDCODED_RETURNS_TRUE_RE.search(text):
        if "hardcoded-returns-true-verifier" not in hits:
            hits.append("hardcoded-returns-true-verifier")
    elif LOOSE_VERIFIER_RETURNS_TRUE_RE.search(text):
        if "hardcoded-returns-true-verifier" not in hits:
            hits.append("hardcoded-returns-true-verifier")
    return hits


def detect_prose_triggers(text: str) -> List[str]:
    """Return prose triggers (V4 §2 A1) present in `text`, case-insensitively.

    De-duplicated; preserves ``PROSE_TRIGGERS`` order.
    """
    hits: List[str] = []
    lower = text.lower()
    for trigger in PROSE_TRIGGERS:
        if trigger.lower() in lower and trigger not in hits:
            hits.append(trigger)
    return hits


def detect_branch_precondition_triggers(text: str) -> List[str]:
    """Return branch/state-precondition trigger phrases present in the draft."""
    hits: List[str] = []
    lower = text.lower()
    for trigger in BRANCH_PRECONDITION_TRIGGERS:
        if trigger.lower() in lower and trigger not in hits:
            hits.append(trigger)
    return hits


def extract_precondition_reachability_section(text: str) -> str:
    """Return the body of `## Precondition-Reachability`, or "" if absent."""
    lines = text.splitlines()
    heading_idx: Optional[int] = None
    for idx, line in enumerate(lines):
        if PRECONDITION_HEADING_RE.match(line):
            heading_idx = idx
            break
    if heading_idx is None:
        return ""

    end_idx = len(lines)
    for j in range(heading_idx + 1, len(lines)):
        if re.match(r"^[#]{1,6}\s+", lines[j]):
            end_idx = j
            break
    return "\n".join(lines[heading_idx + 1 : end_idx]).strip()


def precondition_section_has_external_in_scope_path(section_text: str) -> bool:
    """Heuristic pass iff the section names an external, in-scope path.

    This is deliberately simple and auditable. The gate is not trying to prove
    reachability; it is forcing the draft to carry an explicit code-traced
    reachability argument instead of silently relying on admin/OOS branches.
    """
    if not section_text.strip():
        return False
    return bool(EXTERNAL_REACHABLE_RE.search(section_text) and IN_SCOPE_RE.search(section_text))


def precondition_section_is_oos_only(section_text: str) -> bool:
    """Return True when section appears to list only admin/OOS paths."""
    if not section_text.strip():
        return False
    has_oos = bool(OOS_ONLY_RE.search(section_text))
    has_external = precondition_section_has_external_in_scope_path(section_text)
    return has_oos and not has_external


# ---------------------------------------------------------------------------
# Item-9 (OOS clause citation) recognition
# ---------------------------------------------------------------------------

# Heuristic: an OOS-clause citation is a value that mentions the program by
# name AND a section/clause/bullet identifier (e.g. "OOS-3", "section 4.2",
# "bullet 7", "clause 12", "Cantina rule 6", or a backticked phrase that
# matches a SCOPE.md OOS line). The heuristic intentionally errs on the
# permissive side because OOS-clause vocabulary varies engagement-to-
# engagement; the LLM verdict (A3) provides the stricter check.
OOS_CITATION_RE = re.compile(
    r"\bOOS[-_\s]?\d+\b|"
    r"\b(?:section|clause|bullet|rule|item)\s*\d+(?:\.\d+)?\b|"
    r"`[^`]{4,}`",
    re.IGNORECASE,
)


def has_oos_clause_citation(value: str) -> bool:
    """Return True iff `value` looks like a real OOS-clause citation.

    Empty/whitespace-only values return False. So do filler values like
    "checked", "n/a", "reviewed", "see scope.md" without a specific clause.
    """
    if not value or not value.strip():
        return False
    if OOS_CITATION_RE.search(value):
        return True
    # Last resort: explicit "checked OOS-N" phrasing without the dash.
    if re.search(r"\bOOS\b.*\b\d+\b", value, re.IGNORECASE):
        return True
    return False


# ---------------------------------------------------------------------------
# Local-path-in-PoC gate (V4 §2 A1 acceptance criterion 3)
# ---------------------------------------------------------------------------

# Local audit-tree path patterns that should never appear in a final
# triager-clean PoC (the triager cannot reach `~/audits/...` on their box).
LOCAL_PATH_PATTERNS = [
    re.compile(r"~/audits/", re.IGNORECASE),
    re.compile(r"/Users/[^/]+/audits/", re.IGNORECASE),
    re.compile(r"/home/[^/]+/audits/", re.IGNORECASE),
]


def detect_local_paths_in_poc_section(text: str) -> List[str]:
    """Return local-path strings present inside any `## PoC` section.

    Looks for a heading matching ``## PoC`` (case-insensitive) and walks
    until the next heading. Any match against ``LOCAL_PATH_PATTERNS`` is
    returned as-is (de-duplicated). Returns an empty list when no PoC
    section exists OR when no local paths are found.

    NOTE: the existing `pre-submit-check.sh` also greps for local paths
    via Check #4/#10 (PoC test references). This helper exists because
    V4 §2 A1 calls out local-path-in-PoC as a production-path concern
    that should fail at the production-path gate too — separate from
    the existing PoC-existence gate.
    """
    lines = text.splitlines()
    poc_heading_re = re.compile(r"^[#]{1,6}\s+\**\s*PoC\b", re.IGNORECASE)
    in_poc = False
    hits: List[str] = []
    for line in lines:
        if poc_heading_re.match(line):
            in_poc = True
            continue
        if in_poc and re.match(r"^[#]{1,6}\s+", line):
            in_poc = False
            continue
        if not in_poc:
            continue
        for pat in LOCAL_PATH_PATTERNS:
            for match in pat.finditer(line):
                snippet = match.group(0)
                if snippet not in hits:
                    hits.append(snippet)
    return hits


# ---------------------------------------------------------------------------
# Manifest builder (V4 §2 A2)
# ---------------------------------------------------------------------------

def _split_list_value(value: str) -> List[str]:
    """Split a comma/semicolon/pipe/newline-delimited value into a list.

    Empty entries are filtered out. Used by the manifest builder so a draft
    that writes "MockVerifier, MockProof" produces a real list, not a
    single string.
    """
    if not value or not value.strip():
        return []
    parts = re.split(r"[,;|\n]+", value)
    return [p.strip() for p in parts if p.strip()]


def build_manifest(text: str, *, severity: Optional[str] = None) -> dict:
    """Return the structured ``production_path`` manifest dict.

    Schema (V4 §2 A2):

        {
          "section_present": bool,
          "scope_asset": str,
          "affected_code": str,
          "attacker_controlled_inputs": [str, ...],
          "privileged_preconditions": [str, ...],
          "mock_components": [str, ...],
          "real_component_replacements": [str, ...],
          "oos_clauses_checked": [str, ...],
          "impact_mapping": str,
          "severity": "CRITICAL|HIGH|MEDIUM|LOW|...",
          "mock_triggers_detected": [str, ...],
          "prose_triggers_detected": [str, ...],
          "missing_items": [int, ...],
          "local_paths_in_poc": [str, ...]
          "branch_precondition_triggers": [str, ...],
          "precondition_reachability_present": bool,
          "precondition_reachability_external_in_scope": bool,
        }

    All string fields default to "" and all list fields to [] when the
    section is absent. `severity` is sourced from the explicit parameter
    when provided, otherwise inferred from the draft text.
    """
    section = extract_production_path_section(text)
    sev = (severity or detect_severity(text) or "").upper()

    manifest: dict = {
        "section_present": section.present,
        "scope_asset": section.item(1),
        "affected_code": section.item(2),
        "reachability": section.item(3),
        "attacker_controlled_inputs": _split_list_value(section.item(4)),
        "privileged_preconditions": _split_list_value(section.item(5))
            + _split_list_value(section.item(6)),
        "mock_components": (
            _split_list_value(section.item(7))
            + detect_mock_triggers(text)
        ),
        "real_component_replacements": _split_list_value(section.item(8)),
        "oos_clauses_checked": _split_list_value(section.item(9)),
        "impact_mapping": section.item(10),
        "severity": sev,
        "mock_triggers_detected": detect_mock_triggers(text),
        "prose_triggers_detected": detect_prose_triggers(text),
        "missing_items": section.missing_items if section.present else list(range(1, 11)),
        "local_paths_in_poc": detect_local_paths_in_poc_section(text),
    }
    precondition_section = extract_precondition_reachability_section(text)
    manifest["branch_precondition_triggers"] = detect_branch_precondition_triggers(text)
    manifest["precondition_reachability_present"] = bool(precondition_section)
    manifest["precondition_reachability_external_in_scope"] = (
        precondition_section_has_external_in_scope_path(precondition_section)
    )
    # De-duplicate mock_components while preserving order.
    seen = set()
    deduped = []
    for item in manifest["mock_components"]:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    manifest["mock_components"] = deduped
    return manifest


# ---------------------------------------------------------------------------
# Gate evaluation (V4 §2 A1)
# ---------------------------------------------------------------------------

@dataclass
class GateResult:
    """Outcome of the production-path gate.

    `status`:
        "PASS"        — section present and all required fields satisfied
        "WARN"        — Medium severity with a missing/incomplete section,
                        or High/Critical with the section but with a
                        non-blocking gap (no missing-section AND no
                        mock-trigger-without-replacement AND no prose-
                        trigger-without-citation)
        "FAIL"        — High/Critical with a hard violation (missing
                        section, mock trigger without item-8 value, prose
                        trigger without item-9 OOS citation, or local
                        path inside `## PoC`)

    `reasons`: human-readable bullet points; emitted line-by-line in the
    pre-submit log so the operator knows what to fix.
    """

    status: str
    reasons: List[str] = field(default_factory=list)


def evaluate_gate(text: str, severity: str, *, strict_preconditions: bool = False) -> GateResult:
    """Evaluate the production-path gate per V4 §2 A1 + §9 conservative defaults.

    Args:
      text:     full draft text.
      severity: canonical severity tier (uppercase). When empty, treated
                as Low/Insight (informational pass). The caller is
                responsible for sniffing severity from the draft if they
                want auto-detection (`detect_severity` is exposed).

    Returns:
      GateResult with status PASS / WARN / FAIL and human reasons.
    """
    sev = (severity or "").upper()
    if sev == "INFO":
        sev = "INFORMATIONAL"
    high_plus = sev in {"HIGH", "CRITICAL"}
    medium = sev == "MEDIUM"

    section = extract_production_path_section(text)
    mock_triggers = detect_mock_triggers(text)
    prose_triggers = detect_prose_triggers(text)
    local_paths = detect_local_paths_in_poc_section(text)
    branch_triggers = detect_branch_precondition_triggers(text)
    precondition_section = extract_precondition_reachability_section(text)

    reasons: List[str] = []

    # ---- 1. Section presence -------------------------------------------
    if not section.present:
        if high_plus:
            reasons.append(
                "missing `## Production Path` section (required for "
                "High/Critical drafts per V4 §2 A1)"
            )
            return GateResult(status="FAIL", reasons=reasons)
        if medium:
            reasons.append(
                "missing `## Production Path` section (Medium: warning per V4 §9 "
                "conservative defaults)"
            )
            return GateResult(status="WARN", reasons=reasons)
        # Low / Informational / unknown -> informational pass.
        return GateResult(status="PASS", reasons=["Low/Informational: production-path section not required"])

    # ---- 2. Mock-trigger -> item 8 must be non-empty -------------------
    if mock_triggers and not section.item(8):
        msg = (
            "mock trigger(s) "
            f"[{', '.join(mock_triggers[:4])}] present without a real-component "
            "replacement in item 8 (`Real component replacement for each mock`)"
        )
        if high_plus:
            reasons.append(msg)
            return GateResult(status="FAIL", reasons=reasons)
        # Medium with mock trigger but no item 8 -> WARN
        if medium:
            reasons.append(msg + " (Medium: warning)")
            return GateResult(status="WARN", reasons=reasons)
        # Low: informational
        return GateResult(status="PASS", reasons=[msg + " (Low: informational)"])

    # ---- 3. Prose-trigger -> item 9 must cite an exact clause -----------
    if prose_triggers and not has_oos_clause_citation(section.item(9)):
        msg = (
            "prose trigger(s) "
            f"[{', '.join(prose_triggers[:4])}] present but item 9 "
            "(`OOS clauses checked`) does not cite an exact program clause"
        )
        if high_plus:
            reasons.append(msg)
            return GateResult(status="FAIL", reasons=reasons)
        if medium:
            reasons.append(msg + " (Medium: warning)")
            return GateResult(status="WARN", reasons=reasons)
        return GateResult(status="PASS", reasons=[msg + " (Low: informational)"])

    # ---- 4. Local-path in `## PoC` (always FAIL when present) ----------
    if local_paths:
        msg = (
            "local audit-tree path(s) "
            f"[{', '.join(local_paths[:4])}] inside `## PoC` section — triager "
            "cannot reach these. Inline the PoC contents or reference a "
            "checked-in `poc-tests/*.t.sol` path"
        )
        if high_plus:
            reasons.append(msg)
            return GateResult(status="FAIL", reasons=reasons)
        if medium:
            reasons.append(msg + " (Medium: warning)")
            return GateResult(status="WARN", reasons=reasons)
        return GateResult(status="PASS", reasons=[msg + " (Low: informational)"])

    # ---- 5. Branch/state precondition reachability ---------------------
    if branch_triggers or strict_preconditions:
        if strict_preconditions and not branch_triggers:
            branch_triggers = ["workspace-strict-precondition-marker"]
        msg_base = (
            "branch/state precondition trigger(s) "
            f"[{', '.join(branch_triggers[:4])}] present"
        )
        if not precondition_section:
            msg = (
                msg_base
                + " without a `## Precondition-Reachability` section that code-traces "
                "at least one externally reachable, in-scope path to the branch precondition"
            )
            if high_plus:
                reasons.append(msg)
                return GateResult(status="FAIL", reasons=reasons)
            if medium:
                reasons.append(msg + " (Medium: warning)")
                return GateResult(status="WARN", reasons=reasons)
            return GateResult(status="PASS", reasons=[msg + " (Low: informational)"])
        if precondition_section_is_oos_only(precondition_section):
            msg = (
                msg_base
                + " but `## Precondition-Reachability` lists only admin/OOS/proof-compromise paths"
            )
            if high_plus:
                reasons.append(msg)
                return GateResult(status="FAIL", reasons=reasons)
            if medium:
                reasons.append(msg + " (Medium: warning)")
                return GateResult(status="WARN", reasons=reasons)
            return GateResult(status="PASS", reasons=[msg + " (Low: informational)"])
        if not precondition_section_has_external_in_scope_path(precondition_section):
            msg = (
                msg_base
                + " but `## Precondition-Reachability` does not explicitly mark an "
                "external/permissionless path as in-scope"
            )
            if high_plus:
                reasons.append(msg)
                return GateResult(status="FAIL", reasons=reasons)
            if medium:
                reasons.append(msg + " (Medium: warning)")
                return GateResult(status="WARN", reasons=reasons)
            return GateResult(status="PASS", reasons=[msg + " (Low: informational)"])

    # ---- 6. Section present but item 9 empty (no prose trigger) --------
    # When item 9 is empty AND the draft has no prose trigger, V4 §2 A1
    # downgrades to SUCCESS_WARN at Medium / FAIL at High/Critical only
    # when item-9 emptiness is the ONLY gap (mirrors acceptance test 4:
    # "Draft with `## Production Path` but no OOS clause citations").
    if not section.item(9) and high_plus:
        reasons.append(
            "section present but item 9 (`OOS clauses checked`) is empty "
            "(High/Critical: hard fail per acceptance criterion 4)"
        )
        return GateResult(status="FAIL", reasons=reasons)
    if not section.item(9) and medium:
        reasons.append(
            "section present but item 9 (`OOS clauses checked`) is empty "
            "(Medium: warning per acceptance criterion 4)"
        )
        return GateResult(status="WARN", reasons=reasons)

    # ---- 7. Other missing items -> WARN (don't hard-block on completeness) -
    if section.missing_items:
        reasons.append(
            "section present but missing item(s) "
            f"{section.missing_items} (informational; only items 7-9 hard-block)"
        )
        # Don't change status from PASS: V4 §2 A1 only hard-fails on the
        # specific gaps above. Generic-completeness gaps stay informational
        # so we don't accidentally block well-shaped drafts that omit one
        # boilerplate row.
        return GateResult(status="PASS", reasons=reasons)

    return GateResult(status="PASS", reasons=["all 10 production-path items satisfied"])


# ---------------------------------------------------------------------------
# CLI shim (for the bash gate)
# ---------------------------------------------------------------------------

def _format_reasons(reasons: List[str]) -> str:
    if not reasons:
        return ""
    return "\n".join(f"  - {r}" for r in reasons)


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint used by ``pre-submit-check.sh`` Check #27.

    Usage:
        python3 production_path.py <draft-md> [--severity HIGH|...] [--manifest]

    Exit codes mirror Check #26's convention:
      0 = PASS
      2 = WARN
      1 = FAIL

    With ``--manifest`` the tool emits the full JSON manifest on stdout
    and always exits 0 (downstream tools key off the JSON, not the rc).
    """
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(prog="production_path")
    parser.add_argument("draft", type=Path)
    parser.add_argument("--severity", default=None)
    parser.add_argument("--manifest", action="store_true")
    parser.add_argument(
        "--strict-preconditions",
        action="store_true",
        help="require ## Precondition-Reachability even without keyword triggers",
    )
    args = parser.parse_args(argv)

    if not args.draft.is_file():
        sys.stderr.write(f"draft not found: {args.draft}\n")
        return 1

    text = args.draft.read_text(errors="replace")
    severity = (args.severity or detect_severity(text) or "").upper()

    if args.manifest:
        manifest = build_manifest(text, severity=severity)
        sys.stdout.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        return 0

    result = evaluate_gate(text, severity, strict_preconditions=args.strict_preconditions)
    if result.status == "PASS":
        sys.stdout.write(f"pass\tproduction-path gate ({severity or 'unspecified'})\n")
        if result.reasons:
            sys.stdout.write(_format_reasons(result.reasons) + "\n")
        return 0
    if result.status == "WARN":
        sys.stdout.write(f"warn\tproduction-path gate ({severity or 'unspecified'})\n")
        sys.stdout.write(_format_reasons(result.reasons) + "\n")
        return 2
    sys.stdout.write(f"fail\tproduction-path gate ({severity or 'unspecified'})\n")
    sys.stdout.write(_format_reasons(result.reasons) + "\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
