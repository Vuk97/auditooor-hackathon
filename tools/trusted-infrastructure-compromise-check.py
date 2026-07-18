#!/usr/bin/env python3
"""Rule 46 Trusted-Infrastructure-Compromise preflight (Check #94).

# Rule 46: this tool emits no corpus record.

TRIGGER: HIGH+ drafts whose exploit chain requires compromise of a trusted
infrastructure component (oracle sidecar, proposer/sequencer infra,
validator-set node, signer node, RPC provider, off-chain dispatcher, MEV
relay, keeper node).

Many bounty programs explicitly designate trusted validator / operator
infrastructure as out-of-scope centralization risk. Findings that only work
if one of these components is already compromised carry a structural closure
risk: the triager closes them as "acknowledged by design" or OOS unless the
draft explicitly:
  (a) names the trusted component and its protocol role,
  (b) cites the program's OOS clause verbatim from SEVERITY.md/SCOPE.md,
  (c) classifies whether the trusted component is the PRIMARY defense or
      merely part of defense-in-depth,
  (d) states whether a non-trusted-compromise trigger also exists.

If a non-trusted-compromise trigger ALSO exists (the bug fires without any
trusted infra compromise), the finding is NOT a trusted-infra-compromise
finding - it is an independent bug and the gate passes.

If the trusted component is the PRIMARY defense (not DiD) and the draft does
not walk back severity to acknowledge the OOS centralization risk, the gate
fails closed.

Required section: "Trusted Infrastructure Tabulation" with all 4 fields.

Verdict vocabulary:
  pass-out-of-scope                          (severity below HIGH, or --severity LOW/MEDIUM)
  pass-no-trusted-infra-dep                  (HIGH+ but no trusted-infra trigger found)
  pass-non-trusted-trigger-also-exists       (exploit works without trusted comp compromise)
  pass-trusted-infra-tabulated-with-walk-back (tabulation present + severity walk-back)
  ok-rebuttal                                (r46-rebuttal present, <= 200 chars)
  fail-no-trusted-infra-tabulation           (trigger found, no tabulation section)
  fail-trusted-infra-primary-defense-no-walk-back (primary defense but no walk-back)
  fail-oos-citation-missing                  (tabulation present, OOS clause missing)
  error

Exit codes:
  0 - pass / ok-rebuttal / out-of-scope / no-trusted-dep / non-trusted-trigger
  1 - Rule 46 violation (with --strict or on hard-fail verdicts)
  2 - input error

Schema: auditooor.r46_trusted_infrastructure_compromise.v1
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.r46_trusted_infrastructure_compromise.v1"
GATE = "R46-TRUSTED-INFRASTRUCTURE-COMPROMISE"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
REBUTTAL_MAX_CHARS = 200

# ---------------------------------------------------------------------------
# Default trusted-infra trigger patterns (env-extendable)
#
# Design constraints (iter6 Lane LL FP-fix, 2026-05-23):
#   - Replace bare `.*` with `[^\n]{0,40}` for proximity-bound, single-line
#     matching to prevent greedy cross-sentence matches.
#   - `validator.*set.*node` was over-matching "validator process exits...
#     legacy-node" across 150+ char span; replaced with word-boundary form.
#   - `malicious.*proposer` / `proposer.*malicious` and the validator variants
#     fired on OOS-checklist NEGATION context ("does not require a malicious
#     proposer"). Proximity-bound alone is insufficient for those cases; a
#     post-scan negation filter (NEGATION_CONTEXT_RE below) skips matches
#     whose pre-match context contains an explicit negation word.
#   - `slinky.*oracle` / `oracle.*slinky` fired when Slinky appeared in a
#     defense-in-depth sentence referencing oracle; tightened to 30-char span.
# ---------------------------------------------------------------------------
DEFAULT_TRUSTED_INFRA_PATTERNS = [
    r"oracle[^\n]{0,30}sidecar",
    r"sidecar[^\n]{0,30}oracle",
    r"sequencer[^\n]{0,40}compromise",
    r"compromise[^\n]{0,40}sequencer",
    r"malicious[^\n]{0,40}sequencer",
    r"sequencer[^\n]{0,40}malicious",
    r"proposer[^\n]{0,40}malicious",
    r"malicious[^\n]{0,40}proposer",
    # Word-boundary adjacent form - prevents greedy cross-sentence match on
    # "validator process exits...legacy-node" (iter5 II FP #3, #9 confirmed).
    r"validator[\s\-_]+set[\s\-_]+(node|signer)\b",
    r"validator[^\n]{0,40}node[^\n]{0,30}comprom",
    r"malicious[^\n]{0,40}validator",
    r"validator[^\n]{0,40}malicious",
    r"signer[^\n]{0,40}node[^\n]{0,30}comprom",
    r"comprom[^\n]{0,30}signer[^\n]{0,40}node",
    r"\bRPC\s+provider\b",
    r"off[- ]chain[^\n]{0,40}dispatcher",
    r"dispatcher[^\n]{0,40}off[- ]chain",
    r"malicious[^\n]{0,40}dispatcher",
    r"dispatcher[^\n]{0,40}malicious",
    r"MEV[^\n]{0,30}share",
    r"relayer[^\n]{0,40}malicious",
    r"malicious[^\n]{0,40}relayer",
    r"keeper[^\n]{0,40}malicious",
    r"malicious[^\n]{0,40}keeper",
    r"trusted[^\n]{0,40}infrastructure[^\n]{0,40}comprom",
    r"comprom[^\n]{0,40}trusted[^\n]{0,40}infrastructure",
    # Tightened to 30-char span - prevents "SLINKY-...-VALIDATION)...oracle"
    # and "oracle...Slinky VE consensus" cross-clause matches.
    r"slinky[^\n]{0,30}oracle",
    r"oracle[^\n]{0,30}slinky",
]

# Negation-context filter: if the pre-match context (up to 100 chars before the
# match start on the same line) contains one of these words, the match is likely
# a negation clause and should be skipped.  Applied in _line_hits_trusted_infra.
NEGATION_CONTEXT_RE = re.compile(
    r"\b(?:not|no|without|doesn['’]t|does\s+not|NOT\s+required|"
    r"not\s+required|not\s+a\s+|not\s+an\s+|OOS\s+clauses?\s+checked|"
    r"out[- ]of[- ]scope\s+clauses?\s+checked)\b",
    re.IGNORECASE,
)

# Signals that a non-trusted-compromise trigger ALSO EXISTS (affirmative).
# Must NOT match the tabulation field label "Non-trusted-compromise trigger: No."
# Patterns require either an affirmative qualifier (YES, also, without, etc.)
# or a standalone-path keyword.
NON_TRUSTED_TRIGGER_RE = re.compile(
    # Explicit "yes" or affirmative after field label
    r"non[- ]trusted[- ](?:compromise[- ])?trigger\s*:\s*(?:yes|also|path|both|either)\b"
    r"|exploit.*without.*trusted"
    r"|trigger.*without.*comprom"
    r"|also\s+works\s+without"
    r"|path\s+[ab]\b.*without.*comprom"
    r"|no\s+trusted.*comprom.*required"
    r"|no\s+(?:trusted[- ])?infrastructure\s+compromise\s+(?:is\s+)?(?:needed|required)"
    r"|natural\s+network\s+(?:delay|partition|interruption)"
    r"|sufficient\s+alone"
    r"|non-adversarial\s+(?:trigger|path|scenario)",
    re.IGNORECASE,
)

# Required section header
TABULATION_SECTION_RE = re.compile(
    r"##?\s+Trusted\s+Infrastructure\s+Tabulation",
    re.IGNORECASE,
)

# The 4 required fields inside the tabulation section.
FIELD1_RE = re.compile(
    r"(?:trusted\s+component\s+name|component\s+name|trusted\s+component)\s*[+&]\s*protocol\s+role"
    r"|trusted\s+component.*protocol\s+role"
    r"|\*\*?trusted\s+component\s+name",
    re.IGNORECASE,
)
FIELD2_RE = re.compile(
    r"(?:program\s+)?oos\s+clause"
    r"|out[- ]of[- ]scope\s+clause"
    r"|verbatim\s+from\s+(?:severity|scope)"
    r"|\*\*?program\s+oos",
    re.IGNORECASE,
)
FIELD3_RE = re.compile(
    r"defense\s+layer"
    r"|primary[- ]vs[- ]did\s+classification"
    r"|primary\s+defense"
    r"|\*\*?defense\s+layer",
    re.IGNORECASE,
)
FIELD4_RE = re.compile(
    r"non[- ]trusted[- ]comprom"
    r"|non[- ]trusted.*trigger"
    r"|\*\*?non[- ]trusted",
    re.IGNORECASE,
)

# OOS clause verbatim citations - the section must cite something that looks
# like a direct quote from SCOPE.md or SEVERITY.md.
OOS_CITATION_RE = re.compile(
    r"(?:verbatim\s+from|per\s+(?:scope|severity)\.md|acknowledged\s+(?:as\s+)?(?:oos|out[- ]of[- ]scope)|acknowledged\s+by\s+design|centralization\s+risk\s+acknowledged|is\s+(?:considered\s+)?(?:oos|out[- ]of[- ]scope)|is\s+in[- ]scope|is\s+IN\s+SCOPE)"
    r"|\(verbatim\)"
    r"|(?:SCOPE|SEVERITY)\.md\s+line",
    re.IGNORECASE,
)

# Primary-defense signal inside the tabulation section.
PRIMARY_DEFENSE_RE = re.compile(
    r"\bPRIMARY\s+defense\b"
    r"|is\s+the\s+(?:first\s+line|sole|only|primary)\s+(?:of\s+)?defense"
    r"|primary\s+(?:security\s+)?boundary",
    re.IGNORECASE,
)

# Severity walk-back signals.
WALK_BACK_RE = re.compile(
    r"walk[- ]back"
    r"|walked\s+back"
    r"|severity\s+walk[- ]back"
    r"|(?:walk|reduce|lower|downgrade)\s+(?:severity|the\s+severity|this)\s+(?:from|to|below)"
    r"|cap(?:ped)?\s+(?:at|below)\s+(?:medium|info|informational|low)"
    r"|documentation\s+note"
    r"|not\s+(?:a\s+)?(?:fileable|separate)\s+finding"
    r"|out[- ]of[- ]scope\s+per\s+program"
    r"|this\s+finding\s+is\s+walked\s+back",
    re.IGNORECASE,
)

# Scope docs filenames the tool will scan.
SCOPE_DOC_NAMES = (
    "SEVERITY.md", "severity.md", "Severity.md",
    "SCOPE.md", "scope.md", "Scope.md",
    "SECURITY.md", "security.md",
)

REBUTTAL_HTML_RE = re.compile(r"<!--\s*r46-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)
REBUTTAL_LINE_RE = re.compile(r"(?im)^\s*(?:[-*]\s*)?r46[-_ ]rebuttal\s*:\s*(.+?)\s*$")

# r36-rebuttal: lane r46-source-verify-hardening-2026-05-28 — CAP-GAP-NI-10
# R46 source-verify hardening: auto-grep cited consumer file:line for trust
# gates (#[trusted_relayer] / onlyRole / onlyOwner / etc.) and fail-closed
# when draft claims permissionless access. Anchor: NEAR-Intents merkle-
# malleability paste-ready KILLED 2026-05-28 (operator+Codex caught).

DEFAULT_TRUST_GATE_PATTERNS = [
    # Rust / NEAR macro decorators (above the function)
    r"#\[trusted_relayer\b",
    r"#\[trusted[_-]\w+\b",
    r"#\[(?:require_authorized|access_control|admin_only)\b",
    r"#\[(?:dao_only|owner_only|operator_only)\b",
    # Substrate / FRAME
    r"\bensure_signed!?\s*\(",
    r"\bensure_root!?\s*\(",
    # Solidity OpenZeppelin / standard modifiers
    r"\bonlyOwner\b",
    r"\bonlyRole\s*\(",
    r"\bonlyAdmin\b",
    r"\bonlyOperator\b",
    r"\bonlyRelayer\b",
    r"\bonlyAuthorized\b",
    r"\bonlyKeeper\b",
    r"\bonlyGovernance\b",
    r"\bauth\s*\(\s*\)",
    r"\brequiresAuth\b",
    r"\b_authorizeUpgrade\b",
    # Cosmos-SDK ante / msg-signer
    r"\bGetAuthority\s*\(",
    r"\brequire\s*\(\s*msg\.sender\s*==\s*(?:owner|admin|gov)",
    # Move
    r"\bassert!\s*\(\s*signer::address_of\s*\(",
    # Generic role-check pattern (onlyX(...) modifier form)
    r"\bonly[A-Z]\w+\s*\(",
]

# Draft phrases that claim "no trusted-infra dependency".
NO_TRUSTED_DEP_RE = re.compile(
    r"\btrusted\s+component\b[^\n]{0,80}\bNONE\b"
    r"|\bno\s+trusted[- ]infra(?:structure)?\s+dep\b"
    r"|\bno\s+trusted\s+component\b"
    r"|\bpermissionless\b"
    r"|\bany\s+caller\s+can\s+(?:invoke|call|trigger)\b"
    r"|\bnon[- ]trusted[- ]relayer\b"
    r"|\bnot\s+trusted[- ]relayer[- ]gated\b"
    r"|\b(?:does|do)\s+not\s+consult\s+any\s+trusted\b"
    r"|\bno\s+signer\s+set\b"
    r"|\bsingle[- ]actor\s+permissionless\b",
    re.IGNORECASE,
)

# File:line citation pattern (path/to/file.ext[:LINE[-LINE]])
FILE_LINE_CITATION_RE = re.compile(
    r"\b([a-zA-Z0-9_./\-]+\.(?:rs|sol|go|ts|move|cairo|js|py))"
    r"(?::(\d+)(?:[-,](\d+))?)?",
)

# Source-verify rebuttal (narrower than r46-rebuttal).
SOURCE_VERIFY_REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*r46-source-verify-rebuttal:\s*(.*?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)
SOURCE_VERIFY_REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?r46[-_ ]source[-_ ]verify[-_ ]rebuttal\s*:\s*(.+?)\s*$"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override:
        norm = override.strip().lower()
        if norm in SEVERITY_RANK:
            return norm, "cli"
    for pattern, source in (
        (r"(?im)^\s*\**\s*Severity\s*:\**\s*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*severity_implied\s*:\s*(Critical|High|Medium|Low)\b", "program-impact-mapping"),
        (r"(?im)^\s*severity_tier\s*:\s*(Critical|High|Medium|Low)\b", "impact-contract"),
        (r"(?im)^\s*selected_severity\s*:\s*(Critical|High|Medium|Low)\b", "selected-severity"),
    ):
        m = re.search(pattern, text)
        if m:
            return m.group(1).lower(), source
    for sev in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){sev}(?:[-_.]|$)", path.name.lower()):
            return sev, "filename"
    return None, "missing"


def _workspace_root(draft: Path, ws_override: Path | None) -> Path:
    if ws_override is not None:
        return ws_override.resolve()
    cur = draft.resolve().parent
    for parent in [cur, *cur.parents]:
        if (parent / "poc-tests").is_dir() or (parent / "submissions").is_dir():
            return parent
        for name in SCOPE_DOC_NAMES:
            if (parent / name).is_file():
                return parent
    return draft.resolve().parent


def _find_scope_docs(ws_root: Path) -> list[Path]:
    found = []
    for name in SCOPE_DOC_NAMES:
        p = ws_root / name
        if p.is_file():
            found.append(p)
    return found


def _env_patterns(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return []
    return [item.strip() for item in raw.splitlines() if item.strip()]


def _compile_union(patterns: list[str]) -> re.Pattern[str]:
    return re.compile(
        "|".join(f"(?:{p})" for p in patterns),
        re.IGNORECASE,
    )


def _line_hits(text: str, pattern: re.Pattern[str], limit: int = 12) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        m = pattern.search(line)
        if m:
            hits.append({"line": idx, "token": m.group(0)[:80], "text": line.strip()[:240]})
            if len(hits) >= limit:
                break
    return hits


def _line_hits_trusted_infra(
    text: str, pattern: re.Pattern[str], limit: int = 12
) -> list[dict[str, Any]]:
    """Like _line_hits but applies a negation-context filter for trusted-infra patterns.

    Skips a match when the pre-match context on the same line (up to 100 chars
    before the match start) contains a negation word (not, no, without, etc.).
    This prevents false-positives from OOS-checklist lines that say explicitly
    "does not require a malicious proposer" or enumerate excluded actors.
    """
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        m = pattern.search(line)
        if m:
            pre_ctx = line[max(0, m.start() - 100) : m.start()]
            if NEGATION_CONTEXT_RE.search(pre_ctx):
                # Skip: match is inside a negation clause
                continue
            hits.append({"line": idx, "token": m.group(0)[:80], "text": line.strip()[:240]})
            if len(hits) >= limit:
                break
    return hits


# r36-rebuttal: lane r46-source-verify-hardening-2026-05-28
def _source_verify_rebuttal(text: str) -> str | None:
    """Return narrower r46-source-verify-rebuttal reason if present (<=200 chars)."""
    for rx in (SOURCE_VERIFY_REBUTTAL_HTML_RE, SOURCE_VERIFY_REBUTTAL_LINE_RE):
        m = rx.search(text)
        if m:
            reason = m.group(1).strip()
            if 0 < len(reason) <= REBUTTAL_MAX_CHARS:
                return reason
    return None


def _extract_file_line_citations(text: str, limit: int = 50) -> list[dict[str, Any]]:
    """Extract every file:line citation from the draft body.

    Returns list of {"path": "<relative path>", "line_start": int, "line_end": int|None}.
    Dedup-by-(path,line). Limit to first `limit` distinct citations.
    """
    seen: set[tuple[str, int]] = set()
    out: list[dict[str, Any]] = []
    for m in FILE_LINE_CITATION_RE.finditer(text):
        path = m.group(1)
        line_start = int(m.group(2)) if m.group(2) else None
        line_end = int(m.group(3)) if m.group(3) else None
        # Skip obvious test paths (would over-trigger on test fixture file:line)
        if "/test/" in path or "/tests/" in path:
            continue
        # Skip paths that look like documentation refs (SCOPE.md, SEVERITY.md, etc.)
        if path.endswith(".md") or path.endswith(".json"):
            continue
        if line_start is None:
            continue
        key = (path, line_start)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "path": path,
            "line_start": line_start,
            "line_end": line_end,
        })
        if len(out) >= limit:
            break
    return out


def _grep_trust_gates_in_source(
    ws_root: Path,
    citations: list[dict[str, Any]],
    *,
    window_lines: int = 30,
) -> list[dict[str, Any]]:
    """For each citation, grep the cited source file in a window of
    `window_lines` BEFORE the cited line (decorators above the function in
    Rust; modifiers in the function signature line itself in Solidity).

    Returns list of {"citation": {...}, "matched_pattern": str, "matched_line": str, "matched_line_no": int}.
    """
    trust_gate_re = re.compile("|".join(DEFAULT_TRUST_GATE_PATTERNS))
    env_extras = _env_patterns("AUDITOOOR_R46_TRUST_GATE_PATTERNS")
    if env_extras:
        trust_gate_re = re.compile("|".join(DEFAULT_TRUST_GATE_PATTERNS + env_extras))
    window_lines = int(os.environ.get("AUDITOOOR_R46_TRUST_GATE_WINDOW", str(window_lines)))

    hits: list[dict[str, Any]] = []
    for cite in citations:
        # Resolve path relative to workspace root (or absolute, or 'src/...')
        candidates = [
            ws_root / cite["path"],
            ws_root / "src" / cite["path"],
            Path(cite["path"]),
        ]
        src_path = next((c for c in candidates if c.is_file()), None)
        if not src_path:
            continue
        try:
            src_text = src_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        src_lines = src_text.splitlines()
        line_no = cite["line_start"]
        if line_no < 1 or line_no > len(src_lines):
            continue
        start = max(0, line_no - 1 - window_lines)
        # Include the cited line itself + a few lines AFTER (Solidity modifiers
        # are on the same line as the function signature; closing-line is N+0).
        end = min(len(src_lines), line_no + 3)
        window = src_lines[start:end]
        for i, raw in enumerate(window):
            line = raw.strip()
            m = trust_gate_re.search(line)
            if not m:
                continue
            hits.append({
                "citation": cite,
                "source_path": str(src_path.relative_to(ws_root)) if str(src_path).startswith(str(ws_root)) else str(src_path),
                "matched_pattern": m.group(0)[:80],
                "matched_line": line[:200],
                "matched_line_no": start + i + 1,
                "window_lines": window_lines,
            })
            break  # one gate per citation is enough to fail
    return hits


def _rebuttal(text: str) -> str | None:
    m = REBUTTAL_LINE_RE.search(text)
    if not m:
        m = REBUTTAL_HTML_RE.search(text)
    if not m:
        return None
    return " ".join(m.group(1).split())


def _extract_tabulation_body(text: str) -> str:
    """Return the body of the Trusted Infrastructure Tabulation section.

    Returns the content from the section header up to the next same-level
    header (## ...) or end of document.
    """
    m = TABULATION_SECTION_RE.search(text)
    if not m:
        return ""
    start = m.end()
    # Find next same-level heading
    rest = text[start:]
    next_header = re.search(r"^##?\s+\S", rest, re.MULTILINE)
    if next_header:
        return rest[: next_header.start()]
    return rest


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

def run(
    draft: Path,
    *,
    workspace: Path | None = None,
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
    ws_root = _workspace_root(draft, workspace)

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "file": str(draft),
        "severity": severity,
        "severity_source": severity_source,
        "workspace": str(ws_root),
        "strict": strict,
        "evidence": {},
        "remediation_options": [
            "Add a 'Trusted Infrastructure Tabulation' section with 4 fields: "
            "(1) trusted component name + protocol role, "
            "(2) program OOS clause verbatim from SEVERITY.md/SCOPE.md, "
            "(3) defense layer + primary-vs-DiD classification, "
            "(4) non-trusted-compromise trigger (if any).",
            "If the trusted component is the primary defense, walk back severity to "
            "acknowledge the OOS centralization risk.",
            "If a non-trusted-compromise exploit path also exists, document it as "
            "'Non-trusted-compromise trigger: YES' to pass the gate.",
            "Override: visible line 'r46-rebuttal: <reason>' (<=200 chars) or "
            "<!-- r46-rebuttal: <reason> -->.",
        ],
    }

    # --- Scope gate: only fires on HIGH and above ---
    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH or missing"
        return 0, payload

    # --- Rebuttal gate ---
    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= REBUTTAL_MAX_CHARS:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload

    # --- Build trusted-infra pattern set ---
    all_patterns = DEFAULT_TRUSTED_INFRA_PATTERNS + _env_patterns(
        "AUDITOOOR_R46_TRUSTED_INFRA_PATTERNS"
    )
    trusted_infra_re = _compile_union(all_patterns)

    # --- Scan for trusted-infra triggers ---
    trigger_hits = _line_hits_trusted_infra(text, trusted_infra_re)

    if not trigger_hits:
        # r36-rebuttal: lane r46-source-verify-hardening-2026-05-28
        # CAP-GAP-NI-10: even when the draft uses bland "no trusted-infra dep"
        # language (no trigger pattern hit), we must independently verify the
        # cited source files have NO trust gates before passing. Anchor: NEAR
        # merkle-malleability paste-ready KILLED 2026-05-28.
        sv_rebuttal = _source_verify_rebuttal(text)
        if sv_rebuttal:
            payload["verdict"] = "pass-no-trusted-infra-dep"
            payload["reason"] = "no trigger pattern found; source-verify skipped via r46-source-verify-rebuttal"
            payload["source_verify_rebuttal"] = sv_rebuttal
            return 0, payload
        claims_no_dep = bool(NO_TRUSTED_DEP_RE.search(text))
        payload["evidence"]["claims_no_trusted_dep"] = claims_no_dep
        if claims_no_dep:
            citations = _extract_file_line_citations(text)
            payload["evidence"]["file_line_citations_scanned"] = len(citations)
            if citations:
                trust_gate_hits = _grep_trust_gates_in_source(ws_root, citations)
                if trust_gate_hits:
                    payload["verdict"] = "fail-trusted-infra-source-verify-mismatch"
                    payload["reason"] = (
                        f"draft claims permissionless / no-trusted-infra-dep but "
                        f"source-verify found {len(trust_gate_hits)} trust gate(s) "
                        f"on cited consumer file:line ranges. Either: (a) re-verify "
                        f"the cited source path, (b) walk severity back and add the "
                        f"Trusted Infrastructure Tabulation, or (c) override via "
                        f"`r46-source-verify-rebuttal: <reason>` if the gate is "
                        f"on a sibling protected path that does NOT cover the bug."
                    )
                    payload["evidence"]["trust_gate_hits"] = trust_gate_hits
                    return 1, payload
                payload["evidence"]["source_verify"] = "pass-no-gate-found"
        payload["verdict"] = "pass-no-trusted-infra-dep"
        payload["reason"] = "no trusted-infrastructure trigger pattern found in draft"
        return 0, payload

    payload["evidence"]["trusted_infra_triggers"] = trigger_hits

    # --- Non-trusted-trigger check ---
    non_trusted_hits = _line_hits(text, NON_TRUSTED_TRIGGER_RE)
    if non_trusted_hits:
        payload["verdict"] = "pass-non-trusted-trigger-also-exists"
        payload["reason"] = (
            "the draft documents a non-trusted-compromise exploit path; "
            "trusted infra compromise is not a required precondition"
        )
        payload["evidence"]["non_trusted_trigger_hits"] = non_trusted_hits
        return 0, payload

    # --- Check for Trusted Infrastructure Tabulation section ---
    has_section = bool(TABULATION_SECTION_RE.search(text))
    payload["evidence"]["tabulation_section_found"] = has_section

    if not has_section:
        payload["verdict"] = "fail-no-trusted-infra-tabulation"
        payload["reason"] = (
            "trusted-infra trigger found but no 'Trusted Infrastructure Tabulation' "
            "section present; add the section with 4 required fields"
        )
        return 1, payload

    # --- Extract tabulation body and check 4 fields ---
    tab_body = _extract_tabulation_body(text)

    field1_ok = bool(FIELD1_RE.search(tab_body))
    field2_ok = bool(FIELD2_RE.search(tab_body))
    field3_ok = bool(FIELD3_RE.search(tab_body))
    field4_ok = bool(FIELD4_RE.search(tab_body))

    payload["evidence"]["tabulation_fields"] = {
        "field1_trusted_component_name_and_role": field1_ok,
        "field2_oos_clause_citation": field2_ok,
        "field3_defense_layer_classification": field3_ok,
        "field4_non_trusted_trigger": field4_ok,
    }

    # --- OOS citation check (field 2 present but no verbatim quote signal) ---
    has_oos_citation = bool(OOS_CITATION_RE.search(tab_body))
    payload["evidence"]["oos_citation_signal_found"] = has_oos_citation

    if field2_ok and not has_oos_citation:
        payload["verdict"] = "fail-oos-citation-missing"
        payload["reason"] = (
            "tabulation field 2 (OOS clause) is present but contains no verbatim "
            "citation from SEVERITY.md/SCOPE.md; add the verbatim quoted line "
            "or a reference like 'per SCOPE.md line N:'"
        )
        return 1, payload

    # Accumulate missing fields
    missing_fields = []
    if not field1_ok:
        missing_fields.append("field1: trusted component name + protocol role")
    if not field2_ok:
        missing_fields.append("field2: program OOS clause verbatim citation")
    if not field3_ok:
        missing_fields.append("field3: defense layer + primary-vs-DiD classification")
    if not field4_ok:
        missing_fields.append("field4: non-trusted-compromise trigger statement")

    if missing_fields:
        payload["verdict"] = "fail-no-trusted-infra-tabulation"
        payload["reason"] = (
            "tabulation section found but missing required fields: "
            + "; ".join(missing_fields)
        )
        payload["evidence"]["missing_fields"] = missing_fields
        return 1, payload

    # --- Primary defense + no walk-back check ---
    is_primary_defense = bool(PRIMARY_DEFENSE_RE.search(tab_body))
    has_walk_back = bool(WALK_BACK_RE.search(text))

    payload["evidence"]["is_primary_defense"] = is_primary_defense
    payload["evidence"]["walk_back_signal_found"] = has_walk_back

    if is_primary_defense and not has_walk_back:
        payload["verdict"] = "fail-trusted-infra-primary-defense-no-walk-back"
        payload["reason"] = (
            "the tabulation classifies the trusted component as the PRIMARY defense, "
            "but the draft does not walk back severity to acknowledge the OOS "
            "centralization risk; add a severity walk-back or "
            "r46-rebuttal: <reason> explaining why full severity is still justified"
        )
        return 1, payload

    # --- All checks passed ---
    payload["verdict"] = "pass-trusted-infra-tabulated-with-walk-back"
    payload["reason"] = (
        "trusted infrastructure tabulation present with all 4 fields, "
        "OOS citation included, and severity walk-back documented"
    )
    return 0, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--workspace", type=Path, default=None)
    parser.add_argument(
        "--severity",
        choices=[
            "auto", "Critical", "High", "Medium", "Low",
            "critical", "high", "medium", "low",
        ],
        default="auto",
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", dest="json_out", action="store_true")
    args = parser.parse_args(argv)

    override = None if args.severity == "auto" else args.severity
    rc, payload = run(
        args.draft,
        workspace=args.workspace,
        severity_override=override,
        strict=args.strict,
    )

    if args.json_out:
        print(json.dumps(payload, indent=2))
    else:
        verdict = payload.get("verdict", "error")
        reason = payload.get("reason", payload.get("error", ""))
        print(f"[{GATE}] {verdict}: {reason}")
        if payload.get("rebuttal"):
            print(f"  rebuttal: {payload['rebuttal']}")
        if payload.get("evidence", {}).get("trusted_infra_triggers"):
            triggers = payload["evidence"]["trusted_infra_triggers"]
            print(f"  triggers ({len(triggers)} hits):")
            for h in triggers[:3]:
                print(f"    line {h['line']}: {h['text'][:100]}")
        if payload.get("evidence", {}).get("missing_fields"):
            for f in payload["evidence"]["missing_fields"]:
                print(f"  missing: {f}")

    if rc == 1 and not args.strict:
        # Hard fail verdicts always exit 1 regardless of --strict
        hard_fails = {
            "fail-no-trusted-infra-tabulation",
            "fail-trusted-infra-primary-defense-no-walk-back",
            "fail-oos-citation-missing",
        }
        if payload.get("verdict") in hard_fails:
            return 1
        return 0

    return rc


if __name__ == "__main__":
    sys.exit(main())
