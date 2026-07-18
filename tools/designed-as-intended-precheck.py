#!/usr/bin/env python3
"""Rule 45 Designed-As-Intended precheck (Check #93) - v2.

# Rule 45: this tool emits no corpus record.

TRIGGER: HIGH+ draft whose claim contains omission-pattern language
("should be validated", "missing check", "no finalization wait", etc.).

When a finding claims the protocol is missing a check/guard/wait, the
program may have deliberately omitted it with a documented design-intent
statement and named defense-in-depth alternatives. If the public docs
explicitly record this as a design choice AND name those alternatives
AND those alternatives are verified to be implemented at the audit-pin tree,
the gate fails closed.

v2 adds three tightening constraints to eliminate false positives from
audit-report PDF noise (prior_audits/) and from cited-but-unimplemented defenses:

1. Protocol-own-doc constraint: design-intent phrases must appear in the
   protocol's OWN docs (README.md, docs/, ARCHITECTURE.md, SECURITY.md, SCOPE.md
   at the workspace root), NOT in prior_audits/ (those are audit-report PDFs
   that describe findings using design-intent language).

2. Direct-reference constraint: the phrase must co-occur with contested-behavior
   keywords (e.g. "finaliz", "challenge", "wait") within proximity_chars (default 200)
   of each other in the same document. Generic "designed for cross-chain" without
   proximity to the contested behavior does not count.

3. Defense-implemented constraint: any named defense-in-depth alternative must be
   verified to be ACTUALLY IMPLEMENTED at the audit-pin tree (grep workspace src/
   for the symbol; if it returns "Unimplemented" / "panic" / always-revert, the
   cited defense fails verification -> the omission finding stands).

Verdict vocabulary:
  pass-out-of-scope                              (severity below HIGH, or --severity LOW/MEDIUM)
  pass-no-omission-claim                         (HIGH+ but no omission trigger pattern found)
  pass-not-documented-as-intentional             (docs scanned, no design-intent statement)
  pass-documented-but-not-defended-in-depth      (docs mention design choice but no
                                                  defense-in-depth alternative named; fileable
                                                  but drafter warned to pre-empt triager)
  pass-design-intent-cited-but-defenses-not-implemented
                                                 (v2: protocol own-docs cite design intent and
                                                  name defenses, but grep confirms those defenses
                                                  return Unimplemented/panic/always-revert at
                                                  audit-pin -> omission finding stands)
  ok-rebuttal                                    (visible r45-rebuttal present, <=200 chars)
  fail-designed-as-intended-with-defense-in-depth
                                                 (protocol own-docs + direct-reference + defenses
                                                  verified implemented -> close-as-intended risk)
  fail-public-doc-undisclosed                    (SEVERITY.md/SCOPE.md marks this class
                                                  "acknowledged by design" / OOS but the draft
                                                  does not address it)
  error

Exit codes:
  0 - pass / ok-rebuttal / out-of-scope / not-documented / documented-no-defense /
      pass-design-intent-cited-but-defenses-not-implemented
  1 - Rule 45 violation (any fail-* verdict with --strict; always for
      fail-designed-as-intended-with-defense-in-depth)
  2 - input error

Schema: auditooor.r45_designed_as_intended_precheck.v1
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "auditooor.r45_designed_as_intended_precheck.v1"
GATE = "R45-DESIGNED-AS-INTENDED-PRECHECK"
AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Patterns in the draft that signal an omission-class claim.
# r36-rebuttal: lane near-detector-fixes-2026-05-28 — CAP-GAP-NI-7 expansion
# (added "do not bound", "do not enforce", "no upper bound", "without bound",
# "no requirement that", "no <X>-style check" — found via NEAR merkle-malleability draft miss)
DEFAULT_OMISSION_PATTERNS = [
    r"should be (?:checked|validated|restricted|enforced|verified|bound|bounded)",
    r"missing\s+(?:a\s+)?(?:check|validation|finalization|wait|guard|modifier|restriction|bound)",
    r"no\s+(?:check|validation|wait period|finalization|guard|restriction|upper bound|lower bound|defense)\b",
    r"allows\s+\w+\s+without\s+(?:restriction|limit|check|validation|verification|bound)",
    r"fails to\s+(?:wait|verify|check|validate|reject|enforce|bound)",
    r"accepts\s+(?:unfinalized|unverified|forged|invalid|arbitrary|attacker-controlled)",
    r"do(?:es)? not\s+(?:check|validate|verify|enforce|wait|reject|bound|distinguish|differentiate)",
    r"omit(?:s|ted|ting)?\s+(?:the\s+)?(?:check|validation|wait|guard|bound|distinction)",
    r"lack(?:s|ing)?\s+(?:the\s+)?(?:check|validation|guard|finalization|bound|enforcement)",
    r"\bno requirement that\b",
    r"without\s+(?:any\s+)?bound",
    r"adds no defense",
    r"no\s+\w+(?:-\w+)?-style\s+(?:check|guard|validation|defense)",
]

# Patterns in docs that indicate a design-intent statement.
DESIGN_INTENT_PATTERNS = [
    r"\b(?:by design|intentionally|designed to|this is intended|intended behavior)\b",
    r"\b(?:deliberately|purposefully|on purpose)\b",
    r"\b(?:design choice|design decision|conscious decision)\b",
    r"\b(?:acknowledged|known limitation)\b",
    r"\b(?:documented behavior|expected behavior)\b",
    r"\bwe (?:do not|don't) (?:check|validate|wait|enforce)\b",
    r"\bno (?:finalization|challenge)\s+(?:period|window|wait)\s+(?:is\s+)?(?:required|needed|enforced)\b",
    r"\boptimistic\b.*\bno\s+(?:wait|delay|challenge)\b",
    r"\bdesigned (?:for|as|to)\b",
]

# Patterns in docs that name a defense-in-depth alternative.
DEFENSE_IN_DEPTH_PATTERNS = [
    r"\b(?:challenger|fishermen|watchtower|watcher)\b",
    r"\b(?:bond|stake|slashing|penalty|collateral)\b",
    r"\b(?:economic (?:security|incentive|guarantee))\b",
    r"\b(?:fault proof|fraud proof|dispute game|dispute period)\b",
    r"\b(?:challenge (?:window|period|mechanism))\b",
    r"\b(?:safe(?:ty|guard)|fallback|backup|failsafe)\b",
    r"\b(?:provides?|adds?|includes?|has|with)\s+(?:an?\s+)?additional\s+(?:check|layer|guard|protection|defense)\b",
    r"\b(?:protected (?:by|via|through)|secured (?:by|via|through))\b",
    r"\b(?:alternative (?:check|path|mechanism|enforcement))\b",
    r"\b(?:multi[- ]sig|multisig|threshold|quorum)\b",
    r"\b(?:time[- ]lock|timelock|delay)\b",
    r"\b(?:guardian|operator|admin|protocol)\s+(?:can|will|must)\b",
]

# SEVERITY.md / SCOPE.md patterns that mark a class "acknowledged by design" OOS.
ACKNOWLEDGED_BY_DESIGN_PATTERNS = [
    r"\backnowledged[- ]by[- ]design\b",
    r"\bby[- ]design\b",
    r"\bintentional(?:ly)?\b.*\bout[- ]of[- ]scope\b",
    r"\bout[- ]of[- ]scope\b.*\backnowledged\b",
    r"\bdesigned as intended\b",
    r"\bnot a bug\b",
    r"\bno\s+(?:challenge|finalization)\s+(?:period|window|wait)\s+(?:is\s+)?(?:out[- ]of[- ]scope|oos|not in scope)\b",
    r"\b(?:missing check|missing validation|no validation|no guard)\b.*\boos\b",
    r"\b(?:missing check|missing validation|no validation|no guard)\b.*\bout[- ]of[- ]scope\b",
]

# Doc filenames to scan in the workspace / audit-pin tree.
DOC_FILENAMES = [
    "README.md",
    "readme.md",
    "SECURITY.md",
    "security.md",
    "SCOPE.md",
    "scope.md",
    "ARCHITECTURE.md",
    "architecture.md",
    "DESIGN.md",
    "design.md",
    "FAQ.md",
    "faq.md",
    "KNOWN_ISSUES.md",
    "known_issues.md",
]

# Subdirectories searched for protocol-own-docs.
# Excludes prior_audits/ (audit-report PDFs) and scope_review/ (auditooor-generated briefs).
DOC_SUBDIRS = ["docs", "doc", "documentation"]

# These subdirs are EXCLUDED from protocol-own-doc scan (audit-report noise / auditooor artifacts).
DOC_SUBDIRS_EXCLUDED = ["prior_audits", "scope_review"]

# Filename suffixes that indicate an auditooor-generated artifact, not a protocol doc.
AUDITOOOR_ARTIFACT_SUFFIXES = (
    ".brief.md",
    ".OOS_CHECK.md",
    ".heuristic-review.md",
    ".gate-status.json",
    ".poc-transcript.txt",
    ".hackenproof-plain.txt",
    ".hackenproof-plain.json",
    ".hardening.md",
)

# Contested-behavior keywords: a design-intent phrase must appear within
# PROXIMITY_CHARS of at least one of these to count as a direct reference.
# Configurable via env AUDITOOOR_R45_CONTESTED_KEYWORDS (newline-separated).
DEFAULT_CONTESTED_KEYWORDS = [
    "finaliz",
    "challenge",
    "wait period",
    "soft confirm",
    "output root",
    "unfinalized",
    "unverif",
    "dispute",
    "fraud proof",
    "check",
    "validat",
    "guard",
    "verif",
    "restrict",
    "enforce",
    "root",
    "omit",
    "miss",
]

DEFAULT_PROXIMITY_CHARS = 200

# Symbols that indicate a "defense" is NOT actually implemented at the audit-pin tree.
UNIMPLEMENTED_PATTERNS = [
    r"Unimplemented\b",
    r"unimplemented!\(\)",
    r"todo!\(\)",
    r"FraudProofUnimplemented\b",
    r"NotImplemented\b",
    r"panic!\s*\(",
    r"unreachable!\s*\(",
    r"\breturn\s+Err\(.*[Uu]nimplemented",
    r"raise\s+NotImplementedError",
    r"throw\s+new\s+Error\s*\(\s*[\"'](?:not implemented|unimplemented)",
]

# Source directories to grep when verifying defense implementations.
SRC_SUBDIRS = ["src", "contracts", "lib", "crates", "modules", "packages"]

REBUTTAL_HTML_RE = re.compile(r"<!--\s*r45-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)
REBUTTAL_LINE_RE = re.compile(r"(?im)^\s*(?:[-*]\s*)?r45[-_ ]rebuttal\s*:\s*(.+?)\s*$")

SEVERITY_FILE_NAMES = ("SEVERITY.md", "severity.md", "Severity.md")
SCOPE_FILE_NAMES = ("SCOPE.md", "scope.md", "Scope.md")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _env_patterns(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return []
    return [item.strip() for item in raw.splitlines() if item.strip()]


def _compile_union(patterns: list[str]) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)


def _line_hits(text: str, pattern: re.Pattern[str], limit: int = 12) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        m = pattern.search(line)
        if m:
            hits.append({"line": idx, "token": m.group(0)[:80], "text": line.strip()[:240]})
            if len(hits) >= limit:
                break
    return hits


def _rebuttal(text: str) -> str | None:
    m = REBUTTAL_LINE_RE.search(text)
    if not m:
        m = REBUTTAL_HTML_RE.search(text)
    if not m:
        return None
    return " ".join(m.group(1).split())


def _workspace_root(draft: Path, ws_override: Path | None) -> Path:
    if ws_override is not None:
        return ws_override.resolve()
    cur = draft.resolve().parent
    for parent in [cur, *cur.parents]:
        if (parent / "poc-tests").is_dir() or (parent / "submissions").is_dir():
            return parent
        for name in (*SEVERITY_FILE_NAMES, *SCOPE_FILE_NAMES):
            if (parent / name).is_file():
                return parent
    return draft.resolve().parent


def _find_control_file(ws: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        candidate = ws / name
        if candidate.is_file():
            return candidate
    return None


def _is_auditooor_artifact(p: Path) -> bool:
    """Return True if the file is an auditooor-generated artifact, not a protocol doc."""
    name = p.name
    for suffix in AUDITOOOR_ARTIFACT_SUFFIXES:
        if name.endswith(suffix):
            return True
    # Generated files in workspace auditooor dirs
    for part in p.parts:
        if part in (".auditooor", "scope_review", "agent_outputs", "mining_rounds",
                    "poc_task_briefs", "swarm", "evidence"):
            return True
    return False


def _collect_doc_texts(ws: Path) -> list[tuple[str, str]]:
    """Return list of (filepath_str, text) for all protocol-own doc files found.

    v2: EXCLUDES prior_audits/ and scope_review/ (auditooor-generated briefs).
    Also excludes files with auditooor artifact suffixes (*.brief.md, etc.).
    These contain design-intent language describing findings (noise), not
    the protocol's own endorsement of the contested behavior.
    """
    results: list[tuple[str, str]] = []

    # Top-level doc filenames (protocol-standard names only)
    for name in DOC_FILENAMES:
        p = ws / name
        if p.is_file() and not _is_auditooor_artifact(p):
            try:
                results.append((str(p), _read_text(p)))
            except Exception:
                pass

    # Subdirectory scans (DOC_SUBDIRS excludes prior_audits/ and scope_review/)
    for subdir in DOC_SUBDIRS:
        d = ws / subdir
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*.md")):
            if p.is_file() and not _is_auditooor_artifact(p):
                try:
                    results.append((str(p), _read_text(p)))
                except Exception:
                    pass
        for p in sorted(d.rglob("*.txt")):
            if p.is_file() and not _is_auditooor_artifact(p):
                try:
                    results.append((str(p), _read_text(p)))
                except Exception:
                    pass

    return results


def _scan_protocol_own_docs(workspace: Path) -> list[tuple[str, str]]:
    """v2 constraint 1: return only protocol-own-doc texts, excluding prior_audits/.

    Protocol-own docs = README.md, docs/, ARCHITECTURE.md, SECURITY.md, SCOPE.md.
    Audit-report PDFs (prior_audits/) are explicitly excluded as they contain
    design-intent language describing findings, not endorsing the contested behavior.
    """
    # _collect_doc_texts already excludes prior_audits/ subdirectory
    return _collect_doc_texts(workspace)


def _phrase_co_located_with_contested_behavior(
    phrase_match_text: str,
    phrase_start: int,
    phrase_end: int,
    doc_text: str,
    contested_keywords: list[str] | None = None,
    proximity_chars: int = DEFAULT_PROXIMITY_CHARS,
) -> bool:
    """v2 constraint 2: return True only when a contested keyword appears within
    proximity_chars characters of the phrase match in the document text.

    This filters out generic design-intent phrases ("designed for cross-chain")
    that are not directly referencing the contested behavior (e.g. finalization gap).
    """
    if contested_keywords is None:
        env_kws = _env_patterns("AUDITOOOR_R45_CONTESTED_KEYWORDS")
        contested_keywords = DEFAULT_CONTESTED_KEYWORDS + env_kws

    window_start = max(0, phrase_start - proximity_chars)
    window_end = min(len(doc_text), phrase_end + proximity_chars)
    window = doc_text[window_start:window_end].lower()

    for kw in contested_keywords:
        if kw.lower() in window:
            return True
    return False


def _verify_defense_implemented(
    defense_terms: list[str],
    workspace: Path,
    *,
    src_subdirs: list[str] | None = None,
) -> dict[str, str]:
    """v2 constraint 3: verify that named defense-in-depth terms are implemented
    at the audit-pin tree. Grep workspace src/ for each term.

    Returns a dict: defense_term -> status ('implemented' | 'absent' | 'returns-unimplemented')

    - 'implemented': symbol found in source and NOT immediately followed by an
      unimplemented pattern in nearby lines.
    - 'absent': no grep hit for the symbol.
    - 'returns-unimplemented': symbol found but co-located with an unimplemented pattern.
    """
    import subprocess

    if src_subdirs is None:
        src_subdirs = SRC_SUBDIRS

    unimplemented_re = re.compile(
        "|".join(f"(?:{p})" for p in UNIMPLEMENTED_PATTERNS),
        re.IGNORECASE,
    )

    results: dict[str, str] = {}
    src_dirs: list[Path] = []
    for sd in src_subdirs:
        d = workspace / sd
        if d.is_dir():
            src_dirs.append(d)
    # Also try workspace root itself for small projects
    src_dirs.append(workspace)

    for term in defense_terms:
        found_files: list[Path] = []
        # Normalise: strip special chars for simple glob/grep
        term_clean = re.sub(r"[^a-zA-Z0-9_]", "", term)
        if not term_clean or len(term_clean) < 3:
            results[term] = "absent"
            continue

        for src_dir in src_dirs:
            try:
                proc = subprocess.run(
                    ["grep", "-rl", "--include=*.rs", "--include=*.go",
                     "--include=*.sol", "--include=*.py", "--include=*.ts",
                     term_clean, str(src_dir)],
                    capture_output=True, text=True, timeout=10,
                )
                for fpath_str in proc.stdout.splitlines():
                    p = Path(fpath_str)
                    if p.is_file():
                        found_files.append(p)
            except Exception:
                pass

        if not found_files:
            results[term] = "absent"
            continue

        # Check whether any file with the term also has unimplemented nearby
        any_implemented = False
        any_unimplemented = False
        for fp in found_files[:5]:  # limit for performance
            try:
                content = _read_text(fp)
                # Find all occurrences of the term
                for m in re.finditer(re.escape(term_clean), content, re.IGNORECASE):
                    # Check 300-char window around hit
                    start = max(0, m.start() - 150)
                    end = min(len(content), m.end() + 150)
                    window = content[start:end]
                    if unimplemented_re.search(window):
                        any_unimplemented = True
                    else:
                        any_implemented = True
            except Exception:
                pass

        if any_unimplemented and not any_implemented:
            results[term] = "returns-unimplemented"
        elif any_unimplemented:
            # Mixed: some real implementations, some unimplemented stubs
            results[term] = "partially-implemented"
        else:
            results[term] = "implemented"

    return results


def _extract_defense_terms_from_hits(
    defense_hits: list[dict[str, Any]],
) -> list[str]:
    """Extract searchable symbol candidates from defense-in-depth pattern matches."""
    terms: set[str] = set()
    candidate_patterns = [
        r"\b(challenger|fishermen|watchtower|watcher)\b",
        r"\b(fraud[_\s]?proof|fault[_\s]?proof|dispute[_\s]?game)\b",
        r"\b(challenge[_\s]?window|challenge[_\s]?period)\b",
        r"\b(verify_fraud_proof|verifyFraudProof|verify_fault_proof|verifyFaultProof)\b",
        r"\b(disputeGame|dispute_game|FaultDisputeGame)\b",
        r"\b(slash|slashing|bond)\b",
    ]
    combined = re.compile("|".join(candidate_patterns), re.IGNORECASE)
    for hit in defense_hits:
        text = hit.get("text", "")
        for m in combined.finditer(text):
            term = m.group(0).strip()
            terms.add(term)
    return sorted(terms)


def _extract_search_terms(omission_hits: list[dict[str, Any]]) -> list[str]:
    """Derive search terms from omission hit tokens."""
    terms: set[str] = set()
    keyword_map = {
        "finalization": ["finalization", "finalize", "finalized", "challenge", "challenger"],
        "wait": ["wait", "delay", "period", "window", "timeout"],
        "validation": ["validation", "validate", "verified", "verification"],
        "check": ["check", "guard", "enforce", "restriction"],
        "challenger": ["challenger", "fishermen", "watchtower"],
        "unfinalized": ["unfinalized", "unverified", "finalization", "challenge"],
        "unverified": ["unverified", "verification", "verifier"],
    }
    for hit in omission_hits:
        token_lower = hit["token"].lower()
        for kw, expansions in keyword_map.items():
            if kw in token_lower:
                terms.update(expansions)
        # Also add the raw token (first word)
        first_word = re.sub(r"[^a-z_\-]", "", token_lower.split()[0]) if token_lower.split() else ""
        if first_word and len(first_word) > 3:
            terms.add(first_word)
    return sorted(terms)


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _extract_attack_class(text: str) -> str:
    for pat in (
        r"(?im)^\s*attack[_ -]?class\s*:\s*([^\n#]+)",
        r"(?im)^\s*bug[_ -]?class\s*:\s*([^\n#]+)",
        r"(?im)^\s*class\s*:\s*([a-z0-9_. -]{2,80})\s*$",
    ):
        m = re.search(pat, text)
        if m:
            return m.group(1).strip()[:80]
    return "designed-as-intended-omission"


def _extract_contract_function(text: str, draft: Path) -> str:
    for pat in (
        r"(?im)^\s*(?:contract\.function|contract_function|function|affected function)\s*:\s*([A-Za-z0-9_./:-]+)",
        r"\b([A-Z][A-Za-z0-9_]*(?:\.sol|\.rs|\.go|\.move|\.cairo)?::[A-Za-z_][A-Za-z0-9_]*)\b",
        r"\b([A-Z][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*)\b",
    ):
        m = re.search(pat, text)
        if m:
            return m.group(1).strip()[:160]
    return draft.stem


def _known_dead_ends_path(path_override: Path | None = None) -> Path:
    if path_override is not None:
        return path_override
    env_path = os.environ.get("AUDITOOOR_R45_KDE_PATH")
    if env_path:
        return Path(env_path)
    return AUDITOOOR_ROOT / "reports" / "known_dead_ends.jsonl"


def append_known_dead_end_for_r45(
    payload: dict[str, Any],
    draft_text: str,
    draft: Path,
    *,
    known_dead_ends_path: Path | None = None,
) -> dict[str, Any]:
    """Persist R45 fail-designed verdict to the known-dead-ends JSONL."""
    if payload.get("verdict") != "fail-designed-as-intended-with-defense-in-depth":
        return {"persisted": False, "reason": "verdict_not_r45_fail"}

    path = _known_dead_ends_path(known_dead_ends_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    hits = payload.get("evidence", {}).get("design_intent_doc_hits", []) or []
    first_hit = hits[0] if hits and isinstance(hits[0], dict) else {}
    contract_function = _extract_contract_function(draft_text, draft)
    attack_class = _extract_attack_class(draft_text)
    workspace = str(payload.get("workspace") or "")
    design_quote = str(first_hit.get("text") or first_hit.get("token") or "")[:240]
    dedupe_key = hashlib.sha256(
        json.dumps(
            {
                "rule": "R45",
                "workspace": workspace,
                "attack_class": attack_class,
                "contract_function": contract_function,
                "design_quote": design_quote,
            },
            sort_keys=True,
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()[:24]

    existing_keys: set[str] = set()
    if path.is_file():
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                existing_keys.add(str(row.get("dedupe_key") or ""))
    if dedupe_key in existing_keys:
        return {"persisted": False, "reason": "duplicate", "path": str(path), "dedupe_key": dedupe_key}

    row = {
        "schema_version": "auditooor.known_dead_end.r45.v1",
        "source_rule": GATE,
        "workspace": workspace,
        "attack_class": attack_class,
        "contract.function": contract_function,
        "candidate_pattern": f"{contract_function} {attack_class} designed-as-intended",
        "reason": payload.get("reason") or "",
        "design_intent_quote": design_quote,
        "design_intent_source": first_hit.get("source_file") or "",
        "draft": str(draft),
        "dedupe_key": dedupe_key,
        "added_at_utc": _iso_now(),
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")
    return {"persisted": True, "path": str(path), "dedupe_key": dedupe_key, "row": row}


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def run(
    draft: Path,
    *,
    severity_override: str | None = None,
    workspace: Path | None = None,
    strict: bool = False,
    persist_kde: bool = False,
    known_dead_ends_path: Path | None = None,
) -> tuple[int, dict[str, Any]]:
    # ---- read draft ----
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
            "Add a 'Design Intent Response' section addressing the documented design choice and explaining why your attack vector is NOT covered by the named defense-in-depth alternatives.",
            "Use an explicit 'r45-rebuttal: <reason>' marker (<=200 chars) citing operator approval or a bounded exception.",
            "Walk severity below HIGH if the behavior is definitively by-design with defense-in-depth.",
            "Reframe the finding to a separate attack surface NOT acknowledged in the design docs.",
        ],
    }

    # Below HIGH: out of scope
    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH or missing; R45 does not fire"
        return 0, payload

    # Check rebuttal first
    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= 200:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload

    # Omission pattern detection
    omission_re = _compile_union(
        DEFAULT_OMISSION_PATTERNS + _env_patterns("AUDITOOOR_R45_OMISSION_PATTERNS")
    )
    omission_hits = _line_hits(text, omission_re)
    payload["evidence"]["omission_hits"] = omission_hits

    if not omission_hits:
        payload["verdict"] = "pass-no-omission-claim"
        payload["reason"] = "no omission-pattern language detected in draft; R45 trigger not met"
        return 0, payload

    # Resolve workspace
    ws = _workspace_root(draft, workspace)
    payload["workspace"] = str(ws)

    # ---- SEVERITY.md / SCOPE.md acknowledged-by-design check ----
    design_intent_re = _compile_union(DESIGN_INTENT_PATTERNS + _env_patterns("AUDITOOOR_R45_DESIGN_INTENT_PATTERNS"))
    defense_in_depth_re = _compile_union(DEFENSE_IN_DEPTH_PATTERNS + _env_patterns("AUDITOOOR_R45_DEFENSE_IN_DEPTH_PATTERNS"))
    acknowledged_re = _compile_union(ACKNOWLEDGED_BY_DESIGN_PATTERNS)

    severity_md_path = _find_control_file(ws, SEVERITY_FILE_NAMES)
    scope_md_path = _find_control_file(ws, SCOPE_FILE_NAMES)

    control_acknowledged_hits: list[dict[str, Any]] = []
    for ctrl_path in [severity_md_path, scope_md_path]:
        if ctrl_path is None:
            continue
        try:
            ctrl_text = _read_text(ctrl_path)
        except Exception:
            continue
        hits = _line_hits(ctrl_text, acknowledged_re)
        for h in hits:
            h["source_file"] = str(ctrl_path)
        control_acknowledged_hits.extend(hits)

    payload["evidence"]["control_file_acknowledged_hits"] = control_acknowledged_hits

    # If SEVERITY.md/SCOPE.md marks this class OOS-by-design, check whether
    # the draft addresses it.
    if control_acknowledged_hits:
        # Check if draft acknowledges/addresses the design-intent OOS category
        draft_addresses_re = _compile_union([
            r"\bby[- ]design\b",
            r"\bdesigned as intended\b",
            r"\backnowledged\b",
            r"\bintentional\b",
            r"\bdesign choice\b",
            r"\bwhy this is still a bug\b",
            r"\bdefense[- ]in[- ]depth\b",
            r"\bchallenger\b",
            r"\bfishermen\b",
        ])
        draft_ack_hits = _line_hits(text, draft_addresses_re)
        if not draft_ack_hits:
            payload["verdict"] = "fail-public-doc-undisclosed"
            payload["reason"] = (
                "workspace SEVERITY.md or SCOPE.md marks this class as acknowledged-by-design / OOS "
                "but the draft does not address or rebut the design-intent classification"
            )
            payload["evidence"]["draft_acknowledgment_hits"] = []
            return (1 if strict else 0), payload
        payload["evidence"]["draft_acknowledgment_hits"] = draft_ack_hits

    # ---- Doc scan for design-intent statements (v2: protocol-own-docs only) ----
    # Constraint 1: exclude prior_audits/ - those are audit-report PDFs that use
    # design-intent language to DESCRIBE findings, not to ENDORSE the contested behavior.
    doc_texts = _scan_protocol_own_docs(ws)
    payload["evidence"]["docs_scanned"] = [fp for fp, _ in doc_texts]
    payload["evidence"]["prior_audits_excluded"] = True

    # Constraint 2: direct-reference - design-intent phrase must be co-located with
    # contested-behavior keywords within DEFAULT_PROXIMITY_CHARS characters.
    env_contested = _env_patterns("AUDITOOOR_R45_CONTESTED_KEYWORDS")
    contested_keywords = DEFAULT_CONTESTED_KEYWORDS + env_contested

    design_intent_doc_hits: list[dict[str, Any]] = []
    defense_in_depth_doc_hits: list[dict[str, Any]] = []

    for fp, doc_text in doc_texts:
        # For each design-intent match, check proximity to contested behavior keywords
        for m in design_intent_re.finditer(doc_text):
            if _phrase_co_located_with_contested_behavior(
                m.group(0),
                m.start(),
                m.end(),
                doc_text,
                contested_keywords=contested_keywords,
                proximity_chars=DEFAULT_PROXIMITY_CHARS,
            ):
                line_num = doc_text[:m.start()].count("\n") + 1
                design_intent_doc_hits.append({
                    "line": line_num,
                    "token": m.group(0)[:80],
                    "text": doc_text[max(0, m.start()-40):m.end()+80].strip()[:240],
                    "source_file": fp,
                    "proximity_match": True,
                })
            if len(design_intent_doc_hits) >= 12:
                break

        dd_hits = _line_hits(doc_text, defense_in_depth_re)
        for h in dd_hits:
            h["source_file"] = fp
        defense_in_depth_doc_hits.extend(dd_hits)

    payload["evidence"]["design_intent_doc_hits"] = design_intent_doc_hits
    payload["evidence"]["defense_in_depth_doc_hits"] = defense_in_depth_doc_hits
    payload["evidence"]["search_terms_derived"] = _extract_search_terms(omission_hits)

    # ---- Verdict ----
    has_design_intent = bool(design_intent_doc_hits)
    has_defense_in_depth = bool(defense_in_depth_doc_hits)

    if not has_design_intent:
        payload["verdict"] = "pass-not-documented-as-intentional"
        payload["reason"] = (
            "protocol-own-doc scan (excl. prior_audits/) found no design-intent statement "
            "co-located with the contested behavior; fileable subject to other gates"
        )
        return 0, payload

    if has_design_intent and not has_defense_in_depth:
        payload["verdict"] = "pass-documented-but-not-defended-in-depth"
        payload["reason"] = (
            "protocol-own docs mention the design choice but name no defense-in-depth "
            "alternatives; fileable but recommend adding a 'Design Intent Response' section "
            "to pre-empt triager"
        )
        payload["warning"] = (
            "triager may ask: 'why is your finding not covered by the design choice?'. "
            "Pre-answer this in the draft."
        )
        return 0, payload

    # Both design-intent and defense-in-depth found in protocol-own docs.
    # Constraint 3: verify the cited defenses are actually implemented at audit-pin tree.
    defense_terms = _extract_defense_terms_from_hits(defense_in_depth_doc_hits)
    payload["evidence"]["defense_terms_extracted"] = defense_terms

    defense_verification: dict[str, str] = {}
    if defense_terms:
        defense_verification = _verify_defense_implemented(defense_terms, ws)
    payload["evidence"]["defense_verification"] = defense_verification

    # Determine if ALL named defenses are unimplemented / absent
    verified_statuses = list(defense_verification.values())
    all_defenses_unimplemented = bool(verified_statuses) and all(
        s in ("absent", "returns-unimplemented") for s in verified_statuses
    )
    any_defense_implemented = any(
        s in ("implemented", "partially-implemented") for s in verified_statuses
    )

    if all_defenses_unimplemented and not any_defense_implemented:
        # Design intent cited but the named defenses are not implemented at audit-pin.
        # The omission finding stands - this is the Hyperbridge OP case.
        payload["verdict"] = "pass-design-intent-cited-but-defenses-not-implemented"
        payload["reason"] = (
            "protocol-own docs name defense-in-depth alternatives but grep confirms those "
            "defenses return Unimplemented/absent at the audit-pin tree; the omission finding "
            "stands. Cite the FraudProofUnimplemented / absent evidence in the draft."
        )
        payload["warning"] = (
            "Triager may cite these docs. Pre-empt by citing file:line where the named defense "
            "is Unimplemented or absent at the audit-pin. Explicitly state the defense is NOT "
            "operational at the audit-pin tree."
        )
        return 0, payload

    # Design intent + defense-in-depth both found AND at least one defense is implemented
    payload["verdict"] = "fail-designed-as-intended-with-defense-in-depth"
    payload["reason"] = (
        "protocol-own docs explicitly record this as a design choice AND name defense-in-depth "
        "alternatives that are verified implemented at audit-pin tree; the draft must either "
        "(a) rebut with 'r45-rebuttal: <reason>', "
        "(b) add a 'Design Intent Response' section showing why the attacker bypasses those "
        "defenses, or (c) reframe to a separate attack surface"
    )
    if persist_kde:
        payload["known_dead_end_persistence"] = append_known_dead_end_for_r45(
            payload,
            text,
            draft,
            known_dead_ends_path=known_dead_ends_path,
        )
    # fail-designed-as-intended always exits 1 with strict; also exits 1 by default for this verdict
    return 1, payload


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="R45 Designed-As-Intended precheck (Check #93).",
    )
    parser.add_argument("draft", type=Path, help="Path to draft .md file")
    parser.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="Path to workspace root (SEVERITY.md, SCOPE.md, docs/). "
             "Inferred from draft path if omitted.",
    )
    parser.add_argument(
        "--severity",
        choices=[
            "auto", "Critical", "High", "Medium", "Low",
            "critical", "high", "medium", "low",
        ],
        default="auto",
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--no-persist-kde",
        action="store_true",
        help="Do not append fail-designed-as-intended verdicts to reports/known_dead_ends.jsonl.",
    )
    parser.add_argument(
        "--known-dead-ends",
        type=Path,
        default=None,
        help="Override known_dead_ends.jsonl path for R45 persistence.",
    )
    args = parser.parse_args(argv)

    override = None if args.severity == "auto" else args.severity
    rc, payload = run(
        args.draft,
        severity_override=override,
        workspace=args.workspace,
        strict=args.strict,
        persist_kde=not args.no_persist_kde,
        known_dead_ends_path=args.known_dead_ends,
    )

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        verdict = payload.get("verdict", "error")
        reason = payload.get("reason", payload.get("error", ""))
        prefix = "[PASS]" if verdict.startswith("pass") or verdict == "ok-rebuttal" else "[FAIL]"
        print(f"{prefix} {GATE}: {verdict}")
        if reason:
            print(f"  reason: {reason}")
        if "warning" in payload:
            print(f"  warning: {payload['warning']}")
        hits = payload.get("evidence", {}).get("design_intent_doc_hits", [])
        if hits:
            print(f"  design-intent hits (protocol-own docs, proximity-filtered): {len(hits)}")
        did_hits = payload.get("evidence", {}).get("defense_in_depth_doc_hits", [])
        if did_hits:
            print(f"  defense-in-depth hits: {len(did_hits)}")
        dv = payload.get("evidence", {}).get("defense_verification", {})
        if dv:
            print(f"  defense verification: {dv}")

    return rc


if __name__ == "__main__":
    sys.exit(main())
