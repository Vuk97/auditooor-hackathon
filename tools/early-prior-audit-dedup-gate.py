#!/usr/bin/env python3
# r36-rebuttal: funnel-enforcement-gates-AB
"""Early prior-audit / acknowledged-finding dedup gate (Gate B).

PURPOSE
-------
Kill or flag acknowledged / prior-audited candidates BEFORE draft or PoC work
is started.  This fills the gap between the LLM-hunt emit stage and the late
pre-submit R47/R53 checks: by the time pre-submit fires the draft already
exists.

WHAT IT SCANS (generic, workspace-driven)
-----------------------------------------
For a given candidate (keywords + optional text), the gate scans:

  1. <workspace>/prior_audits/*.txt   - full-text extracted audit reports
  2. <workspace>/prior_audits/DIGEST_*.md / digest_*.md
  3. <workspace>/PRIOR_CONCERNS.md   - curated list of known-acknowledged issues
  4. <workspace>/SCOPE.md            - acknowledged-by-design clauses

A match is classified as:
  strong  - acknowledged/by-design phrasing near the hit, OR hit-density >=
             STRONG_DENSITY_THRESHOLD keywords across >=2 files, OR the
             acknowledged-clause block in SCOPE.md hits a keyword
  weak    - single-file low-density match without acknowledged language

VERDICTS
--------
  pass                   - no match or only weak match without acknowledged lang
  NEEDS-EXTENSION-DISTINCT - weak hit near acknowledged language (R47/R53 risk:
                             needs an extension-distinct argument before PoC)
  KILLED                 - strong prior-audit or acknowledged-by-design hit;
                           candidate blocked before draft/PoC starts
  warn                   - prior_audits/ missing entirely (can't run scan)
  error                  - workspace missing / bad input

EXIT CODES
----------
  0 - pass / warn (not blocked)
  1 - KILLED or NEEDS-EXTENSION-DISTINCT (blocked before PoC)
  2 - error / bad input

WIRING
------
Called from candidate-judgment-packet.py's _packet_state() as an additive
check; if the verdict is KILLED or NEEDS-EXTENSION-DISTINCT the packet state
is set to blocked_prior_disclosure.

Standalone:
    tools/early-prior-audit-dedup-gate.py <workspace> \\
        --keyword onBuy --keyword withdraw --keyword reentrancy \\
        [--title "F04 reentrant withdraw via onBuy"] \\
        [--attack-class reentrancy] \\
        [--json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Schema + version
# ---------------------------------------------------------------------------

SCHEMA = "auditooor.early_prior_audit_dedup_gate.v1"
GATE = "GATE-B-EARLY-PRIOR-AUDIT-DEDUP"

# ---------------------------------------------------------------------------
# Tunable thresholds
# ---------------------------------------------------------------------------

# A file needs at least this many distinct keyword hits to count as a strong
# match (without any acknowledged language boosting it to strong on its own).
STRONG_DENSITY_THRESHOLD = 5

# A match within this many characters of acknowledged language is boosted.

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Acknowledged / by-design / wont-fix language that strongly signals the
# finding is already known and accepted.
ACKNOWLEDGED_RE = re.compile(
    r"\backnowledged\b"
    r"|\baccepted[- ]risk\b"
    r"|\bwont[- ]fix\b"
    r"|\bwon['']t\s+fix\b"
    r"|\bby[- ]design\b"
    r"|\bintentional(?:ly)?\b"
    r"|\brisk[- ]accepted\b"
    r"|\bno[- ](?:fix|patch|mitigation)\s+(?:planned|required|needed)\b"
    r"|\barchitectural(?:ly)?\s+(?:by[- ]design|intentional)\b"
    r"|\bfixed\s+in\b"  # "fixed in PR #872" counts as prior-addressed
    r"|\bpull\s*/?\s*#\d+\b",  # PR reference near a match
    re.IGNORECASE,
)

# SCOPE.md section that explicitly calls out acknowledged-by-design tradeoffs
SCOPE_ACKNOWLEDGED_SECTION_RE = re.compile(
    r"(?:documented\s+design\s+tradeoffs?|acknowledged[- ]by[- ]design"
    r"|known\s+limitations?|out[- ]of[- ]scope)",
    re.IGNORECASE,
)

# Stopwords we never treat as useful keywords
_STOPWORDS = frozenset({
    "the", "and", "for", "with", "from", "into", "this", "that", "would",
    "could", "should", "than", "then", "there", "where", "which", "while",
    "when", "what", "have", "has", "are", "was", "were", "been", "being",
    "but", "not", "all", "any", "may", "can", "if", "is", "it", "of",
    "in", "on", "at", "by", "to", "as", "or", "an", "a", "be", "do", "we",
    "us", "our", "you", "your", "they", "them", "their", "his", "her",
    "audit", "report", "finding", "severity", "high", "medium", "low",
    "critical", "informational", "issue", "bug", "vulnerability", "title",
    "description", "impact", "summary", "section", "page",
    "function", "contract", "address", "uint", "bool", "bytes", "memory",
    "storage", "calldata", "external", "internal", "public", "private",
    "view", "pure", "payable", "returns", "require", "revert",
    # File/path tokens - too common in full-text audit reports
    "sol", "target", "src", "lib", "path", "file", "interface",
    "get", "set", "new", "use", "run", "via", "per",
    # Generic contract library names
    "constantslib", "eventslib", "idlib", "errorslib", "mathlib",
    "safelib", "utilslib", "helperslib",
    # unhunted surface tokens
    "unhunted", "surface",
    # Generic Go / Cosmos-SDK + bare-English noise tokens - they appear in
    # virtually every Go/Cosmos audit report and (because scan uses SUBSTRING
    # matching) short ones like "func" match inside "function" everywhere,
    # anchoring spurious dupe verdicts on UNRELATED prior findings (nuva
    # begin-blocker DoS was falsely KILLED by "func"/"will"/"self" hits on
    # unrelated redemption-sweep + token-management findings, 2026-07-04).
    # NOTE: deliberately does NOT include semantically-specific tokens like
    # walkdue / beginblocker / payouttimeoutqueue that legitimately distinguish
    # a finding - only ubiquitous scaffolding/English words are dropped here.
    "func", "ctx", "err", "keeper", "module", "sdk", "cosmos",
    "context", "handler", "params", "store",
    "will", "self", "call", "calls", "user", "users", "data",
    # Solidity modifiers are not security findings.  In particular, extracting
    # `only` from `onlyManager` must never anchor a prior-audit or scope match.
    "only",
})

# <!-- r36-rebuttal: lane-gateB-extract registered; generic-anchor denylist -->
# DeFi-ubiquitous identifiers.  These are real code identifiers (so they pass
# _STOPWORDS) but they appear in virtually every token/lending contract and in
# every full-text audit report, so they must NOT be allowed to ANCHOR a
# prior-audit dupe match on their own - "transfer" co-locating with any
# acknowledged clause is not evidence the candidate is a known finding.  Used
# only to filter AUTO-EXTRACTED anchors in candidate_judgment_blocker(); they
# can still ride along as secondary keywords once a specific anchor exists.
_DEFI_GENERIC = frozenset({
    "transfer", "transferfrom", "safetransfer", "safetransferfrom",
    "approve", "allowance", "balanceof", "totalsupply", "increaseallowance",
    "decreaseallowance", "mint", "burn", "deposit", "withdraw", "redeem",
    "name", "symbol", "decimals", "owner", "transferownership",
    "renounceownership", "permit", "nonces", "domainseparator",
    "supportsinterface", "balance", "supply", "amount", "value", "token",
    "account", "sender", "recipient", "spender", "from", "msgsender",
    # Protocol-ubiquitous nouns: they appear in EVERY finding on a vault /
    # interest / staking protocol and so cannot distinguish one finding from
    # another - like "transfer" they must never be the SOLE anchor of a dupe
    # match (nuva begin-blocker DoS was falsely KILLED when "vaults"/"interest"/
    # "signer" co-located with an unrelated SCOPE.md ack clause, 2026-07-04).
    "vault", "vaults", "interest", "signer", "signers", "staking", "shares",
    "redeem", "redemption", "redemptions", "reconcile", "payout", "payouts",
    # Ubiquitous verbs/roles that co-locate with any acknowledged clause and so
    # cannot on their own tie a candidate to a SPECIFIC prior finding.
    "admin", "enable", "enabled", "disable", "disabled", "pause", "unpause",
    "paused", "allowlist", "destination",
})


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def _prior_audit_files(workspace: Path) -> list[Path]:
    """Return all scannable prior-audit corpus files in the workspace."""
    base = workspace / "prior_audits"
    if not base.is_dir():
        return []
    files: list[Path] = []
    files.extend(sorted(base.glob("*.txt")))
    files.extend(sorted(base.glob("DIGEST_*.md")))
    files.extend(sorted(base.glob("digest_*.md")))
    # INGESTED_FINDINGS.md / README.md are the CURATED prior-art dedup-class lists
    # (the "class #N ... COVERED" summary + per-finding tables). They were previously
    # unscanned, so a candidate landing in an already-COVERED class sailed past this
    # early gate and was only caught at pre-submit R47/R53 - after a full hunt + PoC
    # were already spent (Strata DiscreteAccounting calculateNAVSplitProjected, 2026-07-07,
    # sat inside covered class #4 "senior/junior nav reconciliation"). Scan them too.
    for name in ("INGESTED_FINDINGS.md", "README.md"):
        p = base / name
        if p.is_file():
            files.append(p)
    return files


def _load_program_eligibility(workspace: Path) -> dict[str, Any]:
    """Read .auditooor/program_rules.json eligibility block.

    Returns {"disclosed_unpatched_eligible": bool|None, "present": bool}.
    `disclosed_unpatched_eligible` is PER-PROGRAM: Strata=false (ANY disclosed
    vuln, fixed OR live, is ineligible) - so a known-issue class match is a hard
    KILL regardless of fix status.  Many programs=true (only a FIXED disclosed
    issue bars a candidate -> a disclosed-but-LIVE bug is a fileable lead).
    """
    p = workspace / ".auditooor" / "program_rules.json"
    out: dict[str, Any] = {"disclosed_unpatched_eligible": None, "present": False}
    try:
        rules = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return out
    out["present"] = True
    # eligibility OR legacy ineligible_if_disclosed block; merge (eligibility wins)
    elig = {**(rules.get("ineligible_if_disclosed") or {}),
            **(rules.get("eligibility") or {})}
    if "disclosed_unpatched_eligible" in elig:
        out["disclosed_unpatched_eligible"] = bool(elig["disclosed_unpatched_eligible"])
    elif elig.get("enforced"):
        # legacy `ineligible_if_disclosed.enforced` == disclosed-unpatched INELIGIBLE
        out["disclosed_unpatched_eligible"] = False
    return out


def _load_known_issues(workspace: Path) -> list[dict[str, Any]]:
    """Read prior_audits/known_issues.jsonl (one row per disclosed prior finding)."""
    p = workspace / "prior_audits" / "known_issues.jsonl"
    rows: list[dict[str, Any]] = []
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
    except OSError:
        pass
    return rows


def _ki_anchor_tokens(row: dict[str, Any]) -> set[str]:
    """Specific (non-generic) match tokens for a known-issue row.

    Drawn from the MOST SPECIFIC fields only - dedup_class + file basename -
    so a match is anchored on a curated bug-class identifier, never on a
    ubiquitous protocol noun.  Generic tokens (_DEFI_GENERIC) and stopwords are
    filtered so, e.g., "cooldown-slot-exhaustion-griefing" contributes
    {cooldown, slot, exhaustion, griefing} but "withdraw-dos" does not
    contribute "withdraw".
    """
    raw: list[str] = []
    dc = str(row.get("dedup_class") or "")
    raw.extend(re.split(r"[^A-Za-z0-9]+", dc))
    f = str(row.get("file") or "")
    base = f.split(":", 1)[0].rsplit("/", 1)[-1]
    base = re.sub(r"\.[A-Za-z0-9]+$", "", base)  # strip extension
    raw.extend(re.split(r"[^A-Za-z0-9]+", base))
    out: set[str] = set()
    for t in raw:
        low = t.strip().lower()
        if len(low) >= 4 and low not in _STOPWORDS and low not in _DEFI_GENERIC:
            out.add(low)
    return out


def _match_known_issues(
    workspace: Path, effective_keywords: list[str]
) -> tuple[str | None, list[dict[str, Any]]]:
    """Structured dedup against prior_audits/known_issues.jsonl, honoring the
    program's per-program disclosed-unpatched eligibility.

    Returns (structured_verdict|None, matches).  structured_verdict is one of:
      "KILLED"                      - disclosed class match that is INELIGIBLE
                                      (program bars all disclosed vulns, OR the
                                      matched issue is fix_verified_at_pin=true)
      "NEEDS-FIX-STATUS-VERIFY"     - matched a row whose fix status is UNKNOWN
                                      and the program only bars FIXED issues
                                      (must verify live-vs-fixed before dedup)
      "LIVE-DISCLOSED-ELIGIBLE"     - matched a disclosed-but-LIVE row on a
                                      program where disclosed-unpatched IS
                                      eligible -> fileable (reverted-fix lead)
      None                          - no structured match
    """
    rows = _load_known_issues(workspace)
    if not rows:
        return None, []
    kwset = set(effective_keywords)
    elig = _load_program_eligibility(workspace)
    disclosed_unpatched_eligible = elig.get("disclosed_unpatched_eligible")
    matches: list[dict[str, Any]] = []
    for row in rows:
        anchors = _ki_anchor_tokens(row)
        shared = anchors & kwset
        if not shared:
            continue
        fix = str(row.get("fix_verified_at_pin")).lower()
        fixed = fix == "true"
        live = fix == "false"
        unknown = fix in ("unknown", "none", "")
        if disclosed_unpatched_eligible is False:
            disp = "KILLED"  # every disclosed vuln ineligible regardless of fix
        elif fixed:
            disp = "KILLED"  # fixed disclosed issue = dupe
        elif live:
            disp = "LIVE-DISCLOSED-ELIGIBLE"  # disclosed-but-live = fileable lead
        else:  # unknown fix status + program bars only fixed issues
            disp = "NEEDS-FIX-STATUS-VERIFY"
        matches.append({
            "id": row.get("id"),
            "dedup_class": row.get("dedup_class"),
            "fix_verified_at_pin": row.get("fix_verified_at_pin"),
            "disposition": disp,
            "shared_anchors": sorted(shared),
            "disclosed_in": row.get("disclosed_in"),
        })
    if not matches:
        return None, []
    # Escalate to the most severe disposition present (KILLED wins).
    order = ["KILLED", "NEEDS-FIX-STATUS-VERIFY", "LIVE-DISCLOSED-ELIGIBLE"]
    for v in order:
        if any(m["disposition"] == v for m in matches):
            return v, matches
    return None, matches


def _ancillary_files(workspace: Path) -> list[Path]:
    """Return PRIOR_CONCERNS.md and SCOPE.md if they exist."""
    out: list[Path] = []
    for name in ("PRIOR_CONCERNS.md", "SCOPE.md"):
        p = workspace / name
        if p.is_file():
            out.append(p)
    return out


# ---------------------------------------------------------------------------
# Keyword helpers
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")


def _is_useful(kw: str) -> bool:
    low = kw.lower()
    if low in _STOPWORDS:
        return False
    if low.isdigit():
        return False
    return True


def normalize_keywords(raw_keywords: list[str]) -> list[str]:
    """Lowercase + deduplicate + filter stopwords."""
    seen: set[str] = set()
    out: list[str] = []
    for kw in raw_keywords:
        norm = kw.strip().lower()
        if norm and norm not in seen and _is_useful(norm):
            seen.add(norm)
            out.append(norm)
    return out


def keywords_from_text(text: str, max_kw: int = 20) -> list[str]:
    """Extract keywords from free-form text (title / attack_class / brief)."""
    tokens = _TOKEN_RE.findall(text)
    return normalize_keywords(tokens)[:max_kw]


# ---------------------------------------------------------------------------
# Per-file scan
# ---------------------------------------------------------------------------

# Sliding-window co-location check: all candidate keywords that hit AND the
# acknowledged phrase must appear within COLOCATE_WINDOW_LINES of each other.
# We require >= COLOCATE_MIN_KW distinct keywords within the window.
COLOCATE_WINDOW_LINES = 25   # half-window around each ack hit
COLOCATE_MIN_KW = 2           # minimum distinct candidate keywords in window


def _is_html_or_minified_js_contaminated(file_text: str) -> bool:
    """True when a prior-audit dump is a scraped web page / bundled JS blob
    rather than clean audit text. Such files carry JS/HTML boilerplate that
    matches short common code keywords and yields spurious dupe verdicts.

    Signals (any one): a leading HTML/JS marker in the first non-blank content;
    OR a very long minified line (bundled JS has no line breaks); OR a high
    density of web-boilerplate tokens near the top.
    """
    if not file_text:
        return False
    head = file_text.lstrip()[:2000]
    low_head = head.lower()
    leading_markers = (
        "!function", "<!doctype", "<html", "<head", "<script", "(function(",
        "window.addeventlistener", "self.__next", "globalthis",
    )
    if any(low_head.startswith(m) or m in low_head[:400] for m in leading_markers):
        return True
    # Bundled/minified JS has extremely long lines with no breaks.
    for line in file_text.splitlines()[:50]:
        if len(line) > 2000 and ("function" in line or "var " in line or "=>" in line):
            return True
    # Web-boilerplate density near the top.
    boiler = ("addeventlistener", "queryselector", "createelement", "getelementbyid",
              "__next", "webpack", "resizeobserver", "stopimmediatepropagation")
    if sum(1 for tok in boiler if tok in low_head) >= 2:
        return True
    return False


def _scan_file(
    path: Path,
    keywords: list[str],
    *,
    is_scope_file: bool = False,
    exact_anchors: set[str] | None = None,
) -> dict[str, Any]:
    """Scan a single file for keyword hits using sliding-window co-location.

    The "near_acknowledged" flag is only set when >= COLOCATE_MIN_KW distinct
    candidate keywords AND an acknowledged phrase appear within a window of
    COLOCATE_WINDOW_LINES lines.  This prevents false positives in large
    full-text audit reports where domain terms appear in table-of-contents
    sections that are not co-located with acknowledged-finding discussion.

    Returns:
        {
          "file": str,
          "hit_lines": list of line-level hits (all across the file),
          "distinct_keywords_hit": int (file-level),
          "near_acknowledged": bool,
          "is_scope_ack_section": bool (SCOPE.md only),
        }
    """
    try:
        file_text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {
            "file": str(path),
            "hit_lines": [],
            "distinct_keywords_hit": 0,
            "near_acknowledged": False,
            "is_scope_ack_section": False,
            "error": "unreadable",
        }

    # HTML / minified-JavaScript contamination guard: some prior_audits/*.txt
    # dumps are scraped web pages (a bundled JS blob), not clean audit text.
    # Their JS/HTML boilerplate (`self`, `func`, `window`, `function`) matches
    # short/common code keywords and produced a spurious KILLED verdict
    # (nuva begin-blocker DoS vs halborn_..._a53e2b.txt, 2026-07-04). Such a
    # file is NOT a real acknowledged-finding source, so scan nothing from it.
    if _is_html_or_minified_js_contaminated(file_text):
        return {
            "file": str(path),
            "hit_lines": [],
            "distinct_keywords_hit": 0,
            "near_acknowledged": False,
            "is_scope_ack_section": False,
            "skipped": "html_or_minified_js_contaminated",
        }

    lines = file_text.splitlines()
    n = len(lines)

    # Pre-compute keyword hit positions (line indices, 0-based).
    # WORD-BOUNDARY matching (not substring): a substring match let a generic
    # token anchor a dupe on an unrelated word - "func" matched inside
    # "function", "vault" inside "vaults", "self" inside "myself" - which
    # falsely KILLED the nuva begin-blocker DoS against unrelated prior findings
    # (2026-07-04). Matching on identifier boundaries keeps real code-identifier
    # hits (e.g. "walkdue", "beginblocker") while dropping the substring noise.
    kw_res = [(kw, re.compile(r"(?<![A-Za-z0-9_])" + re.escape(kw) + r"(?![A-Za-z0-9_])")) for kw in keywords]
    kw_hit_map: dict[int, str] = {}  # lineidx -> first matching keyword
    for idx, line in enumerate(lines):
        low = line.lower()
        for kw, rx in kw_res:
            if rx.search(low):
                kw_hit_map[idx] = kw
                break

    # Pre-compute ack positions
    ack_positions: list[int] = []  # 0-based line indices where ack language appears
    for idx, line in enumerate(lines):
        if ACKNOWLEDGED_RE.search(line):
            ack_positions.append(idx)

    # For SCOPE.md: identify lines inside acknowledged-by-design sections.
    scope_ack_line_set: set[int] = set()
    if is_scope_file:
        in_ack_section = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            # A markdown header line - if it is itself an ack-section header,
            # open the span; ANY OTHER header closes the current span. The
            # header check must run FIRST: the previous ordering plus a
            # literal-backslash bug (r"^#{1,4}\\s" matched a backslash, never a
            # real "## Heading" space) left in_ack_section stuck ON for the whole
            # file once any "out-of-scope" line appeared, so unrelated in-scope
            # asset-list lines were mis-tagged as acknowledged-by-design
            # (nuva begin-blocker DoS false KILL on the nvYLDS asset list, 2026-07-04).
            is_header = bool(re.match(r"^#{1,4}\s", stripped))
            if SCOPE_ACKNOWLEDGED_SECTION_RE.search(stripped):
                in_ack_section = True
            elif is_header:
                in_ack_section = False
            if in_ack_section:
                scope_ack_line_set.add(i)

    # Build hit_lines list (file-wide, for evidence reporting)
    all_hit_lines: list[dict[str, Any]] = []
    all_seen_kw: set[str] = set()
    for idx, kw in kw_hit_map.items():
        all_seen_kw.add(kw)
        all_hit_lines.append({
            "lineno": idx + 1,
            "keyword": kw,
            "snippet": lines[idx].strip()[:200],
        })

    # Sliding window: for each ack position, check how many distinct candidate
    # keywords appear within +-COLOCATE_WINDOW_LINES
    near_ack = False
    for ack_idx in ack_positions:
        lo = max(0, ack_idx - COLOCATE_WINDOW_LINES)
        hi = min(n, ack_idx + COLOCATE_WINDOW_LINES + 1)
        window_kw: set[str] = set()
        for i in range(lo, hi):
            if i in kw_hit_map:
                window_kw.add(kw_hit_map[i])
        if len(window_kw) >= COLOCATE_MIN_KW:
            near_ack = True
            break

    # Check scope-ack section hits (SCOPE.md only)
    is_scope_ack = False
    if is_scope_file and scope_ack_line_set:
        for idx in kw_hit_map:
            if idx in scope_ack_line_set:
                is_scope_ack = True
                break

    # A high-density hit across a long report is only useful when the report
    # also names an exact current code-path anchor.  Generic attack classes and
    # common contract vocabulary are insufficient to establish a duplicate.
    exact_anchor_hits: list[str] = []
    for anchor in exact_anchors or set():
        norm = str(anchor).strip().lower()
        if not norm or norm in _STOPWORDS or norm in _DEFI_GENERIC:
            continue
        rx = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(norm) + r"(?![A-Za-z0-9_])")
        if any(rx.search(line.lower()) for line in lines):
            exact_anchor_hits.append(norm)

    return {
        "file": str(path),
        "hit_lines": all_hit_lines[:40],  # cap for output size
        "distinct_keywords_hit": len(all_seen_kw),
        "near_acknowledged": near_ack,
        "is_scope_ack_section": is_scope_ack,
        "exact_anchor_hits": sorted(set(exact_anchor_hits)),
    }


# ---------------------------------------------------------------------------
# Verdict logic
# ---------------------------------------------------------------------------

def _classify_results(
    prior_audit_results: list[dict[str, Any]],
    ancillary_results: list[dict[str, Any]],
) -> tuple[str, str, list[dict[str, Any]]]:
    """Determine gate verdict from scan results.

    Returns (verdict, reason, strong_evidence_list).

    verdict:
      "pass"                    - no actionable match
      "NEEDS-EXTENSION-DISTINCT" - weak hit near ack language or single strong anchor
      "KILLED"                  - strong match, acknowledged/fixed in prior audit
    """
    strong_evidence: list[dict[str, Any]] = []
    weak_evidence: list[dict[str, Any]] = []

    all_results = prior_audit_results + ancillary_results

    for res in all_results:
        hits = res.get("hit_lines", [])
        if not hits:
            continue
        n_kw = res["distinct_keywords_hit"]
        near_ack = res["near_acknowledged"]
        is_scope_ack = res["is_scope_ack_section"]

        if is_scope_ack:
            # Hit inside SCOPE.md's acknowledged-by-design section - hard kill.
            # Generic single tokens (transfer/approve/...) are filtered upstream
            # in candidate_judgment_blocker via _DEFI_GENERIC, so a hit here is
            # already anchored by a specific identifier.
            strong_evidence.append({
                "file": res["file"],
                "type": "scope_acknowledged_by_design",
                "distinct_keywords_hit": n_kw,
                "sample_hits": hits[:3],
            })
        elif near_ack and n_kw >= 2:
            # Multiple keywords near acknowledged language = strong
            strong_evidence.append({
                "file": res["file"],
                "type": "prior_audit_acknowledged",
                "distinct_keywords_hit": n_kw,
                "sample_hits": hits[:3],
            })
        elif n_kw >= STRONG_DENSITY_THRESHOLD and res.get("exact_anchor_hits"):
            # High keyword density without explicit ack = strong (likely same class)
            strong_evidence.append({
                "file": res["file"],
                "type": "prior_audit_high_density",
                "distinct_keywords_hit": n_kw,
                "sample_hits": hits[:3],
            })
        elif n_kw >= 2 and near_ack and not is_scope_ack:
            # Two+ distinct candidate keywords near acknowledged language = needs extension-distinct
            strong_evidence.append({
                "file": res["file"],
                "type": "prior_audit_weak_ack",
                "distinct_keywords_hit": n_kw,
                "sample_hits": hits[:3],
            })
        elif n_kw >= 1:
            weak_evidence.append({
                "file": res["file"],
                "type": "weak_match",
                "distinct_keywords_hit": n_kw,
                "sample_hits": hits[:3],
            })

    if not strong_evidence and not weak_evidence:
        return "pass", "no_prior_audit_match", []

    if strong_evidence:
        # Determine whether this is an outright KILL or needs extension-distinct
        ack_types = {e["type"] for e in strong_evidence}
        if "scope_acknowledged_by_design" in ack_types:
            return (
                "KILLED",
                "candidate_matches_scope_acknowledged_by_design_clause",
                strong_evidence,
            )
        # A prior_audits/*.txt match (>=2 distinct keywords near "acknowledged"
        # language).  Generic DeFi tokens are filtered upstream in
        # candidate_judgment_blocker via _DEFI_GENERIC, so the keywords that
        # survive to anchor this match are specific identifiers (e.g. "onbuy",
        # "liquidate") - a specific identifier described in a prior audit's
        # acknowledged context is a genuine dupe -> hard KILL (R47/R53).  The
        # downstream R53 gate (pre-submit Check #99) still lets the operator
        # override with an extension-distinct argument.
        if "prior_audit_acknowledged" in ack_types:
            return (
                "KILLED",
                "candidate_root_cause_appears_acknowledged_in_prior_audit",
                strong_evidence,
            )
        if "prior_audit_high_density" in ack_types:
            return (
                "NEEDS-EXTENSION-DISTINCT",
                "high_keyword_density_match_in_prior_audit_needs_extension_distinct_argument",
                strong_evidence,
            )
        # prior_audit_weak_ack
        return (
            "NEEDS-EXTENSION-DISTINCT",
            "weak_acknowledged_match_needs_extension_distinct_argument",
            strong_evidence,
        )

    # Only weak hits - advisory
    return "pass", "weak_match_only_no_acknowledged_language", weak_evidence


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------

def run_gate(
    workspace: Path,
    keywords: list[str],
    *,
    title: str = "",
    attack_class: str = "",
    exact_anchors: set[str] | None = None,
) -> dict[str, Any]:
    """Run the early prior-audit dedup gate.

    Parameters
    ----------
    workspace    : path to the audit workspace root
    keywords     : candidate keywords (extracted from title, code refs, etc.)
    title        : optional candidate title (keywords extracted from it)
    attack_class : optional attack class string (keywords extracted from it)

    Returns a result dict with schema SCHEMA.
    """
    workspace = workspace.expanduser().resolve()
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "gate": GATE,
        "workspace": str(workspace),
        "keywords_input": keywords,
        "verdict": "error",
        "reason": "",
        "strong_evidence": [],
        "weak_evidence_count": 0,
        "files_scanned": [],
        "files_scanned_count": 0,
        "errors": [],
        "warnings": [],
        "action": "",
    }

    if not workspace.is_dir():
        payload["errors"].append(f"workspace not found: {workspace}")
        payload["action"] = "Cannot run gate - workspace missing."
        return payload

    # Merge keywords from all sources
    all_kw_raw = list(keywords)
    if title:
        all_kw_raw.extend(keywords_from_text(title))
    if attack_class:
        all_kw_raw.extend(keywords_from_text(attack_class))
    effective_keywords = normalize_keywords(all_kw_raw)

    payload["effective_keywords"] = effective_keywords

    if not effective_keywords:
        payload["errors"].append("no effective keywords after normalization")
        payload["action"] = "Provide at least one non-stopword keyword."
        return payload

    prior_audit_files = _prior_audit_files(workspace)
    ancillary_files = _ancillary_files(workspace)

    has_known_issues = (workspace / "prior_audits" / "known_issues.jsonl").is_file()
    if not prior_audit_files and not ancillary_files and not has_known_issues:
        payload["verdict"] = "warn"
        payload["reason"] = "no_prior_audits_corpus"
        payload["warnings"].append(
            "prior_audits/ directory is missing or empty; cannot run prior-audit dedup"
        )
        payload["action"] = (
            "Populate prior_audits/ with audit report TXT extracts to enable early dedup."
        )
        return payload

    all_files_scanned: list[str] = []
    prior_audit_results: list[dict[str, Any]] = []
    ancillary_results: list[dict[str, Any]] = []

    for path in prior_audit_files:
        res = _scan_file(
            path, effective_keywords, is_scope_file=False,
            exact_anchors=exact_anchors,
        )
        prior_audit_results.append(res)
        all_files_scanned.append(str(path))

    for path in ancillary_files:
        is_scope = path.name == "SCOPE.md"
        res = _scan_file(
            path, effective_keywords, is_scope_file=is_scope,
            exact_anchors=exact_anchors,
        )
        ancillary_results.append(res)
        all_files_scanned.append(str(path))

    payload["files_scanned"] = all_files_scanned
    payload["files_scanned_count"] = len(all_files_scanned)

    verdict, reason, evidence = _classify_results(prior_audit_results, ancillary_results)

    # Separate strong from weak in evidence list for clarity
    strong = [e for e in evidence if e.get("type") != "weak_match"]
    weak = [e for e in evidence if e.get("type") == "weak_match"]

    # ---- Structured known_issues.jsonl + per-program eligibility pass --------
    # The free-text scan above matches the audit-report *prose*.  This pass
    # matches the CURATED known_issues.jsonl rows (dedup_class + file) and
    # applies the program's disclosed-unpatched eligibility rule + each row's
    # fix_verified_at_pin ("is it still live") flag.  It can ESCALATE the verdict
    # to KILLED (never downgrades a KILL), and surfaces the two nuanced cases the
    # free-text scan cannot: a disclosed-but-LIVE class that IS eligible on this
    # program (fileable reverted-fix lead), and an UNKNOWN-fix-status class that
    # must be verified live-vs-fixed before deduping.
    struct_verdict, ki_matches = _match_known_issues(workspace, effective_keywords)
    payload["known_issue_matches"] = ki_matches
    payload["program_eligibility"] = _load_program_eligibility(workspace)
    _RANK = {"pass": 0, "warn": 0, "LIVE-DISCLOSED-ELIGIBLE": 1,
             "NEEDS-FIX-STATUS-VERIFY": 2, "NEEDS-EXTENSION-DISTINCT": 3, "KILLED": 4}
    if struct_verdict:
        if struct_verdict == "KILLED" and _RANK.get(verdict, 0) < 4:
            verdict = "KILLED"
            reason = "candidate_matches_disclosed_known_issue_ineligible"
        elif struct_verdict == "NEEDS-FIX-STATUS-VERIFY" and _RANK.get(verdict, 0) < 2:
            verdict = "NEEDS-EXTENSION-DISTINCT"
            reason = "matched_known_issue_with_UNKNOWN_fix_status_verify_live_vs_fixed_first"
        elif struct_verdict == "LIVE-DISCLOSED-ELIGIBLE":
            # Do NOT kill: a disclosed-but-LIVE bug is fileable on this program.
            # Keep the free-text verdict; surface a prominent advisory lead.
            payload.setdefault("warnings", []).append(
                "LIVE DISCLOSED LEAD: candidate overlaps a prior-audit class whose fix is "
                "ABSENT at the current pin (known_issues.fix_verified_at_pin=false) and this "
                "program treats disclosed-but-unpatched bugs as ELIGIBLE - this is a fileable "
                "reverted-fix lead, frame the draft as the incomplete/absent fix (R47/R53)."
            )
        payload["structured_dedup_verdict"] = struct_verdict

    payload["verdict"] = verdict
    payload["reason"] = reason
    payload["strong_evidence"] = strong
    payload["weak_evidence_count"] = len(weak)

    _ACTION_MAP = {
        "pass": "Candidate has no prior-audit overlap detected. Proceed to PoC planning.",
        "warn": "Populate prior_audits/ to enable early dedup before PoC.",
        "NEEDS-EXTENSION-DISTINCT": (
            "BLOCKED BEFORE PoC: candidate overlaps a prior-audit finding. "
            "Write an extension-distinct argument (new bypass / downstream surface not covered) "
            "before spending any draft or PoC effort."
        ),
        "KILLED": (
            "KILLED BEFORE PoC: candidate root cause is acknowledged in a prior audit or "
            "SCOPE.md acknowledged-by-design clause. Either (a) produce a strictly-stronger "
            "extension-distinct argument citing a new code path, or (b) drop the candidate."
        ),
    }
    payload["action"] = _ACTION_MAP.get(verdict, "Review gate output.")

    return payload


# <!-- r36-rebuttal: lane-gateB-extract registered in agent_pathspec.json; Gate B real-row auto-extraction fix -->
# ---------------------------------------------------------------------------
# Precise code-identifier extraction (for real exploit-queue rows)
# ---------------------------------------------------------------------------
#
# Real exploit-queue rows (queue[].* in exploit_queue.json) do NOT carry a
# "function" / "entrypoint" field.  They carry:
#   - source_refs: a list like ["engage_report.json:src/src/Midnight.sol:581"]
#   - title / root_cause_hypothesis: prose
#   - attack_class
# The function-name fields the gate originally keyed on are empty on real
# input, so candidate_judgment_blocker() extracted nothing and passed every
# candidate (dead-on-arrival).  These helpers recover PRECISE code identifiers
# (not generic prose) from the fields real rows actually populate:
#   1. resolve each source_ref file:line -> the enclosing function name
#   2. pull camelCase / PascalCase identifiers out of prose (onBuy,
#      buyerCallback, maxRepaid) - specific code refs, while generic lowercase
#      prose ("drains", "reserves") is excluded.

# file.ext:LINE  (sol/rs/go/vy/cairo/move/py) anywhere inside a source_ref token
_REF_FILELINE_RE = re.compile(
    r"([\w./\-]+\.(?:sol|rs|go|vy|cairo|move|py)):(\d+)"
)
# `function NAME(` (Solidity/Vyper) / `fn NAME` (Rust) / `func NAME` (Go) / `def NAME`
_DEF_RE = re.compile(r"\b(?:function|fn|func|def)\s+([A-Za-z_]\w*)")
# camelCase / PascalCase identifiers embedded in prose (>=1 internal capital)
_CAMEL_RE = re.compile(r"\b[A-Za-z][a-z0-9]+[A-Z][A-Za-z0-9]*\b")


def _resolve_ws_file(workspace: Path, rel: str) -> Path | None:
    """Locate a source file referenced as rel under the workspace."""
    cand = workspace / rel
    if cand.is_file():
        return cand
    base = Path(rel).name
    try:
        for hit in workspace.rglob(base):
            if hit.is_file():
                return hit
    except OSError:
        return None
    return None


def enclosing_function_names(workspace: Path, source_refs: Any) -> list[str]:
    """For each file:line in source_refs, return the enclosing def name (lower)."""
    refs: list[str] = []
    if isinstance(source_refs, str):
        refs = [source_refs]
    elif isinstance(source_refs, list):
        refs = [r for r in source_refs if isinstance(r, str)]
    names: list[str] = []
    for ref in refs:
        for m in _REF_FILELINE_RE.finditer(ref):
            rel, line_s = m.group(1), m.group(2)
            try:
                line = int(line_s)
            except ValueError:
                continue
            path = _resolve_ws_file(workspace, rel)
            if path is None:
                continue
            try:
                lines = path.read_text(errors="ignore").splitlines()
            except OSError:
                continue
            start = min(line, len(lines)) - 1
            for i in range(start, -1, -1):
                dm = _DEF_RE.search(lines[i])
                if dm:
                    names.append(dm.group(1).lower())
                    break
    return names


def camel_identifiers(text: Any) -> list[str]:
    """Return camelCase/PascalCase identifiers (lowercased) from prose."""
    if not isinstance(text, str):
        return []
    return [m.group(0).lower() for m in _CAMEL_RE.finditer(text)]


# ---------------------------------------------------------------------------
# Integration helper for candidate-judgment-packet.py
# ---------------------------------------------------------------------------

def candidate_judgment_blocker(
    row: dict[str, Any],
    workspace: Path,
) -> dict[str, Any] | None:
    """Check a single exploit-queue row for early prior-audit dupe.

    Returns a blocker dict if the gate fires (KILLED or NEEDS-EXTENSION-DISTINCT),
    or None if the candidate passes.  Designed to be called from
    candidate-judgment-packet.py's _packet_state() before other checks.

    This function ONLY uses precise code-path keywords: specific function names
    from the source_refs or function fields, and the attack_class.  It does NOT
    use prose from title or root_cause_hypothesis, which produce too many false
    positives against full-text prior-audit reports.

    Blocker dict shape:
        {
          "blocker_code": "early_prior_audit_dedup:<verdict>",
          "gate_verdict": str,
          "gate_reason": str,
          "strong_evidence": [...],
          "action": str,
        }
    """
    # Only extract keywords from code-path fields, not prose.
    # Prose fields (title, root_cause_hypothesis) contain generic DeFi terms
    # that produce false positives in full-text audit reports.
    code_kw: list[str] = []

    # Specific function/entrypoint names (e.g. "onBuy", "withdraw", "liquidate")
    for key in ("function", "function_name", "function_signature", "entrypoint",
                "permissionless_action", "attacker_action"):
        val = row.get(key)
        if isinstance(val, str) and val.strip():
            # Only use camelCase/PascalCase tokens as they are specific code refs
            import re as _re
            tokens = _re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", val)
            for tok in tokens:
                low = tok.lower()
                if low not in _STOPWORDS and len(low) >= 3:
                    code_kw.append(low)

    # Real exploit-queue rows carry no function field - recover precise code
    # identifiers from the fields they DO populate (source_refs file:line +
    # camelCase tokens in prose).  Without this the gate is dead on real input.
    # <!-- r36-rebuttal: lane-gateB-extract registered; Gate B real-row fix -->
    # r36-rebuttal: lane-gateB-extract registered; generic-anchor filter.
    # Drop DeFi-ubiquitous tokens so a generic word like "transfer" cannot be
    # the sole anchor of a dupe match (caused 110 false hard-kills on morpho).
    for name in enclosing_function_names(workspace, row.get("source_refs")):
        if name not in _STOPWORDS and name not in _DEFI_GENERIC and len(name) >= 3:
            code_kw.append(name)
    for field in ("title", "root_cause_hypothesis", "impact_path", "proof_path"):
        for ident in camel_identifiers(row.get(field)):
            if (ident not in _STOPWORDS and ident not in _DEFI_GENERIC
                    and len(ident) >= 4):
                code_kw.append(ident)

    # Attack class - but only domain-specific classes, not generic DeFi prose
    attack_class = str(row.get("attack_class") or "").strip().lower()
    SPECIFIC_ATTACK_CLASSES = {
        "reentrancy", "reentrant", "reentrancy_attack",
        "integer_overflow", "arithmetic_overflow",
        "access_control", "missing_access_control",
        "price_manipulation", "oracle_manipulation",
        "signature_replay", "replay_attack",
        "double_spending", "double_spend",
        "flash_loan_attack",
        "front_running", "frontrunning",
        "sandwich_attack",
    }
    for cls in SPECIFIC_ATTACK_CLASSES:
        if cls in attack_class or attack_class in cls:
            code_kw.extend(keywords_from_text(attack_class))
            break

    if not code_kw:
        return None  # no code-specific keywords - skip scan

    # Deduplicate and require at least 2 distinct specific keywords
    # r36-rebuttal: lane-gateB-extract registered. Single chokepoint: drop
    # DeFi-ubiquitous tokens from the anchor set no matter which extraction
    # path produced them (function field, source_refs, prose, or attack_class).
    # "transfer" et al. co-locate with any acknowledged clause and must never
    # anchor a dupe match on their own (caused 131 false hard-kills on morpho).
    effective = list(dict.fromkeys(
        kw for kw in code_kw if kw and kw not in _DEFI_GENERIC
    ))
    if len(effective) < 2:
        return None  # single-token rows have too many false positives

    exact_anchors = {
        name for name in enclosing_function_names(workspace, row.get("source_refs"))
        if name not in _STOPWORDS and name not in _DEFI_GENERIC
    }
    exact_anchors.update(
        ident for field in ("function", "function_name", "function_signature", "entrypoint")
        for ident in camel_identifiers(row.get(field))
        if ident not in _STOPWORDS and ident not in _DEFI_GENERIC
    )

    result = run_gate(
        workspace,
        effective,
        title="",        # do NOT pass prose title to run_gate
        attack_class="",  # already included in effective if relevant
        exact_anchors=exact_anchors,
    )

    verdict = result.get("verdict", "pass")
    if verdict in ("KILLED", "NEEDS-EXTENSION-DISTINCT"):
        return {
            "blocker_code": f"early_prior_audit_dedup:{verdict}",
            "gate_verdict": verdict,
            "gate_reason": result.get("reason", ""),
            "strong_evidence": result.get("strong_evidence", []),
            "action": result.get("action", ""),
        }
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", help="workspace root directory path")
    parser.add_argument(
        "--keyword", "-k", action="append", default=[],
        help="keyword to scan for (repeatable)",
    )
    parser.add_argument(
        "--title", default="", help="candidate title (keywords extracted)",
    )
    parser.add_argument(
        "--attack-class", default="", help="attack class string (keywords extracted)",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit JSON output",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    workspace = Path(args.workspace)
    result = run_gate(
        workspace,
        args.keyword or [],
        title=args.title or "",
        attack_class=args.attack_class or "",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    verdict = result.get("verdict", "error")
    if verdict in ("KILLED", "NEEDS-EXTENSION-DISTINCT"):
        return 1
    if verdict == "error":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
