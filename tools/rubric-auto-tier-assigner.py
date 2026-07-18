#!/usr/bin/env python3
# r36-rebuttal: lane-RULE-63 registered in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py (fix uppercase severity arg)
"""Rule 63 Auto-Tier-Assignment from SEVERITY.md semantics (Check #115).

# Rule 63: this tool emits no corpus record.

GENERAL RULE - applies to ANY draft (LOW+) before paste_ready promotion.

R63 catches the kill pattern where the cited rubric row matches (R52 PASS)
and the impact class isn't out-of-scope DoS (R35 PASS), but the SEVERITY
TIER claimed in the draft does NOT match the impact SEMANTICS of the
text. Triagers re-tier; if the draft over-claims, the response is "your
impact is actually Low/Medium/etc.", which costs the submission its
authority and frequently its payout.

The dYdX rubric is the empirical anchor:

  Critical:  fund loss / theft / insolvency / permanent freezing / minting
  High:      network downtime / liveness failure / matching-engine degradation
  Medium:    non-core (staking/governance) UX degradation without fund loss
  Low:       display / event-parsing / Indexer-side misleading; no on-chain impact

R52 (Check #97) already checks "does ANY rubric row match"; R56 (Check #102)
checks "component on core surface". MISSING: "does the impact SEMANTICS
match the TIER claimed".

R63 fills that gap. It:

  (a) Parses the workspace SEVERITY.md into a per-tier keyword set
      (load-bearing nouns + impact phrases extracted from each tier section).
  (b) Extracts the draft's Impact text + the claimed Severity tier.
  (c) Scores the impact text against each tier's keyword set
      (case-insensitive, normalized).
  (d) Identifies the top-scoring tier; refuses if the claimed tier is more
      than `--max-tier-distance` (default 0) tiers ABOVE the top-scoring
      tier (over-claim), or BELOW (under-claim) when --strict.

Distinct from sibling gates:
  R52 (rubric-row-coverage)    : "no row at all" matches the impact
  R56 (rubric-fit-program-level): "component non-core for program"
  R35 (DoS-class reframe)      : "wrong impact class (DoS-OOS)"
  R63 (this rule)              : "the cited tier mismatches the impact text's semantic tier"

Trigger: ANY draft (LOW+) with a discoverable Severity header and an
Impact section / `selected_impact` line, AND a workspace SEVERITY.md.

Verdict vocabulary:
  pass-tier-matches-impact-semantics  - claimed tier matches the top-scoring
                                        tier inferred from impact text
  pass-out-of-scope                   - no valid severity OR no workspace
                                        SEVERITY.md (cannot semantically score)
  pass-low-confidence                 - top-scoring tier confidence is below
                                        the --confidence-threshold (default
                                        0.3); auto-tier assignment punts
  ok-rebuttal                         - r63-rebuttal marker with <=200-char
                                        reason
  fail-tier-overclaim                 - claimed tier is N tiers ABOVE the
                                        top-scoring tier (N > max-tier-distance)
  fail-tier-underclaim                - (--strict only) claimed tier is N
                                        tiers BELOW the top-scoring tier
  fail-no-impact-section              - draft has no Impact section / claim
                                        the gate cannot score
  error                               - cannot read draft or workspace

Exit codes:
  0 - pass-*, ok-rebuttal
  1 - Rule 63 violation
  2 - input error

Override marker: visible line `r63-rebuttal: <reason>` (<=200 chars) OR
HTML-comment form `<!-- r63-rebuttal: <reason> -->`. Empty or oversized
reason is ignored; original verdict stands.

Env extension hooks:
  AUDITOOOR_R63_TIER_KEYWORDS_<TIER>  - newline-separated extra impact-semantic
      keywords appended to tier <TIER> (CRITICAL/HIGH/MEDIUM/LOW).
      Example: AUDITOOOR_R63_TIER_KEYWORDS_HIGH="matching engine\\nblock prod"
  AUDITOOOR_R63_TIER_KEYWORD_PATH    - JSON file path with per-tier overrides
      structure: {"critical": ["..."], "high": ["..."], ...}

CLI:
  rubric-auto-tier-assigner.py <draft.md>
      [--workspace <ws>]
      [--severity {auto,LOW,MEDIUM,HIGH,CRITICAL}]
      [--confidence-threshold FLOAT]   (default 0.3)
      [--max-tier-distance INT]        (default 0; 0 = exact match required)
      [--strict]                        (also fail under-claims)
      [--json]

Schema: auditooor.r63_auto_tier_assignment.v1

Empirical anchors:
  - dydx cantina-238 x/feegrant MEDIUM: tier-correct (non-core UX), R63 PASS.
  - dydx cantina-213 in-process timing High: R63 would have caught
    tier-overclaim (impact text is localized rate-limit/pressure / Medium,
    not High matching-engine SLO breach).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SCHEMA_VERSION = "auditooor.r63_auto_tier_assignment.v1"
GATE = "R63-AUTO-TIER-ASSIGNMENT"

# Canonical tier ordering. We map them to ranks so over/under claim is a
# simple integer delta. CRITICAL > HIGH > MEDIUM > LOW.
TIER_RANK: Dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
TIERS = ["critical", "high", "medium", "low"]

SEVERITY_FILE_NAMES = ("SEVERITY.md", "severity.md", "Severity.md")


# Rebuttal patterns (shared form with sibling gates).
REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*r63-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL
)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?r63[-_ ]rebuttal\s*:\s*(.+?)\s*$"
)


# Tier section heading patterns in SEVERITY.md. We accept several common
# shapes: "### Critical", "## Critical (Blockchain/DLT)", "### Critical -- USD ...",
# also "## Critical" or "* Critical:" embedded in summary tables.
TIER_HEADING_RE = re.compile(
    r"(?im)^\s*(?:#+|[*-])\s*"
    r"(?P<tier>critical|high|medium|low)"
    r"\b[^\n]*$"
)


# Default load-bearing semantic keywords per tier. These are the fallbacks
# used when no per-tier text is found in SEVERITY.md. They reflect the
# canonical impact taxonomy seen across Cantina / Immunefi / Hackenproof
# rubrics. Lowercase, substring match.
DEFAULT_TIER_KEYWORDS: Dict[str, List[str]] = {
    "critical": [
        # Fund-loss family
        "loss of funds", "loss of user funds", "theft of funds", "fund drain",
        "drain", "stolen", "steal", "stolen funds",
        "insolvency", "insolvent", "protocol insolvency",
        "permanent freezing", "permanently freeze", "permanently lock",
        "irrecoverable", "unrecoverable",
        "unauthorized minting", "unauthorized printing", "mint without authorization",
        "double-spend", "double spend",
        "unauthorized asset movement", "unauthorized fund movement",
        "direct loss", "direct theft", "significant loss",
        "bridge / message-proof logic failure", "message-proof logic failure",
        # Governance takeover
        "governance takeover", "theft of governance", "governance control",
    ],
    "high": [
        # Liveness / consensus
        "network downtime", "network-level downtime", "liveness failure",
        "halting block production", "halt block production",
        "chain halt", "crash the chain", "crashing the chain",
        "preventing settlement", "settlement failure",
        "consensus halt", "consensus stall", "consensus failure",
        # Matching engine
        "matching engine degradation", "material degradation of the matching engine",
        "matching engine slo", "matching-engine slo",
        "matching engine failure",
        # RPC API crash family (Immunefi blockchain Tier-2 style)
        "rpc api crash",
        # Severe but not directly stealing funds
        "meaningful loss", "serious incorrect behavior", "severe logic failure",
        "transaction manipulation",
    ],
    "medium": [
        # Non-core, UX degradation, bounded
        "non-core", "ux degradation", "ux degrade",
        "staking", "governance", "delegate accounting",
        "proposal lifecycle", "vote tally", "voting",
        "ibc integration",
        "logic error", "reentrancy", "reordering", "rounding",
        "overflow", "underflow", "arithmetic",
        "bounded impact", "bounded loss",
        "degrade", "degraded",
    ],
    "low": [
        # Display / parsing / off-chain misleading
        "display", "event parsing", "event-parsing",
        "indexer", "misleading users", "misleading", "indexer-side",
        "sdk client-side", "sdk validation",
        "do not affect on-chain", "no on-chain impact",
        "best-practice", "best practice",
        "informational", "engineering note",
    ],
}


# Anti-patterns - keywords that DOWN-WEIGHT a tier even if a positive
# keyword would otherwise score (e.g., "without fund loss" anti-matches
# CRITICAL because the impact text explicitly disclaims funds-loss).
ANTI_KEYWORDS: Dict[str, List[str]] = {
    "critical": [
        "without fund loss", "no fund loss", "no funds lost",
        "no on-chain", "no on-chain impact",
        "do not affect on-chain", "does not affect on-chain",
    ],
    "high": [
        "localized", "localized pressure",
        "rate limit", "rate-limit", "rate limiting", "rate-limiting",
        "in-process", "in-process only", "microbenchmark",
        "checktx-internal", "checktx-only",
    ],
}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _env_keywords_for_tier(tier: str) -> List[str]:
    """Read AUDITOOOR_R63_TIER_KEYWORDS_<TIER> (newline-separated)."""
    env_name = f"AUDITOOOR_R63_TIER_KEYWORDS_{tier.upper()}"
    raw = os.environ.get(env_name, "")
    if not raw.strip():
        return []
    out: List[str] = []
    for line in raw.splitlines():
        s = line.strip()
        if s:
            out.append(s)
    return out


def _env_keyword_path_overrides() -> Dict[str, List[str]]:
    """Load JSON file referenced by AUDITOOOR_R63_TIER_KEYWORD_PATH."""
    p = os.environ.get("AUDITOOOR_R63_TIER_KEYWORD_PATH", "").strip()
    if not p:
        return {}
    try:
        data = json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return {}
    out: Dict[str, List[str]] = {}
    if isinstance(data, dict):
        for k, v in data.items():
            tk = str(k).strip().lower()
            if tk in TIER_RANK and isinstance(v, list):
                out[tk] = [str(x).strip() for x in v if str(x).strip()]
    return out


def _severity(text: str, path: Path, override: Optional[str]) -> Tuple[Optional[str], str]:
    """Detect severity from draft text or override."""
    if override:
        normalized = override.strip().lower()
        if normalized in TIER_RANK:
            return normalized, "cli"
    for pattern, source in (
        (r"(?im)^\s*\**\s*Severity\s*:\**\s*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*severity_implied\s*:\s*(Critical|High|Medium|Low)\b", "program-impact-mapping"),
        (r"(?im)^\s*severity_tier\s*:\s*(Critical|High|Medium|Low)\b", "impact-contract"),
        (r"(?im)^\s*selected_severity\s*:\s*(Critical|High|Medium|Low)\b", "selected-severity"),
    ):
        m = re.search(pattern, text)
        if m:
            return m.group(1).lower(), source
    for sev in TIERS:
        if re.search(rf"(?:^|[-_]){sev}(?:[-_.]|$)", path.name.lower()):
            return sev, "filename"
    return None, "missing"


def _find_severity_md(draft: Path, workspace: Optional[Path]) -> Optional[Path]:
    """Walk up from draft (or workspace root) looking for SEVERITY.md."""
    search_roots: List[Path] = []
    if workspace:
        search_roots.append(workspace.resolve())
    search_roots.append(draft.resolve().parent)
    for root in search_roots:
        for name in SEVERITY_FILE_NAMES:
            candidate = root / name
            if candidate.is_file():
                return candidate
    cur = draft.resolve().parent
    for parent in [cur, *cur.parents]:
        for name in SEVERITY_FILE_NAMES:
            candidate = parent / name
            if candidate.is_file():
                return candidate
    return None


def _rebuttal(text: str) -> Optional[str]:
    m = REBUTTAL_LINE_RE.search(text)
    if not m:
        m = REBUTTAL_HTML_RE.search(text)
    if not m:
        return None
    reason = " ".join(m.group(1).split())
    if not reason or len(reason) > 200:
        return None
    return reason


def parse_severity_md_tiers(severity_md_text: str) -> Dict[str, List[str]]:
    """Parse SEVERITY.md into per-tier keyword/phrase sets.

    Strategy: locate each tier heading, then read the body of that section
    up to the next tier heading or top-level heading. From the body, pull
    bullet-list items, table rows (the listed-impact sentences), and any
    sentence containing a strong "impact" verb. Extract noun-phrases.

    The result is a dict {tier: [keywords...]} that is MERGED on top of the
    DEFAULT_TIER_KEYWORDS at score time, so SEVERITY.md is treated as
    authoritative when present.
    """
    out: Dict[str, List[str]] = {t: [] for t in TIERS}
    if not severity_md_text:
        return out

    # Find all tier headings (any heading whose line starts a tier
    # subsection).
    headings: List[Tuple[int, str, str]] = []  # (offset, tier, heading_line)
    for m in re.finditer(
        r"(?im)^\s*(?:#+|[*-])\s*(critical|high|medium|low)\b[^\n]*$",
        severity_md_text,
    ):
        headings.append((m.start(), m.group(1).lower(), m.group(0)))

    # Filter: only first occurrence per tier as the "section start" (the
    # subsequent occurrences may be table-row mentions etc.).
    first_offset: Dict[str, int] = {}
    for offset, tier, _ in headings:
        if tier not in first_offset:
            first_offset[tier] = offset

    # Sort by offset to walk forward.
    sorted_sections = sorted(
        ((tier, off) for tier, off in first_offset.items()),
        key=lambda x: x[1],
    )
    for idx, (tier, start) in enumerate(sorted_sections):
        # End offset: next section start, or EOF.
        end = (
            sorted_sections[idx + 1][1]
            if idx + 1 < len(sorted_sections)
            else len(severity_md_text)
        )
        body = severity_md_text[start:end]
        keywords = _extract_keywords_from_section(body)
        out[tier].extend(keywords)
    return out


def _extract_keywords_from_section(body: str) -> List[str]:
    """Extract keyword phrases from a single tier section body."""
    out: List[str] = []
    # Strategy 1: bullet list items (- foo bar / * foo bar).
    for m in re.finditer(
        r"(?m)^\s*[-*]\s+(?!\*\*)(.+?)$",
        body,
    ):
        phrase = m.group(1).strip().rstrip(".")
        # Strip leading markdown bold/italic + reward strings like
        # "USD 30,000 flat" which leak in.
        phrase = re.sub(r"\*\*", "", phrase)
        if not phrase:
            continue
        # Drop pure reward / floor / ceiling rows.
        if re.match(r"(?i)^(reward|floor|ceiling|payout)\b", phrase):
            continue
        if re.match(r"(?i)^(usd|\$)\s*\d", phrase):
            continue
        # Drop "(see ...)" footnote-only rows.
        if re.match(r"(?i)^\([^)]+\)\s*$", phrase):
            continue
        # Truncate to a sane length.
        phrase = phrase[:160].lower().strip()
        if phrase and phrase not in out:
            out.append(phrase)

    # Strategy 2: table row listed-impact sentences. Match a 3-column row
    # `| CRIT-1 | Direct loss of funds | $30k |` and pull the middle cell.
    for m in re.finditer(
        r"(?m)^\s*\|\s*[A-Z0-9\-]+\s*\|\s*(.+?)\s*\|.*?\|\s*$",
        body,
    ):
        phrase = m.group(1).strip().lower()
        # Drop separator rows.
        if re.match(r"^[-:|\s]+$", phrase):
            continue
        # Drop header rows that say "listed-impact sentence (verbatim)".
        if "listed-impact sentence" in phrase or "rubric-tag" in phrase:
            continue
        phrase = phrase[:160]
        if phrase and phrase not in out:
            out.append(phrase)

    # Strategy 3: any sentence that contains an impact verb. This is a
    # weaker signal but catches dydx-style paragraphs like
    # "Significant loss or theft of user funds" sitting between bullets.
    impact_verb_re = re.compile(
        r"(?i)\b("
        r"loss|theft|stolen|drain|drained|insolvency|insolvent|"
        r"freezing|frozen|irrecoverable|unrecoverable|"
        r"minting|printing|double[- ]spend|"
        r"downtime|halt|halting|crash|crashing|"
        r"degradation|degrade|"
        r"display|event[- ]pars|indexer|"
        r"manipulation|reentrancy|reordering|"
        r"unauthorized|"
        r"misleading"
        r")\b"
    )
    for m in re.finditer(r"(?m)^[^\n#|*-].*?[.!?]\s*$", body):
        sentence = m.group(0).strip()
        if not sentence:
            continue
        if impact_verb_re.search(sentence):
            s = sentence.lower()[:200]
            if s and s not in out:
                out.append(s)

    return out


def _normalize(text: str) -> str:
    """Lowercase + collapse whitespace + drop common punctuation."""
    s = text.lower()
    s = re.sub(r"[\r\n\t]+", " ", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def _impact_from_draft(text: str) -> str:
    """Extract the draft's Impact section prose (or fall back to
    `selected_impact:` / `impact_claim_verbatim:` lines)."""
    # Primary: Impact section heading.
    m = re.search(
        r"(?im)^#+\s*(?:impact(?:[_ ]claim)?|selected[_ ]impact)\b.*?\n(.*?)"
        r"(?=^#+\s|\Z)",
        text,
        re.DOTALL | re.MULTILINE,
    )
    if m:
        body = m.group(1).strip()
        # Cap to first ~1500 chars; long bodies dilute scoring.
        return body[:1500]
    # Fallbacks: structured key lines.
    fallbacks = []
    for pattern in (
        r"(?im)^\s*selected_impact\s*:\s*(.+?)(?:\n|$)",
        r"(?im)^\s*impact_claim_verbatim\s*:\s*(.+?)(?:\n|$)",
        r"(?im)^\s*listed_impact_sentence\s*:\s*(.+?)(?:\n|$)",
        r"(?im)^\s*impact\s*:\s*(.+?)(?:\n|$)",
    ):
        for m2 in re.finditer(pattern, text):
            fallbacks.append(m2.group(1).strip())
    return " | ".join(fallbacks)[:1500] if fallbacks else ""


def score_impact_against_tier(
    impact_norm: str,
    tier_keywords: List[str],
    anti_keywords: List[str],
) -> Tuple[int, List[str], List[str]]:
    """Return (raw_score, matched_kw, matched_anti)."""
    matched: List[str] = []
    matched_anti: List[str] = []
    for kw in tier_keywords:
        kw_norm = kw.lower().strip()
        if not kw_norm or len(kw_norm) < 3:
            continue
        if kw_norm in impact_norm:
            matched.append(kw_norm)
    for anti in anti_keywords:
        anti_norm = anti.lower().strip()
        if anti_norm and anti_norm in impact_norm:
            matched_anti.append(anti_norm)
    raw = len(matched) - len(matched_anti)
    return raw, matched, matched_anti


def auto_assign_tier(
    impact_text: str,
    severity_md_tiers: Dict[str, List[str]],
) -> Tuple[Optional[str], float, Dict[str, Any]]:
    """Score impact_text against each tier; return (top_tier, confidence, evidence).

    Confidence = top_tier_score / (total_matches + 1), bounded to [0, 1].
    Returns (None, 0.0, evidence) when no tier scored above zero.
    """
    impact_norm = _normalize(impact_text)
    if not impact_norm:
        return None, 0.0, {"reason": "empty impact text"}

    env_overrides = _env_keyword_path_overrides()

    per_tier_evidence: Dict[str, Any] = {}
    scores: Dict[str, int] = {}
    for tier in TIERS:
        # Combine defaults + SEVERITY.md-extracted + env-NEWLINE + env-JSON.
        combined = list(DEFAULT_TIER_KEYWORDS.get(tier, []))
        combined.extend(severity_md_tiers.get(tier, []))
        combined.extend(_env_keywords_for_tier(tier))
        combined.extend(env_overrides.get(tier, []))
        # De-duplicate while preserving order.
        seen = set()
        dedup = []
        for kw in combined:
            kw_low = kw.lower()
            if kw_low not in seen:
                seen.add(kw_low)
                dedup.append(kw)

        anti = list(ANTI_KEYWORDS.get(tier, []))
        score, matched, matched_anti = score_impact_against_tier(
            impact_norm, dedup, anti
        )
        per_tier_evidence[tier] = {
            "score": score,
            "matched_keywords": matched[:10],
            "anti_matched": matched_anti[:10],
            "keyword_count": len(dedup),
        }
        scores[tier] = score

    # Pick the tier with the maximum score. Ties are broken by tier rank
    # ASCENDING (prefer a lower / less inflated tier on tie - if impact
    # text matches both MEDIUM and HIGH equally, we prefer MEDIUM to push
    # the operator toward honest claims).
    max_score = max(scores.values())
    if max_score <= 0:
        return None, 0.0, {"per_tier": per_tier_evidence, "max_score": max_score}

    # All tiers with the max score.
    top_tiers = [t for t, s in scores.items() if s == max_score]
    # Prefer lowest rank tier among the tied tiers (less inflated).
    top_tier = sorted(top_tiers, key=lambda t: TIER_RANK[t])[0]

    total = sum(max(s, 0) for s in scores.values()) or 1
    confidence = max_score / (total + 0.0)
    confidence = max(0.0, min(1.0, confidence))

    return top_tier, confidence, {
        "per_tier": per_tier_evidence,
        "top_tier": top_tier,
        "max_score": max_score,
        "tied_tiers": top_tiers,
    }


def run(
    draft: Path,
    *,
    workspace: Optional[Path] = None,
    severity_override: Optional[str] = None,
    confidence_threshold: float = 0.3,
    max_tier_distance: int = 0,
    strict: bool = False,
) -> Tuple[int, Dict[str, Any]]:
    """Run the R63 gate. Returns (exit_code, payload)."""
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

    payload: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "file": str(draft),
        "severity": severity,
        "severity_source": severity_source,
        "strict": strict,
        "confidence_threshold": confidence_threshold,
        "max_tier_distance": max_tier_distance,
        "evidence": {},
        "remediation_options": [
            "Re-tier the draft to match the impact text's semantic tier.",
            "Add concrete impact language matching the claimed tier's "
            "rubric keywords (e.g. for HIGH cite 'matching engine degradation' "
            "or 'halting block production'; for CRITICAL cite 'loss of funds' "
            "or 'theft of funds').",
            "If the impact genuinely matches the claimed tier despite the "
            "auto-scorer disagreeing, override with a visible "
            "`r63-rebuttal: <reason>` line or `<!-- r63-rebuttal: <reason> -->`.",
        ],
    }

    # Rebuttal check (runs at all severities).
    rebuttal = _rebuttal(text)
    if rebuttal:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload

    # No severity? out-of-scope.
    if severity is None:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "no valid severity detected"
        return 0, payload

    # Find workspace SEVERITY.md.
    severity_md_path = _find_severity_md(draft, workspace)
    severity_md_text = ""
    if severity_md_path and severity_md_path.is_file():
        try:
            severity_md_text = _read_text(severity_md_path)
            payload["severity_md"] = str(severity_md_path)
        except Exception:
            severity_md_text = ""

    if not severity_md_text:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = (
            "no workspace SEVERITY.md found; cannot semantically score the "
            "impact text. Pass --workspace pointing to a workspace with "
            "SEVERITY.md, or wait until SEVERITY.md is populated."
        )
        return 0, payload

    # Extract impact text.
    impact_text = _impact_from_draft(text)
    if not impact_text or len(impact_text.strip()) < 10:
        payload["verdict"] = "fail-no-impact-section"
        payload["reason"] = (
            "draft has no Impact section / claim the gate can score; "
            "add an '## Impact' section with concrete impact language."
        )
        return 1, payload

    payload["evidence"]["impact_text_preview"] = impact_text[:300]

    # Parse SEVERITY.md into per-tier keyword sets.
    severity_md_tiers = parse_severity_md_tiers(severity_md_text)
    payload["evidence"]["severity_md_tier_keyword_counts"] = {
        t: len(severity_md_tiers.get(t, [])) for t in TIERS
    }

    # Auto-score the impact text.
    top_tier, confidence, score_evidence = auto_assign_tier(
        impact_text, severity_md_tiers
    )
    payload["evidence"]["scoring"] = score_evidence
    payload["evidence"]["top_tier_inferred"] = top_tier
    payload["evidence"]["confidence"] = round(confidence, 4)

    if top_tier is None:
        payload["verdict"] = "pass-low-confidence"
        payload["reason"] = (
            "no tier scored above zero on the impact text; auto-tier "
            "assignment is inconclusive. Add concrete impact language "
            "from the rubric keywords, or accept tier as-is."
        )
        return 0, payload

    if confidence < confidence_threshold:
        payload["verdict"] = "pass-low-confidence"
        payload["reason"] = (
            f"top tier '{top_tier}' inferred but confidence "
            f"{round(confidence, 4)} < threshold {confidence_threshold}; "
            "auto-tier-assignment punts. Strengthen impact language or "
            "lower --confidence-threshold."
        )
        return 0, payload

    claimed_rank = TIER_RANK.get(severity)
    inferred_rank = TIER_RANK.get(top_tier)
    assert claimed_rank is not None and inferred_rank is not None
    delta = claimed_rank - inferred_rank  # >0 = overclaim, <0 = underclaim

    payload["evidence"]["claimed_tier"] = severity
    payload["evidence"]["tier_delta"] = delta

    # Overclaim: tier-distance ABOVE threshold.
    if delta > max_tier_distance:
        payload["verdict"] = "fail-tier-overclaim"
        payload["reason"] = (
            f"claimed tier '{severity}' is {delta} tier(s) ABOVE the "
            f"inferred tier '{top_tier}' (confidence "
            f"{round(confidence, 4)}). Re-tier to '{top_tier}', or add "
            f"impact language matching '{severity}' rubric semantics, or "
            f"override with r63-rebuttal."
        )
        return 1, payload

    # Underclaim only matters in --strict mode.
    if strict and delta < -max_tier_distance:
        payload["verdict"] = "fail-tier-underclaim"
        payload["reason"] = (
            f"claimed tier '{severity}' is {-delta} tier(s) BELOW the "
            f"inferred tier '{top_tier}' (confidence "
            f"{round(confidence, 4)}). --strict mode flags under-claims; "
            "consider re-tiering up, or override with r63-rebuttal."
        )
        return 1, payload

    payload["verdict"] = "pass-tier-matches-impact-semantics"
    payload["reason"] = (
        f"claimed tier '{severity}' matches inferred tier '{top_tier}' "
        f"within max_tier_distance={max_tier_distance} (confidence "
        f"{round(confidence, 4)})"
    )
    return 0, payload


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="Path to workspace root containing SEVERITY.md.",
    )
    # r36-rebuttal: lane-RULE-63 registered in .auditooor/agent_pathspec.json
    parser.add_argument(
        "--severity",
        choices=[
            "auto", "Critical", "High", "Medium", "Low",
            "critical", "high", "medium", "low",
            "CRITICAL", "HIGH", "MEDIUM", "LOW",
        ],
        default="auto",
    )
    parser.add_argument(
        "--confidence-threshold",
        type=float,
        default=0.3,
        help="Minimum confidence to trigger a tier-mismatch verdict (default 0.3).",
    )
    parser.add_argument(
        "--max-tier-distance",
        type=int,
        default=0,
        help="Max allowed tier delta (default 0 = exact match required).",
    )
    parser.add_argument("--strict", action="store_true", help="Also fail under-claims.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    override = None if args.severity == "auto" else args.severity
    rc, payload = run(
        args.draft,
        workspace=args.workspace,
        severity_override=override,
        confidence_threshold=args.confidence_threshold,
        max_tier_distance=args.max_tier_distance,
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
