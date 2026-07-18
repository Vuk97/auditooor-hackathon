#!/usr/bin/env python3
"""program-impact-mapping-check.py — Pre-submit Check #31 (PR #526 gap 0).

Fail-closed gate that forces every Critical/High/Medium (or "paste-ready")
draft to explicitly map its proof to a listed program-impact class. Closes the
over-framing class of bug exposed by FN7, where a real Base Rust/DLT bug was
labelled "Critical candidate" without proving any of the listed
Base Azul Immunefi Critical impacts (total network shutdown, hardfork-
required chain split, permanent fund freeze, or direct bridge loss >= 10%).

The gate enforces TRUTH-IN-MAPPING, not severity downgrade:

  * A High or Medium finding with a valid same-tier listed-impact mapping passes.
  * A Critical claim without a matching Critical-tier listed impact fails.
  * `not_proven_impacts:` must be present (even as `[]`) so authors document
    what evidence does NOT cover.

PR #527 follow-up (Wave 7 GG2 — Minimax adversarial review hardening):

  * BC1: rubric grounding now matches against parsed rubric ROWS (one
    bullet per row), not the whole-file haystack. ``selected_impact``
    must equal one exact listed-impact sentence in the matching severity
    tier. Defeats substring / heading-only / paraphrase bypasses.
  * BC2: rubric is parsed into ``{tier: [rows]}``. ``selected_impact``
    must be grounded in the section matching ``severity_implied``. A
    Critical claim with a Medium-tier listed impact now FAILs with
    ``tier mismatch`` (the FN7 over-framing class the gate is named to
    close).
  * BC3: severity-claim detection now scans the whole body
    (case-insensitive), skips fenced code blocks, understands
    ``<!-- severity: X -->`` HTML comments, and recognizes additional
    paste-ready alternates (``ready to paste``, ``FINAL PASTE``,
    ``Status: ready``). Bare body words like ``**Critical**`` are still
    detected, but ONLY when no explicit severity line is present (so
    narrative phrases like "Critical is NOT recommended" don't
    false-fire when an explicit ``severity:`` line says otherwise).
  * NF1: ``proof_artifact`` must be a regular file (not a directory or
    the SEVERITY.md itself).
  * NF2: ``not_proven_impacts: (none) | TBD | see below`` is normalised to
    empty list and a Critical/High/Medium claim with empty
    ``not_proven_impacts`` produces a loud warning (semantic alarm).
  * NF3: accept ``### Program Impact Mapping`` (h3) as a fallback with a
    helpful "found at h3 — please use h2" message, instead of the
    misleading "missing block" error.
  * NF4: trailing punctuation on ``severity_implied`` (``High.``) is
    stripped before validation.
  * NF5: workspace upward-walk anchor preference is OOS_CHECKLIST.md /
    SCOPE.md > severity-md fallback.
  * SZ2: mapping block extraction stops on H1/H2 only (H3 sub-headings
    inside the block are content, not block terminators).
  * SZ3: when no rubric file is found for an explicit ``--draft`` run,
    rubric grounding is SKIPPED with a warning rather than failing
    silently against an empty haystack.

G9 follow-up (impact-methodology wiring audit -- drift gate):

  * ``--check-methodology-drift``: a fail-closed completeness gate over the
    hand-maintained ``IMPACT_METHODOLOGY_TO_CHECK31`` map. Without it, a 33rd
    playbook added to the live corpus
    (``audit/corpus_tags/impact_hunting_methodology.yaml``) would silently go
    unmapped, forking the hunt-time impact taxonomy from the submit-time tier
    vocabulary. The gate parses every ``impact_id`` slug out of that YAML
    (dependency-free line parse, no PyYAML) and FAILs (rc=1) if any is absent
    from the map. rc=2 (advisory) when the corpus is not present in the
    checkout (the gate is repo-portable). Existing mappings are never changed
    by this gate -- it only forces future additions to be mapped.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = (
    "program",
    "asset",
    "selected_impact",
    "severity_implied",
    "proof_artifact",
    "not_proven_impacts",
)

VALID_SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")

# Severity tiers used for tier-binding (BC2). Tier names are the canonical
# severity levels; the rubric parser maps headings to one of these tiers
# (e.g. ``## Critical-tier listed impacts`` -> Critical;
# ``## 2. Base Azul -- operator-brief Critical impacts`` -> Critical).
TIER_NAMES = ("Critical", "High", "Medium", "Low", "Informational")

# ---------------------------------------------------------------------------
# WIRING_SPEC item D -- impact_hunting_methodology <-> Check #31 reconciliation
# ---------------------------------------------------------------------------
#
# This gate does NOT carry a fixed impact_id enum. Its impact-class vocabulary
# is the set of verbatim SEVERITY*.md / RUBRIC_COVERAGE.md rows, grouped by the
# canonical severity TIER (``VALID_SEVERITIES`` / ``TIER_NAMES`` above). The
# per-impact hunting corpus
# (``agent_outputs/impact_methodology_full_2026-06-28/impact_hunting_methodology.yaml``
# and its sibling ``IMPACT_*.yaml`` / ``*.methodology.yaml`` playbooks, schema
# ``auditooor.impact_hunting_methodology.v1``) DOES carry a stable internal
# taxonomy of 32 ``impact_id``s (enumerated in
# ``TAXONOMY.json`` in that same directory).
#
# To keep the two taxonomies RECONCILED rather than FORKED (the methodology's
# ``impact_id`` and the submit-time ``selected_impact`` must be the same axis,
# never two), this table maps every corpus ``impact_id`` to:
#   * the Check #31 impact CLASS it grounds at -- i.e. the canonical severity
#     tier (one of ``VALID_SEVERITIES``) this impact's ceiling lives in; and
#   * ``rubric_row_hint`` -- the verbatim SEVERITY.md row family the hunter
#     should expect Check #31 to demand an EXACT match against at filing
#     (``_row_grounds_impact`` does ``a_norm == b_norm``). The hint is the
#     canonical rubric phrasing; the per-program SEVERITY.md row is still the
#     single source of truth at filing time (e.g. The Graph grades
#     theft-unclaimed-yield Critical while most programs grade it High, so the
#     ceiling here is the cross-program MAX -- always read the target's own row).
#
# This is a DOC-ONLY reconciliation constant. The gate's runtime behaviour is
# unchanged: it still grounds ``selected_impact`` verbatim against the parsed
# rubric rows per tier. The constant exists so consumers (and reviewers) can
# verify the hunt-time impact taxonomy and the submit-time tier vocabulary share
# one axis. Provenance: TAXONOMY.json (``impact_id``, ``aliases[0]`` ->
# rubric_row_hint, ``severity_ceiling`` -> tier).
#
# Each value is ``(check31_tier, rubric_row_hint)``. ``check31_tier`` is always
# a member of ``VALID_SEVERITIES``.
IMPACT_METHODOLOGY_TO_CHECK31: dict[str, tuple[str, str]] = {
    "direct-theft-funds": (
        "Critical",
        "Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
    ),
    "protocol-insolvency": ("Critical", "Protocol insolvency"),
    "permanent-freeze-funds": ("Critical", "Permanent freezing of funds"),
    "temporary-freeze-funds": ("High", "Temporary freezing of funds"),
    "theft-unclaimed-yield": ("High", "Theft of unclaimed yield"),
    "permanent-freeze-yield": ("High", "Permanent freezing of unclaimed yield"),
    "governance-manipulation": ("Critical", "Manipulation of governance voting result"),
    "unauthorized-mint": ("Critical", "Unauthorized minting of NFTs"),
    "share-supply-inflation": ("Critical", "share-price manipulation"),
    "oracle-manipulation": ("Critical", "oracle price manipulation"),
    "liquidation-abuse": (
        "Critical",
        "Incorrect liquidation/interest enabling unfair value transfer",
    ),
    "bridge-cross-chain-drain": ("Critical", "Drain bridge via invalid withdrawal proofs"),
    "cross-chain-replay-double-spend": ("Critical", "cross-chain replay"),
    "signature-replay-forgery": ("Critical", "no-nonce replay"),
    "reentrancy": ("Critical", "callback mid-state mutation"),
    "access-control-bypass": ("Critical", "missing modifier"),
    "arithmetic-precision-corruption": ("Critical", "rounding-direction-attack"),
    "chain-halt-shutdown": ("Critical", "total network shutdown"),
    "chain-split-fork": ("Critical", "permanent split requiring hardfork"),
    "bc-consensus-transient-failure": ("High", "transient consensus failures"),
    "bc-node-resource-exhaustion": ("Medium", "resource-exhaustion-node"),
    "bc-rpc-api-crash": ("High", "RPC crash excl DoS-vector"),
    "griefing-dos-blockstuffing": ("Medium", "griefing"),
    "gas-theft-fee-vault": ("Medium", "Theft of gas"),
    "operability-lack-of-funds": (
        "Medium",
        "Smart contract unable to operate due to lack of token funds",
    ),
    "fails-promised-returns": (
        "Low",
        "Contract fails to deliver promised returns but does not lose value",
    ),
    "bc-direct-loss-of-funds": ("Critical", "Direct loss of funds"),
    "bc-permanent-freeze-hardfork": (
        "Critical",
        "Permanent freezing of funds (fix requires hardfork)",
    ),
    "crypto-key-recovery-leak": ("Critical", "recover private spend keys/shares"),
    "crypto-incorrect-formula-verifier": ("Critical", "verifier-callstack formula error"),
    "dispute-game-resolution": (
        "Critical",
        "incorrectly resolved dispute game allowing invalid withdrawal",
    ),
    "unauthorized-upgrade-impl-swap": ("Critical", "unauthorized upgrade"),
}

# Aliases so the hunt-time impact-methodology vocab (hacker_question_renderer /
# exploit-queue impact_class) resolves to the Check#31 table even when the exact
# id differs. Maps a renderer impact_id -> a key present in the table above.
_IMPACT_ID_ALIASES: dict[str, str] = {
    "yield-theft": "theft-unclaimed-yield",
    "freeze-funds": "permanent-freeze-funds",
    "governance-takeover": "governance-manipulation",
    "griefing-dos": "griefing-dos-blockstuffing",
}


def suggest_check31_for_impact(impact_id: str) -> tuple[str, str] | None:
    """Cross-wire #2: resolve a lead's impact-methodology impact_id to its
    Check#31 (tier, rubric_row_hint). Public lookup so a lead/draft can derive a
    submit-time selected_impact + severity from its hunt-time impact class - the
    table previously had NO runtime consumer beyond the G9 key-set drift gate.
    Returns None for an unknown id (caller stays unchanged / fails closed)."""
    key = (impact_id or "").strip().lower()
    if not key:
        return None
    key = _IMPACT_ID_ALIASES.get(key, key)
    return IMPACT_METHODOLOGY_TO_CHECK31.get(key)


# ---------------------------------------------------------------------------
# G9 -- IMPACT_METHODOLOGY_TO_CHECK31 drift gate (fail-closed completeness)
# ---------------------------------------------------------------------------
#
# ``IMPACT_METHODOLOGY_TO_CHECK31`` above is hand-maintained. The live impact-
# hunting corpus that the hunters actually read is
# ``audit/corpus_tags/impact_hunting_methodology.yaml`` (schema
# ``auditooor.impact_hunting_methodology.v1``), a flat list of
# ``- impact_id: <slug>`` playbook entries. Without a coverage assertion, a
# 33rd playbook added to that YAML would silently go UNMAPPED here -- the
# methodology axis and the Check #31 submit-time tier vocabulary would fork
# with no signal (GAP_REPORT G9).
#
# ``impact_ids_from_methodology_yaml`` parses the playbook ``impact_id`` slugs
# out of the corpus YAML WITHOUT a PyYAML dependency (this fail-closed gate
# must run in minimal checkouts). ``check_methodology_mapping_drift`` returns
# the set of corpus impact_ids that are missing from the map; an empty set
# means the map fully covers the corpus. ``find_methodology_yaml`` locates the
# corpus file relative to a checkout root so the test (and any caller) can run
# the gate from any cwd.

# Matches a top-level playbook entry: ``- impact_id: some-slug`` (with the
# tolerant indentation the corpus uses). The slug is hyphen-cased lowercase.
_METHODOLOGY_IMPACT_ID_RE = re.compile(
    r"^\s*-\s*impact_id:\s*['\"]?([a-z0-9]+(?:-[a-z0-9]+)*)['\"]?\s*$"
)

# Path of the live corpus relative to the repo root.
_METHODOLOGY_YAML_REL = Path("audit") / "corpus_tags" / "impact_hunting_methodology.yaml"


def impact_ids_from_methodology_yaml(yaml_path: Path) -> set[str]:
    """Return the set of ``impact_id`` slugs declared in the corpus YAML.

    Dependency-free line parse (no PyYAML): the corpus is a flat
    ``playbooks:`` list of ``- impact_id: <slug>`` entries. Raises
    ``FileNotFoundError`` if the path does not exist so callers fail loud
    rather than silently passing on a typo'd path.
    """
    text = yaml_path.read_text(encoding="utf-8", errors="replace")
    ids: set[str] = set()
    for ln in text.splitlines():
        m = _METHODOLOGY_IMPACT_ID_RE.match(ln)
        if m:
            ids.add(m.group(1))
    return ids


def find_methodology_yaml(start: Path | None = None) -> Path | None:
    """Locate ``impact_hunting_methodology.yaml`` by walking up from ``start``.

    Returns the first existing
    ``<root>/audit/corpus_tags/impact_hunting_methodology.yaml`` found while
    walking upward from ``start`` (default: this file's directory), or
    ``None`` if the corpus is not present in this checkout (the gate is
    repo-portable; callers skip drift checking when the corpus is absent).
    """
    cur = (start or Path(__file__).resolve().parent).resolve()
    root = Path(cur.anchor or "/")
    while True:
        cand = cur / _METHODOLOGY_YAML_REL
        if cand.is_file():
            return cand
        if cur == root:
            return None
        cur = cur.parent


def check_methodology_mapping_drift(yaml_path: Path) -> set[str]:
    """Return corpus ``impact_id``s MISSING from IMPACT_METHODOLOGY_TO_CHECK31.

    An empty set means the hand-maintained map fully covers the live
    corpus (no drift). A non-empty set is the fail-closed signal: a new
    playbook was added to the corpus but not mapped here, so the
    methodology axis and the Check #31 tier vocabulary have forked.

    NB: this is intentionally one-directional (corpus -> map). A map entry
    with no corpus playbook is tolerated (it can pre-stage a forthcoming
    playbook); a corpus playbook with no map entry is the drift that
    silently kills the reconciliation, so only that direction fails closed.
    """
    corpus_ids = impact_ids_from_methodology_yaml(yaml_path)
    return corpus_ids - set(IMPACT_METHODOLOGY_TO_CHECK31)


# BC1: exact row matching replaced the old substring-length heuristic. Keep
# the constant for compatibility with downstream imports, but do not reject
# short exact rows such as "RPC API crash."
MIN_IMPACT_LEN = 1

# Strings (case-insensitive substrings) that, when present in title or any
# heading line that begins with `severity`, mark a draft as reportable.
_TIER_TOKEN_CRIT = "critical"
_TIER_TOKEN_HIGH = "high"

# Free-form markers that trigger mapping-required regardless of severity.
# (BC3 expansion -- the original code only matched the literal token
# `paste-ready`.)
_PASTE_READY_TOKENS = (
    "paste-ready",
    "paste ready",
    "ready to paste",
    "ready-to-paste",
    "final paste",
    "final-paste",
    "status: ready",
    "status:ready",
    "status: paste",
    "ready to file",
)

# Sentinel forms (case-insensitive) treated as "explicitly empty" for
# `not_proven_impacts` (NF2).
_EMPTY_LIST_SENTINELS = ("none", "(none)", "n/a", "na", "tbd", "see below", "-")

# File extensions allowed for proof_artifact when a regular file is required.
# Empty whitelist means "any extension"; we keep this lenient.
_PROOF_EXT_WHITELIST = {
    ".txt", ".md", ".rs", ".sol", ".py", ".json", ".log", ".yaml", ".yml",
    ".toml", ".sh", ".js", ".ts", ".go", ".cairo", ".circom", ".vy",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class MappingBlock:
    program: str = ""
    asset: str = ""
    selected_impact: str = ""
    selected_impact_candidates: list = field(default_factory=list)  # multi-bullet selected_impact (BC2/DDD2)
    severity_implied: str = ""
    proof_artifact: str = ""
    not_proven_impacts: list = field(default_factory=list)
    not_proven_impacts_present: bool = False  # explicit field presence
    raw_lines: list = field(default_factory=list)


# PR #541 follow-up F8: structured error codes so lib consumers can bucket
# failures without substring matching against English error prose. The
# canonical gate continues to emit human-readable error strings for the
# CLI, but every error string is paired with a stable, language-independent
# code via DraftReport.error_codes (see ``add_error`` below).
ERR_MAPPING_BLOCK_MISSING = "mapping_block_missing"
ERR_FIELD_MISSING = "field_missing"
ERR_SEVERITY_IMPLIED_INVALID = "severity_implied_invalid"
ERR_SEVERITY_IMPLIED_CONTRADICTS_CLAIM = "severity_implied_contradicts_claim"
ERR_TIER_MISMATCH = "tier_mismatch"
ERR_RUBRIC_GROUNDING_MISSING = "rubric_grounding_missing"
ERR_PROOF_ARTIFACT_MISSING = "proof_artifact_missing"
ERR_PROOF_ARTIFACT_INVALID = "proof_artifact_invalid"

ALL_ERR_CODES = (
    ERR_MAPPING_BLOCK_MISSING,
    ERR_FIELD_MISSING,
    ERR_SEVERITY_IMPLIED_INVALID,
    ERR_SEVERITY_IMPLIED_CONTRADICTS_CLAIM,
    ERR_TIER_MISMATCH,
    ERR_RUBRIC_GROUNDING_MISSING,
    ERR_PROOF_ARTIFACT_MISSING,
    ERR_PROOF_ARTIFACT_INVALID,
)


@dataclass
class DraftReport:
    path: Path
    requires_mapping: bool
    severity_claim: str  # "Critical"/"High"/"Medium"/"Low"/"Informational"/""
    paste_ready: bool
    has_mapping_block: bool
    block: MappingBlock | None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # PR #541 follow-up F8: parallel list of stable error codes. Always
    # the same length as ``errors`` -- entries align by index.
    error_codes: list[str] = field(default_factory=list)

    def passed(self) -> bool:
        return not self.errors

    def add_error(self, code: str, message: str) -> None:
        """Append a structured (code, message) pair to errors / error_codes."""
        self.errors.append(message)
        self.error_codes.append(code)


# ---------------------------------------------------------------------------
# Severity / mapping detection in drafts
# ---------------------------------------------------------------------------


# BC3: capture only the FIRST severity word after `severity[:_-]`. Greedy
# `.+?` was overrunning end-of-line and pulling in narrative tokens like
# "Critical is NOT recommended" from "Severity: HIGH with .... Critical is NOT
# recommended ...". Now we capture a single word, but tolerate bold wrap,
# `severity rating` / `severity_rating`, and an optional parenthetical
# qualifier (`Severity (RECOMMENDED): HIGH`).
_SEVERITY_HEADING_RE = re.compile(
    r"^\s*(?:#{1,6}\s*)?\*{0,2}severity(?:[ _]rating)?\*{0,2}"
    r"(?:\s*\([^)]*\))?\*{0,2}\s*[:\-]\s*\*{0,2}\s*\*{0,2}([A-Za-z]+)\b",
    re.IGNORECASE,
)

# BC3: HTML-comment severity like `<!-- severity: Critical -->` (anywhere
# in the body).
_HTML_COMMENT_SEVERITY_RE = re.compile(
    r"<!--\s*severity\s*[:\-]?\s*([A-Za-z]+)\s*-->",
    re.IGNORECASE,
)

# BC3: code fence detector. Whole-body scans skip fenced blocks so that
# code samples don't trip narrative-severity detection.
_CODE_FENCE_RE = re.compile(r"^\s*```")


def _strip_md_decoration(s: str) -> str:
    return s.replace("*", "").replace("`", "").strip()


def _strip_lines_in_code_fences(text: str) -> str:
    """Return ``text`` with content inside ``` fences blanked out (BC3)."""
    out: list[str] = []
    in_fence = False
    for ln in text.splitlines():
        if _CODE_FENCE_RE.match(ln):
            in_fence = not in_fence
            out.append("")  # drop the fence line itself too
            continue
        out.append("" if in_fence else ln)
    return "\n".join(out)


def _detect_severity_claim(text: str) -> tuple[str, bool]:
    """Return (severity_claim_str, paste_ready_bool).

    BC3 hardening:
      * Whole-body scan (case-insensitive) for explicit ``severity:`` lines,
        not just top 200.
      * HTML comments (``<!-- severity: Critical -->``) are recognised.
      * Fenced code blocks are excluded so example payloads in code don't
        trip detection.
      * Bare ``**Critical**`` / "this is a Critical bug" body words trip
        detection ONLY when no explicit severity line is present (so
        narrative phrases like "Critical is NOT recommended" don't
        false-fire when the explicit severity line says High).
    """
    severity = ""
    paste_ready = False

    # Strip code fences first so `## ✅ Submission N — High — ...` example
    # payloads in a code block don't trip detection.
    scrubbed = _strip_lines_in_code_fences(text)
    lines = scrubbed.splitlines()

    # Title: first heading line (in scrubbed text).
    title = ""
    for ln in lines:
        sl = ln.strip()
        if sl.startswith("#"):
            title = sl.lstrip("#").strip()
            break

    explicit_candidates: list[str] = []
    has_explicit_marker = False  # True if any severity line / HTML comment was seen
    if title:
        explicit_candidates.append(title)

    # Whole-body scan (BC3 — was lines[:200]).
    for ln in lines:
        m = _SEVERITY_HEADING_RE.match(ln)
        if m:
            explicit_candidates.append(m.group(1))
            has_explicit_marker = True

    # HTML-comment severity (BC3) -- scan whole text, including inside ``` fences
    # is fine here because fences are stripped above.
    for m in _HTML_COMMENT_SEVERITY_RE.finditer(scrubbed):
        explicit_candidates.append(m.group(1))
        has_explicit_marker = True

    # paste-ready detection: any of the alternates appearing anywhere in
    # the (scrubbed) body (BC3 — was just the literal "paste-ready" token).
    low = scrubbed.lower()
    for tok in _PASTE_READY_TOKENS:
        if tok in low:
            paste_ready = True
            break

    explicit_blob = " ".join(explicit_candidates).lower()

    def _pick_strongest(blob: str) -> str:
        # Strongest token wins; word-boundary on "high"/"low"/"info" so
        # "high-throughput" doesn't trip High.
        if "critical" in blob:
            return "Critical"
        if re.search(r"\bhigh\b", blob):
            return "High"
        if "medium" in blob:
            return "Medium"
        if re.search(r"\blow\b", blob):
            return "Low"
        if "informational" in blob or blob.strip() == "info":
            return "Informational"
        return ""

    if explicit_candidates:
        severity = _pick_strongest(explicit_blob)

    # BC3 fallback: only when there is NO explicit severity line / comment
    # AND title produced no severity word, look for bold-wrapped reportable
    # tokens (``**Critical**``, ``**High**``, ``**Medium**``). Bare narrative words like
    # "Slither flagged HIGH" or "Critical is NOT recommended" deliberately
    # do NOT trip the fallback -- they generate too many false positives
    # on auditooor working notes. The bold-wrapped form is the explicit
    # "this is the severity" rendering used by paste-ready drafts.
    if not has_explicit_marker and not severity:
        body_blob = scrubbed.lower()
        if re.search(r"\*\*\s*critical\s*\*\*", body_blob):
            severity = "Critical"
        elif re.search(r"\*\*\s*high\s*\*\*", body_blob):
            severity = "High"
        elif re.search(r"\*\*\s*medium\s*\*\*", body_blob):
            severity = "Medium"

    return severity, paste_ready


# NF3: accept H2..H4 for the block heading. _BLOCK_HEADING_RE used for the
# canonical h2 form; _BLOCK_HEADING_RE_LENIENT picks up h3/h4 too.
_BLOCK_HEADING_RE = re.compile(r"^\s*##\s+Program Impact Mapping\s*$", re.IGNORECASE)
_BLOCK_HEADING_RE_LENIENT = re.compile(
    r"^\s*#{2,4}\s+Program Impact Mapping\s*$", re.IGNORECASE
)
# SZ2: stop on H1/H2 only -- H3+ inside the mapping block is content.
_NEXT_HEADING_RE = re.compile(r"^\s*#{1,2}\s+\S")


def _extract_block(text: str) -> tuple[bool, list[str], int]:
    """Return (found, lines_inside_block_excluding_heading, heading_level).

    NF3: if no h2 ``Program Impact Mapping`` heading is found, fall back to
    h3/h4 and return ``heading_level=3`` (or 4) so the caller can emit a
    helpful warning. ``heading_level=2`` means canonical.
    """
    lines = text.splitlines()

    def _scan(level_re: re.Pattern[str]) -> tuple[int, int]:
        for i, ln in enumerate(lines):
            if level_re.match(ln):
                # Determine actual heading level from the line itself.
                hashes = len(ln) - len(ln.lstrip("#")) if ln.lstrip().startswith("#") else 0
                # Re-compute via lstrip-aware:
                stripped = ln.lstrip()
                level = 0
                while level < len(stripped) and stripped[level] == "#":
                    level += 1
                return i, level
        return -1, 0

    start, level = _scan(_BLOCK_HEADING_RE)
    if start < 0:
        # NF3: lenient h3/h4 fallback.
        start, level = _scan(_BLOCK_HEADING_RE_LENIENT)
        if start < 0:
            return False, [], 0
    inner: list[str] = []
    for ln in lines[start + 1 :]:
        if _NEXT_HEADING_RE.match(ln):
            break
        inner.append(ln)
    return True, inner, level


_KV_RE = re.compile(
    r"^\s*(?:[-*+]\s+)?(?:\*\*)?(?P<k>[A-Za-z_][A-Za-z0-9_ ]*?)(?:\*\*)?"
    r"(?:\s*\([^)]*\))?"  # optional trailing parenthetical commentary on the key
    r"\s*:\s*(?P<v>.*?)\s*$"
)

# DDD2: extract a verbatim phrase from a sub-bullet. Recognises
# ``LABEL: **"PHRASE"**`` and ``"PHRASE"`` patterns. If neither matches,
# returns the whole stripped sub-bullet (callers handle MIN_IMPACT_LEN).
_QUOTED_PHRASE_RE = re.compile(r'\*{0,2}["“]([^"”]{4,200})["”]\*{0,2}')


def _extract_candidate_phrases(sub_bullet: str) -> list[str]:
    """Return a list of grounding candidates from a sub-bullet line.

    Always includes the cleaned full sub-bullet text. If the sub-bullet
    contains one or more ``"..."`` quoted phrases (or ``**"..."**``), each
    is also returned as a separate candidate so DDD2-style
    ``LABEL: **"PHRASE"** (commentary)`` lines ground on the quoted
    phrase rather than the whole-bullet narrative.
    """
    out: list[str] = []
    cleaned = _strip_md_decoration(sub_bullet)
    if cleaned:
        out.append(cleaned)
    for m in _QUOTED_PHRASE_RE.finditer(sub_bullet):
        phrase = m.group(1).strip()
        if phrase and phrase not in out:
            out.append(phrase)
    return out


def _normalize_key(k: str) -> str:
    return k.strip().lower().replace(" ", "_")


def _parse_block(inner: list[str]) -> MappingBlock:
    """Parse simple key:value (or `- key:` sub-bullet) lines.

    `not_proven_impacts:` may be inline `[]`, inline `[a, b]`, or the field
    name followed by sub-bullets.

    DDD2 support: `selected_impact:` may also be empty + followed by
    sub-bullets. Each sub-bullet becomes a candidate; tier-binding picks
    the first candidate that grounds in the right rubric tier.
    """
    block = MappingBlock(raw_lines=list(inner))
    pending_list_key: str | None = None
    for raw in inner:
        ln = raw.rstrip()
        if not ln.strip():
            continue
        # Sub-bullet for the active list field (e.g. not_proven_impacts or
        # selected_impact or proof_artifact).
        if pending_list_key and re.match(r"^\s+[-*+]\s+\S", ln):
            item = re.sub(r"^\s+[-*+]\s+", "", ln).strip()
            if pending_list_key == "not_proven_impacts":
                # NF2: strip sentinel markers from each sub-bullet too.
                cleaned = _strip_md_decoration(item)
                if cleaned and cleaned.lower() not in _EMPTY_LIST_SENTINELS:
                    block.not_proven_impacts.append(cleaned)
            elif pending_list_key == "selected_impact":
                # DDD2 multi-bullet: extract candidate phrases (quoted
                # subexpressions get individual candidates).
                for cand in _extract_candidate_phrases(item):
                    if cand not in block.selected_impact_candidates:
                        block.selected_impact_candidates.append(cand)
            elif pending_list_key == "proof_artifact":
                # First sub-bullet wins (most likely the primary artifact).
                if not block.proof_artifact:
                    # Strip everything after first whitespace+em-dash to
                    # isolate the path from any "-- description" suffix.
                    raw = _strip_md_decoration(item)
                    # Snip at " — " or " -- " (em-dash / double-dash narratives)
                    raw = re.split(r"\s+[—-]{1,2}\s+", raw, maxsplit=1)[0].strip()
                    block.proof_artifact = raw
            continue
        m = _KV_RE.match(ln)
        if not m:
            pending_list_key = None
            continue
        key = _normalize_key(m.group("k"))
        val = m.group("v").strip()
        if key not in REQUIRED_FIELDS:
            pending_list_key = None
            continue
        if key == "not_proven_impacts":
            block.not_proven_impacts_present = True
            stripped = val.strip()
            # NF2: sentinels are explicitly empty.
            if stripped.lower() in _EMPTY_LIST_SENTINELS or stripped == "":
                pending_list_key = "not_proven_impacts" if stripped == "" else None
                if stripped == "":
                    continue
                # explicit sentinel like `(none)` -> empty list, field present
                pending_list_key = None
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                guts = stripped[1:-1].strip()
                if guts:
                    parts = [p.strip().strip('"').strip("'") for p in guts.split(",")]
                    block.not_proven_impacts = [p for p in parts if p]
                # explicit `[]` -> empty list, but field is present
                pending_list_key = None
                continue
            # comma-separated inline value
            block.not_proven_impacts = [p.strip() for p in stripped.split(",") if p.strip()]
            pending_list_key = None
            continue
        if key == "selected_impact":
            cleaned = _strip_md_decoration(val)
            if cleaned == "":
                # DDD2-style: empty value, sub-bullets follow.
                pending_list_key = "selected_impact"
            else:
                # Inline value -- also extract any quoted phrase as an
                # additional candidate.
                phrases = _extract_candidate_phrases(val)
                # Default scalar (first phrase) for legacy callers, but keep
                # all candidates for tier-binding.
                block.selected_impact = phrases[0] if phrases else cleaned
                for cand in phrases:
                    if cand not in block.selected_impact_candidates:
                        block.selected_impact_candidates.append(cand)
                if cleaned and cleaned not in block.selected_impact_candidates:
                    block.selected_impact_candidates.append(cleaned)
                pending_list_key = None
            continue
        if key == "proof_artifact":
            cleaned = _strip_md_decoration(val)
            if cleaned == "":
                # Multi-bullet style: first sub-bullet will be picked up.
                pending_list_key = "proof_artifact"
                continue
            # Inline value -- snip narrative suffix.
            cleaned = re.split(r"\s+[—-]{1,2}\s+", cleaned, maxsplit=1)[0].strip()
            block.proof_artifact = cleaned
            pending_list_key = None
            continue
        # Scalar fields
        pending_list_key = None
        cleaned = _strip_md_decoration(val)
        if key == "program":
            block.program = cleaned
        elif key == "asset":
            block.asset = cleaned
        elif key == "severity_implied":
            block.severity_implied = cleaned
        elif key == "proof_artifact":
            block.proof_artifact = cleaned
    # Promote first candidate to selected_impact if scalar empty (DDD2).
    if not block.selected_impact and block.selected_impact_candidates:
        block.selected_impact = block.selected_impact_candidates[0]
    return block


# ---------------------------------------------------------------------------
# Workspace rubric loading + tier parsing (BC1 / BC2)
# ---------------------------------------------------------------------------


def _load_rubric_text(workspace: Path) -> tuple[bool, str]:
    """Return (found_any, concatenated_text). SEVERITY*.md AND RUBRIC_COVERAGE.md."""
    chunks: list[str] = []
    found = False
    if workspace.is_dir():
        # Top-level only — workspace contract puts these at the root.
        for entry in sorted(workspace.iterdir()):
            name = entry.name
            if not entry.is_file():
                continue
            lname = name.lower()
            if lname.startswith("severity") and lname.endswith(".md"):
                try:
                    chunks.append(entry.read_text(encoding="utf-8", errors="replace"))
                    found = True
                except OSError:
                    pass
            elif lname == "rubric_coverage.md":
                try:
                    chunks.append(entry.read_text(encoding="utf-8", errors="replace"))
                    found = True
                except OSError:
                    pass
    return found, "\n\n".join(chunks)


# BC2: identify which severity tier a heading announces. Examples:
#   ## Critical-tier listed impacts                 -> Critical
#   ## 2. Base Azul -- operator-brief Critical impacts -> Critical
#   ## 3. Immunefi v2.3 -- Blockchain / DLT          -> (parent tier; subsections decide)
#   ### Critical                                     -> Critical
#   ### High                                         -> High
_TIER_HEADING_RE = re.compile(
    r"^\s*#{2,4}\s+(?:.*?)\b(critical|high|medium|low|informational)\b",
    re.IGNORECASE,
)
# A line that declares a section but doesn't mention a tier word is "ambient" -- it
# resets the active tier UNLESS it also matches _TIER_HEADING_RE.
_ANY_HEADING_RE = re.compile(r"^\s*#{2,4}\s+\S")
# Bullet-row match: `-`, `*`, or `+` followed by content.
_BULLET_ROW_RE = re.compile(r"^\s*[-*+]\s+(.+?)\s*$")
_GFM_TABLE_ROW_RE = re.compile(r"^\s*\|(.+)\|\s*$")
_GFM_TABLE_SEPARATOR_CELL_RE = re.compile(r"^\s*:?-{3,}:?\s*$")


def _parse_gfm_table_cells(line: str) -> list[str]:
    """Return trimmed cells for a simple GFM table row, or [] for non-rows."""
    m = _GFM_TABLE_ROW_RE.match(line)
    if not m:
        return []
    return [_strip_md_decoration(cell.strip()) for cell in m.group(1).split("|")]


def _is_gfm_separator(cells: list[str]) -> bool:
    return bool(cells) and all(_GFM_TABLE_SEPARATOR_CELL_RE.match(cell) for cell in cells)


def _impact_cell_from_gfm_row(cells: list[str], header: list[str] | None) -> str:
    """Extract the listed-impact sentence from a data row using its table header."""
    if not cells or not header:
        return ""
    header_l = [cell.lower() for cell in header]
    preferred_indexes: list[int] = []
    for idx, name in enumerate(header_l):
        if "listed" in name and "impact" in name:
            preferred_indexes.append(idx)
    for idx, name in enumerate(header_l):
        if idx in preferred_indexes:
            continue
        if "impact" in name and not any(skip in name for skip in ("id", "severity", "reward")):
            preferred_indexes.append(idx)
    for idx in preferred_indexes:
        if idx < len(cells):
            cell = cells[idx].strip()
            if cell:
                return cell
    return ""


# --- Per-row severity-column tables (Immunefi "Scope A/B" rubric shape) ----
#
# Some programs (e.g. Obyte) publish their rubric as ONE table per scope with
# a `Severity` column carrying the tier per ROW, instead of one table PER
# tier under a `## Critical` / `## High` heading:
#
#   | Severity | Reward | In-scope impact rows |
#   |----------|--------|----------------------|
#   | Critical | ...    | - Direct theft ...<br>- Permanent freezing ...   |
#   | High     | ...    | Temporary freezing of network transactions ...  |
#
# The heading-based tier tracker above never sees a tier word (the scope
# heading is "## Scope B - Smart Contract ...", not "## Critical"), so those
# rows were silently dropped -- every selected_impact failed BC1 grounding
# even when it was a verbatim rubric sentence. This helper is purely
# ADDITIVE: it detects a header row naming both a "severity" column and an
# impact column, reads the tier from the ROW's own severity cell, and
# explodes multi-sentence cells (`<br>`-joined, each a leading `- ` bullet)
# into individual candidate sentences. It never overrides the existing
# heading-based path -- it only contributes extra, exact-text rows.
def _severity_and_impact_columns(header: list[str]) -> tuple[int, int] | None:
    header_l = [cell.lower() for cell in header]
    severity_idx: int | None = None
    for idx, name in enumerate(header_l):
        if name.strip() == "severity" or name.strip().startswith("severity"):
            severity_idx = idx
            break
    if severity_idx is None:
        return None
    impact_idx: int | None = None
    for idx, name in enumerate(header_l):
        if idx == severity_idx:
            continue
        if "impact" in name and not any(skip in name for skip in ("id", "severity")):
            impact_idx = idx
            break
    if impact_idx is None:
        return None
    return severity_idx, impact_idx


def _split_multi_impact_cell(cell: str) -> list[str]:
    """Split a `<br>`-joined, bullet-per-sentence table cell into sentences.

    Handles the Obyte-style packed cell:
      "- Direct theft of any user funds...<br>- Permanent freezing of funds"
    A cell with no `<br>` and no leading bullet is returned as a single
    single-item list (still routed through `_strip_md_decoration`).
    """
    if not cell:
        return []
    parts = re.split(r"<br\s*/?>", cell, flags=re.IGNORECASE)
    out: list[str] = []
    for part in parts:
        p = part.strip()
        p = re.sub(r"^[-*+]\s+", "", p)
        p = _strip_md_decoration(p)
        if p:
            out.append(p)
    return out


def _parse_rubric_tiers(rubric_text: str) -> dict[str, list[str]]:
    """Parse rubric markdown into ``{tier_name: [bullet_row_text, ...]}``.

    A bullet row's tier is the most-recently-declared tier heading
    (H2..H4). Rows declared before any tier heading are ignored. Headings
    that change topic without a tier word (e.g. ``## Out of scope``) reset
    the active tier to None, so subsequent bullets don't get mis-tagged.

    GFM tables are also accepted under an active tier heading when their
    header has an impact/listed-impact column. Header and separator rows are
    ignored; only the impact sentence cell is used for exact grounding.

    The rubric grouping is intentionally permissive: if a section heading
    mentions multiple tier words (rare), the LAST matched word wins
    because that's typically the leaf-most tier ("operator-brief Critical
    impacts" -> Critical).
    """
    tiers: dict[str, list[str]] = {t: [] for t in TIER_NAMES}
    active: str | None = None
    pending_table_header: list[str] | None = None
    active_table_header: list[str] | None = None
    pending_severity_cols: tuple[int, int] | None = None
    active_severity_cols: tuple[int, int] | None = None
    for raw in rubric_text.splitlines():
        ln = raw.rstrip()
        if not ln.strip():
            pending_table_header = None
            active_table_header = None
            pending_severity_cols = None
            active_severity_cols = None
            continue
        m_tier = _TIER_HEADING_RE.match(ln)
        if m_tier:
            tier_word = m_tier.group(1).capitalize()
            active = tier_word if tier_word in tiers else None
            pending_table_header = None
            active_table_header = None
            pending_severity_cols = None
            active_severity_cols = None
            continue
        if _ANY_HEADING_RE.match(ln):
            # Heading without a tier word -- reset active AND all table
            # state. A per-row-severity table (e.g. "## Scope B - ...")
            # starts fresh right after this line: its own header/separator
            # rows (re)populate pending/active_severity_cols independently
            # of the ambient `active` tier, so resetting here is safe.
            active = None
            pending_table_header = None
            active_table_header = None
            pending_severity_cols = None
            active_severity_cols = None
            continue
        table_cells = _parse_gfm_table_cells(ln)
        if table_cells:
            if _is_gfm_separator(table_cells):
                if pending_table_header is not None:
                    active_table_header = pending_table_header
                if pending_severity_cols is not None:
                    active_severity_cols = pending_severity_cols
                pending_table_header = None
                pending_severity_cols = None
                continue
            # Per-row severity-column table (Immunefi Scope-A/B rubric shape,
            # e.g. Obyte SEVERITY.md): the tier comes from THIS row's own
            # `Severity` cell, not from an ambient heading, so this branch
            # runs regardless of `active`. Purely additive -- never removes
            # rows the heading-based path below would otherwise add.
            if active_severity_cols is None and active_table_header is None:
                cols = _severity_and_impact_columns(table_cells)
                if cols:
                    pending_severity_cols = cols
            if active_severity_cols is not None:
                sev_idx, impact_idx = active_severity_cols
                if sev_idx < len(table_cells) and impact_idx < len(table_cells):
                    row_tier = _strip_md_decoration(table_cells[sev_idx].strip()).capitalize()
                    if row_tier in tiers:
                        for sentence in _split_multi_impact_cell(table_cells[impact_idx]):
                            tiers[row_tier].append(sentence)
            if active is None:
                continue
            row_clean = _impact_cell_from_gfm_row(table_cells, active_table_header)
            if row_clean:
                tiers[active].append(row_clean)
            elif active_table_header is None and any("impact" in cell.lower() for cell in table_cells):
                pending_table_header = table_cells
            continue
        pending_table_header = None
        active_table_header = None
        pending_severity_cols = None
        active_severity_cols = None
        m_bullet = _BULLET_ROW_RE.match(ln)
        if m_bullet and active is not None:
            row = m_bullet.group(1).strip()
            # Remove leading bold/italic decoration on the row.
            row_clean = _strip_md_decoration(row)
            if row_clean:
                tiers[active].append(row_clean)
    return tiers


def _row_grounds_impact(row: str, impact: str) -> bool:
    """Return True iff ``impact`` equals one exact listed-impact row.

    Base Azul promotion discipline is intentionally stricter than the old
    substring heuristic: severity must be derived from the selected program
    impact sentence, so paraphrases and partial-row selections are not enough
    to proceed to PoC, harness, or report-ready work.
    """
    a = impact.strip().strip('"').strip("'")
    b = row.strip()
    if not a or not b:
        return False
    a_norm = re.sub(r"\s+", " ", a.lower())
    b_norm = re.sub(r"\s+", " ", b.lower())
    return a_norm == b_norm


def _ground_in_tier(rows: list[str], impact: str) -> tuple[bool, str | None]:
    """Return (ok, matched_row). BC1+BC2 grounding."""
    if len(impact.strip()) < MIN_IMPACT_LEN:
        return False, None
    for row in rows:
        if _row_grounds_impact(row, impact):
            return True, row
    return False, None


def _resolve_workspace_for_draft(draft: Path) -> Path | None:
    """Walk upwards from the draft to find the workspace root.

    NF5: anchor preference is OOS_CHECKLIST.md / SCOPE.md (strongest);
    SEVERITY*.md is only used as the workspace marker if no stronger
    anchor was found anywhere in the upward path. This avoids picking a
    nested package directory that happens to ship a SEVERITY mirror.
    """
    cur = draft.resolve().parent
    root = Path(cur.anchor or "/")

    severity_only_candidate: Path | None = None
    while cur != root:
        if (cur / "OOS_CHECKLIST.md").exists() or (cur / "SCOPE.md").exists():
            return cur
        # Remember the first severity-only directory but don't return yet --
        # a stronger anchor higher up wins.
        if severity_only_candidate is None and any(
            p.name.lower().startswith("severity") and p.name.lower().endswith(".md")
            for p in cur.glob("*.md")
        ):
            severity_only_candidate = cur
        cur = cur.parent
    return severity_only_candidate


# ---------------------------------------------------------------------------
# Draft checking
# ---------------------------------------------------------------------------


def _is_safe_proof_artifact(p: Path, ws: Path | None) -> tuple[bool, str | None]:
    """NF1: validate proof_artifact is a regular file in workspace."""
    try:
        rp = p.resolve()
    except OSError:
        return False, "could not resolve path"
    if not rp.exists():
        return False, "does not exist"
    if not rp.is_file():
        return False, "must be a regular file (got directory or special file)"
    # Reject proof_artifact pointing at the rubric itself or system dirs.
    name = rp.name.lower()
    if name.startswith("severity") and name.endswith(".md"):
        return False, "must not be the SEVERITY.md / rubric file"
    if name == "rubric_coverage.md":
        return False, "must not be RUBRIC_COVERAGE.md (rubric file)"
    # Workspace-rooted check (best-effort: only if ws is provided).
    if ws is not None:
        try:
            rp.relative_to(ws.resolve())
        except ValueError:
            return False, f"must live under workspace root ({ws})"
    return True, None


def check_draft(
    draft: Path,
    rubric_text: str | None,
    rubric_tiers: dict[str, list[str]] | None = None,
    workspace: Path | None = None,
) -> DraftReport:
    text = draft.read_text(encoding="utf-8", errors="replace")
    severity, paste_ready = _detect_severity_claim(text)
    requires = paste_ready or severity in ("Critical", "High", "Medium")

    found_block, inner, level = _extract_block(text)
    block = _parse_block(inner) if found_block else None

    report = DraftReport(
        path=draft,
        requires_mapping=requires,
        severity_claim=severity,
        paste_ready=paste_ready,
        has_mapping_block=found_block,
        block=block,
    )

    if not requires:
        return report

    if not found_block or block is None:
        report.add_error(
            ERR_MAPPING_BLOCK_MISSING,
            "missing `## Program Impact Mapping` block (required for "
            f"severity={severity or 'unknown'} / paste_ready={paste_ready})",
        )
        return report

    # NF3: warn if block was found at h3/h4 instead of h2.
    if level >= 3:
        report.warnings.append(
            f"`Program Impact Mapping` block found at heading level h{level} "
            "-- please use h2 (`## Program Impact Mapping`) for canonical form"
        )

    # Field presence
    missing: list[str] = []
    if not block.program:
        missing.append("program")
    if not block.asset:
        missing.append("asset")
    if not block.selected_impact:
        missing.append("selected_impact")
    if not block.severity_implied:
        missing.append("severity_implied")
    if not block.proof_artifact:
        missing.append("proof_artifact")
    if not block.not_proven_impacts_present:
        missing.append("not_proven_impacts")
    if missing:
        report.add_error(
            ERR_FIELD_MISSING,
            "mapping block is missing required field(s): " + ", ".join(missing),
        )

    # severity_implied normalisation (NF4 -- strip trailing punctuation).
    sev_norm = ""
    if block.severity_implied:
        sev_clean = block.severity_implied.strip().rstrip(".,:;").strip()
        sev_norm = sev_clean.capitalize()
        if sev_norm not in VALID_SEVERITIES:
            report.add_error(
                ERR_SEVERITY_IMPLIED_INVALID,
                f"severity_implied `{block.severity_implied}` is not one of {VALID_SEVERITIES}",
            )
            sev_norm = ""
        elif severity and sev_norm != severity:
            report.add_error(
                ERR_SEVERITY_IMPLIED_CONTRADICTS_CLAIM,
                f"severity_implied=`{sev_norm}` contradicts draft severity claim "
                f"`{severity}` -- pick one source of truth (truth-in-severity)",
            )

    # NF2: loud warning when not_proven_impacts is empty for reportable severity.
    if (
        block.not_proven_impacts_present
        and not block.not_proven_impacts
        and severity in ("Critical", "High", "Medium")
    ):
        report.warnings.append(
            "`not_proven_impacts` is empty for a Critical/High/Medium claim -- "
            "are you sure your PoC proves EVERY listed impact at this tier? "
            "(if not, list the impacts your evidence does NOT cover)"
        )

    # BC1+BC2: rubric tier-binding grounding.
    if block.selected_impact and rubric_text and rubric_tiers is not None:
        # Resolve which tier the selected_impact must live in: prefer the
        # validated severity_implied, fall back to severity_claim if the
        # implied field was missing/invalid.
        tier_for_grounding = sev_norm or severity
        if tier_for_grounding and tier_for_grounding in rubric_tiers:
            # Try every candidate (DDD2 multi-bullet support); the first
            # candidate that grounds in the right tier wins.
            candidates = block.selected_impact_candidates or [block.selected_impact]
            tier_rows = rubric_tiers.get(tier_for_grounding, [])
            grounded = False
            matched_row = None
            for cand in candidates:
                ok, row = _ground_in_tier(tier_rows, cand)
                if ok:
                    grounded = True
                    matched_row = row
                    break
            if not grounded:
                # Did the candidate ground in SOME tier? If so, surface a
                # tier-mismatch error (BC2 -- the FN7 over-framing class).
                cross_tier_hit: str | None = None
                for cand in candidates:
                    for other_tier, rows in rubric_tiers.items():
                        if other_tier == tier_for_grounding:
                            continue
                        ok, _row = _ground_in_tier(rows, cand)
                        if ok:
                            cross_tier_hit = other_tier
                            break
                    if cross_tier_hit:
                        break
                if cross_tier_hit:
                    report.add_error(
                        ERR_TIER_MISMATCH,
                        f"tier mismatch: severity_implied=`{tier_for_grounding}` "
                        f"but selected_impact found in `{cross_tier_hit}` section "
                        "of the rubric -- align severity_implied with the rubric "
                        "tier of selected_impact (BC2 over-framing guard)",
                    )
                else:
                    report.add_error(
                        ERR_RUBRIC_GROUNDING_MISSING,
                        "rubric grounding missing: selected_impact "
                        f"`{block.selected_impact[:80]}` is not an exact listed "
                        f"impact sentence in the `{tier_for_grounding}` section of "
                        "SEVERITY*.md / RUBRIC_COVERAGE.md (BC1 -- severity must "
                        "derive only from the selected rubric row)",
                    )
            else:
                report.warnings.append(
                    f"selected_impact grounded in `{tier_for_grounding}` tier row: "
                    f"`{(matched_row or '')[:80]}`"
                )
        elif tier_for_grounding:
            # Severity not present in tier dict -- shouldn't happen with
            # canonical levels, but be loud.
            report.warnings.append(
                f"could not bind selected_impact to tier `{tier_for_grounding}` "
                "(no rubric rows parsed under that tier)"
            )

    # Proof artifact path on disk (NF1).
    if block.proof_artifact:
        ws = workspace if workspace is not None else _resolve_workspace_for_draft(draft)
        candidates: list[Path] = []
        pa = Path(block.proof_artifact)
        if pa.is_absolute():
            candidates.append(pa)
        else:
            if ws is not None:
                candidates.append(ws / pa)
            candidates.append(draft.parent / pa)
            candidates.append(Path.cwd() / pa)
        # NF1: must be a regular file under workspace (or absolute, with file check).
        chosen: Path | None = None
        last_reason: str | None = None
        for c in candidates:
            ok, reason = _is_safe_proof_artifact(c, ws)
            if ok:
                chosen = c
                break
            last_reason = reason
        if chosen is None:
            existed = any(c.exists() for c in candidates)
            if existed and last_reason:
                report.add_error(
                    ERR_PROOF_ARTIFACT_INVALID,
                    f"proof_artifact `{block.proof_artifact}` exists but is invalid: "
                    f"{last_reason}",
                )
            else:
                report.add_error(
                    ERR_PROOF_ARTIFACT_MISSING,
                    f"proof_artifact path does not exist on disk: `{block.proof_artifact}` "
                    f"(searched: {', '.join(str(c) for c in candidates)})",
                )

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _iter_drafts(args) -> tuple[list[Path], Path | None]:
    explicit_ws = Path(args.workspace).resolve() if args.workspace else None
    if args.draft:
        p = Path(args.draft).resolve()
        ws = explicit_ws if explicit_ws is not None else _resolve_workspace_for_draft(p)
        return [p], ws
    if explicit_ws is None:
        return [], None
    staging = explicit_ws / "submissions" / "staging"
    if not staging.is_dir():
        return [], explicit_ws
    drafts = sorted(explicit_ws.glob("submissions/staging/*.md"))
    return drafts, explicit_ws


def _run_methodology_drift_gate(as_json: bool) -> int:
    """G9 drift gate runner. rc=0 covered, rc=1 drift, rc=2 corpus absent."""
    yaml_path = find_methodology_yaml()
    if yaml_path is None:
        if as_json:
            print(json.dumps({
                "gate": "methodology_mapping_drift",
                "corpus_found": False,
                "rc": 2,
                "note": "advisory: impact_hunting_methodology.yaml not in this checkout",
            }))
        else:
            print(
                "[program-impact-mapping] advisory: no "
                "audit/corpus_tags/impact_hunting_methodology.yaml in this checkout"
            )
        return 2
    missing = sorted(check_methodology_mapping_drift(yaml_path))
    rc = 1 if missing else 0
    if as_json:
        print(json.dumps({
            "gate": "methodology_mapping_drift",
            "corpus_found": True,
            "corpus_yaml": str(yaml_path),
            "missing_from_map": missing,
            "rc": rc,
        }, indent=2))
    elif missing:
        print(
            "[program-impact-mapping] FAIL: impact_id(s) in the corpus YAML are "
            "NOT mapped in IMPACT_METHODOLOGY_TO_CHECK31 (G9 drift): "
            + ", ".join(missing)
            + f"\n    corpus: {yaml_path}\n    fix: add each missing impact_id to "
            "IMPACT_METHODOLOGY_TO_CHECK31 with (tier, rubric_row_hint)."
        )
    else:
        print(
            "[program-impact-mapping] PASS: IMPACT_METHODOLOGY_TO_CHECK31 covers "
            f"every impact_id in {yaml_path} (G9 drift gate)"
        )
    return rc


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Program Impact Mapping fail-closed gate (Check #31)"
    )
    parser.add_argument("--draft", help="Path to a single draft markdown")
    parser.add_argument("--workspace", help="Workspace root (scans submissions/staging/*.md)")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON summary")
    parser.add_argument(
        "--allow-no-rubric",
        action="store_true",
        help=(
            "Treat missing SEVERITY*/RUBRIC_COVERAGE.md as advisory rc=2 "
            "instead of skipping rubric grounding (default behaviour)."
        ),
    )
    parser.add_argument(
        "--check-methodology-drift",
        action="store_true",
        help=(
            "G9 drift gate: fail (rc=1) if any impact_id in "
            "audit/corpus_tags/impact_hunting_methodology.yaml is missing from "
            "IMPACT_METHODOLOGY_TO_CHECK31. Does not require --draft/--workspace."
        ),
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.check_methodology_drift:
        return _run_methodology_drift_gate(args.json)

    if not args.draft and not args.workspace:
        parser.error("must pass --draft or --workspace")

    drafts, ws = _iter_drafts(args)
    if ws is None and args.draft and drafts:
        ws = _resolve_workspace_for_draft(drafts[0])

    rubric_found = False
    rubric_text = ""
    rubric_tiers: dict[str, list[str]] = {t: [] for t in TIER_NAMES}
    if ws is not None:
        rubric_found, rubric_text = _load_rubric_text(ws)
        if rubric_found:
            rubric_tiers = _parse_rubric_tiers(rubric_text)

    if not drafts:
        if args.json:
            print(json.dumps({"drafts": [], "rubric_found": rubric_found, "rc": 2 if not rubric_found else 0}))
        else:
            print("[program-impact-mapping] no drafts found")
        return 2 if not rubric_found else 0

    # SZ3: workspace flow blocks on missing rubric (rc=2 advisory). Per-draft
    # flow continues but skips rubric grounding silently with a warning.
    if not rubric_found and args.workspace:
        if args.json:
            print(json.dumps({
                "drafts": [str(d) for d in drafts],
                "rubric_found": False,
                "rc": 2,
                "note": "advisory: workspace has no SEVERITY*.md / RUBRIC_COVERAGE.md",
            }))
        else:
            print(
                f"[program-impact-mapping] advisory: no SEVERITY*.md / RUBRIC_COVERAGE.md in {ws}"
            )
        return 2

    # SZ3: when --draft is used and rubric is missing, pass rubric_text=None to
    # signal "skip grounding".
    grounding_text: str | None = rubric_text if rubric_found else None
    grounding_tiers: dict[str, list[str]] | None = rubric_tiers if rubric_found else None

    reports = [
        check_draft(d, grounding_text, grounding_tiers, workspace=ws) for d in drafts
    ]
    failed = [r for r in reports if r.requires_mapping and not r.passed()]

    if args.json:
        print(
            json.dumps(
                {
                    "drafts": [
                        {
                            "path": str(r.path),
                            "requires_mapping": r.requires_mapping,
                            "severity_claim": r.severity_claim,
                            "paste_ready": r.paste_ready,
                            "has_mapping_block": r.has_mapping_block,
                            "errors": r.errors,
                            "warnings": r.warnings,
                        }
                        for r in reports
                    ],
                    "rubric_found": rubric_found,
                    "failed_count": len(failed),
                    "rc": 1 if failed else 0,
                },
                indent=2,
            )
        )
    else:
        if not rubric_found and args.draft:
            print(
                "[program-impact-mapping] WARN: no SEVERITY*.md / RUBRIC_COVERAGE.md "
                f"under workspace ({ws}); skipping rubric-grounding check (SZ3)"
            )
        for r in reports:
            tag = "PASS" if r.passed() else "FAIL"
            need = "REQ" if r.requires_mapping else "skip"
            print(f"[{tag}/{need}] {r.path}  severity={r.severity_claim or '-'}  paste_ready={r.paste_ready}")
            for w in r.warnings:
                print(f"    ! {w}")
            for err in r.errors:
                print(f"    - {err}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
