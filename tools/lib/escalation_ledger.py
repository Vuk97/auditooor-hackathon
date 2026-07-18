#!/usr/bin/env python3
"""escalation_ledger.py - shared library for the escalation-workflow enforcement.

Motivation (operator ask 2026-07-04): the existing escalate-first gate
(tools/escalate-first-required-check.py, pre-submit Check #127) is a STATIC TEXT
check - it accepts a *sentence in the draft* ("I attempted Critical, the blocker
was X") written by a SINGLE agent, with no requirement that (a) the candidate
higher in-scope impacts were ENUMERATED from the impact library, (b) each was
tested by an INDEPENDENT, multi-lane (adversarial) workflow rather than one
agent's self-assessment, or (c) the attempt was LOGGED to a durable, auditable
ledger. This library backs the two tools that close that gap:
  - escalation-workflow-planner.py : enumerate candidate higher in-scope impacts
    from impact_mechanism_library.json + the ws SEVERITY.md, emit one escalation
    lane per candidate, and LOG a `planned` record to the ledger.
  - escalation-workflow-required-check.py : the enforcement gate. A finding that
    sits BELOW its max reachable in-scope tier must carry a `resolved` ledger
    record whose every higher candidate has a TERMINAL verdict (escalated with a
    PoC ref, or proof-of-impossibility with a code-cited guard/bound/recovery)
    backed by >= MIN_VERIFICATION_LANES independent lanes. Else it fails
    (advisory-first; strict under AUDITOOOR_ESCALATION_WORKFLOW_STRICT=1).

Ledger path: <ws>/.auditooor/escalation_attempts.jsonl (append-only, one JSON
object per line). Schema: auditooor.escalation_attempt.v1.

Generic + language-agnostic: reads only the ws SEVERITY.md + the repo impact
library + the ws ledger. No network, no source mutation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.escalation_attempt.v1"
LEDGER_RELPATH = ".auditooor/escalation_attempts.jsonl"

# How many INDEPENDENT verification lanes a terminal candidate verdict needs.
# The whole point of the operator ask: not one agent's say-so. >=2 adversarial
# lanes (e.g. one attempts to PROVE the higher tier, one attempts to REFUTE it).
MIN_VERIFICATION_LANES = 2

TIER_RANK = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RANK_TIER = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def tier_rank(tier: str) -> int:
    return TIER_RANK.get((tier or "").strip().lower(), -1)


# ---------------------------------------------------------------------------
# shared tier inference (rank-1 red-team fix: gate + planner MUST share this so
# they can never diverge; widened to the common Immunefi/Cantina template shapes
# an honest agent hits by accident, not just an adversary)
# ---------------------------------------------------------------------------

_TIER_ALTS = r"critical|crit|high|hi|medium|med|low|lo|info(?:rmational)?"
_TIER_NORM = {"crit": "critical", "hi": "high", "med": "medium", "lo": "low"}


def _norm_tier(t: str) -> str:
    t = (t or "").lower()
    if t.startswith("info"):
        return "info"
    return _TIER_NORM.get(t, t)


# The tier token must be a standalone word: NOT followed by a hyphen-letter
# (rejects "Medium-effort" / "Low-level ..."). `(?![-\w])` after the alternation.
_LABEL = r"(?:severity(?:\s+level)?|risk(?:\s+level)?|impact\s+rating|rating|tier)"
_INFER_PATTERNS = [
    # explicit label: "Severity: High", "Risk = Critical", "Rating | Med", "Tier is Low"
    re.compile(r"(?im)^[\s>|*_#`-]*" + _LABEL + r"\s*(?:[:=|]|\bis\b|-)\s*[\[(*_`]*\s*("
               + _TIER_ALTS + r")(?![-\w])"),
    # parenthetical: "Severity (High)"
    re.compile(r"(?im)\b" + _LABEL + r"\s*\(\s*(" + _TIER_ALTS + r")(?![-\w])\s*\)"),
    # heading-lead: "# High: ...", "## [Critical] ...", "# Medium" (tier is the
    # first heading token, followed by :/]/) or end-of-heading; NOT "# Medium-effort")
    re.compile(r"(?im)^#{1,6}\s*[\[(*_`]*\s*(" + _TIER_ALTS + r")(?![-\w])\s*(?:[:\])]|$)"),
    # markdown table cell holding a lone tier token: "| ... | High | ..."
    re.compile(r"(?im)^\s*\|(?:[^|]*\|)*?\s*(" + _TIER_ALTS + r")(?![-\w])\s*\|"),
]


def infer_tier(text: str) -> str | None:
    """Best-effort claimed-severity tier from a draft. Shared by the gate and the
    planner so they never disagree. Returns a normalized tier or None."""
    for rx in _INFER_PATTERNS:
        m = rx.search(text or "")
        if m:
            return _norm_tier(m.group(1))
    return None


# ---------------------------------------------------------------------------
# SEVERITY.md parsing  ->  ranked in-scope impact rows
# ---------------------------------------------------------------------------

_HEADER_TIER_RE = re.compile(
    r"^\s*(?:#{1,6}\s*|\*\*)?\b(critical|high|medium|low|info(?:rmational)?)\b",
    re.IGNORECASE,
)
_BULLET_RE = re.compile(r"^\s*(?:[-*+]|\d+\.)\s+(.*\S)\s*$")


_TIER_WORD_RE = re.compile(r"^(critical|crit|high|hi|medium|med|low|lo|info(?:rmational)?)$", re.I)
_SETEXT_RE = re.compile(r"^\s*(=+|-+)\s*$")
_TABLE_SEP_RE = re.compile(r"^\s*\|?[\s:\-|]+\|?\s*$")
_REWARD_CELL_RE = re.compile(r"(?i)\b(usd|reward|max|min|flat|n/?a)\b|\$|^\s*-+\s*$")
# Inline bullet whose leading word is a tier LABEL (not impact prose): a
# STANDALONE tier word (rejects "Low-level"/"Medium-of-N" via (?![-\w]))
# followed by an optional (...) then a ':' or '-' separator then the impact.
_INLINE_TIER_RE = re.compile(
    r"^(?:\*\*\s*)?(critical|crit|high|hi|medium|med|low|lo|info(?:rmational)?)"
    r"(?![-\w])(?:\s*\*\*)?\s*(?:\([^)]*\))?\s*[:\-]\s*(.+)$",
    re.IGNORECASE,
)


def parse_severity_rows(severity_md: Path) -> list[dict[str, Any]]:
    """Return [{tier, tier_rank, text}] - one row per rubric impact. Robust to:
    ATX headings (`### Critical`, `**High**`), inline `- **Critical** (USD ...):
    <impact>` bullets, SETEXT headings (a bare tier word underlined with ===/---),
    and markdown TABLE rows (`| Critical | ... | <impact> |`). Rank-2 red-team
    hardening: a bullet's leading word is treated as a tier LABEL only when it is
    a STANDALONE tier word with a separator (so "Low-level ... permanent freezing"
    inherits its section tier instead of being mis-demoted to Low)."""
    rows: list[dict[str, Any]] = []
    if not severity_md.is_file():
        return rows
    try:
        lines = severity_md.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return rows
    current_tier: str | None = None
    prev_nonblank: str | None = None
    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()

        # SETEXT heading: ===/--- underline under a bare tier word.
        if _SETEXT_RE.match(line) and prev_nonblank is not None:
            pw = prev_nonblank.strip().strip("*_`# ").strip()
            if _TIER_WORD_RE.match(pw):
                current_tier = _norm_tier(pw.lower())
                prev_nonblank = None
                continue

        if not stripped:
            continue

        # Markdown TABLE row (a lone tier cell -> that tier; impact = longest
        # non-tier, non-reward cell). Skip header/separator rows.
        if stripped.startswith("|") and stripped.count("|") >= 2 and not _TABLE_SEP_RE.match(stripped):
            cells = [c.strip().strip("*_`") for c in stripped.strip("|").split("|")]
            tier_cells = [c for c in cells if _TIER_WORD_RE.match(c)]
            if len(tier_cells) == 1:
                t = _norm_tier(tier_cells[0].lower())
                impact_cands = [c for c in cells
                                if c and not _TIER_WORD_RE.match(c) and not _REWARD_CELL_RE.search(c)]
                if impact_cands:
                    impact = max(impact_cands, key=len)
                    rows.append({"tier": t, "tier_rank": tier_rank(t), "text": impact})
                prev_nonblank = stripped
                continue

        prev_nonblank = stripped

        is_heading = bool(re.match(r"^\s*#{1,6}\s", line)) or bool(
            re.match(r"^\s*\*\*(critical|high|medium|low|info)", line, re.IGNORECASE))
        bullet = _BULLET_RE.match(line)
        if is_heading and not bullet:
            m = _HEADER_TIER_RE.match(stripped)
            if m:
                current_tier = _norm_tier(m.group(1).lower())
            continue
        if bullet:
            text = bullet.group(1).strip()
            inline = _INLINE_TIER_RE.match(text)
            if inline and inline.group(2).strip():
                tier = _norm_tier(inline.group(1).lower())
                impact_text = inline.group(2).strip()
            elif current_tier:
                tier = current_tier
                impact_text = text
            else:
                continue
            rows.append({"tier": tier, "tier_rank": tier_rank(tier), "text": impact_text})
    return rows


# ---------------------------------------------------------------------------
# impact library crosswalk:  SEVERITY row text  ->  impact_mechanism_library key
# ---------------------------------------------------------------------------

def load_impact_library(repo_root: Path) -> dict[str, Any]:
    for cand in (
        repo_root / "audit/corpus_tags/impact_mechanism_library.json",
        repo_root / "impact_mechanism_library.json",
    ):
        if cand.is_file():
            try:
                return json.loads(cand.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return {}
    return {}


# Keyword -> library impact-class. First matching (checked in this order) wins.
# Ordering matters: more-specific phrases before generic ones.
_CROSSWALK: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"chain split|network partition|hard ?fork to resolve|unintended.*fork", re.I), "chain-split-fork"),
    (re.compile(r"permanent freez|no on-chain remediation|fix requires (a )?hard ?fork", re.I), "bc-permanent-freeze-hardfork"),
    (re.compile(r"halt|liveness|crash or halt|validators?", re.I), "chain-halt-shutdown"),
    (re.compile(r"rpc|grpc|api crash|crash of rpc", re.I), "bc-rpc-api-crash"),
    (re.compile(r"block ?production delay|block stuffing|block freeze|resource exhaustion|unbounded gas|out of memory|oom", re.I), "bc-node-resource-exhaustion"),
    (re.compile(r"governance|voting result", re.I), "governance-manipulation"),
    (re.compile(r"insolven", re.I), "share-supply-inflation"),
    (re.compile(r"replay|double ?spend|double-spend", re.I), "cross-chain-replay-double-spend"),
    (re.compile(r"unauthorized (transfer|mint|burn)|direct (theft|loss) of|theft of .*funds|direct loss", re.I), "bc-direct-loss-of-funds"),
    (re.compile(r"theft of unclaimed yield|steal.*yield", re.I), "bc-direct-loss-of-funds"),
    (re.compile(r"temporary freez|freezing of funds", re.I), "bc-permanent-freeze-hardfork"),
    (re.compile(r"mempool|fee calc|transaction fee|selection and priority", re.I), "griefing-dos-blockstuffing"),
    (re.compile(r"unable to operate|lack of token funds", re.I), "operability-lack-of-funds"),
    (re.compile(r"griefing|damage to users", re.I), "griefing-dos-blockstuffing"),
    (re.compile(r"gas", re.I), "gas-theft-fee-vault"),
    (re.compile(r"deterministic unintended smart contract execution|unintended.*execution", re.I), "bc-consensus-transient-failure"),
]


def crosswalk_row_to_impact_class(row_text: str) -> str | None:
    for rx, key in _CROSSWALK:
        if rx.search(row_text or ""):
            return key
    return None


def higher_in_scope_targets(
    current_tier: str, severity_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """The rubric impact rows strictly ABOVE current_tier - the escalation
    targets. De-duplicated by (tier, text). Each carries its library impact
    class + the library mechanisms that produce it (context for the lane)."""
    cur = tier_rank(current_tier)
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in severity_rows:
        if row["tier_rank"] <= cur:
            continue
        key = (row["tier"], row["text"])
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "tier": row["tier"],
            "tier_rank": row["tier_rank"],
            "severity_row": row["text"],
            "impact_class": crosswalk_row_to_impact_class(row["text"]),
        })
    out.sort(key=lambda r: -r["tier_rank"])
    return out


def max_reachable_tier(severity_rows: list[dict[str, Any]]) -> str:
    if not severity_rows:
        return "info"
    return RANK_TIER.get(max(r["tier_rank"] for r in severity_rows), "info")


# ---------------------------------------------------------------------------
# ledger read / write
# ---------------------------------------------------------------------------

def ledger_path(ws: Path) -> Path:
    return ws / LEDGER_RELPATH


def finding_id_for(draft_path: Path, ws: Path) -> str:
    """Stable finding id = ws-relative path if under ws, else a content hash."""
    try:
        return str(draft_path.resolve().relative_to(ws.resolve()))
    except (ValueError, OSError):
        try:
            h = hashlib.sha256(draft_path.read_bytes()).hexdigest()[:16]
            return f"sha256:{h}"
        except OSError:
            return str(draft_path)


def read_ledger(ws: Path) -> list[dict[str, Any]]:
    p = ledger_path(ws)
    if not p.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except ValueError:
            continue
    return records


def append_ledger(ws: Path, record: dict[str, Any]) -> None:
    p = ledger_path(ws)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")


def latest_record_for(ws: Path, finding_id: str) -> dict[str, Any] | None:
    """The most-recently-appended record for a finding (last line wins)."""
    match = None
    for rec in read_ledger(ws):
        if rec.get("finding_id") == finding_id:
            match = rec
    return match


def spawn_worker_records(ws: Path) -> list[dict[str, Any]]:
    """Real dispatch records from <ws>/.auditooor/spawn_worker_log.jsonl
    (schema auditooor.spawn_worker.v1: lane_id, ts, prompt_sha256, workspace)."""
    p = ws / ".auditooor" / "spawn_worker_log.jsonl"
    out: list[dict[str, Any]] = []
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


# ---------------------------------------------------------------------------
# terminal-verdict validation (the never-false-pass core)
# ---------------------------------------------------------------------------

_TERMINAL_VERDICTS = {"escalated", "proof-of-impossibility"}


def candidate_is_terminal(
    cand: dict[str, Any], ws: Path | None = None, planned_at: str | None = None,
    require_dispatch_log: bool = False,
) -> tuple[bool, str]:
    """A candidate escalation target is terminally resolved iff:
      - verdict in {escalated, proof-of-impossibility}, AND
      - it carries >= MIN_VERIFICATION_LANES lanes each a dict with a NON-EMPTY
        lane_id AND agent, spanning >= MIN_VERIFICATION_LANES DISTINCT AGENTS
        (rank-3 fix: no positional/vacuous fallback; two lanes from one author
        never both count), AND
      - when a real <ws>/.auditooor/spawn_worker_log.jsonl exists, the counted
        lanes cross-reference to >= MIN_VERIFICATION_LANES real dispatches (by
        lane_id, ts >= planned_at) with DISTINCT prompt_sha256 (rank-4 fix: the
        multi-lane requirement is genuine enforcement, not a self-attested honor
        system - forging it now requires actually dispatching independent
        workers), AND
      - evidence: `escalated` -> a poc/evidence ref; `proof-of-impossibility` ->
        a code-cited guard/bound/recovery (file:line / bound / recovery token).

    rank-7 fix (self-attest-when-log-absent loophole): the rank-4 dispatch
    cross-ref SILENTLY SKIPPED whenever no spawn_worker_log.jsonl existed - the
    DEFAULT state for any workspace that has not used spawn-worker.sh - so a
    single agent could green every candidate with two fabricated `agent` strings
    it never dispatched. When `require_dispatch_log=True` (threaded from the
    STRICT env), a MISSING or EMPTY dispatch log now FAILS CLOSED instead of
    skipping, so the multi-agent guarantee holds under strict enforcement.
    Advisory (default) behavior is unchanged (skip when absent).
    Returns (ok, reason)."""
    verdict = (cand.get("verdict") or "").strip().lower()
    if verdict not in _TERMINAL_VERDICTS:
        return False, f"non-terminal verdict '{verdict or 'MISSING'}'"
    lanes = cand.get("verification_lanes") or []
    real = [
        l for l in lanes
        if isinstance(l, dict) and (l.get("lane_id") or "").strip() and (l.get("agent") or "").strip()
    ]
    distinct_agents = {(l.get("agent") or "").strip().lower() for l in real}
    if len(distinct_agents) < MIN_VERIFICATION_LANES:
        return False, (
            f"only {len(distinct_agents)} distinct-agent lane(s) with non-empty lane_id+agent; "
            f"need >= {MIN_VERIFICATION_LANES} (multi-agent, not one agent's say-so)"
        )
    if ws is not None:
        sw = spawn_worker_records(ws)
        if sw:
            lane_ids = {(l.get("lane_id") or "").strip() for l in real}
            matched = [
                r for r in sw
                if (r.get("lane_id") or "").strip() in lane_ids
                and (not planned_at or str(r.get("ts") or "") >= str(planned_at))
            ]
            shas = {(r.get("prompt_sha256") or "").strip() for r in matched if r.get("prompt_sha256")}
            if len(shas) < MIN_VERIFICATION_LANES:
                return False, (
                    f"dispatch cross-ref: only {len(shas)} distinct dispatched brief(s) in "
                    f"spawn_worker_log.jsonl match these lanes after planned_at; need >= "
                    f"{MIN_VERIFICATION_LANES} independent dispatches (no forged self-attested lanes)"
                )
        elif require_dispatch_log:
            # rank-7: strict mode + no real dispatch log = the self-attested lanes
            # are unverifiable. Fail closed rather than trust the honor system.
            return False, (
                "dispatch cross-ref (STRICT): no <ws>/.auditooor/spawn_worker_log.jsonl "
                f"records exist to verify these {len(distinct_agents)} self-attested lane(s); "
                f"strict enforcement requires >= {MIN_VERIFICATION_LANES} genuinely-dispatched "
                "briefs (route lanes through spawn-worker.sh so the dispatch is logged, "
                "not self-attested)"
            )
    ev = (cand.get("evidence") or "").strip()
    if verdict == "escalated":
        if not ev:
            return False, "escalated verdict with no poc/evidence ref"
    else:  # proof-of-impossibility
        if not (re.search(r"\S+\.\w+:\d+", ev) or re.search(r"\b(bound|recover|cap|revert|circuit)\w*\b", ev, re.I)):
            return False, "proof-of-impossibility with no code-cited guard/bound/recovery"
    return True, "terminal"


def record_is_resolved(
    record: dict[str, Any] | None,
    ws: Path | None = None,
    required_targets: list[dict[str, Any]] | None = None,
    draft_sha: str | None = None,
    require_dispatch_log: bool = False,
) -> tuple[bool, str, list[str]]:
    """A ledger record terminally resolves the escalation workflow iff it is
    `status: resolved`, is NOT stale (rank-5: its stored draft_content_sha256, if
    any, still matches the current draft), COVERS every currently-required higher
    target (rank-6: superset of required_targets), AND every candidate target is
    terminally resolved (candidate_is_terminal, with dispatch cross-ref when ws is
    given). rank-7: pass require_dispatch_log=True (from the STRICT env) to fail
    closed when no spawn_worker_log.jsonl backs the self-attested lanes.
    Returns (ok, reason, failures)."""
    if not record:
        return False, "no escalation_attempts record for this finding", []
    if (record.get("status") or "").strip().lower() != "resolved":
        return False, f"record status is '{record.get('status')}' (not resolved)", []
    stored = (record.get("draft_content_sha256") or "").strip()
    if draft_sha and stored and stored != draft_sha:
        return False, "record is STALE (draft content changed since the escalation was resolved)", []
    cands = record.get("candidate_targets") or []
    if not cands:
        return False, "record has zero candidate_targets (nothing was attempted)", []
    if required_targets:
        # key coverage on the impact ROW TEXT (its identity) - robust to a record
        # that mislabels a candidate's tier.
        covered = {c.get("severity_row") for c in cands}
        missing = [t for t in required_targets if t.get("severity_row") not in covered]
        if missing:
            return (False,
                    f"{len(missing)} required higher target(s) not covered by the record",
                    [f"UNCOVERED: {m.get('severity_row', '?')[:60]}" for m in missing])
    planned_at = record.get("planned_at")
    failures: list[str] = []
    for c in cands:
        ok, reason = candidate_is_terminal(
            c, ws=ws, planned_at=planned_at, require_dispatch_log=require_dispatch_log)
        if not ok:
            failures.append(f"{c.get('severity_row', c.get('impact_class', '?'))[:60]}: {reason}")
    if failures:
        return False, f"{len(failures)} candidate(s) not terminally resolved", failures
    return True, "all candidates terminally resolved (multi-lane)", []
