#!/usr/bin/env python3
"""
novel-hypothesis-probe.py — saturation-aware corpus probe (PR #126 MVP).

Codex framing (PR #125 08:28Z #3, plan revision absorbed 2026-04-25):
the useful concrete version of "novel hypothesis generation" is NOT an
"LLM-be-creative" pass. It is a *saturation-aware* read-only probe that
takes already-covered detector / root classes as **negative space** and
asks for mechanisms that are not represented in the workspace's prior
submission ledger or in the auditooor detector pattern corpus.

This is the MVP build per PR #126 plan
(`docs/PLAN_NOVEL_HYPOTHESIS_GENERATOR.md`). MVP rules — preserved verbatim
from the plan so reviewers can audit compliance:

  1. **MVP standalone, not an `engage.py` stage.** Read-only. Emits
     artifacts under `<workspace>/swarm/novel_hypothesis_briefs/`. Does
     not call `engage.py`. Does not auto-dispatch agents.
  2. **Consumes precomputed evidence from the originality stack
     (seed-evidence MVP).** Survey table in the plan names the tools
     (`originality-grep.sh`, `variant-detector.py`, `pattern-dedupe.py`,
     `dedup-grep.py`). This MVP does NOT shell out to them at runtime;
     instead it accepts their output as pre-populated `extra_evidence`
     on each seed candidate and runs only cheap in-process scans
     (substring match against `prior_audits/`, in-process title check,
     best-effort `check-novel-vector.sh` invocation when the script is
     in-tree). Wiring runtime composition of the full originality stack
     is an explicit follow-up ticket — the plumbing is in place via the
     `extra_evidence` schema so a follow-up PR only has to swap in
     subprocess calls.
  3. **5 hypothesis shapes** with two Codex narrowings:
       - `trust_boundary`              — new (caller-role, callee-role) pair
       - `external_callback_ordering`  — call-after-state-write paths not
                                         already covered by reentrancy /
                                         CEI detector family.
       - `cross_domain_replay`         — chain-id / domain-separator /
                                         nonce reuse beyond classified cases.
       - `stale_config_after_admin_op` — admin op leaves a *concrete reachable
                                         secondary state slot* un-reconciled.
                                         Generic centralization / admin-rug
                                         signals MUST be rejected here.
       - `economic_grief`              — refund-skip / partial-fill-replay /
                                         gas-asymmetry where the candidate
                                         carries explicit attacker-cost <
                                         defender-loss math. Hand-wavy "this
                                         is annoying" MUST be rejected.
  4. **Output:** mining-brief-compatible markdown + JSON sidecar.
  5. **Confidence is advisory only.** `high|medium|low|needs_review|unknown`.
     No submission gate, no dispatch gate, no PR-merge gate consumes the
     `confidence` field. If CCIA reachability / source / deployment evidence
     is missing → emit `needs_review` (or `unknown`).
  6. **MVP scope:** negative-space scan + ranked briefs + hermetic tests.
     **NO auto-dispatch in this PR.**

Inputs (best-effort; missing inputs reduce confidence, not crash):

  <workspace>/CCIA_REPORT.md or <workspace>/ccia_report.json
  <workspace>/HYPOTHESES.md            (optional; from generate-hypotheses.sh)
  <workspace>/prior_audits/*.txt       (optional; for corpus-distance)
  <workspace>/submissions/...          (workspace ledger)
  <workspace>/novel_hypothesis_seeds.json
                                       (optional structured seed feed)

Outputs:

  <workspace>/swarm/novel_hypothesis_briefs/brief_NNN_<shape>_<slug>.md
  <workspace>/swarm/novel_hypothesis_briefs/brief_NNN_<shape>_<slug>.json
  <workspace>/swarm/novel_hypothesis_briefs/index.json   (run summary)

Usage:
  python3 tools/novel-hypothesis-probe.py <workspace> [--top N]
                                          [--out-dir DIR]
                                          [--seeds FILE]
                                          [--no-shell-out]

`--no-shell-out` is reserved for the future runtime-composition mode (when
the probe will shell out to `originality-grep.sh` / `variant-detector.py` /
`dedup-grep.py`). In this seed-evidence MVP it only disables the cheap
in-process substring scan against `<workspace>/prior_audits/` — there is
NO subprocess spawned to the originality stack today. Hermetic tests pass
this flag so they don't read the real corpus.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Shapes — Codex named exactly these five. Order matters for stable ranking.
# ---------------------------------------------------------------------------

SHAPES: Tuple[str, ...] = (
    "trust_boundary",
    "external_callback_ordering",
    "cross_domain_replay",
    "stale_config_after_admin_op",
    "economic_grief",
)

# Detector classes that "cover" each shape (negative space lookup keys).
# Used to populate `negative_space_evidence.covered_classes_checked` AND to
# reject candidates whose target overlaps an already-covered class.
COVERED_CLASSES_BY_SHAPE: Dict[str, Tuple[str, ...]] = {
    "trust_boundary":              ("A-AUTH", "A-DELEGATE", "A-ACCESS"),
    "external_callback_ordering":  ("A-REENT", "A-CEI", "A-CALLBACK"),
    "cross_domain_replay":         ("A-EIP712", "A-NONCE", "A-DOMAIN"),
    "stale_config_after_admin_op": ("A-PAUSE", "A-UPGRADE", "A-CONFIG"),
    "economic_grief":              ("A-GRIEF", "A-REFUND", "A-FEE"),
}

# Centralization / admin-rug signals that must NOT alone trigger
# stale_config_after_admin_op (Codex narrowing).
GENERIC_CENTRALIZATION_TOKENS = (
    "admin can rug",
    "owner can drain",
    "trusted admin",
    "centralization risk",
    "privileged role",
    "governance can",
    "admin key compromise",
)

# Required tokens for stale_config_after_admin_op — at least one of these
# must appear together with a concrete state-slot reference.
STALE_CONFIG_ADMIN_OP_TOKENS = (
    "pause",
    "retire",
    "blacklist",
    "upgrade",
    "setrate",
    "setoracle",
    "setconfig",
    "setfeerecipient",
    "deprecate",
)

# Required tokens for economic_grief — must carry attacker-cost vs
# defender-loss math (Codex narrowing).
ECON_GRIEF_COST_TOKENS = (
    "attacker cost",
    "attacker spends",
    "attacker pays",
    "defender loses",
    "defender loss",
    "victim loses",
    "victim loss",
    "asymmetry ratio",
    "cost ratio",
    "$/$",
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Candidate:
    """A raw seed before shape-narrowing / scoring."""
    shape: str
    title: str
    contract: str = ""
    function: str = ""
    interaction: str = ""
    rationale: str = ""
    # Free-form text used by shape-specific narrowing rules (e.g. economic
    # grief checks for attacker-cost math here).
    body: str = ""
    # Optional CCIA cross-reference (angle id like "A-AUTH").
    ccia_angle_id: str = ""
    ccia_reachable: Optional[bool] = None
    ccia_rationale: str = ""
    # Operator-supplied extra evidence pre-computed before the probe ran.
    extra_evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Brief:
    """Ranked output."""
    rank: int
    candidate: Candidate
    sidecar: Dict[str, Any]
    markdown: str


# ---------------------------------------------------------------------------
# Workspace I/O — defensive: missing files are normal, not fatal.
# ---------------------------------------------------------------------------

def load_ccia_angles(ws: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Mirror tools/mining-brief-generator.py loader for compatibility."""
    json_path = ws / "ccia_report.json"
    if json_path.exists():
        try:
            data = json.loads(json_path.read_text())
        except Exception:
            data = None
        if isinstance(data, dict):
            return data.get("ccia", {}), data.get("attack_angles", []) or []
        if isinstance(data, list):
            return {}, data
    md_path = ws / "ccia_report.md"
    if not md_path.exists():
        md_path = ws / "CCIA_REPORT.md"
    if md_path.exists():
        angles: List[Dict[str, Any]] = []
        for line in md_path.read_text().splitlines():
            m = re.match(r'###\s+(A-[A-Z0-9]+)\s+—\s+(\w+)\s+—\s+(.+)', line)
            if m:
                angles.append(
                    {"id": m.group(1), "severity": m.group(2), "title": m.group(3)}
                )
        return {}, angles
    return {}, []


def load_seeds(ws: Path, seeds_path: Optional[Path]) -> List[Dict[str, Any]]:
    """Operator-supplied structured seeds (JSON list of candidate dicts).

    Used for hermetic tests + as an explicit override channel. Real-world
    operators will normally rely on CCIA + HYPOTHESES.md, but the seed file
    keeps the probe testable without standing up a full mock workspace.
    """
    candidates: List[Path] = []
    if seeds_path:
        candidates.append(Path(seeds_path).expanduser())
    candidates.append(ws / "novel_hypothesis_seeds.json")
    for p in candidates:
        if not p or not p.is_file():
            continue
        try:
            data = json.loads(p.read_text())
        except Exception:
            continue
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        if isinstance(data, dict) and isinstance(data.get("seeds"), list):
            return [d for d in data["seeds"] if isinstance(d, dict)]
    return []


def load_prior_audit_corpus(ws: Path) -> str:
    """Concatenated text of <ws>/prior_audits/*.txt for substring checks."""
    pa = ws / "prior_audits"
    if not pa.is_dir():
        return ""
    chunks: List[str] = []
    for f in sorted(pa.glob("*.txt")):
        try:
            chunks.append(f.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
    return "\n".join(chunks)


# ---------------------------------------------------------------------------
# Shape narrowing — these are the Codex hard rules. They MUST reject
# generic centralization (stale_config) and hand-wavy grief (economic_grief).
# ---------------------------------------------------------------------------

def _has_concrete_state_slot(text: str) -> bool:
    """Heuristic: a 'reachable secondary state slot' looks like a named
    storage var / mapping referenced alongside an admin op. We require at
    least one of:
      - a mapping(...) reference
      - a `<contract>.<storageVar>` ref
      - an explicit "state slot" / "storage slot" mention
      - a reachable user-facing function naming the slot.

    This is intentionally conservative — better to drop a candidate to
    `needs_review` than to let generic centralization ride through.
    """
    t = text.lower()
    if "state slot" in t or "storage slot" in t:
        return True
    if "secondary state" in t and "reconcil" in t:
        return True
    if re.search(r"mapping\s*\(", t):
        return True
    if re.search(r"\b[a-z_][a-z0-9_]*\.[a-z_][a-zA-Z0-9_]*\b", text):
        # contract.var-style reference — generic but better than nothing.
        # Still require an admin-op token co-occurrence, checked by caller.
        return True
    return False


def stale_config_admin_op_passes_narrowing(c: Candidate) -> Tuple[bool, str]:
    """Codex narrowing: reachable secondary state, NOT generic centralization.

    Returns (passes, rejection_reason_if_any).
    """
    blob = " ".join([c.title, c.rationale, c.body, c.interaction]).lower()
    if not blob.strip():
        return False, "stale_config_after_admin_op: empty rationale"
    # Hard reject if ONLY a generic centralization signal is present.
    has_generic = any(tok in blob for tok in GENERIC_CENTRALIZATION_TOKENS)
    has_admin_op = any(tok in blob for tok in STALE_CONFIG_ADMIN_OP_TOKENS)
    has_state_slot = _has_concrete_state_slot(c.body or c.rationale or c.title)
    has_user_facing_read = (
        "non-admin" in blob
        or "user-facing" in blob
        or "reader" in blob
        or "read by" in blob
        or "read path" in blob
    )
    if has_generic and not (has_admin_op and has_state_slot and has_user_facing_read):
        return False, (
            "stale_config_after_admin_op: looks like generic centralization "
            "/ admin-rug signal — Codex narrowing requires a concrete "
            "reachable secondary state slot read by a non-admin path"
        )
    if not has_admin_op:
        return False, (
            "stale_config_after_admin_op: no admin-op token "
            "(pause/retire/blacklist/upgrade/setX/deprecate) found"
        )
    if not has_state_slot:
        return False, (
            "stale_config_after_admin_op: no concrete state-slot reference "
            "(mapping(...), contract.var, or 'state slot') found"
        )
    if not has_user_facing_read:
        return False, (
            "stale_config_after_admin_op: secondary state must be read by a "
            "non-admin / user-facing path (reachable secondary state)"
        )
    return True, ""


def economic_grief_passes_narrowing(c: Candidate) -> Tuple[bool, str]:
    """Codex narrowing: must carry attacker-cost < defender-loss evidence.

    Pure 'this costs gas to mitigate' / 'griefing is annoying' → reject.
    """
    blob = " ".join([c.title, c.rationale, c.body]).lower()
    if not blob.strip():
        return False, "economic_grief: empty rationale"
    has_cost_math = any(tok in blob for tok in ECON_GRIEF_COST_TOKENS)
    # Also accept explicit dollar / gwei / wei math like "$5 vs $500".
    has_dollar_pair = bool(
        re.search(r"\$[\d,]+(?:\.\d+)?\s*(?:vs|versus|<|>|to)\s*\$[\d,]+", blob)
    )
    has_gas_pair = bool(
        re.search(
            r"\b\d+\s*(?:gas|wei|gwei|eth)\b.*\b(?:vs|versus|<|>|to)\b.*\b\d+\s*(?:gas|wei|gwei|eth|usd|\$)\b",
            blob,
        )
    )
    if has_cost_math or has_dollar_pair or has_gas_pair:
        # Also reject pure-gas-inconvenience language even if cost-math is
        # present, when it is the ONLY claim. We require at least one of
        # the explicit cost tokens OR explicit dollar-pair / gas-pair math.
        return True, ""
    return False, (
        "economic_grief: hand-wavy — Codex narrowing requires explicit "
        "attacker-cost < defender-loss math (e.g. '$5 vs $500', "
        "'attacker pays 30k gas, defender loses $1200 collateral')"
    )


def candidate_passes_shape_narrowing(c: Candidate) -> Tuple[bool, str]:
    """Dispatch to the per-shape narrowing rule."""
    if c.shape == "stale_config_after_admin_op":
        return stale_config_admin_op_passes_narrowing(c)
    if c.shape == "economic_grief":
        return economic_grief_passes_narrowing(c)
    if c.shape not in SHAPES:
        return False, f"unknown novelty_shape '{c.shape}'"
    # The other 3 shapes don't have Codex-mandated extra narrowing in this
    # MVP. We still require non-empty rationale to avoid blank briefs.
    if not (c.title or c.rationale):
        return False, f"{c.shape}: empty title and rationale"
    return True, ""


# ---------------------------------------------------------------------------
# Negative-space + corpus-distance evidence collection.
# ---------------------------------------------------------------------------

def collect_negative_space_evidence(c: Candidate) -> Dict[str, Any]:
    covered = list(COVERED_CLASSES_BY_SHAPE.get(c.shape, ()))
    uncovered_pair = ""
    if c.contract or c.function:
        uncovered_pair = (
            f"{c.contract}::{c.function} x {c.interaction}".strip(" :x")
        )
    # `pattern_dedupe_neighbours` — empty in MVP unless operator-supplied
    # `extra_evidence` pre-populated it (seed-evidence MVP). Runtime
    # composition with `pattern-dedupe.py` is a follow-up ticket; that tool
    # wants the full DSL corpus loaded so we keep it out of the hot path
    # here and just thread the plumbing through `extra_evidence`.
    neighbours = c.extra_evidence.get("pattern_dedupe_neighbours", []) or []
    if not isinstance(neighbours, list):
        neighbours = []
    return {
        "covered_classes_checked": covered,
        "uncovered_pair": uncovered_pair,
        "pattern_dedupe_neighbours": neighbours,
    }


def collect_corpus_distance_evidence(
    c: Candidate, prior_audit_text: str, no_shell_out: bool
) -> Dict[str, Any]:
    """Seed-evidence MVP: consumes precomputed
    `extra_evidence['corpus_distance_matches']` +
    `extra_evidence['corpus_distance_keywords']` if the operator already ran
    `originality-grep.sh` out-of-band; otherwise falls back to a cheap
    in-process substring scan against `<workspace>/prior_audits/` text. The
    probe does NOT shell out to `originality-grep.sh` itself in this MVP —
    runtime shell-out is a follow-up ticket.
    """
    keywords = c.extra_evidence.get("corpus_distance_keywords", []) or []
    if not isinstance(keywords, list):
        keywords = []
    if not keywords:
        # Derive cheap keywords from contract / function / shape tokens.
        derived: List[str] = []
        for tok in (c.contract, c.function, c.interaction):
            if tok and isinstance(tok, str):
                derived.append(tok)
        derived.extend(c.shape.split("_"))
        keywords = [k for k in derived if k]
    matches = c.extra_evidence.get("corpus_distance_matches", []) or []
    if not isinstance(matches, list):
        matches = []
    # Cheap in-process substring grep across the prior_audits corpus when
    # we have it loaded; this is a fallback when shelling out is disabled.
    if not matches and prior_audit_text and not no_shell_out:
        for k in keywords:
            if not k:
                continue
            if re.search(re.escape(k), prior_audit_text, re.IGNORECASE):
                matches.append({"keyword": k, "in": "prior_audits"})
    is_empty = len(matches) == 0
    return {
        "originality_grep_keywords": keywords,
        "matches": matches,
        "is_empty": is_empty,
    }


def collect_ccia_reachability(
    c: Candidate, ws: Path, ccia_angles: Sequence[Dict[str, Any]]
) -> Dict[str, Any]:
    report_path = ""
    for cand in (
        ws / "ccia_report.json",
        ws / "ccia_report.md",
        ws / "CCIA_REPORT.md",
    ):
        if cand.exists():
            report_path = str(cand)
            break
    reachable: Optional[bool] = c.ccia_reachable
    rationale = c.ccia_rationale
    if reachable is None and c.ccia_angle_id and ccia_angles:
        for a in ccia_angles:
            if a.get("id") == c.ccia_angle_id:
                # Presence of the angle in CCIA implies reachability per the
                # CCIA semantics; rationale defaults to the angle title.
                reachable = True
                if not rationale:
                    rationale = str(a.get("title", "")) or rationale
                break
    return {
        "report_path": report_path,
        "reachable": reachable,
        "rationale": rationale,
    }


def collect_dedup_evidence(c: Candidate) -> Dict[str, Any]:
    """variant-detector / dedup-grep proxy (seed-evidence MVP).

    The probe does NOT shell out to `variant-detector.py` or `dedup-grep.py`
    at runtime in this MVP — `variant-detector.py` wants a fully rendered
    draft on disk before scoring, and `dedup-grep.py` wants the prior_audits
    corpus loaded. Instead we consume precomputed evidence supplied by the
    operator (or a follow-up orchestrator) via `extra_evidence`. Wiring
    runtime composition is an explicit follow-up ticket.
    """
    score = c.extra_evidence.get("variant_detector_score", 0)
    try:
        score = int(score)
    except Exception:
        score = 0
    matches = c.extra_evidence.get("dedup_grep_matches", []) or []
    if not isinstance(matches, list):
        matches = []
    ap26 = c.extra_evidence.get("anti_pattern_26_clear", True)
    if not isinstance(ap26, bool):
        ap26 = True
    return {
        "variant_detector_score": score,
        "dedup_grep_matches": matches,
        "anti_pattern_26_clear": ap26,
    }


def collect_scope_oos_evidence(c: Candidate) -> Dict[str, Any]:
    ap25 = c.extra_evidence.get("anti_pattern_25_clear", True)
    if not isinstance(ap25, bool):
        ap25 = True
    centralization_risk = bool(c.extra_evidence.get("centralization_risk", False))
    cap_usd = c.extra_evidence.get("absurd_capital_required_usd", None)
    if cap_usd is not None:
        try:
            cap_usd = float(cap_usd)
        except Exception:
            cap_usd = None
    return {
        "anti_pattern_25_clear": ap25,
        "centralization_risk": centralization_risk,
        "absurd_capital_required_usd": cap_usd,
    }


# ---------------------------------------------------------------------------
# Confidence resolution — ADVISORY ONLY (Codex correction #4).
# ---------------------------------------------------------------------------

def resolve_confidence(sidecar: Dict[str, Any]) -> str:
    """Map evidence into one of {high, medium, low, needs_review, unknown}.

    Hard rules:
      - CCIA reachability evidence missing  → `unknown`
      - variant-detector score >= 70        → `needs_review`
      - variant-detector score in 30..69    → `needs_review`
      - anti_pattern_26 not clear           → `needs_review`
      - centralization_risk True            → `needs_review`
      - corpus_distance not empty AND no    → `low`
        explicit clearance evidence
      - everything-clear path:
          high   if pattern_dedupe_neighbours empty AND
                    corpus_distance_evidence.is_empty AND
                    ccia.reachable is True
          medium otherwise
    """
    ccia = sidecar.get("ccai_or_ccia_reachability") or {}
    if ccia.get("reachable") is None:
        return "unknown"
    dedup = sidecar.get("dedup_evidence") or {}
    if int(dedup.get("variant_detector_score", 0)) >= 30:
        return "needs_review"
    if dedup.get("anti_pattern_26_clear") is False:
        return "needs_review"
    scope = sidecar.get("scope_oos_evidence") or {}
    if scope.get("centralization_risk") is True:
        return "needs_review"
    if scope.get("anti_pattern_25_clear") is False:
        return "needs_review"
    corpus = sidecar.get("corpus_distance_evidence") or {}
    neg = sidecar.get("negative_space_evidence") or {}
    neighbours = neg.get("pattern_dedupe_neighbours") or []
    if not corpus.get("is_empty", True):
        # Real corpus matches exist — operator must explicitly clear.
        return "low"
    if not ccia.get("reachable"):
        return "needs_review"
    if not neighbours and corpus.get("is_empty") and ccia.get("reachable") is True:
        return "high"
    return "medium"


# ---------------------------------------------------------------------------
# Brief rendering — mining-brief-compatible (markdown headings match the
# established schema closely enough that downstream consumers and human
# reviewers will see the same shape).
# ---------------------------------------------------------------------------

def slugify(text: str, maxlen: int = 40) -> str:
    out = re.sub(r"[^\w\-]", "_", text or "")
    out = re.sub(r"_+", "_", out).strip("_")
    return out[:maxlen] or "candidate"


def render_brief_markdown(rank: int, c: Candidate, sidecar: Dict[str, Any]) -> str:
    confidence = sidecar.get("confidence", "unknown")
    contract = c.contract or "UNKNOWN"
    func = c.function or ""
    ccia = sidecar.get("ccai_or_ccia_reachability") or {}
    corpus = sidecar.get("corpus_distance_evidence") or {}
    neg = sidecar.get("negative_space_evidence") or {}
    dedup = sidecar.get("dedup_evidence") or {}
    scope = sidecar.get("scope_oos_evidence") or {}
    lines: List[str] = []
    # The H1 must carry the operator-authored title so check-novel-vector.sh
    # (which extracts the first H1) sees a function + verb + impact, not a
    # generic "Brief #NNN — shape" header. Brief metadata moves to the
    # subtitle / metadata block.
    lines.append(f"# {c.title or '(untitled candidate)'}")
    lines.append("")
    lines.append(f"_Novel-Hypothesis Brief #{rank:03d} — `{c.shape}`_")
    lines.append("")
    lines.append(f"**Novelty shape:** `{c.shape}`")
    lines.append(f"**Target:** `{contract}`{('.' + func) if func else ''}")
    if c.interaction:
        lines.append(f"**Interaction:** {c.interaction}")
    lines.append(f"**Confidence (advisory only):** `{confidence}`")
    lines.append("")
    lines.append("## Negative-space evidence")
    covered = neg.get("covered_classes_checked") or []
    if covered:
        lines.append(
            "Covered classes checked (NOT a match for this candidate): "
            + ", ".join(f"`{x}`" for x in covered)
        )
    if neg.get("uncovered_pair"):
        lines.append(f"Uncovered pair: `{neg['uncovered_pair']}`")
    if neg.get("pattern_dedupe_neighbours"):
        lines.append(
            "Pattern-dedupe neighbours (review): "
            + ", ".join(str(x) for x in neg["pattern_dedupe_neighbours"])
        )
    lines.append("")
    lines.append("## Corpus-distance evidence")
    keys = corpus.get("originality_grep_keywords") or []
    if keys:
        lines.append("Keywords checked: " + ", ".join(f"`{k}`" for k in keys))
    if corpus.get("is_empty"):
        lines.append("originality-grep result: **empty** (novel-finding candidate).")
    else:
        lines.append("originality-grep matches:")
        for m in corpus.get("matches") or []:
            if isinstance(m, dict):
                lines.append(f"- {m}")
            else:
                lines.append(f"- {str(m)}")
    lines.append("")
    lines.append("## CCIA reachability")
    if ccia.get("reachable") is True:
        lines.append("Reachable per CCIA report.")
    elif ccia.get("reachable") is False:
        lines.append("CCIA marks the path NOT reachable.")
    else:
        lines.append("CCIA reachability **unknown** — confidence demoted accordingly.")
    if ccia.get("report_path"):
        lines.append(f"Report: `{ccia['report_path']}`")
    if ccia.get("rationale"):
        lines.append(f"Rationale: {ccia['rationale']}")
    lines.append("")
    lines.append("## Dedup evidence")
    lines.append(
        f"variant-detector score: **{dedup.get('variant_detector_score', 0)}**"
    )
    if dedup.get("dedup_grep_matches"):
        lines.append("dedup-grep hits:")
        for h in dedup["dedup_grep_matches"]:
            lines.append(f"- {h}")
    lines.append(
        "anti-pattern #26 clear: "
        + ("yes" if dedup.get("anti_pattern_26_clear") else "**NO — review**")
    )
    lines.append("")
    lines.append("## Scope / OOS evidence")
    lines.append(
        "anti-pattern #25 clear: "
        + ("yes" if scope.get("anti_pattern_25_clear") else "**NO — review**")
    )
    lines.append(
        "centralization risk flagged: "
        + ("**yes — review**" if scope.get("centralization_risk") else "no")
    )
    cap = scope.get("absurd_capital_required_usd")
    if cap is not None:
        lines.append(f"capital required (USD): {cap}")
    lines.append("")
    lines.append("## Mechanism (operator-authored)")
    lines.append("")
    lines.append(c.rationale or "_(no rationale supplied; populate before mining)_")
    if c.body:
        lines.append("")
        lines.append("### Notes")
        lines.append("")
        lines.append(c.body)
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        "_Generated by `tools/novel-hypothesis-probe.py` (PR #126 MVP). "
        "Confidence is advisory; no submission / dispatch gate consumes it._"
    )
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Candidate construction.
# ---------------------------------------------------------------------------

def coerce_candidate(d: Dict[str, Any]) -> Optional[Candidate]:
    shape = str(d.get("shape", "") or d.get("novelty_shape", "")).strip()
    if shape not in SHAPES:
        return None
    extra = d.get("extra_evidence") or {}
    if not isinstance(extra, dict):
        extra = {}
    return Candidate(
        shape=shape,
        title=str(d.get("title", "") or ""),
        contract=str(d.get("contract", "") or ""),
        function=str(d.get("function", "") or ""),
        interaction=str(d.get("interaction", "") or ""),
        rationale=str(d.get("rationale", "") or ""),
        body=str(d.get("body", "") or ""),
        ccia_angle_id=str(d.get("ccia_angle_id", "") or ""),
        ccia_reachable=d.get("ccia_reachable"),
        ccia_rationale=str(d.get("ccia_rationale", "") or ""),
        extra_evidence=extra,
    )


# ---------------------------------------------------------------------------
# check-novel-vector.sh hook — a brief whose title fails the rule has its
# confidence demoted to needs_review (Codex consistency: the existing
# Check #9 enforces novel-vector titling).
# ---------------------------------------------------------------------------

def title_fails_novel_vector(title: str) -> bool:
    """Lightweight in-process re-implementation of check-novel-vector.sh.

    The shell script enforces:
      1. title contains a function-like identifier (camelCase or .name())
      2. title contains an action verb
    We mirror just enough to demote bad titles. Real wiring still runs the
    shell tool when available; this function is the deterministic fallback.
    """
    if not title:
        return True
    has_fn = bool(
        re.search(r"[a-z][A-Z][a-zA-Z]+", title)
        or re.search(r"\.[a-z_][a-zA-Z_]+\(", title)
    )
    if not has_fn:
        return True
    action_verbs = (
        "drains", "drain", "allows", "enables", "reverts", "overflows",
        "underflows", "skips", "leaves", "leaks", "bricks", "locks",
        "burns", "double", "replays",
    )
    if not any(re.search(rf"\b{v}\b", title, re.IGNORECASE) for v in action_verbs):
        return True
    return False


def maybe_run_check_novel_vector(brief_md_path: Path) -> bool:
    """Best-effort: if the shell tool is in-tree, run it. Else fall back to
    the in-process check above on the H1 title.
    """
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "tools" / "check-novel-vector.sh"
    if script.is_file() and shutil.which("sh"):
        try:
            proc = subprocess.run(
                ["sh", str(script), str(brief_md_path)],
                capture_output=True, text=True, timeout=10,
            )
            return proc.returncode == 0
        except Exception:
            pass
    # Fallback: parse first H1.
    try:
        for ln in brief_md_path.read_text().splitlines():
            m = re.match(r"^#\s+(.*)$", ln)
            if m:
                return not title_fails_novel_vector(m.group(1))
    except Exception:
        return True
    return True


# ---------------------------------------------------------------------------
# Main probe.
# ---------------------------------------------------------------------------

def run_probe(
    ws: Path,
    *,
    top: int = 10,
    out_dir: Optional[Path] = None,
    seeds_path: Optional[Path] = None,
    no_shell_out: bool = False,
) -> Dict[str, Any]:
    """Run the probe end-to-end and write artifacts. Returns the run summary."""
    out_dir = out_dir or (ws / "swarm" / "novel_hypothesis_briefs")
    out_dir.mkdir(parents=True, exist_ok=True)

    _, ccia_angles = load_ccia_angles(ws)
    seeds = load_seeds(ws, seeds_path)
    prior_audit_text = "" if no_shell_out else load_prior_audit_corpus(ws)

    # I-09 (PR #158 session): the probe was silent on workspaces that had
    # neither a seeds file nor an explicit `--seeds` override. Operators
    # saw `raw=0 accepted=0 rejected=0` and could not tell whether the
    # probe had nothing to say or had simply found no input. Surface the
    # condition explicitly via `loader_status` so downstream callers can
    # distinguish "no seeds available" from "all candidates rejected".
    seed_candidate_paths: List[Path] = []
    if seeds_path:
        seed_candidate_paths.append(Path(seeds_path).expanduser())
    seed_candidate_paths.append(ws / "novel_hypothesis_seeds.json")
    seeds_file_present = any(p.is_file() for p in seed_candidate_paths)
    if not seeds:
        if not seeds_file_present:
            loader_status = "no_seeds_file_found"
        else:
            loader_status = "seeds_file_empty_or_invalid"
    else:
        loader_status = "seeds_loaded"

    raw_candidates: List[Candidate] = []
    for s in seeds:
        c = coerce_candidate(s)
        if c is None:
            continue
        raw_candidates.append(c)

    accepted: List[Brief] = []
    rejected: List[Dict[str, Any]] = []

    for c in raw_candidates:
        ok, reason = candidate_passes_shape_narrowing(c)
        if not ok:
            rejected.append({
                "shape": c.shape,
                "title": c.title,
                "reason": reason,
            })
            continue

        sidecar = {
            "novelty_shape": c.shape,
            "negative_space_evidence": collect_negative_space_evidence(c),
            "corpus_distance_evidence": collect_corpus_distance_evidence(
                c, prior_audit_text, no_shell_out
            ),
            "ccai_or_ccia_reachability": collect_ccia_reachability(
                c, ws, ccia_angles
            ),
            "dedup_evidence": collect_dedup_evidence(c),
            "scope_oos_evidence": collect_scope_oos_evidence(c),
            "confidence": "unknown",
        }
        sidecar["confidence"] = resolve_confidence(sidecar)
        # Title-rule demotion.
        if title_fails_novel_vector(c.title):
            if sidecar["confidence"] in ("high", "medium"):
                sidecar["confidence"] = "needs_review"

        rank = len(accepted) + 1
        md = render_brief_markdown(rank, c, sidecar)
        accepted.append(Brief(rank=rank, candidate=c, sidecar=sidecar, markdown=md))
        if rank >= top:
            break

    # Write artifacts.
    written: List[str] = []
    for b in accepted:
        slug = slugify(b.candidate.title or b.candidate.function or b.candidate.shape)
        stem = f"brief_{b.rank:03d}_{b.candidate.shape}_{slug}"
        md_path = out_dir / f"{stem}.md"
        json_path = out_dir / f"{stem}.json"
        md_path.write_text(b.markdown)
        json_path.write_text(json.dumps(b.sidecar, indent=2, sort_keys=True) + "\n")
        # Re-run the shell title rule once the md is on disk; a failure
        # demotes confidence in BOTH markdown body and json sidecar.
        if not maybe_run_check_novel_vector(md_path):
            if b.sidecar["confidence"] in ("high", "medium"):
                b.sidecar["confidence"] = "needs_review"
                json_path.write_text(
                    json.dumps(b.sidecar, indent=2, sort_keys=True) + "\n"
                )
                md_path.write_text(render_brief_markdown(b.rank, b.candidate, b.sidecar))
        written.append(stem)

    summary = {
        "workspace": str(ws),
        "out_dir": str(out_dir),
        "accepted": [
            {
                "rank": b.rank,
                "shape": b.candidate.shape,
                "title": b.candidate.title,
                "confidence": b.sidecar["confidence"],
            }
            for b in accepted
        ],
        "rejected": rejected,
        "counts": {
            "raw": len(raw_candidates),
            "accepted": len(accepted),
            "rejected": len(rejected),
        },
        "loader_status": loader_status,
        "shapes_supported": list(SHAPES),
        "mvp_invariants": {
            "auto_dispatch": False,
            "confidence_consumed_by_gate": False,
        },
    }
    (out_dir / "index.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("workspace", help="Audit workspace directory")
    p.add_argument("--top", type=int, default=10, help="Cap on emitted briefs")
    p.add_argument("--out-dir", default=None, help="Override output directory")
    p.add_argument("--seeds", default=None, help="Operator-supplied seed JSON")
    p.add_argument(
        "--no-shell-out",
        action="store_true",
        help="Seed-evidence MVP: skip the in-process prior_audits/ substring "
             "scan (used by hermetic tests). Reserved for future "
             "runtime-shell-out mode against originality-grep / "
             "variant-detector / dedup-grep — those subprocesses are NOT "
             "invoked in this MVP.",
    )
    args = p.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.exists():
        print(f"[novel-probe] workspace not found: {ws}", file=sys.stderr)
        return 1

    summary = run_probe(
        ws,
        top=args.top,
        out_dir=Path(args.out_dir).expanduser() if args.out_dir else None,
        seeds_path=Path(args.seeds).expanduser() if args.seeds else None,
        no_shell_out=args.no_shell_out,
    )
    print(
        f"[novel-probe] ws={ws.name} "
        f"raw={summary['counts']['raw']} "
        f"accepted={summary['counts']['accepted']} "
        f"rejected={summary['counts']['rejected']} "
        f"loader={summary['loader_status']}"
    )
    if summary["counts"]["raw"] == 0 and summary["loader_status"] == "no_seeds_file_found":
        print(
            "[novel-probe] hint: workspace has no novel_hypothesis_seeds.json. "
            "Author one with the candidate hypothesis shapes "
            f"({', '.join(sorted(summary['shapes_supported']))}) or pass --seeds.",
            file=sys.stderr,
        )
    for row in summary["accepted"]:
        print(
            f"  #{row['rank']:03d} {row['shape']:32s} "
            f"confidence={row['confidence']:13s} "
            f"{row['title'][:60]}"
        )
    if summary["rejected"]:
        print("[novel-probe] rejected:")
        for r in summary["rejected"]:
            print(f"  - shape={r['shape']:32s} reason={r['reason'][:90]}")
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
