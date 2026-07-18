#!/usr/bin/env python3
"""engagement-prescreen.py - Phase 0 L0.4 corpus-fit prescreen for active /
upcoming bounty engagements.

Counter-test for HACKER_BRAIN_MASTER_PLAN §5 Phase 0 L0.4 "engagement-rate
ceiling": ranks a candidate engagement by how much of our existing corpus
(61K records + 1,494 detectors + 38 R-rules) is applicable to its target
type, so the operator can pre-select engagements where we have an edge
BEFORE committing audit hours.

Inputs:
  --target-meta '{"languages":["solidity","go"],
                  "categories":["bridge","lending","oracle"],
                  "code_loc":15000,
                  "audit_pin":"<sha>"}'
  --workspace-path <ws>      # OPTIONAL. When present, the tool reads
                             # SCOPE.md / SEVERITY.md / INTAKE_BASELINE.md /
                             # prior_audits/ to infer target-meta when
                             # --target-meta is absent or partial. Also
                             # boosts the prior-audit-similarity score.
  --json                     # JSON output instead of markdown.
  --workspace-name <name>    # Optional override of the engagement name
                             # surfaced in the report.

Outputs (schema `auditooor.engagement_prescreen.v1`):
  - corpus_fit_score: 0..100 composite of
      {language_coverage * 0.35,
       detector_density   * 0.25,
       R_rule_hits_per_kloc * 0.20,
       prior_audit_similarity * 0.20}
  - per-language detector count + R-rule applicability
  - category hits in `vault_bug_family_heatmap`
  - recommended workspace setup time estimate (vs cold-start)
  - verdict: HIGH-FIT (>=70) | MEDIUM-FIT (40-69) | LOW-FIT (<40)

The tool is read-only, stdlib-only, network-free. It reads
- `reference/patterns.dsl*/...` for detector and per-language counts
  (mirrors the data surfaced by `vault_language_patterns`).
- `CLAUDE.md` for R-rule presence (counts rules whose body language
  matches the target's languages or categories).
- Optional `<workspace>/INTAKE_BASELINE.md`, `<workspace>/SCOPE.md`,
  `<workspace>/SEVERITY.md`, `<workspace>/prior_audits/` for workspace-
  level context.

Verdict thresholds are tunable via env hooks:
  AUDITOOOR_PRESCREEN_HIGH_THRESHOLD  (default 70)
  AUDITOOOR_PRESCREEN_MEDIUM_THRESHOLD (default 40)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.engagement_prescreen.v1"

# Canonical language set (mirrors vault_language_patterns output).
CANONICAL_LANGUAGES = ("solidity", "rust", "go", "move", "cairo", "vyper")

# Category -> canonical bug-family clusters. When a target declares one of
# these categories, the corresponding bug families count as "applicable"
# corpus surface, even if they were never observed for that exact target.
CATEGORY_TO_BUG_FAMILIES: dict[str, set[str]] = {
    "bridge": {
        "cross-chain-auth",
        "signature-replay",
        "refund-escrow-loss",
        "state-machine-race",
        "deploy-state-divergence",
        "batching-auth",
    },
    "lending": {
        "oracle-staleness",
        "reentrancy",
        "rounding-asymmetry",
        "decimals-mismatch",
        "integer-casting",
        "approval-abuse",
    },
    "oracle": {
        "oracle-staleness",
        "decimals-mismatch",
        "rounding-asymmetry",
    },
    "dex": {
        "reentrancy",
        "rounding-asymmetry",
        "decimals-mismatch",
        "hook-bypass",
        "state-machine-race",
        "approval-abuse",
    },
    "perpetuals": {
        "oracle-staleness",
        "rounding-asymmetry",
        "state-machine-race",
        "integer-casting",
    },
    "rollup": {
        "cross-chain-auth",
        "signature-replay",
        "state-machine-race",
        "deploy-state-divergence",
    },
    "vault": {
        "rounding-asymmetry",
        "reentrancy",
        "hook-bypass",
        "approval-abuse",
        "decimals-mismatch",
    },
    "staking": {
        "rounding-asymmetry",
        "approval-abuse",
        "reentrancy",
        "state-machine-race",
    },
    "amm": {
        "reentrancy",
        "rounding-asymmetry",
        "decimals-mismatch",
        "hook-bypass",
    },
    "governance": {
        "access-control-escalation",
        "state-machine-race",
        "signature-replay",
    },
    "bitcoin-l2": {
        "signature-replay",
        "state-machine-race",
        "cross-chain-auth",
    },
    "cosmos-appchain": {
        "state-machine-race",
        "cross-chain-auth",
        "access-control-escalation",
    },
}

DEFAULT_HIGH_THRESHOLD = 70
DEFAULT_MEDIUM_THRESHOLD = 40


def _err(msg: str) -> None:
    print(f"[engagement-prescreen] {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Corpus inventory (mirrors vault_language_patterns output, but local-disk)
# ---------------------------------------------------------------------------


# Path-tagged language inference for `reference/patterns.dsl.<wave>_<tag>/...`
# directories. Most patterns are Solidity (no language suffix); per-language
# directories use these explicit suffixes.
_LANG_DIR_SUFFIX = {
    "_go": "go",
    "_rust": "rust",
    "_move": "move",
    "_cairo": "cairo",
    "_vyper": "vyper",
    "_sway": "sway",
}

# Path-tagged bug-family inference for `reference/patterns.dsl.r94_solodit_<cat>/`
# style directories. Maps the suffix to a canonical bug-family/category.
_CATEGORY_DIR_SUFFIX = {
    "_oracle": "oracle-staleness",
    "_oracle2": "oracle-staleness",
    "_reentrancy": "reentrancy",
    "_reentrancy2": "reentrancy",
    "_sigreplay": "signature-replay",
    "_sigreplay2": "signature-replay",
    "_sig": "signature-replay",
    "_bridge": "cross-chain-auth",
    "_accesscontrol": "access-control-escalation",
    "_governance": "access-control-escalation",
    "_governance2": "access-control-escalation",
    "_aa": "signature-replay",
    "_hooks": "hook-bypass",
    "_callback": "reentrancy",
    "_erc4626": "rounding-asymmetry",
    "_vault2": "rounding-asymmetry",
    "_wrongmath": "rounding-asymmetry",
    "_liquidation": "rounding-asymmetry",
    "_perps": "state-machine-race",
    "_amm": "rounding-asymmetry",
    "_amm2": "rounding-asymmetry",
    "_clob": "state-machine-race",
    "_staking": "state-machine-race",
    "_restaking": "state-machine-race",
    "_layerzero": "cross-chain-auth",
    "_token_standard": "approval-abuse",
    "_tokenomics": "rounding-asymmetry",
    "_stablecoin": "rounding-asymmetry",
    "_proxy": "access-control-escalation",
    "_vesting": "state-machine-race",
    "_flashloan": "reentrancy",
    "_mev": "state-machine-race",
    "_zk": "signature-replay",
    "_nft": "approval-abuse",
    "_func": "state-machine-race",
    "_crypto": "signature-replay",
    "_circom": "signature-replay",
}


def _classify_pattern_dir(dirname: str) -> tuple[str | None, str | None]:
    """Infer (language, bug_family) from a pattern-dir name like
    `patterns.dsl.r94_solodit_oracle` -> ('solidity', 'oracle-staleness').

    Pure path-based inference - no file-content reads. Returns
    (language, bug_family); either may be None when uninferable.
    """
    name = dirname.lower()
    if not name.startswith("patterns.dsl"):
        return None, None
    # extract the suffix after `patterns.dsl[.<...>]`
    suffix = name.replace("patterns.dsl", "").lstrip(".")
    lang: str | None = None
    fam: str | None = None
    for marker, l in _LANG_DIR_SUFFIX.items():
        if suffix.endswith(marker):
            lang = l
            break
    if lang is None:
        # solidity is the implicit default for the un-suffixed solodit dirs
        if "solodit" in suffix or suffix == "" or "polymarket" in suffix:
            lang = "solidity"
    for marker, f in _CATEGORY_DIR_SUFFIX.items():
        if marker in suffix:
            fam = f
            break
    return lang, fam


def _scan_pattern_corpus(repo_root: Path) -> dict[str, Any]:
    """Walk `reference/patterns.dsl*` and count YAML files per language /
    bug-family using path-based inference.

    This is a path-only scan: no per-file content reads, so it is O(files)
    cheap (~4900 files in <1s). The path-name conventions are documented
    in `_LANG_DIR_SUFFIX` and `_CATEGORY_DIR_SUFFIX` above.

    A YAML inside a dir whose suffix names BOTH a language AND a category
    contributes to BOTH counters. A YAML whose dir tags neither is counted
    as `solidity` (the corpus-wide default).
    """
    summary: dict[str, int] = {lang: 0 for lang in CANONICAL_LANGUAGES}
    total = 0
    bug_family_counts: dict[str, int] = {}
    bases = [
        p for p in (repo_root / "reference").glob("patterns.dsl*")
        if p.is_dir()
    ]
    for base in bases:
        lang, fam = _classify_pattern_dir(base.name)
        # count YAMLs at any depth under this base
        count = sum(1 for _ in base.rglob("*.yaml"))
        total += count
        if lang and lang in summary:
            summary[lang] += count
        if fam:
            bug_family_counts[fam] = bug_family_counts.get(fam, 0) + count
    return {
        "language_summary": summary,
        "total_patterns": total,
        "bug_family_counts": bug_family_counts,
    }


def _count_r_rules(repo_root: Path) -> dict[str, Any]:
    """Count R-rules from authoritative registries.

    Sources, in priority order:
      1. ``~/.claude/CLAUDE.md`` (the operator's global rule registry;
         contains every codified Rule N).
      2. ``<repo_root>/CLAUDE.md`` (the repo-local copy; may lag).
      3. ``<repo_root>/AGENTS.md``.

    Header shapes recognised: ``## Hard rule: ... (Rule NN)``,
    ``### Rule NN``, and inline ``(Rule NN)`` citations.
    """
    candidates = [
        Path.home() / ".claude" / "CLAUDE.md",
        repo_root / "CLAUDE.md",
        repo_root / "AGENTS.md",
    ]
    r_rule_ids: set[int] = set()
    for path in candidates:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in re.finditer(r"\(Rule\s+(\d+)\)", text):
            r_rule_ids.add(int(m.group(1)))
        for m in re.finditer(r"^###\s+Rule\s+(\d+)", text, re.M):
            r_rule_ids.add(int(m.group(1)))
        for m in re.finditer(r"^##\s+Hard rule:[^\n]*\(Rule\s+(\d+)\)", text, re.M):
            r_rule_ids.add(int(m.group(1)))
    return {"r_rule_count": len(r_rule_ids), "r_rule_ids": sorted(r_rule_ids)}


# ---------------------------------------------------------------------------
# Workspace introspection (optional, when --workspace-path is given)
# ---------------------------------------------------------------------------


_LANG_HINTS = {
    "solidity": (r"\bsolidity\b", r"\.sol\b", r"smart contract"),
    "rust": (r"\brust\b", r"\.rs\b", r"cargo", r"substrate", r"pallet"),
    "go": (r"\bgo(?:lang)?\b", r"\.go\b", r"cosmos[- ]?sdk", r"cometbft"),
    "move": (r"\bmove\b", r"\.move\b", r"aptos", r"\bsui\b"),
    "cairo": (r"\bcairo\b", r"\.cairo\b", r"starknet"),
    "vyper": (r"\bvyper\b", r"\.vy\b"),
}

_CATEGORY_HINTS = {
    "bridge": (r"\bbridge\b", r"cross[- ]chain", r"ismp\b", r"\bhyperbridge\b"),
    "lending": (r"\blending\b", r"\bborrow\b", r"\bcollateral\b", r"\bmorpho\b"),
    "oracle": (r"\boracle\b", r"\bchainlink\b", r"\bpyth\b"),
    "dex": (r"\bdex\b", r"\bswap\b", r"uniswap", r"orderbook"),
    "perpetuals": (r"\bperpetual\b", r"\bperps?\b", r"\bdydx\b"),
    "rollup": (r"\brollup\b", r"\bl2\b", r"\boptimism\b", r"\barbitrum\b"),
    "vault": (r"\bvault\b", r"\berc[- ]?4626\b"),
    "staking": (r"\bstak(?:e|ing)\b", r"\brestak(?:e|ing)\b"),
    "amm": (r"\bamm\b", r"\bcurve\b", r"\bbalancer\b"),
    "governance": (r"\bgovernance\b", r"\bgov\b", r"\bvoting\b"),
    "bitcoin-l2": (r"\bbitcoin\b", r"\blightning\b", r"\bspark\b", r"\bstatechain\b"),
    "cosmos-appchain": (r"\bcosmos\b", r"\bappchain\b", r"\bibc\b"),
}


def _infer_target_meta_from_workspace(ws: Path) -> dict[str, Any]:
    """Best-effort inference when --target-meta is absent / partial.

    Reads SCOPE.md, SEVERITY.md, INTAKE_BASELINE.md and looks for language
    / category hints. NEVER fails - missing files become empty result.
    """
    languages: set[str] = set()
    categories: set[str] = set()
    code_loc: int | None = None
    audit_pin: str | None = None

    text_corpus = ""
    for name in ("SCOPE.md", "SEVERITY.md", "INTAKE_BASELINE.md"):
        p = ws / name
        if not p.is_file():
            continue
        try:
            text_corpus += "\n" + p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    low = text_corpus.lower()

    for lang, patterns in _LANG_HINTS.items():
        for pat in patterns:
            if re.search(pat, low):
                languages.add(lang)
                break
    for cat, patterns in _CATEGORY_HINTS.items():
        for pat in patterns:
            if re.search(pat, low):
                categories.add(cat)
                break

    m = re.search(r"audit[ _-]?pin[^\n]*?([0-9a-f]{8,40})", text_corpus, re.I)
    if m:
        audit_pin = m.group(1)
    # rough LoC bucket (orders-of-magnitude): use INTAKE_BASELINE "Files indexed"
    m = re.search(r"Files indexed.*?(\d{2,7})", text_corpus)
    if m:
        # heuristic: ~250 LoC per indexed file
        code_loc = int(m.group(1)) * 250

    return {
        "languages": sorted(languages),
        "categories": sorted(categories),
        "code_loc": code_loc,
        "audit_pin": audit_pin,
    }


def _measure_prior_audit_similarity(ws: Path | None) -> dict[str, Any]:
    """Score 0..100 - how much prior-audit context the workspace ships.

    Heuristic:
      - 0 prior_audits files: 0
      - 1-2: 30
      - 3-5: 60
      - >=6: 100
    Plus +20 if ANY prior_audits file mentions a familiar bug family from
    `CATEGORY_TO_BUG_FAMILIES.values()`. Capped at 100.
    """
    if ws is None:
        return {"score": 0, "n_files": 0, "familiar_family_hits": []}
    pa = ws / "prior_audits"
    if not pa.is_dir():
        return {"score": 0, "n_files": 0, "familiar_family_hits": []}
    files = [p for p in pa.iterdir() if p.is_file()]
    n = len(files)
    if n == 0:
        score = 0
    elif n <= 2:
        score = 30
    elif n <= 5:
        score = 60
    else:
        score = 100
    familiar = set()
    for fam_set in CATEGORY_TO_BUG_FAMILIES.values():
        familiar |= fam_set
    fam_hits: list[str] = []
    for p in files:
        try:
            head = p.read_text(encoding="utf-8", errors="replace")[:65536]
        except OSError:
            continue
        for fam in familiar:
            if fam in head and fam not in fam_hits:
                fam_hits.append(fam)
    if fam_hits:
        score = min(100, score + 20)
    return {"score": score, "n_files": n, "familiar_family_hits": fam_hits}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _score_language_coverage(
    target_langs: list[str], lang_summary: dict[str, int]
) -> dict[str, Any]:
    """0..100: per-language absolute-count score, averaged across the
    target's languages.

    Per-language scoring (each is 0..100):
      >=500 patterns -> 100 (saturated)
      100..499        -> 80
      30..99          -> 60
      10..29          -> 40
      1..9            -> 20
      0               -> 0

    A target that names a single language for which we have many
    patterns scores high; a target naming multiple languages we cover
    well also scores high (the score is the AVG, not the SUM, because
    we're measuring "edge per language" not "total surface").
    """
    if not target_langs:
        return {"score": 0, "per_lang": {}, "rationale": "no languages declared"}

    def _bucket(n: int) -> int:
        if n >= 500:
            return 100
        if n >= 100:
            return 80
        if n >= 30:
            return 60
        if n >= 10:
            return 40
        if n >= 1:
            return 20
        return 0

    per_lang: dict[str, dict[str, Any]] = {}
    bucket_scores: list[int] = []
    for lang in target_langs:
        n = lang_summary.get(lang, 0)
        b = _bucket(n)
        per_lang[lang] = {
            "patterns": n,
            "per_lang_score": b,
        }
        bucket_scores.append(b)
    score = round(sum(bucket_scores) / max(len(bucket_scores), 1), 1)
    return {
        "score": score,
        "per_lang": per_lang,
        "rationale": "avg of per-language bucket scores (>=500 patterns = 100)",
    }


def _score_detector_density(
    target_langs: list[str], lang_summary: dict[str, int], code_loc: int | None
) -> dict[str, Any]:
    """0..100: detectors-per-kloc for the target's languages.

    Heuristic: take the sum of patterns across the target's languages,
    divide by the code-LoC in kloc. A density of 0.1 patterns/kloc is
    already strong (a 100-kloc target hit by 10 patterns is enough to
    seed a productive scan); 1 pattern/kloc saturates the score.

    Without code_loc, fall back to raw pattern-count buckets (matches
    the language-coverage bucket spirit so the two scores compose).
    """
    n = sum(lang_summary.get(lang, 0) for lang in target_langs)
    if not code_loc:
        if n >= 500:
            score = 100.0
        elif n >= 100:
            score = 80.0
        elif n >= 30:
            score = 60.0
        elif n >= 10:
            score = 40.0
        elif n >= 1:
            score = 20.0
        else:
            score = 0.0
        return {
            "score": round(score, 1),
            "patterns_for_target_langs": n,
            "code_loc": None,
            "patterns_per_kloc": None,
            "rationale": "no code_loc -> raw pattern-count bucket",
        }
    kloc = max(code_loc / 1000.0, 0.001)
    per_kloc = n / kloc
    # score: 1 pattern/kloc saturates
    score = min(100.0, per_kloc / 1.0 * 100.0)
    return {
        "score": round(score, 1),
        "patterns_for_target_langs": n,
        "code_loc": code_loc,
        "patterns_per_kloc": round(per_kloc, 4),
        "rationale": "1 pattern/kloc = 100",
    }


def _score_r_rule_hits_per_kloc(
    r_rule_count: int, code_loc: int | None
) -> dict[str, Any]:
    """0..100: R-rule applicability density.

    All R-rules are platform-agnostic by design. The density score is
    (r_rule_count / kloc) scaled. 1 rule per 100 LoC -> 100. 1 rule per
    1000 LoC -> 10.
    """
    if not code_loc:
        score = min(100, r_rule_count / 50.0 * 100.0)
        return {
            "score": round(score, 1),
            "r_rule_count": r_rule_count,
            "code_loc": None,
            "rules_per_kloc": None,
            "rationale": "no code_loc -> raw R-rule-count scaling (50 rules = 100)",
        }
    kloc = max(code_loc / 1000.0, 0.001)
    per_kloc = r_rule_count / kloc
    # score: 0.5 rules/kloc = 100 (50 rules in 100 kloc target = saturated)
    score = min(100, per_kloc / 0.5 * 100.0)
    return {
        "score": round(score, 1),
        "r_rule_count": r_rule_count,
        "code_loc": code_loc,
        "rules_per_kloc": round(per_kloc, 4),
        "rationale": "0.5 rules/kloc = 100",
    }


def _score_category_coverage(
    target_cats: list[str], pattern_bug_families: dict[str, int]
) -> dict[str, Any]:
    """Side-channel: enumerate the bug families the target's categories
    map to + show which ones the corpus actually has detectors for.

    NOT folded into the composite score - it is informational. Returns
    a per-category dict so the report can show the coverage breakdown.
    """
    per_cat: dict[str, dict[str, Any]] = {}
    for cat in target_cats:
        fams = CATEGORY_TO_BUG_FAMILIES.get(cat, set())
        covered = sorted(f for f in fams if pattern_bug_families.get(f, 0) > 0)
        uncovered = sorted(f for f in fams if f not in covered)
        per_cat[cat] = {
            "applicable_bug_families": sorted(fams),
            "covered_in_corpus": covered,
            "uncovered_in_corpus": uncovered,
        }
    return per_cat


def _compute_setup_time_estimate(score: int) -> dict[str, Any]:
    """Setup-time estimate (hours) vs cold-start baseline of 40 h.

    HIGH-FIT (>=70): ~8 h (corpus + R-rules + heatmap apply directly)
    MEDIUM-FIT (40-69): ~20 h (some categories need new detectors)
    LOW-FIT (<40): ~40 h (cold-start; new language or category)
    """
    if score >= DEFAULT_HIGH_THRESHOLD:
        hrs = 8
    elif score >= DEFAULT_MEDIUM_THRESHOLD:
        hrs = 20
    else:
        hrs = 40
    return {"hours_estimated": hrs, "cold_start_baseline_hours": 40, "savings_pct": round((40 - hrs) / 40.0 * 100.0, 1)}


def _verdict_for(score: int) -> str:
    high = int(os.environ.get("AUDITOOOR_PRESCREEN_HIGH_THRESHOLD", DEFAULT_HIGH_THRESHOLD))
    med = int(os.environ.get("AUDITOOOR_PRESCREEN_MEDIUM_THRESHOLD", DEFAULT_MEDIUM_THRESHOLD))
    if score >= high:
        return "HIGH-FIT"
    if score >= med:
        return "MEDIUM-FIT"
    return "LOW-FIT"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def prescreen(
    target_meta: dict[str, Any],
    workspace_path: Path | None = None,
    repo_root: Path | None = None,
    workspace_name: str | None = None,
) -> dict[str, Any]:
    """Compute the prescreen result for a single engagement.

    The repo_root defaults to the location of this script's parent
    (i.e. the auditooor checkout root). Override for tests.
    """
    if repo_root is None:
        repo_root = Path(__file__).resolve().parent.parent

    # When workspace is given AND target_meta is empty, infer from workspace.
    inferred_meta: dict[str, Any] = {}
    used_inferred_fields: list[str] = []
    if workspace_path is not None and workspace_path.is_dir():
        inferred_meta = _infer_target_meta_from_workspace(workspace_path)
    # Merge: explicit target_meta overrides inferred where present.
    merged = dict(inferred_meta)
    for k, v in (target_meta or {}).items():
        if v not in (None, [], "", 0):
            merged[k] = v
    # Track which fields came from inference vs explicit user input.
    for k in ("languages", "categories", "code_loc", "audit_pin"):
        if k in inferred_meta and not (target_meta or {}).get(k):
            used_inferred_fields.append(k)
    languages = sorted({l.lower() for l in (merged.get("languages") or [])})
    categories = sorted({c.lower() for c in (merged.get("categories") or [])})
    code_loc = merged.get("code_loc")
    audit_pin = merged.get("audit_pin")

    corpus = _scan_pattern_corpus(repo_root)
    r_rules = _count_r_rules(repo_root)
    prior_sim = _measure_prior_audit_similarity(workspace_path)

    lang_cov = _score_language_coverage(languages, corpus["language_summary"])
    det_dens = _score_detector_density(
        languages, corpus["language_summary"], code_loc
    )
    rr_dens = _score_r_rule_hits_per_kloc(r_rules["r_rule_count"], code_loc)
    cat_cov = _score_category_coverage(categories, corpus["bug_family_counts"])

    composite = (
        lang_cov["score"] * 0.35
        + det_dens["score"] * 0.25
        + rr_dens["score"] * 0.20
        + prior_sim["score"] * 0.20
    )
    composite = round(composite, 1)
    verdict = _verdict_for(int(composite))
    setup = _compute_setup_time_estimate(int(composite))

    return {
        "schema": SCHEMA,
        "engagement_name": workspace_name
        or (workspace_path.name if workspace_path else "unnamed"),
        "target_meta_used": {
            "languages": languages,
            "categories": categories,
            "code_loc": code_loc,
            "audit_pin": audit_pin,
            "inferred_from_workspace_fields": used_inferred_fields,
        },
        "corpus_fit_score": composite,
        "verdict": verdict,
        "score_breakdown": {
            "language_coverage": lang_cov,
            "detector_density": det_dens,
            "r_rule_hits_per_kloc": rr_dens,
            "prior_audit_similarity": prior_sim,
        },
        "category_coverage": cat_cov,
        "setup_time_estimate": setup,
        "corpus_totals": {
            "total_patterns": corpus["total_patterns"],
            "language_summary": corpus["language_summary"],
            "unique_bug_families_in_corpus": len(corpus["bug_family_counts"]),
            "r_rule_count": r_rules["r_rule_count"],
        },
        "thresholds": {
            "high_fit_min": int(
                os.environ.get(
                    "AUDITOOOR_PRESCREEN_HIGH_THRESHOLD", DEFAULT_HIGH_THRESHOLD
                )
            ),
            "medium_fit_min": int(
                os.environ.get(
                    "AUDITOOOR_PRESCREEN_MEDIUM_THRESHOLD",
                    DEFAULT_MEDIUM_THRESHOLD,
                )
            ),
        },
    }


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def render_markdown(result: dict[str, Any]) -> str:
    out: list[str] = []
    out.append(f"# Engagement Prescreen - {result['engagement_name']}\n")
    out.append(f"- Schema: `{result['schema']}`\n")
    tm = result["target_meta_used"]
    out.append(f"- Languages: {tm['languages']}")
    out.append(f"- Categories: {tm['categories']}")
    out.append(f"- Code LoC: {tm['code_loc']}")
    out.append(f"- Audit pin: {tm['audit_pin']}")
    out.append(f"- Inferred-from-workspace fields: {tm['inferred_from_workspace_fields']}\n")
    out.append(f"## Verdict: **{result['verdict']}** (corpus_fit_score = {result['corpus_fit_score']})\n")
    sb = result["score_breakdown"]
    out.append("## Score breakdown")
    out.append(
        f"- language_coverage = {sb['language_coverage']['score']} (weight 0.35)"
    )
    out.append(
        f"- detector_density = {sb['detector_density']['score']} (weight 0.25)"
    )
    out.append(
        f"- r_rule_hits_per_kloc = {sb['r_rule_hits_per_kloc']['score']} (weight 0.20)"
    )
    out.append(
        f"- prior_audit_similarity = {sb['prior_audit_similarity']['score']} (weight 0.20)"
    )
    out.append("")
    st = result["setup_time_estimate"]
    out.append(
        f"## Setup time estimate: ~{st['hours_estimated']} h "
        f"(vs cold-start {st['cold_start_baseline_hours']} h; "
        f"savings {st['savings_pct']}%)\n"
    )
    out.append("## Category coverage")
    for cat, payload in result["category_coverage"].items():
        cov_n = len(payload["covered_in_corpus"])
        tot = len(payload["applicable_bug_families"])
        out.append(
            f"- **{cat}**: {cov_n}/{tot} bug families covered "
            f"(covered: {payload['covered_in_corpus']}, "
            f"uncovered: {payload['uncovered_in_corpus']})"
        )
    out.append("")
    ct = result["corpus_totals"]
    out.append("## Corpus totals (snapshot)")
    out.append(f"- total_patterns: {ct['total_patterns']}")
    out.append(f"- language_summary: {ct['language_summary']}")
    out.append(
        f"- unique_bug_families_in_corpus: {ct['unique_bug_families_in_corpus']}"
    )
    out.append(f"- r_rule_count: {ct['r_rule_count']}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Corpus-fit prescreen for an engagement")
    p.add_argument(
        "--target-meta",
        default="{}",
        help="JSON: {languages, categories, code_loc, audit_pin}",
    )
    p.add_argument(
        "--workspace-path",
        default=None,
        help="Optional workspace dir under /Users/wolf/audits/<engagement>",
    )
    p.add_argument(
        "--workspace-name",
        default=None,
        help="Override the engagement name surfaced in the report",
    )
    p.add_argument(
        "--repo-root",
        default=None,
        help="Override auditooor repo root (defaults to parent of this script)",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON instead of markdown")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        target_meta = json.loads(args.target_meta)
    except json.JSONDecodeError as e:
        _err(f"--target-meta is not valid JSON: {e}")
        return 2
    ws = Path(args.workspace_path) if args.workspace_path else None
    repo_root = Path(args.repo_root) if args.repo_root else None
    result = prescreen(
        target_meta,
        workspace_path=ws,
        repo_root=repo_root,
        workspace_name=args.workspace_name,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render_markdown(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
