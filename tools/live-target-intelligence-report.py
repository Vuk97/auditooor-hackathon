#!/usr/bin/env python3
"""live-target-intelligence-report.py - P5 MVP3 hunt-prioritization report.

PLAN-P5 (HACKER_BRAIN_MASTER_PLAN §10) ships P5 as the bridge between corpus
knowledge (P1/P2/P3/P4) and live-target action. MVP1 (v1) was the standalone
slice that did NOT require P1/P3/P4 deliverables. MVP2 (v2) COMPOSES the
pillars: per-entry P3 pattern_id + P1 invariant_id citations replace the
v1 ``TBD-P3-*`` placeholders + empty ``p1_invariant_hits`` arrays.

MVP2 scope:
  - all MVP1 fields preserved (schema-compatible superset)
  - ``matched_anti_patterns``: real P3 ``pattern_id`` strings from
    ``obsidian-vault/anti-patterns/v2/<lang>/*.yaml`` joined by detector
    cluster slug -> category mapping. Documented ``no-P3-match`` entry
    when target lang has no anti-pattern for the cluster's category yet.
  - ``matched_p1_invariants``: real ``invariant_id`` strings (e.g.
    ``INV-DET-005``) from
    ``audit/corpus_tags/derived/invariants_{extracted,pilot}.jsonl``
    joined by cluster category + target_lang (``go``/``rust``/``solidity``
    plus the ``any`` cross-language bucket).
  - ``composability_score``: count of (matched P1 + matched P3) per entry.
    Entries with ``composability_score >= AUDITOOOR_P5_COMPOSABILITY_BUMP``
    (default 3) get a one-bucket priority promotion
    (LOW -> MEDIUM, MEDIUM -> HIGH-PRIORITY-HUNT).

MVP3 scope:
  - ``p1_semantic_invariant_gaps``: explicit per-entry gap rows when a
    cluster is only topically matched to P1, has no P1 catalog hit, or has no
    cluster-to-category mapping.
  - ``p4_triager_precheck``: rules-only P4 local precheck output for the
    top ``triager_precheck_budget`` ranked entries. The report calls the
    existing ``tools/triager-pre-filing-simulator.py::build_precheck`` helper
    and preserves the provider boundary: no provider-backed simulation, no
    provider call, no triager verdict/clearance claim.

CLI (unchanged from MVP1):
    python3 tools/live-target-intelligence-report.py \\
      --workspace /Users/wolf/audits/dydx \\
      --output /Users/wolf/audits/dydx/docs/LIVE_TARGET_REPORT.md \\
      [--top-n 50] \\
      [--triager-precheck-budget 10]
      [--if-stale-only]
      [--strict]
      [--json]

Schema: ``auditooor.live_target_intelligence.v3`` (v1/v2 fields preserved).

Stdlib-only. Network-free. Reads optional yaml files via a tiny inline
parser (no PyYAML dependency).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Iterable

SCHEMA = "auditooor.live_target_intelligence.v3"
SCHEMA_V2 = "auditooor.live_target_intelligence.v2"
SCHEMA_V1 = "auditooor.live_target_intelligence.v1"
TOOL_VERSION = "0.4.4-mvp3-bug-bounty-oos-cross-check"
DEFAULT_STALENESS_SECONDS = 3600  # 1 hour
DEFAULT_SHAPE_CLUSTER_PREDICATES_JSONL = (
    "reports/v3_iter_2026-05-25/"
    "lane_II17_PARENT_BATCH_SHAPE_CLUSTER/predicate_candidates.jsonl"
)

# Engage severity bucket weights (LOW/MEDIUM/HIGH from detector hits).
SEVERITY_WEIGHT = {"HIGH": 100, "MEDIUM": 60, "LOW": 30, "INFO": 10}

# Hunt priority thresholds (env-tunable).
HIGH_PRIORITY_THRESHOLD = int(os.environ.get("AUDITOOOR_P5_HIGH_THRESHOLD", "70"))
MEDIUM_PRIORITY_THRESHOLD = int(os.environ.get("AUDITOOOR_P5_MEDIUM_THRESHOLD", "40"))
BUG_BOUNTY_OOS_PRIORITY = "NEEDS-EXTENSION-DISTINCT-ARGUMENT"

# Cap the number of per-cluster entry points we surface (avoids the
# share/cantina-202-triager-evidence/ kind of 418-hit cluster swamping
# the report). The remainder show up in the cluster-summary section.
MAX_ENTRIES_PER_CLUSTER = int(os.environ.get("AUDITOOOR_P5_MAX_PER_CLUSTER", "5"))

# Composability gate: entries with at-least N matched P1+P3 anchors get
# bumped one bucket up (LOW -> MEDIUM, MEDIUM -> HIGH-PRIORITY-HUNT).
COMPOSABILITY_BUMP_THRESHOLD = int(
    os.environ.get("AUDITOOOR_P5_COMPOSABILITY_BUMP", "3")
)

# CAP-014: documented false-positive detector shapes should not outrank
# source-context-supported findings while the upstream detectors are still
# being tightened.
DOCUMENTED_FP_SCORE_PENALTY = float(
    os.environ.get("AUDITOOOR_P5_DOCUMENTED_FP_SCORE_PENALTY", "20")
)

# CAP-014 tie closure: keep within-band refinement below one point so the
# existing severity/composability model remains the primary rank signal.
BAND_DIFFERENTIATOR_MAX_DELTA = float(
    os.environ.get("AUDITOOOR_P5_BAND_DIFFERENTIATOR_MAX_DELTA", "0.98")
)

# CAP-001 score-uniformity tiebreaker: when top-N score stddev falls below
# this threshold the ranking signal collapses (every entry looks identical
# to the operator). The tiebreaker then differentiates entries via:
#   (a) detector-density per cluster - small clusters score higher than
#       large ones (focused signal vs sweeping noise),
#   (b) prior-coverage delta - clusters with NO existing submission rank
#       higher than already-hunted clusters,
#   (c) cross-cluster file-overlap - files surfaced by >=2 detectors carry
#       higher cumulative evidence.
# Empirical anchor: 2026-05-24 Hyperbridge dogfood produced top-30 scores
# of all 51.9; spread post-tiebreaker should be >=10 pts.
SCORE_STDDEV_TIEBREAKER_THRESHOLD = float(
    os.environ.get("AUDITOOOR_P5_STDDEV_TIEBREAKER_THRESHOLD", "1.0")
)

# Repo root - used to locate the P1 invariants + P3 yaml catalog.
_REPO_ROOT = Path(__file__).resolve().parent.parent

# Detector-cluster-slug -> (p1_category, p3_category) mapping. The slug
# token taxonomy follows the engage_report detector convention:
#   - go.crypto.race.*               -> atomicity / reentrancy
#   - go.crypto.skip_allowed.*       -> ordering / external-call-handling
#   - go.crypto.parse.*              -> bounds / bounds-and-bounds-checks
#   - go.crypto.panic.*              -> bounds / bounds-and-bounds-checks
#   - go.go.panic.*                  -> determinism / (no-P3-match for Go)
# Solidity-side mappings (sol.*) round out the table so the v2 report
# composes properly when a workspace ships .sol detectors.
CLUSTER_TOKEN_TO_CATEGORY: dict[str, tuple[str, str]] = {
    # token-prefix              p1_cat          p3_cat
    "race":               ("atomicity",   "atomicity-and-ordering"),
    "reentrancy":         ("atomicity",   "reentrancy"),
    "skip_allowed":       ("ordering",    "atomicity-and-ordering"),
    "external_call":      ("ordering",    "external-call-handling"),
    "parse":              ("bounds",      "bounds-and-bounds-checks"),
    "panic":              ("bounds",      "bounds-and-bounds-checks"),
    "unbounded":          ("bounds",      "bounds-and-bounds-checks"),
    "loop":               ("bounds",      "bounds-and-bounds-checks"),
    "auth":               ("authorization", "authorization"),
    "tx_origin":          ("authorization", "authorization"),
    "access_control":     ("authorization", "authorization"),
    "timestamp":          ("determinism", "randomness-and-determinism"),
    "randomness":         ("determinism", "randomness-and-determinism"),
    "dereference":        ("determinism", "atomicity-and-ordering"),  # nil-deref
    "nil_check":          ("determinism", "atomicity-and-ordering"),
    "uniqueness":         ("uniqueness",  ""),
    "monotonic":          ("monotonicity",""),
    "conservation":       ("conservation","custody-and-accounting"),
    "freshness":          ("freshness",   ""),
    "custody":            ("custody",     "custody-and-accounting"),
}

# CAP-003 (2026-05-24, hyperbridge anchor): descriptive cluster slugs
# (kebab-case "external-call-before-state-update") that the token-prefix
# resolver above cannot recognize because their tokens carry hyphens not
# dots. Keyword-substring matching on the full slug. Each slug maps to
# the SAME (p1_category, p3_category) shape as CLUSTER_TOKEN_TO_CATEGORY.
# The matcher tries token-resolver first; on miss it tries keyword
# fallback against this table. Empirical anchor: 2026-05-24 hyperbridge
# 30 candidates ALL resolved to (None, None) via token-resolver because
# their slugs use hyphens not dots; all 30 then had p1_invariant_hits=[].
CLUSTER_KEYWORD_TO_CATEGORY: list[tuple[str, str, str]] = [
    # (keyword_substring,                p1_cat,         p3_cat)
    # Reentrancy / ordering / atomicity
    ("external-call-before-state",      "ordering",     "external-call-handling"),
    ("reentrancy",                      "atomicity",    "reentrancy"),
    ("unchecked-low-level-call",        "ordering",     "external-call-handling"),
    ("unchecked",                       "conservation", "external-call-handling"),
    ("transfer-return-not-checked",     "conservation", "external-call-handling"),
    ("raw-transfer-no-bool-check",      "conservation", "external-call-handling"),
    ("fee-on-transfer-not-accounted",   "conservation", "custody-and-accounting"),
    ("return-bomb-low-level-call",      "return-bomb",  "external-call-handling"),
    # Signature / permit families
    ("ecrecover-without-zero-check",    "uniqueness",   "authorization"),
    ("ecdsa-malleability-low-s",        "uniqueness",   "authorization"),
    ("eip-712-missing",                 "uniqueness",   "authorization"),
    ("permit-frontrun",                 "atomicity",    "authorization"),
    ("wrong-spender-eip2612",           "authorization", "authorization"),
    # Authorization
    ("access-control",                  "authorization", "authorization"),
    ("unprotected-admin-transfer",      "authorization", "authorization"),
    ("unprotected-initialize",          "authorization", "authorization"),
    ("initialize-multiple-calls",       "authorization", "authorization"),
    ("initializer-modifier",            "authorization", "authorization"),
    ("setters-with-no-access-control",  "authorization", "authorization"),
    ("missing-unpause",                 "authorization", "authorization"),
    ("pausable-no-unpause-exposed",     "authorization", "authorization"),
    ("constructor-no-zero-address",     "authorization", "authorization"),
    ("eoa-restricted-via-extcodesize",  "authorization", "authorization"),
    ("lzReceive-no-sender-check",       "authorization", "authorization"),
    ("signature-without-nonce",         "uniqueness",    "authorization"),
    ("erc-2771",                        "authorization", "authorization"),
    ("msgSender-forgery",               "authorization", "authorization"),
    # Bounds / arithmetic
    ("downcast",                        "bounds",       "bounds-and-bounds-checks"),
    ("uint256-to-int256",               "bounds",       "bounds-and-bounds-checks"),
    ("int256-cast",                     "bounds",       "bounds-and-bounds-checks"),
    ("division-by-zero",                "bounds",       "bounds-and-bounds-checks"),
    ("division-to-zero",                "bounds",       "bounds-and-bounds-checks"),
    ("overflow",                        "bounds",       "bounds-and-bounds-checks"),
    ("underflow",                       "bounds",       "bounds-and-bounds-checks"),
    ("unbounded-loop",                  "bounds",       "bounds-and-bounds-checks"),
    # Target-specific economic assertions
    ("insurance-fund-draw",             "conservation", "custody-and-accounting"),
    ("insurance-fund",                  "conservation", "custody-and-accounting"),
    ("collateral-pool",                 "freshness",    "custody-and-accounting"),
    ("yield-diversion",                 "monotonicity", "custody-and-accounting"),
    ("governance-vote-dilution",        "conservation", "authorization"),
    # Bridge / cross-domain
    ("excessive-erc20-withdrawal",      "custody",      "custody-and-accounting"),
    ("hardcoded-sqrtPriceLimitX96",     "determinism",  "randomness-and-determinism"),
    ("uniswap-v4-poolkey-no-whitelist", "authorization", "authorization"),
    # State / proxy / determinism
    ("delegatecall-to-state",           "authorization", "authorization"),
    ("state-variable-shadowing",        "determinism",  "atomicity-and-ordering"),
    ("named-return-shadows-storage",    "determinism",  "atomicity-and-ordering"),
    ("delete-enumerable-set-struct",    "determinism",  "atomicity-and-ordering"),
    ("eip1153-transient-auth",          "authorization", "authorization"),
    # ERC compliance
    ("erc165-missing",                  "authorization", "authorization"),
    ("erc4626-functions-no-slippage",   "erc4626",     "custody-and-accounting"),
    ("erc4626-asset-not-pulled",        "erc4626",     "custody-and-accounting"),
    ("erc4626-max-fn-must-not-revert",  "erc4626",     "custody-and-accounting"),
    ("staking-reward-loss",             "conservation", "custody-and-accounting"),
    ("deprecated-safeapprove",          "custody",      "custody-and-accounting"),
]


def _resolve_cluster_category_keyword(cluster_id: str) -> tuple[str | None, str | None]:
    """CAP-003 fallback: keyword-substring matching for descriptive slugs.

    Used when the token-prefix resolver returns (None, None). The fallback
    tries each (keyword, p1_cat, p3_cat) row from CLUSTER_KEYWORD_TO_CATEGORY
    in order; the first whose keyword appears as a case-insensitive substring
    of the cluster_id wins. Returns (None, None) if nothing matches.
    """
    if not cluster_id:
        return (None, None)
    cid_lower = cluster_id.lower()
    for keyword, p1_cat, p3_cat in CLUSTER_KEYWORD_TO_CATEGORY:
        if keyword.lower() in cid_lower:
            return (p1_cat or None, p3_cat or None)
    return (None, None)

# Extension hooks for operators with custom cluster taxonomies.
def _load_env_overrides() -> dict[str, tuple[str, str]]:
    raw = os.environ.get("AUDITOOOR_P5_CLUSTER_TO_CATEGORY", "")
    if not raw:
        return {}
    out: dict[str, tuple[str, str]] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        token, rest = line.split("=", 1)
        parts = [p.strip() for p in rest.split(",")]
        if len(parts) == 2:
            out[token.strip()] = (parts[0], parts[1])
    return out


# ---------------------------------------------------------------------------
# P1 invariant library loader (atomic JSONL slurp, indexed by category x lang).
# ---------------------------------------------------------------------------

def _load_p1_invariants(repo_root: Path | None = None) -> dict[str, list[str]]:
    """Load P1 invariants and index them by ``(category, target_lang)`` key.

    Returns a dict ``{ "atomicity|go": ["INV-...", ...], "atomicity|any": [...] }``.
    Prefers ``invariants_pilot_audited.jsonl`` (audited retained subset)
    when present; falls back to the legacy breadth sources
    (``invariants_extracted.jsonl`` + ``invariants_pilot.jsonl``).
    """
    root = repo_root if repo_root is not None else _REPO_ROOT
    index: dict[str, list[str]] = {}

    audited_path = (
        root
        / "audit"
        / "corpus_tags"
        / "derived"
        / "invariants_pilot_audited.jsonl"
    )
    breadth_paths = [
        root / "audit" / "corpus_tags" / "derived" / "invariants_pilot.jsonl",
        root / "audit" / "corpus_tags" / "derived" / "invariants_extracted.jsonl",
    ]

    def _quality_passed(rec: dict[str, Any]) -> bool:
        quality_audited = rec.get("quality_audited")
        if isinstance(quality_audited, bool) and not quality_audited:
            return False
        if isinstance(quality_audited, str):
            qa_norm = quality_audited.strip().lower()
            if qa_norm in {"0", "false", "no"}:
                return False
        verdict = str(rec.get("audit_verdict") or "").strip().lower()
        if verdict.startswith("false-positive") or verdict in {
            "false-positive",
            "drop",
            "reject",
            "rejected",
            "quarantine",
        }:
            return False
        return True

    def _load_into(path: Path, *, audited: bool, only_missing_keys: bool) -> None:
        if not path.is_file():
            return
        try:
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    inv_id = rec.get("invariant_id")
                    cat = rec.get("category")
                    lang = rec.get("target_lang") or "any"
                    if not inv_id or not cat:
                        continue
                    if audited and not _quality_passed(rec):
                        continue
                    key = f"{cat}|{lang}"
                    if only_missing_keys and key in index:
                        continue
                    index.setdefault(key, []).append(str(inv_id))
        except OSError:
            return

    if audited_path.is_file():
        _load_into(audited_path, audited=True, only_missing_keys=False)
        # Coverage-preserving fallback: fill category/lang holes from the
        # broader pilot+extracted sources when audited subset lacks a key.
        for path in breadth_paths:
            _load_into(path, audited=False, only_missing_keys=True)
    else:
        for path in breadth_paths:
            _load_into(path, audited=False, only_missing_keys=False)
    # De-dup per key.
    for key in list(index.keys()):
        index[key] = sorted(set(index[key]))
    return index


# ---------------------------------------------------------------------------
# P3 anti-pattern catalog loader (tiny YAML subset parser, no PyYAML dep).
# ---------------------------------------------------------------------------

_YAML_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$")


def _parse_pattern_yaml(text: str) -> dict[str, str]:
    """Tiny YAML reader that only extracts top-level scalar fields we need.

    The P3 yaml files have the shape::

        schema_version: ...
        pattern_id: solidity.reentrancy-without-modifier
        category: reentrancy
        language: solidity
        ...

    We only need ``pattern_id``, ``category``, ``language`` for V2 compose.
    Multi-line ``description: |`` / ``query_source: |`` blocks are skipped
    by ignoring lines that don't start at column 0 with ``key:``.
    """
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith(" ") or line.startswith("\t") or line.startswith("#"):
            continue
        m = _YAML_KEY_RE.match(line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        # Strip trailing inline block-start markers (``|`` / ``>``).
        if val in ("|", ">"):
            continue
        if val:
            # Strip surrounding quotes if present.
            if (val.startswith('"') and val.endswith('"')) or (
                val.startswith("'") and val.endswith("'")
            ):
                val = val[1:-1]
            out[key] = val
    return out


def _load_p3_patterns(repo_root: Path | None = None) -> dict[str, list[str]]:
    """Load P3 anti-pattern catalog and index by ``(category, language)`` key.

    Returns ``{ "reentrancy|solidity": ["solidity.reentrancy-...", ...], ... }``.
    """
    root = repo_root if repo_root is not None else _REPO_ROOT
    index: dict[str, list[str]] = {}
    base = root / "obsidian-vault" / "anti-patterns" / "v2"
    if not base.is_dir():
        return index
    for lang_dir in sorted(base.iterdir()):
        if not lang_dir.is_dir():
            continue
        for yaml_path in sorted(lang_dir.glob("*.yaml")):
            try:
                text = yaml_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            fields = _parse_pattern_yaml(text)
            pid = fields.get("pattern_id")
            cat = fields.get("category")
            lang = fields.get("language") or lang_dir.name
            if not pid or not cat:
                continue
            key = f"{cat}|{lang}"
            index.setdefault(key, []).append(str(pid))
    for key in list(index.keys()):
        index[key] = sorted(set(index[key]))
    return index


# ---------------------------------------------------------------------------
# Cluster-slug -> (p1_category, p3_category) resolver.
# ---------------------------------------------------------------------------

def _resolve_cluster_category(cluster_id: str) -> tuple[str | None, str | None]:
    """Map a detector-cluster slug to its (p1_category, p3_category) pair.

    Resolver chain (first match wins):
      1. Env override (AUDITOOOR_P5_CLUSTER_TO_CATEGORY) - per-token.
      2. CLUSTER_TOKEN_TO_CATEGORY - per-token (dotted slugs like
         ``go.crypto.race.unsynchronized_concurrent_access``).
      3. CAP-003 keyword fallback (CLUSTER_KEYWORD_TO_CATEGORY) -
         substring match on the full slug for descriptive kebab-case
         slugs like ``external-call-before-state-update``.
    """
    if not cluster_id:
        return (None, None)
    overrides = _load_env_overrides()
    tokens = cluster_id.split(".")
    for tok in tokens:
        if tok in overrides:
            p1, p3 = overrides[tok]
            return (p1 or None, p3 or None)
        if tok in CLUSTER_TOKEN_TO_CATEGORY:
            p1, p3 = CLUSTER_TOKEN_TO_CATEGORY[tok]
            return (p1 or None, p3 or None)
    # CAP-003 keyword fallback for descriptive kebab-case slugs.
    return _resolve_cluster_category_keyword(cluster_id)


def _cluster_lang(cluster_id: str, file_hint: str | None = None) -> str:
    """Extract target language from cluster slug prefix (go/rust/sol).

    ``go.crypto.race...`` -> ``go``;
    ``sol.reentrancy.*``  -> ``solidity``;
    ``rust.parse.*``      -> ``rust``.
    Falls back to ``any``.

    CAP-003 (2026-05-24): when the cluster slug has no language prefix
    (e.g. descriptive kebab-case slugs like ``external-call-before-state-update``),
    fall back to inspecting ``file_hint`` (file extension) to derive the
    language. This lets the matcher target solidity-specific invariants
    when the cluster touches .sol files even though the slug itself has
    no lang prefix.
    """
    if cluster_id:
        prefix = cluster_id.split(".", 1)[0].lower()
        if prefix == "go":
            return "go"
        if prefix in ("sol", "solidity"):
            return "solidity"
        if prefix == "rust":
            return "rust"
        if prefix == "move":
            return "move"
    # CAP-003 fallback: derive from file extension. The file_hint shape is
    # "<path>/<file>.<ext>[:<line>]" - strip the line suffix before extension
    # checking so both "src/foo.sol" and "src/foo.sol:100" resolve correctly.
    if file_hint:
        fh = file_hint.lower()
        path_only = fh.split(":", 1)[0]  # strip ":<line>" suffix
        if path_only.endswith(".go"):
            return "go"
        if path_only.endswith(".sol"):
            return "solidity"
        if path_only.endswith(".rs"):
            return "rust"
        if path_only.endswith(".move"):
            return "move"
    return "any"


def _match_p1_for_cluster(
    cluster_id: str,
    *,
    p1_index: dict[str, list[str]],
    max_ids: int = 5,
    file_hint: str | None = None,
) -> list[str]:
    """Return P1 invariant_ids matching the cluster's category x language.

    CAP-003 (2026-05-24): loosened matcher.

    Lookup order (de-duped, capped at ``max_ids`` total):
      1. ``<cat>|<lang>`` where lang resolves from cluster_id prefix OR
         ``file_hint`` extension (e.g. .sol -> solidity).
      2. ``<cat>|any``    cross-language bucket.
      3. When lang is ``any`` (e.g. kebab-case slug with no prefix and no
         file_hint), scan ALL language buckets ``<cat>|*`` so cluster
         categories with NO any-bucket entries still surface invariants.

    Empirical anchor: hyperbridge cluster slugs like
    ``external-call-before-state-update`` have no lang prefix; the file
    hint gives ``.sol`` -> lang ``solidity`` -> ``ordering|solidity``
    yields 3 P1 invariants (was 0 before this patch).
    """
    p1_cat, _ = _resolve_cluster_category(cluster_id)
    if not p1_cat:
        return []
    lang = _cluster_lang(cluster_id, file_hint=file_hint)
    out: list[str] = []
    out.extend(p1_index.get(f"{p1_cat}|{lang}", []))
    if lang != "any":
        out.extend(p1_index.get(f"{p1_cat}|any", []))
    else:
        # CAP-003: lang unknown - scan every language bucket for the
        # category. Keeps coverage for descriptive slugs that lack both
        # a lang prefix and a meaningful file hint.
        for key, ids in p1_index.items():
            if key.startswith(f"{p1_cat}|") and key != f"{p1_cat}|{lang}":
                out.extend(ids)
    # de-dup, stable order
    seen: set[str] = set()
    deduped: list[str] = []
    for x in out:
        if x in seen:
            continue
        seen.add(x)
        deduped.append(x)
    return deduped[:max_ids]


def _match_p3_for_cluster(
    cluster_id: str,
    *,
    p3_index: dict[str, list[str]],
    file_hint: str | None = None,
) -> list[str]:
    """Return P3 pattern_ids matching the cluster's category x language.

    When the target lang has no P3 anti-pattern for the category yet
    (e.g. Go clusters under a category covered only by Solidity P3 yamls),
    returns the documented ``no-P3-match:<category>:<lang>`` sentinel so
    the report is honest about the coverage gap.

    CAP-003 (2026-05-24): file_hint allows lang derivation from the file
    extension when the cluster slug has no lang prefix.
    """
    _, p3_cat = _resolve_cluster_category(cluster_id)
    if not p3_cat:
        return []
    lang = _cluster_lang(cluster_id, file_hint=file_hint)
    ids = list(p3_index.get(f"{p3_cat}|{lang}", []))
    if ids:
        return ids
    # Honest gap: category recognized but no per-lang P3 yet.
    return [f"no-P3-match:{p3_cat}:{lang}"]


CAP020_BRIDGE_PROOF_PATTERN_ID = (
    "solidity.batch03-bridge-proof-verifier-accepts-zero-root-or-default-branch"
)


def _cap020_bridge_proof_live_context_supported(
    *,
    file_hint: str,
    snippet: str,
    source_context: str,
    source_contract_context: str,
) -> bool:
    """CAP-020 live-report guard for the bridge proof-verifier P3 pattern."""
    line_window = _strip_comments_and_strings("\n".join([file_hint, snippet, source_context]))
    if not re.search(
        r"\b(?:root|branch|sibling|default\s+branch|zero)\b|bytes32\s*\(\s*0\s*\)",
        line_window,
        re.I | re.S,
    ):
        return False

    context = _strip_comments_and_strings(
        "\n".join([file_hint, snippet, source_context, source_contract_context])
    )
    has_bridge_verifier_context = bool(
        re.search(r"\b(?:bridge|verif(?:y|ier)|proof|relay|withdraw|finalize|claim)\w*\b", context, re.I)
        and _bridge_006_verifier_context_re().search(context)
    )
    return bool(
        has_bridge_verifier_context
        and _bridge_006_source_domain_re().search(context)
        and _bridge_006_destination_domain_re().search(context)
    )


def _filter_live_target_p3_matches(
    pattern_ids: list[str],
    *,
    file_hint: str,
    snippet: str,
    source_context: str,
    source_contract_context: str,
) -> list[str]:
    """Apply report-pipeline precision guards to broad category P3 joins."""
    filtered: list[str] = []
    for pattern_id in pattern_ids:
        if (
            pattern_id == CAP020_BRIDGE_PROOF_PATTERN_ID
            and not _cap020_bridge_proof_live_context_supported(
                file_hint=file_hint,
                snippet=snippet,
                source_context=source_context,
                source_contract_context=source_contract_context,
            )
        ):
            continue
        filtered.append(pattern_id)
    return filtered


def _split_file_line(file_line: str) -> tuple[str, int | None]:
    """Split ``path:line`` while tolerating bare paths."""
    if not file_line:
        return "", None
    m = re.match(r"^(?P<path>.+?):(?P<line>\d+)(?::\d+)?$", file_line)
    if not m:
        return file_line, None
    return m.group("path"), int(m.group("line"))


def _source_file_text_and_line(
    workspace: Path,
    file_line: str,
) -> tuple[str, int | None]:
    """Best-effort full source text plus parsed line number for ``file:line``."""
    rel, line_no = _split_file_line(file_line)
    if not rel:
        return "", None
    path = Path(rel)
    candidates = [path] if path.is_absolute() else [workspace / path, _REPO_ROOT / path]
    src_path = next((p for p in candidates if p.is_file()), None)
    if src_path is None:
        return "", line_no
    try:
        return src_path.read_text(encoding="utf-8", errors="replace"), line_no
    except OSError:
        return "", line_no


def _source_context(
    workspace: Path,
    file_line: str,
    *,
    radius: int = 40,
    max_chars: int = 16000,
) -> str:
    """Best-effort source window around a report ``file:line``."""
    text, line_no = _source_file_text_and_line(workspace, file_line)
    if not text:
        return ""
    lines = text.splitlines()
    if not line_no:
        return "\n".join(lines)[:max_chars]
    start = max(line_no - radius - 1, 0)
    end = min(line_no + radius, len(lines))
    return "\n".join(lines[start:end])[:max_chars]


_SOLIDITY_CONTRACT_RE = re.compile(
    r"\b(?:abstract\s+)?(?:contract|library|interface)\s+[A-Za-z_][A-Za-z0-9_]*[^;{]*\{",
    re.S,
)


def _line_to_offset(text: str, line_no: int | None) -> int | None:
    if not line_no:
        return None
    if line_no <= 1:
        return 0
    offset = 0
    for current, line in enumerate(text.splitlines(True), start=1):
        if current >= line_no:
            return offset
        offset += len(line)
    return len(text)


def _find_matching_brace(text: str, open_brace: int) -> int | None:
    """Return the matching ``}`` for ``text[open_brace]`` using a light lexer."""
    if open_brace < 0 or open_brace >= len(text) or text[open_brace] != "{":
        return None
    depth = 0
    i = open_brace
    in_string: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
            i += 1
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
            else:
                i += 1
            continue
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_string:
                in_string = None
            i += 1
            continue
        if ch == "/" and nxt == "/":
            line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            block_comment = True
            i += 2
            continue
        if ch in {"'", '"'}:
            in_string = ch
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _source_contract_context(workspace: Path, file_line: str, *, max_chars: int = 200000) -> str:
    """Return the Solidity contract/library/interface body containing ``file_line``."""
    text, line_no = _source_file_text_and_line(workspace, file_line)
    if not text:
        return ""
    target = _line_to_offset(text, line_no)
    if target is None:
        return text[:max_chars]
    for match in _SOLIDITY_CONTRACT_RE.finditer(text):
        open_brace = text.rfind("{", match.start(), match.end())
        close_brace = _find_matching_brace(text, open_brace)
        if close_brace is None:
            continue
        if match.start() <= target <= close_brace:
            return text[match.start() : close_brace + 1][:max_chars]
    return ""


def _normalize_workspace_source_path(path_text: str, workspace: Path) -> str:
    """Normalize absolute/relative source refs to a workspace-relative POSIX path."""
    raw = str(path_text or "").strip()
    if not raw:
        return ""
    path = Path(raw)
    if path.is_absolute():
        try:
            return path.relative_to(workspace).as_posix()
        except ValueError:
            return path.as_posix()
    return path.as_posix()


def _parse_source_ref(ref: str, workspace: Path) -> tuple[str, int | None, int | None]:
    """Parse ``path[:start[-end]]`` source refs used by accepted P1 sidecars."""
    raw = str(ref or "").strip()
    if not raw:
        return "", None, None
    m = re.match(r"^(?P<path>.+?):(?P<start>\d+)(?:-(?P<end>\d+))?$", raw)
    if not m:
        return _normalize_workspace_source_path(raw, workspace), None, None
    start = int(m.group("start"))
    end = int(m.group("end") or start)
    return _normalize_workspace_source_path(m.group("path"), workspace), start, end


def _source_ref_matches_file_line(workspace: Path, file_line: str, source_ref: str) -> bool:
    """True only when ``file_line`` is exactly covered by ``source_ref``."""
    entry_path_raw, entry_line = _split_file_line(file_line)
    entry_path = _normalize_workspace_source_path(entry_path_raw, workspace)
    ref_path, ref_start, ref_end = _parse_source_ref(source_ref, workspace)
    if not entry_path or not ref_path or entry_path != ref_path:
        return False
    if entry_line is not None and ref_start is not None and ref_end is not None:
        return ref_start <= entry_line <= ref_end
    return False


def _source_proof_refs(payload: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for value in payload.get("source_refs") or []:
        if isinstance(value, str):
            refs.append(value)
    impact = payload.get("impact_contract")
    if isinstance(impact, dict):
        for value in impact.get("source_refs") or []:
            if isinstance(value, str):
                refs.append(value)
    return sorted(set(refs))


def _accepted_p1_source_proof_matches(workspace: Path, file_line: str) -> list[dict[str, Any]]:
    """Return accepted local-review P1 mappings whose source proof covers ``file_line``.

    This is intentionally stricter than audited-catalog membership. CAP-020
    allows semantic P1 only when a specific predicate or source-proof location
    supports the cited entry. The sidecar path is accepted only if the local
    review row is accepted, the source proof is proved, and a source ref exactly
    covers the entry line.
    """
    sidecar = workspace / ".auditooor" / "p1_invariant_attribution_sidecar.json"
    if not sidecar.is_file():
        return []
    try:
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in payload.get("mappings") or []:
        if not isinstance(row, dict):
            continue
        if row.get("attribution_status") != "accepted_by_local_review":
            continue
        inv_id = str(row.get("p1_invariant_id") or row.get("invariant_id") or "").strip()
        if not inv_id:
            continue
        proof_paths: list[Path] = []
        for ref in row.get("evidence_refs") or []:
            if not str(ref).endswith("source_proof.json"):
                continue
            proof_path = Path(str(ref))
            if not proof_path.is_absolute():
                proof_path = workspace / proof_path
            proof_paths.append(proof_path)
        for proof_path in proof_paths:
            if not proof_path.is_file():
                continue
            try:
                proof = json.loads(proof_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if proof.get("blockers") not in ([], None):
                continue
            final_verdict = str(proof.get("final_verdict") or "").strip().lower()
            if not final_verdict.startswith("proved"):
                continue
            for source_ref in _source_proof_refs(proof):
                if not _source_ref_matches_file_line(workspace, file_line, source_ref):
                    continue
                key = (inv_id, str(row.get("candidate_id") or ""), source_ref)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    {
                        "invariant_id": inv_id,
                        "candidate_id": row.get("candidate_id"),
                        "source_ref": source_ref,
                        "source_proof": str(proof_path),
                        "basis": "accepted_by_local_review_source_proof",
                    }
                )
    return out


def _shape_cluster_predicates_enabled() -> bool:
    return os.environ.get("AUDITOOOR_P5_SHAPE_CLUSTER_PREDICATES", "1").lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _shape_cluster_predicate_candidates_path(workspace: Path) -> Path | None:
    raw = os.environ.get(
        "AUDITOOOR_P5_SHAPE_CLUSTER_PREDICATE_CANDIDATES",
        DEFAULT_SHAPE_CLUSTER_PREDICATES_JSONL,
    ).strip()
    if not raw:
        return None
    path = Path(raw)
    candidates = [path] if path.is_absolute() else [workspace / path, _REPO_ROOT / path]
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def _shape_cluster_candidate_string(record: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = record.get(key)
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            for item in value:
                text = str(item).strip()
                if text:
                    return text
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _shape_cluster_candidate_invariant_ids(record: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key in ("support_invariant_ids", "invariant_ids"):
        value = record.get(key)
        if isinstance(value, list):
            for item in value:
                inv_id = str(item).strip()
                if inv_id:
                    out.append(inv_id)
        elif isinstance(value, str):
            for token in value.split(","):
                inv_id = token.strip()
                if inv_id:
                    out.append(inv_id)
    single = _shape_cluster_candidate_string(
        record,
        ("invariant_id", "p1_invariant_id", "p1_invariant", "inv_id"),
    )
    if single:
        out.append(single)
    return sorted(dict.fromkeys(out))


def _shape_cluster_expression_is_synthetic(expression: str, *, shape_cluster_key: str) -> bool:
    expr = str(expression or "").strip().lower()
    if not expr:
        return False
    if "shape_cluster_key" in expr:
        return True
    if shape_cluster_key and expr == shape_cluster_key.strip().lower():
        return True
    return False


def _normalize_shape_cluster_predicate_candidates(record: dict[str, Any]) -> list[dict[str, Any]]:
    cluster_id = _shape_cluster_candidate_string(
        record,
        ("cluster_id", "detector_slug", "cluster", "cluster_slug", "shape_cluster_key"),
    )
    shape_cluster_key = _shape_cluster_candidate_string(record, ("shape_cluster_key",))
    invariant_ids = _shape_cluster_candidate_invariant_ids(record)
    if not cluster_id or not invariant_ids:
        return []
    candidate_id = _shape_cluster_candidate_string(record, ("candidate_id", "predicate_id", "id"))
    status = _shape_cluster_candidate_string(
        record,
        ("candidate_status", "validation_status", "status", "attribution_status"),
    ).lower()
    expression = _shape_cluster_candidate_string(
        record,
        ("predicate_expression", "expression", "predicate", "predicate_expr"),
    )
    function_signature = _shape_cluster_candidate_string(
        record,
        (
            "function_signature_sample",
            "function_signature",
            "signature",
            "function",
            "function_decl",
        ),
    )
    source_ref = _shape_cluster_candidate_string(
        record,
        ("source_ref", "file_line", "file_path", "source_refs"),
    )
    expression_synthetic = _shape_cluster_expression_is_synthetic(
        expression,
        shape_cluster_key=shape_cluster_key,
    )

    out: list[dict[str, Any]] = []
    for idx, invariant_id in enumerate(invariant_ids):
        out.append(
            {
                "cluster_id": cluster_id,
                "shape_cluster_key": shape_cluster_key,
                "invariant_id": invariant_id,
                "candidate_id": (
                    candidate_id
                    if candidate_id
                    else f"{cluster_id}:{invariant_id}:{idx}"
                ),
                "status": status,
                "predicate_expression": expression,
                "expression_synthetic": expression_synthetic,
                "function_signature": function_signature,
                "source_ref": source_ref,
                "support_invariant_ids": invariant_ids,
            }
        )
    return out


def _shape_cluster_candidate_status_is_rejected(status: str) -> bool:
    normalized = str(status or "").strip().lower()
    return any(token in normalized for token in ("reject", "fail", "invalid"))


def _load_shape_cluster_predicate_candidates(workspace: Path) -> dict[str, list[dict[str, Any]]]:
    if not _shape_cluster_predicates_enabled():
        return {}
    path = _shape_cluster_predicate_candidates_path(workspace)
    if path is None:
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                for normalized in _normalize_shape_cluster_predicate_candidates(record):
                    if _shape_cluster_candidate_status_is_rejected(str(normalized.get("status") or "")):
                        continue
                    out.setdefault(normalized["cluster_id"].lower(), []).append(normalized)
                    invariant_keys = {
                        str(normalized.get("invariant_id") or "").strip().lower()
                    }
                    invariant_keys.update(
                        str(inv or "").strip().lower()
                        for inv in (normalized.get("support_invariant_ids") or [])
                    )
                    for invariant_id in {inv for inv in invariant_keys if inv}:
                        out.setdefault(f"invariant:{invariant_id}", []).append(normalized)
    except OSError:
        return {}
    return out


def _normalize_shape_text(value: str) -> str:
    return re.sub(r"\s+", "", _strip_comments_and_strings(str(value or "")).lower())


def _shape_cluster_signature_name(signature: str) -> str:
    for pattern in (
        r"\b(?:function|fn)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
        r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    ):
        match = re.search(pattern, signature)
        if match:
            return str(match.group("name") or "")
    return ""


def _shape_cluster_candidate_signature_matches(
    signature: str,
    *,
    function_context: str,
    source_context: str,
) -> bool:
    sig_norm = _normalize_shape_text(signature)
    if not sig_norm:
        return False
    for haystack in (function_context, source_context):
        if sig_norm and sig_norm in _normalize_shape_text(haystack):
            return True
    fn_name = _shape_cluster_signature_name(signature)
    if not fn_name:
        return False
    return bool(
        re.search(rf"\b{re.escape(fn_name)}\s*\(", function_context, re.I)
        or re.search(rf"\b{re.escape(fn_name)}\s*\(", source_context, re.I)
    )


def _shape_cluster_candidate_expression_matches(
    expression: str,
    *,
    function_context: str,
    source_context: str,
    snippet: str,
) -> bool:
    expr_norm = _normalize_shape_text(expression)
    if not expr_norm:
        return False
    return any(
        expr_norm in _normalize_shape_text(haystack)
        for haystack in (function_context, source_context, snippet)
        if haystack
    )


def _shape_cluster_candidate_source_ref_matches(
    workspace: Path,
    *,
    file_line: str,
    source_ref: str,
) -> bool:
    if not source_ref:
        return False
    if _source_ref_matches_file_line(workspace, file_line, source_ref):
        return True
    entry_path_raw, _ = _split_file_line(file_line)
    entry_path = _normalize_workspace_source_path(entry_path_raw, workspace)
    ref_path, _, _ = _parse_source_ref(source_ref, workspace)
    return bool(entry_path and ref_path and entry_path == ref_path)


def _shape_cluster_predicate_semantic_matches(
    workspace: Path,
    *,
    cluster_id: str,
    file_line: str,
    snippet: str,
    source_context: str,
    source_contract_context: str,
    candidates_by_cluster: dict[str, list[dict[str, Any]]],
    matched_p1: Iterable[str] = (),
) -> list[dict[str, str]]:
    candidates = list(candidates_by_cluster.get(cluster_id.lower(), []))
    for invariant_id in matched_p1:
        key = f"invariant:{str(invariant_id or '').strip().lower()}"
        candidates.extend(candidates_by_cluster.get(key, []))
    if not candidates:
        return []
    function_context = (
        _solidity_function_context_for_snippet(source_contract_context, snippet)
        or _solidity_function_context_for_snippet(source_context, snippet)
        or source_contract_context
        or source_context
    )
    matches: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for candidate in candidates:
        source_ref = str(candidate.get("source_ref") or "")
        source_ref_match = _shape_cluster_candidate_source_ref_matches(
            workspace,
            file_line=file_line,
            source_ref=source_ref,
        ) if source_ref else False
        if source_ref and not source_ref_match:
            continue

        expression = str(candidate.get("predicate_expression") or "")
        expression_synthetic = bool(candidate.get("expression_synthetic"))
        signature = str(candidate.get("function_signature") or "")

        expr_match = False
        if expression and not expression_synthetic:
            expr_match = _shape_cluster_candidate_expression_matches(
                expression,
                function_context=function_context,
                source_context=source_context,
                snippet=snippet,
            )
        sig_match = _shape_cluster_candidate_signature_matches(
            signature,
            function_context=function_context,
            source_context=source_context,
        ) if signature else False
        evidence: list[str] = []
        if sig_match:
            evidence.append("signature")
        if expr_match:
            evidence.append("expression")
        if source_ref_match:
            evidence.append("source_ref")
        # Conservative gate: do not promote on synthetic cluster metadata alone.
        if not evidence:
            continue

        status = str(candidate.get("status") or "")
        key = (
            str(candidate.get("invariant_id") or ""),
            str(candidate.get("candidate_id") or ""),
            status,
        )
        if key in seen:
            continue
        seen.add(key)
        matches.append(
            {
                "invariant_id": str(candidate.get("invariant_id") or ""),
                "candidate_id": str(candidate.get("candidate_id") or ""),
                "status": status,
                "basis": "shape_cluster_predicate_candidate",
                "evidence": "+".join(evidence),
            }
        )
    return matches


def _strip_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"//[^\n\r]*", "", source)


def _strip_comments_and_strings(source: str) -> str:
    source = _strip_comments(source)
    return re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', source, flags=re.S)


class _PredicateSource(str):
    """String source plus optional wider context for IR-backed predicates."""

    def __new__(
        cls,
        value: str,
        *,
        source_context: str = "",
        contract_source: str = "",
        snippet: str = "",
        file_line: str = "",
    ) -> "_PredicateSource":
        obj = str.__new__(cls, value or "")
        obj.source_context = source_context or ""
        obj.contract_source = contract_source or ""
        obj.snippet = snippet or ""
        obj.file_line = file_line or ""
        return obj


_AST_ENGINE_MISSING = object()
_AST_ENGINE_MODULE: Any | object | None = None
_AST_ENGINE_CACHE: dict[tuple[str, str], Any | None] = {}
_AST_SOURCE_MAX_CHARS = int(
    os.environ.get("AUDITOOOR_P5_AST_PREDICATE_MAX_CHARS", "200000")
)


def _ast_predicates_enabled() -> bool:
    return os.environ.get("AUDITOOOR_P5_AST_PREDICATES", "1").lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _load_ast_engine_module() -> Any | None:
    global _AST_ENGINE_MODULE
    if _AST_ENGINE_MODULE is _AST_ENGINE_MISSING:
        return None
    if _AST_ENGINE_MODULE is not None:
        return _AST_ENGINE_MODULE
    try:
        spec = importlib.util.spec_from_file_location(
            "auditooor_live_target_ast_engine",
            _REPO_ROOT / "tools" / "ast-engine.py",
        )
        if spec is None or spec.loader is None:
            _AST_ENGINE_MODULE = _AST_ENGINE_MISSING
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _AST_ENGINE_MODULE = module
        return module
    except Exception:
        _AST_ENGINE_MODULE = _AST_ENGINE_MISSING
        return None


def _ast_engine_for_source(lang: str, source: str) -> Any | None:
    if not _ast_predicates_enabled():
        return None
    if lang not in {"go", "rust", "move"}:
        return None
    if not source or len(source) > _AST_SOURCE_MAX_CHARS:
        return None
    module = _load_ast_engine_module()
    if module is None:
        return None
    key = (lang, hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest())
    if key in _AST_ENGINE_CACHE:
        return _AST_ENGINE_CACHE[key]
    try:
        engine = module.AstEngine(lang, source.encode("utf-8", errors="replace"))
        engine.parse()
    except Exception:
        engine = None
    _AST_ENGINE_CACHE[key] = engine
    return engine


def _ast_function_name(engine: Any, fn: Any) -> str:
    try:
        return str(engine.fn_name(fn) or "")
    except Exception:
        return ""


def _ast_function_call_texts(engine: Any, fn: Any) -> list[str]:
    try:
        body = engine.fn_body(fn)
    except Exception:
        body = None
    if body is None:
        return []
    try:
        result = engine.query_structural("call", node=body)
    except Exception:
        return []
    if not getattr(result, "ok", False):
        return []
    texts: list[str] = []
    capture_texts = getattr(result, "capture_texts", None)
    if callable(capture_texts):
        try:
            texts.extend(str(text) for text in capture_texts("call"))
        except Exception:
            pass
    if not texts:
        for capture in getattr(result, "captures", []) or []:
            if getattr(capture, "name", "") == "call":
                texts.append(str(getattr(capture, "text", "")))
    return [text for text in texts if text]


def _ast_function_assignment_texts(engine: Any, fn: Any) -> list[str]:
    try:
        body = engine.fn_body(fn)
    except Exception:
        body = None
    if body is None:
        return []
    try:
        result = engine.query_structural("assignment", node=body)
    except Exception:
        return []
    if not getattr(result, "ok", False):
        return []
    texts: list[str] = []
    capture_texts = getattr(result, "capture_texts", None)
    if callable(capture_texts):
        try:
            texts.extend(str(text) for text in capture_texts("assignment"))
        except Exception:
            pass
    if not texts:
        for capture in getattr(result, "captures", []) or []:
            if getattr(capture, "name", "") == "assignment":
                texts.append(str(getattr(capture, "text", "")))
    return [text for text in texts if text]


def _ast_function_has_call_without_call(
    source: str,
    *,
    lang: str,
    target_call_pattern: str,
    forbidden_call_pattern: str = "",
    fn_names: tuple[str, ...] = (),
) -> bool:
    """Tree-sitter-backed call-shape check used before regex fallback."""
    engine = _ast_engine_for_source(lang, source)
    if engine is None:
        return False
    try:
        target_re = re.compile(target_call_pattern, re.I)
        forbidden_re = re.compile(forbidden_call_pattern, re.I) if forbidden_call_pattern else None
    except re.error:
        return False
    wanted = {name.lower() for name in fn_names}
    try:
        functions = list(engine.functions())
    except Exception:
        return False
    for fn in functions:
        if wanted and _ast_function_name(engine, fn).lower() not in wanted:
            continue
        calls = _ast_function_call_texts(engine, fn)
        if not any(target_re.search(call) for call in calls):
            continue
        if forbidden_re and any(forbidden_re.search(call) for call in calls):
            continue
        return True
    return False


def _ast_function_has_structural_call_without_call(
    source: str,
    *,
    lang: str,
    structural_predicate: str,
    target_call_pattern: str,
    forbidden_call_pattern: str = "",
    fn_names: tuple[str, ...] = (),
) -> bool:
    """Tree-sitter structural predicate + call-shape check before fallback."""
    engine = _ast_engine_for_source(lang, source)
    if engine is None:
        return False
    try:
        target_re = re.compile(target_call_pattern, re.I)
        forbidden_re = re.compile(forbidden_call_pattern, re.I) if forbidden_call_pattern else None
    except re.error:
        return False
    wanted = {name.lower() for name in fn_names}
    try:
        functions = list(engine.functions())
    except Exception:
        return False
    for fn in functions:
        if wanted and _ast_function_name(engine, fn).lower() not in wanted:
            continue
        try:
            if not engine.predicate_structural_match(fn, structural_predicate):
                continue
        except Exception:
            continue
        calls = _ast_function_call_texts(engine, fn)
        if not any(target_re.search(call) for call in calls):
            continue
        if forbidden_re and any(forbidden_re.search(call) for call in calls):
            continue
        return True
    return False


def _extract_identifiers(source: str, pattern: str) -> list[str]:
    """Extract identifier matches for declaration-like patterns."""
    return sorted(
        {
            m.group("id")
            for m in re.finditer(pattern, source, re.I | re.S)
            if m.group("id")
        }
    )


def _first_solidity_function_body(source: str, names: tuple[str, ...]) -> str | None:
    """Extract the first implemented Solidity function body for any name."""
    for name in names:
        pattern = re.compile(rf"\bfunction\s+{re.escape(name)}\s*\(", re.S)
        for match in pattern.finditer(source):
            open_brace = source.find("{", match.end())
            if open_brace < 0:
                continue
            semi = source.find(";", match.end(), open_brace)
            if semi >= 0:
                continue
            close_brace = _find_matching_brace(source, open_brace)
            if close_brace is None:
                continue
            return source[open_brace + 1 : close_brace]
    return None


def _first_solidity_function_segment(source: str, names: tuple[str, ...]) -> str | None:
    """Extract the first implemented Solidity function declaration + body."""
    for name in names:
        pattern = re.compile(rf"\bfunction\s+{re.escape(name)}\s*\(", re.S)
        for match in pattern.finditer(source):
            open_brace = source.find("{", match.end())
            if open_brace < 0:
                continue
            semi = source.find(";", match.end(), open_brace)
            if semi >= 0:
                continue
            close_brace = _find_matching_brace(source, open_brace)
            if close_brace is None:
                continue
            return source[match.start() : close_brace + 1]
    return None


def _solidity_function_segments(
    source: str,
    names: tuple[str, ...] | None = None,
) -> list[dict[str, str]]:
    """Extract implemented Solidity function declaration/body segments."""
    clean = _strip_comments(source)
    wanted = {name.lower() for name in names or ()}
    rows: list[dict[str, str]] = []
    for match in re.finditer(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(", clean):
        name = match.group("name")
        if wanted and name.lower() not in wanted:
            continue
        open_brace = clean.find("{", match.end())
        if open_brace < 0:
            continue
        semi = clean.find(";", match.end(), open_brace)
        if semi >= 0:
            continue
        close_brace = _find_matching_brace(clean, open_brace)
        if close_brace is None:
            continue
        rows.append(
            {
                "name": name,
                "signature": clean[match.start() : open_brace],
                "body": clean[open_brace + 1 : close_brace],
                "segment": clean[match.start() : close_brace + 1],
            }
        )
    return rows


def _first_go_function_segment(source: str, names: tuple[str, ...]) -> str | None:
    """Extract the first implemented Go function declaration + body."""
    clean = _strip_comments(source)
    wanted = {name.lower() for name in names}
    signature_re = re.compile(
        r"\bfunc\b\s*(?:\([^)]*\)\s*)?(?:\*?[A-Za-z_][A-Za-z0-9_]*\.)?\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
        re.S,
    )
    for match in signature_re.finditer(clean):
        name_match = match
        name = name_match.group("name")
        if name.lower() not in wanted:
            continue
        open_brace = clean.find("{", match.end())
        if open_brace < 0:
            continue
        semi = clean.find(";", match.end(), open_brace)
        if semi >= 0:
            continue
        close_brace = _find_matching_brace(clean, open_brace)
        if close_brace is None:
            continue
        return clean[match.start() : close_brace + 1]
    return None


def _solidity_param_names(signature: str, type_pattern: str) -> list[str]:
    """Return simple parameter names matching a Solidity type regex."""
    open_paren = signature.find("(")
    close_paren = signature.rfind(")")
    if open_paren < 0 or close_paren <= open_paren:
        return []
    names: list[str] = []
    for raw in signature[open_paren + 1 : close_paren].split(","):
        param = raw.strip()
        if not re.search(type_pattern, param, re.I):
            continue
        tokens = [
            tok
            for tok in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", param)
            if tok
            not in {
                "address",
                "bool",
                "bytes",
                "calldata",
                "int",
                "memory",
                "payable",
                "storage",
                "string",
                "uint",
                "uint256",
            }
            and not re.fullmatch(r"(?:u?int)(?:8|16|32|64|128|256)?", tok)
        ]
        if tokens:
            names.append(tokens[-1])
    return names


def _is_revert_only_body(function_body: str | None) -> bool:
    if not function_body:
        return False
    body = _strip_comments(function_body).strip()
    if not body:
        return False
    return bool(
        re.fullmatch(
            r"revert(?:\s+[A-Za-z_][A-Za-z0-9_.]*)?\s*\([^;{}]*\)\s*;",
            body,
            flags=re.S,
        )
    )


_SOLIDITY_WRITE_RE = re.compile(
    r"(?:delete\s+)?"
    r"(?P<slot>[A-Za-z_][A-Za-z0-9_]*(?:\s*(?:\[[^\]]+\]|\.[A-Za-z_][A-Za-z0-9_]*))+)"
    r"\s*(?:[+\-*/]?=|\+\+|--)",
    re.S,
)


_SOLIDITY_ANY_WRITE_RE = re.compile(
    r"(?:delete\s+)?"
    r"(?P<slot>[A-Za-z_][A-Za-z0-9_]*(?:\s*(?:\[[^\]]+\]|\.[A-Za-z_][A-Za-z0-9_]*))*)"
    r"\s*(?:[+\-*/]?=|\+\+|--)",
    re.S,
)


def _normalise_solidity_expr(expr: str) -> str:
    return re.sub(r"\s+", "", expr)


def _call_position(source_context: str, snippet: str) -> int:
    """Return the best source-context offset for the reported low-level call."""
    if snippet and ".call" in snippet:
        snippet_pos = source_context.find(snippet)
        if snippet_pos >= 0:
            local = snippet.find(".call")
            return snippet_pos + max(local, 0)
    return source_context.find(".call")


def _cap019_lzreceive_call_position(source_context: str, snippet: str) -> int:
    source_lower = source_context.lower()
    snippet_lower = snippet.lower()
    if snippet and ".lzreceive" in snippet_lower:
        snippet_pos = source_lower.find(snippet_lower)
        if snippet_pos >= 0:
            return snippet_pos + snippet_lower.find(".lzreceive")
    return source_lower.find(".lzreceive")


def _solidity_call_slices_in_current_function(
    source_context: str,
    snippet: str,
) -> tuple[int, str, str]:
    """Return call offset plus before/after slices bounded to one function."""
    call_pos = _call_position(source_context, snippet)
    if call_pos < 0:
        return -1, "", ""
    before = source_context[:call_pos]
    after = source_context[call_pos:]
    function_pos = before.lower().rfind("function ")
    if function_pos >= 0:
        before = before[function_pos:]
    next_function_pos = after.lower().find("function ", 1)
    if next_function_pos >= 0:
        after = after[:next_function_pos]
    return call_pos, before, after


def _solidity_function_context_for_snippet(source: str, snippet: str) -> str:
    """Return the implemented Solidity function enclosing ``snippet``."""
    if not source or not snippet:
        return ""
    target = source.find(snippet)
    if target < 0 and ".call" in snippet:
        target = source.find(".call")
    if target < 0:
        return ""
    for match in re.finditer(r"\bfunction\s+[A-Za-z_][A-Za-z0-9_]*\s*\(", source):
        open_brace = source.find("{", match.end())
        if open_brace < 0:
            continue
        semi = source.find(";", match.end(), open_brace)
        if semi >= 0:
            continue
        close_brace = _find_matching_brace(source, open_brace)
        if close_brace is None:
            continue
        if match.start() <= target <= close_brace:
            return source[match.start() : close_brace + 1]
    return ""


def _solidity_statement_at(source: str, start: int, end: int) -> str:
    stmt_end = source.find(";", end)
    if stmt_end < 0:
        stmt_end = end
    return source[start:stmt_end]


def _solidity_write_rows(source: str, *, broad: bool = False) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    pattern = _SOLIDITY_ANY_WRITE_RE if broad else _SOLIDITY_WRITE_RE
    for match in pattern.finditer(source):
        slot = _normalise_solidity_expr(match.group("slot"))
        if slot in {"return", "require", "assert", "if", "for", "while", "emit"}:
            continue
        stmt = _solidity_statement_at(source, match.start(), match.end())
        rows.append({"slot": slot, "statement": stmt, "statement_norm": _normalise_solidity_expr(stmt)})
    return rows


_SLITHER_PREDICATES_MISSING = object()
_SLITHER_PREDICATES_MODULE: Any | object | None = None
_SLITHER_FUNCTION_CACHE: dict[str, list[Any]] = {}
_SLITHER_SOURCE_MAX_CHARS = int(
    os.environ.get("AUDITOOOR_P5_SLITHER_PREDICATE_MAX_CHARS", "200000")
)


def _slither_predicates_enabled() -> bool:
    return os.environ.get("AUDITOOOR_P5_SLITHER_PREDICATES", "1").lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _load_slither_predicates_module() -> Any | None:
    global _SLITHER_PREDICATES_MODULE
    if _SLITHER_PREDICATES_MODULE is _SLITHER_PREDICATES_MISSING:
        return None
    if _SLITHER_PREDICATES_MODULE is not None:
        return _SLITHER_PREDICATES_MODULE
    try:
        spec = importlib.util.spec_from_file_location(
            "auditooor_live_target_slither_predicates",
            _REPO_ROOT / "tools" / "slither_predicates.py",
        )
        if spec is None or spec.loader is None:
            _SLITHER_PREDICATES_MODULE = _SLITHER_PREDICATES_MISSING
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _SLITHER_PREDICATES_MODULE = module
        return module
    except Exception:
        _SLITHER_PREDICATES_MODULE = _SLITHER_PREDICATES_MISSING
        return None


def _source_looks_like_solidity_unit(source: str) -> bool:
    if not source or len(source) > _SLITHER_SOURCE_MAX_CHARS:
        return False
    clean = _strip_comments(source)
    return bool(
        re.search(r"\b(?:contract|library|interface)\s+[A-Za-z_][A-Za-z0-9_]*", clean)
        and re.search(r"\bfunction\s+[A-Za-z_][A-Za-z0-9_]*\s*\(", clean)
    )


def _slither_probe_source(source: str) -> str:
    if re.search(r"\bpragma\s+solidity\b", source):
        return source
    return "// SPDX-License-Identifier: UNLICENSED\npragma solidity >=0.8.0;\n" + source


def _slither_functions_for_source(source: str) -> list[Any]:
    if not _slither_predicates_enabled() or not _source_looks_like_solidity_unit(source):
        return []
    key = hashlib.sha256(source.encode("utf-8", errors="ignore")).hexdigest()
    if key in _SLITHER_FUNCTION_CACHE:
        return _SLITHER_FUNCTION_CACHE[key]
    functions: list[Any] = []
    try:
        import contextlib
        import io
        from slither.slither import Slither  # type: ignore

        with tempfile.TemporaryDirectory(prefix="auditooor-p1-slither-") as tmp:
            probe = Path(tmp) / "PredicateProbe.sol"
            probe.write_text(_slither_probe_source(source), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                slither = Slither(str(probe))
            for contract in getattr(slither, "contracts", []) or []:
                for function in getattr(contract, "functions_declared", []) or []:
                    functions.append(function)
    except Exception:
        functions = []
    _SLITHER_FUNCTION_CACHE[key] = functions
    return functions


def _normalise_source_for_match(source: str) -> str:
    return re.sub(r"\s+", "", _strip_comments(source or ""))


def _slither_function_source(function: Any) -> str:
    try:
        return str(getattr(getattr(function, "source_mapping", None), "content", "") or "")
    except Exception:
        return ""


def _slither_function_row(function: Any) -> dict[str, str]:
    source = _slither_function_source(function)
    rows = _solidity_function_segments(source)
    if rows:
        return rows[0]
    name = str(getattr(function, "name", "") or "")
    visibility = str(getattr(function, "visibility", "") or "")
    signature = f"function {name}() {visibility}".strip()
    return {"name": name, "signature": signature, "body": source, "segment": source}


def _slither_function_is_external_entry(function: Any, row: dict[str, str]) -> bool:
    visibility = str(getattr(function, "visibility", "") or "").lower()
    if visibility in {"internal", "private"}:
        return False
    if visibility in {"external", "public"}:
        return True
    return _solidity_segment_is_external_entry(row)


def _slither_synthetic_function_from_row(row: dict[str, str]) -> Any:
    signature = row.get("signature", "") or ""
    known_words = {
        "address",
        "bool",
        "bytes",
        "bytes32",
        "calldata",
        "external",
        "function",
        "internal",
        "memory",
        "override",
        "payable",
        "private",
        "public",
        "returns",
        "storage",
        "string",
        "uint",
        "uint256",
        "view",
        "virtual",
    }
    close_paren = signature.rfind(")")
    suffix = signature[close_paren + 1 :] if close_paren >= 0 else signature
    modifiers = []
    for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", suffix):
        if token in known_words or re.fullmatch(r"u?int(?:8|16|32|64|128|256)?", token):
            continue
        modifiers.append(type("_SyntheticModifier", (), {"name": token})())
    return type(
        "_SyntheticSlitherFunction",
        (),
        {
            "name": row.get("name", ""),
            "visibility": " ".join(
                tok for tok in ("external", "public", "internal", "private")
                if re.search(rf"\b{tok}\b", signature)
            ),
            "modifiers": modifiers,
            "nodes": [],
            "source_mapping": type(
                "_SyntheticSourceMapping",
                (),
                {"content": row.get("segment", "")},
            )(),
        },
    )()


def _slither_candidate_functions_for_predicate(source: str) -> list[Any]:
    full_source = getattr(source, "contract_source", "") or str(source)
    functions = _slither_functions_for_source(full_source)
    if not functions:
        return []

    narrowed: list[Any] = []
    snippet = getattr(source, "snippet", "") or ""
    snippet_norm = _normalise_source_for_match(snippet)
    if snippet_norm:
        for function in functions:
            if snippet_norm in _normalise_source_for_match(_slither_function_source(function)):
                narrowed.append(function)
        if narrowed:
            return narrowed

    source_norm = _normalise_source_for_match(str(source))
    if source_norm:
        for function in functions:
            function_norm = _normalise_source_for_match(_slither_function_source(function))
            if source_norm in function_norm or function_norm in source_norm:
                narrowed.append(function)
        if narrowed:
            return narrowed

    return [] if snippet_norm else functions


def _slither_ast_check(function: Any, label: str) -> bool:
    module = _load_slither_predicates_module()
    if module is None:
        return False
    try:
        return bool(module.check(function, label))
    except Exception:
        return False


def _slither_has_bridge_caller_guard(function: Any, source: str) -> bool:
    if _slither_ast_check(function, "has_only_owner_modifier"):
        return True
    if not _has_bridge_caller_guard(source):
        return False
    if re.search(r"\bmsg\.sender\b", source):
        return _slither_ast_check(function, "reads_msg_sender")
    return True


def _slither_has_role_guard(function: Any, source: str) -> bool:
    if _slither_ast_check(function, "has_only_owner_modifier"):
        return True
    if not _has_solidity_role_guard(source):
        return False
    if re.search(r"\bmsg\.sender\b", source):
        return _slither_ast_check(function, "reads_msg_sender")
    return True


def _slither_call_name(call: Any) -> str:
    try:
        if isinstance(call, (list, tuple)) and len(call) >= 2:
            call = call[1]
        return str(getattr(call, "name", None) or call or "")
    except Exception:
        return ""


def _slither_node_has_external_effect(node: Any) -> bool:
    try:
        if getattr(node, "low_level_calls", []) or []:
            return True
    except Exception:
        pass
    try:
        for call in getattr(node, "high_level_calls", []) or []:
            if re.search(r"^(?:safeTransfer|safeTransferFrom|transfer|transferFrom|sendValue)$", _slither_call_name(call), re.I):
                return True
    except Exception:
        pass
    return False


def _slither_state_var_names(values: Any) -> set[str]:
    names: set[str] = set()
    for value in values or []:
        try:
            name = str(getattr(value, "name", None) or value or "")
        except Exception:
            name = ""
        if name:
            names.add(name)
    return names


def _slither_indexed_state_reads(node: Any) -> set[str]:
    expr = str(getattr(node, "expression", "") or "")
    if "[" not in expr or "]" not in expr:
        return set()
    return _slither_state_var_names(getattr(node, "state_variables_read", []) or [])


def _slither_truthy_indexed_state_writes(node: Any) -> set[str]:
    expr = str(getattr(node, "expression", "") or "")
    if "[" not in expr or "]" not in expr:
        return set()
    if re.search(
        r"\bdelete\b|=\s*(?:false\b|0\b|0x0+\b|address\s*\(\s*0\s*\)|bytes32\s*\(\s*0\s*\))",
        expr,
        re.I,
    ):
        return set()
    return _slither_state_var_names(getattr(node, "state_variables_written", []) or [])


def _slither_indexed_state_writes(node: Any) -> set[str]:
    expr = str(getattr(node, "expression", "") or "")
    if "[" not in expr or "]" not in expr:
        return set()
    return _slither_state_var_names(getattr(node, "state_variables_written", []) or [])


def _slither_bridge_003_function_violation(function: Any) -> bool | None:
    if not (
        _slither_ast_check(function, "has_low_level_call")
        or _slither_ast_check(function, "has_low_level_delegatecall")
        or _slither_ast_check(function, "has_safe_transfer")
        or _slither_ast_check(function, "has_transfer_from")
    ):
        return None
    nodes = list(getattr(function, "nodes", []) or [])
    first_call_idx = None
    for idx, node in enumerate(nodes):
        if _slither_node_has_external_effect(node):
            first_call_idx = idx
            break
    if first_call_idx is None:
        return None

    before_call = nodes[:first_call_idx]
    after_call = nodes[first_call_idx + 1 :]
    pre_reads = set().union(*(_slither_indexed_state_reads(node) for node in before_call)) if before_call else set()
    pre_truthy_writes = (
        set().union(*(_slither_truthy_indexed_state_writes(node) for node in before_call))
        if before_call
        else set()
    )
    post_writes = (
        set().union(*(_slither_indexed_state_writes(node) for node in after_call))
        if after_call
        else set()
    )

    if pre_truthy_writes:
        return False
    if pre_reads or post_writes:
        if _slither_ast_check(function, "has_non_reentrant_modifier"):
            return False
        return True
    return None


def _slither_bridge_001_function_violation(function: Any) -> bool | None:
    row = _slither_function_row(function)
    if not _slither_function_is_external_entry(function, row):
        return None
    if not _is_bridge_inbound_segment(row):
        return None
    return not _slither_has_bridge_caller_guard(function, row["segment"])


def _slither_bridge_002_function_violation(function: Any) -> bool | None:
    row = _slither_function_row(function)
    if not _slither_function_is_external_entry(function, row):
        return None
    registration_re = re.compile(
        r"\b(?:addChain|addClient|registerChain|registerStateMachine|setClient|setStateMachine)\s*\(",
        re.I,
    )
    if not (registration_re.search(row.get("name", "") + "(") or registration_re.search(row["segment"])):
        return None
    return not _slither_has_role_guard(function, row["segment"])


def _slither_expr_has_source_nonce_tuple(expr: str) -> bool:
    return bool(
        re.search(r"\b(?:nonce|messageNonce)\b", expr, re.I)
        and re.search(r"\b(?:sourceChain|srcChain|srcEid|chainId)\b", expr, re.I)
    )


def _bridge_004_request_hash_re() -> re.Pattern[str]:
    return re.compile(r"\b(?:response\s*\.\s*)?request\s*\.\s*hash\s*\(\s*\)", re.I)


def _bridge_004_expr_has_request_hash(expr: str) -> bool:
    return bool(_bridge_004_request_hash_re().search(expr))


def _bridge_004_commitment_aliases(segment: str) -> set[str]:
    aliases: set[str] = set()
    for match in re.finditer(
        r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:response\s*\.\s*)?request\s*\.\s*hash\s*\(\s*\)",
        segment,
        re.I,
    ):
        aliases.add(match.group("name"))
    return aliases


def _bridge_004_expr_uses_commitment_hash_key(expr: str, aliases: set[str]) -> bool:
    if "[" not in expr or "]" not in expr:
        return False
    if re.search(
        r"\[[^\]]*(?:response\s*\.\s*)?request\s*\.\s*hash\s*\(\s*\)[^\]]*\]",
        expr,
        re.I | re.S,
    ):
        return True
    if not aliases:
        return False
    alias_re = "|".join(re.escape(alias) for alias in sorted(aliases))
    return bool(re.search(rf"\[[^\]]*\b(?:{alias_re})\b[^\]]*\]", expr, re.I | re.S))


def _bridge_004_segment_has_replay_key(segment: str) -> bool:
    return _slither_expr_has_source_nonce_tuple(segment) or _bridge_004_expr_has_request_hash(segment)


def _bridge_004_segment_tracks_commitment_hash(segment: str) -> bool:
    return _bridge_004_expr_uses_commitment_hash_key(segment, _bridge_004_commitment_aliases(segment))


def _slither_replay_key_tracked(function: Any, row: dict[str, str]) -> bool:
    saw_indexed_state = False
    saw_tuple_state_access = False
    saw_commitment_hash_state_access = False
    aliases = _bridge_004_commitment_aliases(row["segment"])
    for node in getattr(function, "nodes", []) or []:
        expr = str(getattr(node, "expression", "") or "")
        indexed_state = bool(
            _slither_indexed_state_reads(node)
            or _slither_indexed_state_writes(node)
            or _slither_truthy_indexed_state_writes(node)
        )
        saw_indexed_state = saw_indexed_state or indexed_state
        if indexed_state and _slither_expr_has_source_nonce_tuple(expr):
            saw_tuple_state_access = True
        if indexed_state and _bridge_004_expr_uses_commitment_hash_key(expr, aliases):
            saw_commitment_hash_state_access = True
    if saw_tuple_state_access or saw_commitment_hash_state_access:
        return True
    segment = row["segment"]
    tuple_segment_tracked = bool(
        saw_indexed_state
        and (
            _slither_ast_check(function, "computes_keccak")
            or re.search(r"\bkeccak256\s*\(", segment, re.I)
        )
        and _slither_expr_has_source_nonce_tuple(segment)
    )
    return tuple_segment_tracked or _bridge_004_segment_tracks_commitment_hash(segment)


def _slither_bridge_004_function_violation(function: Any) -> bool | None:
    row = _slither_function_row(function)
    if not _slither_function_is_external_entry(function, row):
        return None
    if not _is_bridge_inbound_segment(row):
        return None
    segment = row["segment"]
    if not _bridge_004_segment_has_replay_key(segment):
        return None
    return not _slither_replay_key_tracked(function, row)


def _slither_bridge_005_function_violation(function: Any) -> bool | None:
    row = _slither_function_row(function)
    if not _slither_function_is_external_entry(function, row):
        return None
    segment = row["segment"]
    if not re.search(r"\b(?:finalityProof|stateProof|proof)\b", segment, re.I):
        return None
    proof_height = re.search(
        r"\b(?:finalityProof|stateProof|proof)\s*\.\s*(?:blockNumber|height|slot|timestamp)\b",
        segment,
        re.I,
    )
    if proof_height is None:
        return None
    has_block_clock = _slither_ast_check(function, "reads_block_number") or _slither_ast_check(
        function, "reads_block_timestamp"
    )
    if has_block_clock and re.search(
        r"\b(?:FRESHNESS_WINDOW|FINALITY_WINDOW|MAX_PROOF_AGE|STALE_PROOF|STALE_SLOT)\b"
        r"|(?:-|>|>=|<|<=)",
        segment,
        re.I,
    ):
        return False
    return True


def _bridge_006_source_domain_re() -> re.Pattern[str]:
    return re.compile(
        r"\b(?:source|src|origin)\w*(?:ChainId|Domain|DomainId|NetworkId)\b"
        r"|\b(?:sourceChain|srcChain|srcEid)\b",
        re.I,
    )


def _bridge_006_destination_domain_re() -> re.Pattern[str]:
    return re.compile(
        r"\b(?:destination|dest|dst|target|local)\w*(?:ChainId|Domain|DomainId|NetworkId)\b"
        r"|\b(?:destinationChain|destChain|dstChain|targetChain|localDomain)\b",
        re.I,
    )


def _bridge_006_verifier_context_re() -> re.Pattern[str]:
    return re.compile(
        r"\b(?:verify|process|consume|finalize|prove|relay|claim)\w*\b"
        r"|\b(?:proof|root|leaf|nonce|message|payload|withdrawal|commitment|replay|consumed)\b",
        re.I,
    )


def _bridge_006_flow_context_re() -> re.Pattern[str]:
    return re.compile(
        r"\b(?:proof|bridge|withdraw|relay|message|gateway|mailbox)\b"
        r"|bridge\w*proof|proof\w*bridge",
        re.I,
    )


def _bridge_006_digest_re() -> re.Pattern[str]:
    return re.compile(
        r"\bkeccak256\s*\(\s*abi\.encode(?:Packed)?\s*\([^;{}]{0,320}\)\s*\)",
        re.I | re.S,
    )


def _bridge_006_function_is_relevant(row: dict[str, str]) -> bool:
    segment = row["segment"]
    context = row.get("name", "") + " " + segment
    return bool(
        _bridge_006_verifier_context_re().search(context)
        and _bridge_006_source_domain_re().search(segment)
        and (
            _is_bridge_inbound_segment(row)
            or _bridge_006_flow_context_re().search(context)
        )
    )


def _bridge_006_digest_missing_domain_binding(segment: str) -> bool | None:
    saw_digest = False
    for match in _bridge_006_digest_re().finditer(segment):
        saw_digest = True
        digest = match.group(0)
        source_bound = _bridge_006_source_domain_re().search(digest)
        destination_bound = _bridge_006_destination_domain_re().search(digest)
        if source_bound and destination_bound:
            continue
        if not source_bound:
            continue
        if _bridge_006_verifier_context_re().search(digest) or re.search(
            r"\b(?:proof|root|leaf|nonce|message|payload|withdrawal|commitment)\b",
            digest,
            re.I,
        ):
            return True
    if saw_digest:
        return False
    return None


def _bridge_006_signature_declares_both_domains(row: dict[str, str]) -> bool:
    signature = row.get("signature", "")
    return bool(
        _bridge_006_source_domain_re().search(signature)
        and _bridge_006_destination_domain_re().search(signature)
    )


def _bridge_006_digest_has_bridge_payload_context(digest: str) -> bool:
    return bool(
        re.search(
            r"\b(?:proof|root|leaf|message|payload|withdrawal|commitment)\b",
            digest,
            re.I,
        )
    )


def _bridge_006_slither_digest_missing_both_domains(row: dict[str, str]) -> bool:
    segment = row["segment"]
    if not _bridge_006_signature_declares_both_domains(row):
        return False
    for match in _bridge_006_digest_re().finditer(segment):
        digest = match.group(0)
        if (
            _bridge_006_source_domain_re().search(digest)
            or _bridge_006_destination_domain_re().search(digest)
        ):
            continue
        if _bridge_006_digest_has_bridge_payload_context(digest):
            return True
    return False


def _slither_bridge_006_function_violation(function: Any) -> bool | None:
    row = _slither_function_row(function)
    if not _slither_function_is_external_entry(function, row):
        return None
    if not _bridge_006_function_is_relevant(row):
        return None
    if not _slither_ast_check(function, "computes_abi_encode"):
        return False
    if not (
        _slither_ast_check(function, "computes_keccak")
        or re.search(r"\bkeccak256\s*\(", row["segment"], re.I)
    ):
        return False
    verdict = _bridge_006_digest_missing_domain_binding(row["segment"])
    if verdict is False and _bridge_006_slither_digest_missing_both_domains(row):
        return True
    return False if verdict is None else verdict


def _p1_predicate_bridge_slither(source: str, checker: Callable[[Any], bool | None]) -> bool | None:
    functions = _slither_candidate_functions_for_predicate(source)
    if not functions:
        return None
    saw_relevant_safe = False
    for function in functions:
        verdict = checker(function)
        if verdict is True:
            return True
        if verdict is False:
            saw_relevant_safe = True
    if saw_relevant_safe:
        return False
    return None


def _p1_predicate_bridge_001_slither(source: str) -> bool | None:
    return _p1_predicate_bridge_slither(source, _slither_bridge_001_function_violation)


def _p1_predicate_bridge_002_slither(source: str) -> bool | None:
    return _p1_predicate_bridge_slither(source, _slither_bridge_002_function_violation)


def _p1_predicate_bridge_003_slither(source: str) -> bool | None:
    return _p1_predicate_bridge_slither(source, _slither_bridge_003_function_violation)


def _p1_predicate_bridge_004_slither(source: str) -> bool | None:
    return _p1_predicate_bridge_slither(source, _slither_bridge_004_function_violation)


def _p1_predicate_bridge_005_slither(source: str) -> bool | None:
    return _p1_predicate_bridge_slither(source, _slither_bridge_005_function_violation)


def _p1_predicate_bridge_006_slither(source: str) -> bool | None:
    return _p1_predicate_bridge_slither(source, _slither_bridge_006_function_violation)


def _p1_predicate_solidity_function_slither(
    source: str,
    checker: Callable[[Any], bool | None],
) -> bool | None:
    functions = _slither_candidate_functions_for_predicate(source)
    if not functions:
        return None
    saw_relevant_safe = False
    for function in functions:
        verdict = checker(function)
        if verdict is True:
            return True
        if verdict is False:
            saw_relevant_safe = True
    if saw_relevant_safe and len(functions) == 1:
        return False
    return None


def _slither_auth_001_function_violation(function: Any) -> bool | None:
    row = _slither_function_row(function)
    if row["name"] not in {"_authorizeUpgrade", "upgradeTo", "upgradeToAndCall"}:
        return None
    if _slither_ast_check(function, "has_only_owner_modifier"):
        return False
    return not _has_solidity_role_guard(row.get("body", "") or row["segment"])


def _slither_auth_006_function_violation(function: Any) -> bool | None:
    row = _slither_function_row(function)
    if not _slither_function_is_external_entry(function, row):
        return None
    name = row["name"].lower()
    segment = row["segment"]
    emergency_name = re.search(
        r"(?:pause|emergency|withdrawall|sweep|rescue|selfdestruct|destroy)",
        name,
        re.I,
    )
    emergency_effect = (
        _slither_ast_check(function, "calls_selfdestruct")
        or re.search(
            r"\b(?:_pause|pause|selfdestruct|suicide)\s*\("
            r"|\bpaused\s*=\s*true\b"
            r"|\b(?:withdrawAll|sweep|rescue)[A-Za-z0-9_]*\s*\(",
            segment,
            re.I | re.S,
        )
    )
    if not (emergency_name or emergency_effect):
        return None
    return not _has_timelock_or_multisig_guard(segment)


def _slither_defi_003_function_violation(function: Any) -> bool | None:
    row = _slither_function_row(function)
    if not re.search(
        r"\b(?:getPrice|price|quote|consult|valueOf|assetValue|latestPrice|_price)\b",
        row["name"],
        re.I,
    ):
        return None
    segment = row["segment"]
    has_spot_oracle_read = _slither_ast_check(function, "has_latest_round_data") or bool(
        re.search(r"\b(?:slot0|getReserves|latestAnswer)\s*\(", segment, re.I)
    )
    if not has_spot_oracle_read:
        return None
    has_freshness_or_twap = bool(
        re.search(
            r"\b(?:observe|consult|TWAP|twap|timeWeighted|meanTick|secondsAgo|"
            r"updatedAt|answeredInRound|heartbeat|STALE|MAX_STALENESS|MAX_DELAY|"
            r"block\.timestamp\s*-\s*updatedAt)\b",
            segment,
            re.I,
        )
    )
    if has_freshness_or_twap:
        return False
    return True


def _slither_defi_001_function_violation(function: Any) -> bool | None:
    row = _slither_function_row(function)
    if not re.search(
        r"(?:addLiquidity|deposit|fill|fund|mint|pay|purchase|stake|supply)",
        row["name"],
        re.I,
    ):
        return None
    segment = row["segment"]
    if not re.search(
        r"\.\s*(?:safeTransferFrom|transferFrom)\s*\([^;{}]*address\s*\(\s*this\s*\)[^;{}]*\)",
        segment,
        re.I | re.S,
    ):
        return None
    has_observed_balance_read = _slither_ast_check(function, "has_balance_of") or bool(
        re.search(r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)", segment, re.I)
    )
    if not has_observed_balance_read:
        return True
    has_delta_accounting = bool(
        re.search(
            r"\b(?:balanceBefore|beforeBalance|preBalance|assetsBefore)\b"
            r"[\s\S]{0,260}\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)"
            r"|\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)"
            r"[\s\S]{0,260}\b(?:balanceAfter|afterBalance|postBalance|assetsAfter)\b"
            r"|\b(?:received|actualReceived|assetsReceived|delta)\s*=\s*"
            r"(?:balanceAfter|afterBalance|postBalance|assetsAfter)\s*-\s*"
            r"(?:balanceBefore|beforeBalance|preBalance|assetsBefore)",
            segment,
            re.I | re.S,
        )
    )
    if not has_delta_accounting:
        return True
    return False


def _slither_defi_002_function_violation(function: Any) -> bool | None:
    row = _slither_function_row(function)
    segment = row["segment"]
    if not re.search(r"\b(?:rebase|rebasing|elastic|stETH|aToken|cToken|scaledBalance|gons)\b", segment, re.I):
        return None
    if not re.search(
        r"\b(?:totalAssets|exchangeRate|previewRedeem|previewWithdraw|redeem|withdraw)\b",
        row["name"],
        re.I,
    ):
        return None
    has_raw_balance_read = _slither_ast_check(function, "has_balance_of") or bool(
        re.search(r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)", segment, re.I)
    )
    if not has_raw_balance_read:
        return None
    has_share_index_accounting = bool(
        re.search(
            r"\b(?:convertToAssets|convertToShares|getPooledEthByShares|getSharesByPooledEth|"
            r"scaledBalanceOf|liquidityIndex|sharePrice|exchangeRateStored|rebasingCreditsPerToken|"
            r"sharesOf|totalShares)\b",
            segment,
            re.I,
        )
    )
    if not has_share_index_accounting:
        return True
    return False


def _slither_uni_002_function_violation(function: Any) -> bool | None:
    row = _slither_function_row(function)
    segment = row["segment"]
    has_signature_path = _slither_ast_check(function, "calls_ecrecover") or bool(
        re.search(
            r"\b(?:ECDSA\.recover|recover)\s*\("
            r"|\bpermit\s*\("
            r"|\b_hashTypedDataV4\s*\(",
            segment,
            re.I | re.S,
        )
    )
    if not has_signature_path:
        return None
    has_typed_domain = bool(
        re.search(
            r"\b(domain_separator|domainseparator|DOMAIN_SEPARATOR|EIP712|permit)\b",
            segment,
            re.I | re.S,
        )
    )
    if not has_typed_domain:
        return None
    nonce_bumped = bool(
        re.search(
            r"\bnonces?\s*(?:\[[^\]]+\]|\([^)]+\)|\.[A-Za-z_][A-Za-z0-9_]*)"
            r"\s*(?:\+\+|\+=\s*1|=\s*[^;]+\+\s*1)",
            segment,
            re.I | re.S,
        )
    )
    return not nonce_bumped


def _solidity_write_debits_amount(row: dict[str, str], amount_expr: str) -> bool:
    stmt = row["statement"]
    stmt_norm = row["statement_norm"]
    return bool(
        f"-={amount_expr}" in stmt_norm
        or f"-{amount_expr}" in stmt_norm
        or re.search(r"-=\s*[A-Za-z_][A-Za-z0-9_]*", stmt)
        or re.search(
            r"=\s*[A-Za-z_][A-Za-z0-9_]*\s*-\s*[A-Za-z_][A-Za-z0-9_]*",
            stmt,
        )
    )


def _native_value_call_debited_before_call(source_context: str, snippet: str) -> bool:
    """Conservative CAP-007 shape: ledger slot is debited before native value call.

    This suppresses Checks-Effects-Interactions false positives such as:
    ``_orders[commitment][token] = escrowed - amount;`` followed by
    ``beneficiary.call{value: amount}("")``. It intentionally requires a
    bracket/member storage-looking slot and amount-decrement evidence.
    """
    call_pos, before, after = _solidity_call_slices_in_current_function(
        source_context,
        snippet,
    )
    if call_pos < 0:
        return False
    call_window = source_context[call_pos : call_pos + 260]
    value_match = re.search(r"\.call\s*\{\s*value\s*:\s*([^}]+)\}", call_window, re.S)
    if not value_match:
        return False
    amount_expr = _normalise_solidity_expr(value_match.group(1)).strip()
    if not amount_expr:
        return False

    after_amount_debits = [
        row for row in _solidity_write_rows(after, broad=True)
        if _solidity_write_debits_amount(row, amount_expr)
    ]
    for row in _solidity_write_rows(before):
        slot = row["slot"]
        if not _solidity_write_debits_amount(row, amount_expr):
            continue
        same_slot_after = any(after_row["slot"] == slot for after_row in after_amount_debits)
        other_amount_debit_after = any(after_row["slot"] != slot for after_row in after_amount_debits)
        if not same_slot_after and not other_amount_debit_after:
            return True
    return False


def _has_storage_write_after_call(source_context: str, snippet: str) -> bool:
    call_pos, _, after = _solidity_call_slices_in_current_function(source_context, snippet)
    if call_pos < 0:
        return False
    return bool(_solidity_write_rows(after, broad=True))


def _cap005_nonzero_constant_names(source: str) -> set[str]:
    names: set[str] = set()
    for stmt in _strip_comments(source).split(";"):
        if "constant" not in stmt.lower():
            continue
        match = re.search(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*((?:[1-9]\d*(?:e\d+)?)|(?:10\s*\*\*\s*[^;\n]+))\s*$",
            stmt.strip(),
            re.I | re.S,
        )
        if match:
            names.add(match.group(1))
    return names


def _cap005_divisors(source: str) -> list[str]:
    divisors: list[str] = []
    for match in re.finditer(
        r"/\s*(?P<divisor>10\s*\*\*\s*[^;\n,)]+|[1-9]\d*(?:e\d+)?|[A-Za-z_][A-Za-z0-9_]*)\b",
        source,
        re.I,
    ):
        divisors.append(match.group("divisor").strip())
    return divisors


def _cap005_divisor_safe(source_context: str, contract_context: str, snippet: str) -> bool:
    source = _strip_comments(source_context)
    target = _strip_comments(snippet) if snippet and "/" in snippet else source
    contract = _strip_comments(contract_context or source_context)
    divisors = _cap005_divisors(target)
    if not divisors:
        return False

    constants = _cap005_nonzero_constant_names(contract)
    for divisor in divisors:
        if re.fullmatch(r"(?:[1-9]\d*(?:e\d+)?|10\s*\*\*\s*.+)", divisor, re.I):
            continue
        name = divisor
        if name in constants:
            continue
        escaped = re.escape(name)
        if re.search(rf"%\s*{escaped}\b[\s\S]{{0,160}}/\s*{escaped}\b", source):
            continue
        return False
    return True


def _contract_exposes_effective_unpause(contract_context: str) -> bool:
    clean = _strip_comments(contract_context)
    pattern = re.compile(r"\bfunction\s+unpause\s*\(", re.S)
    for match in pattern.finditer(clean):
        open_brace = clean.find("{", match.end())
        if open_brace < 0:
            continue
        semi = clean.find(";", match.end(), open_brace)
        if semi >= 0:
            continue
        close_brace = _find_matching_brace(clean, open_brace)
        if close_brace is None:
            continue
        signature = clean[match.start():open_brace]
        body = clean[open_brace + 1:close_brace]
        if not re.search(r"\b(?:external|public)\b", signature):
            continue
        if re.search(r"\b(?:internal|private)\b", signature):
            continue
        clears_pause = (
            any(
                "paused" in match.group(1).lower()
                for match in re.finditer(
                    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*false\b",
                    body,
                    re.I,
                )
            )
            or re.search(r"\b_unpause\s*\(", body)
        )
        if clears_pause:
            return True
    return False


def _cap019_validated_oapp_delivery(call_context: str, snippet: str) -> bool:
    clean = _strip_comments_and_strings(call_context)
    call_pos = _cap019_lzreceive_call_position(clean, snippet)
    if call_pos < 0:
        return False
    before_call = clean[:call_pos].lower()
    signature = clean[: clean.find("{")] if "{" in clean else before_call

    if not re.search(r"\bonlyhost\b", signature, re.I):
        return False

    from_validation = re.search(
        r"\b(?:if|require)\s*\([^;{}]*request\.from[^;{}]*(?:==|!=)[^;{}]*\)",
        before_call,
        re.I | re.S,
    )
    source_validation = (
        ("request.source" in before_call or "_statemachinetoeid" in before_call)
        and re.search(
            r"\b(?:if|require)\s*\([^;{}]*(?:request\.source|expectedeid|srceid|_statemachinetoeid)"
            r"[^;{}]*(?:==|!=)[^;{}]*\)",
            before_call,
            re.I | re.S,
        )
    )
    nonce_validation = (
        "_inboundnonce" in before_call
        and re.search(
            r"\b(?:if|require)\s*\([^;{}]*nonce[^;{}]*(?:==|!=|<=|>=|<|>)[^;{}]*"
            r"(?:expectednonce|_inboundnonce|nonce)[^;{}]*\)",
            before_call,
            re.I | re.S,
        )
    )
    nonce_consumed = re.search(r"_inboundnonce\s*\[[^;]+?\]\s*=\s*nonce\b", before_call, re.I | re.S)
    return bool(from_validation and source_validation and nonce_validation and nonce_consumed)


def _low_level_call_return_checked(call_context: str, snippet: str) -> bool:
    """Return true when the cited low-level call result is checked locally."""
    call_pos = _call_position(call_context, snippet)
    if call_pos < 0:
        return False

    statement_start = max(
        call_context.rfind(";", 0, call_pos),
        call_context.rfind("{", 0, call_pos),
    )
    statement_start = 0 if statement_start < 0 else statement_start + 1
    statement_end = call_context.find(";", call_pos)
    if statement_end < 0:
        statement_end = min(len(call_context), call_pos + 520)
    statement = call_context[statement_start : statement_end + 1]
    after_statement = call_context[statement_end + 1 : min(len(call_context), statement_end + 640)]

    if re.search(
        r"\brequire\s*\([^;{}]{0,180}\.call\s*(?:\{[^{}]*\})?\s*\(",
        statement,
        re.I | re.S,
    ):
        return True

    assigned = re.search(
        r"\(\s*bool\s+([A-Za-z_][A-Za-z0-9_]*)\b[^)]*\)\s*=\s*[^;]*?\.call\s*(?:\{[^{}]*\})?\s*\("
        r"|\bbool\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]*?\.call\s*(?:\{[^{}]*\})?\s*\(",
        statement,
        re.I | re.S,
    )
    if not assigned:
        return False
    var_name = next(group for group in assigned.groups() if group)
    var = re.escape(var_name)
    return bool(
        re.search(
            rf"\b(?:if|require|assert)\s*\([^;{{}}]*(?:!\s*{var}\b|"
            rf"{var}\s*(?:==|!=)\s*(?:false|true)|"
            rf"{var}\b)[^;{{}}]*\)",
            after_statement,
            re.I | re.S,
        )
    )


def _detector_false_positive_suppression(
    cluster_id: str,
    *,
    file_line: str,
    snippet: str,
    source_context: str,
    source_contract_context: str = "",
) -> dict[str, Any]:
    """Suppress documented CAP false-positive source shapes.

    This lives in the report pipeline, not in the underlying detector, so it
    is intentionally conservative: it only fires on the exact documented
    detector families and context shapes.
    """
    cid = cluster_id.lower()
    contract_context = source_contract_context or source_context
    text = "\n".join([file_line, snippet, source_context, contract_context]).lower()
    reasons: list[str] = []

    if "unchecked-low-level-call" in cid:
        call_context = (
            _solidity_function_context_for_snippet(contract_context, snippet)
            or _solidity_function_context_for_snippet(source_context, snippet)
            or source_context
        )
        if _low_level_call_return_checked(call_context, snippet):
            reasons.append("CAP-022: low-level call return value is checked in cited function")

    if "inverted-verify-return" in cid:
        bool_verify_return_shape = re.search(
            r"\bfunction\s+verify\w*\s*\([^;{}]*\)\s*[^;{}]*returns\s*\(\s*(?:bool|boolean)\b",
            contract_context,
            re.I | re.S,
        )
        bool_call_shape = (
            re.search(r"\bverify\w*\s*\([^;]*\)\s*(?:==|!=|&&|\|\|)", source_context)
            or re.search(r"(?:!|\bif\s*\(|\brequire\s*\(|\bassert\s*\()[^;{}]*\bverify\w*\s*\(", source_context)
        )
        interface_tuple_shape = (
            "function verify" in text
            and re.search(r"returns\s*\([^)]*bytes[^)]*intermediatestate[^)]*uint", contract_context, re.I)
        )
        reverting_verifier_shape = "verifyproof" in text and not bool_call_shape
        if interface_tuple_shape or (reverting_verifier_shape and not bool_verify_return_shape):
            reasons.append("CAP-004: verify() interface/reverting-proof shape is not an inverted bool return")

    if "division-by-zero" in cid:
        if _cap005_divisor_safe(source_context, contract_context, snippet):
            reasons.append("CAP-005: divisor is literal/constant or guarded by prior modulo")

    if "erc-2771" in cid or "msgsender-forgery" in cid.lower():
        mentions_msg_sender = "_msgsender" in text
        has_plain_oz_context = "@openzeppelin/contracts/utils/context.sol" in text or "contract context" in text
        has_forwarder = any(
            token in text
            for token in ("erc2771context", "_trustedforwarder", "istrustedforwarder", "minimalforwarder")
        )
        if mentions_msg_sender and has_plain_oz_context and not has_forwarder:
            reasons.append("CAP-006: OpenZeppelin Context _msgSender() without ERC-2771 forwarder scope")

    if "external-call-before-state-update" in cid:
        call_context = (
            _solidity_function_context_for_snippet(contract_context, snippet)
            or _solidity_function_context_for_snippet(source_context, snippet)
            or source_context
        )
        call_pos = _call_position(call_context, snippet)
        if _native_value_call_debited_before_call(call_context, snippet):
            reasons.append("CAP-007: native value call is preceded by same-ledger debit")
        elif call_pos >= 0 and not _has_storage_write_after_call(call_context, snippet):
            reasons.append("CAP-007: no post-call storage mutation in cited function window")
        source_text = "\n".join([file_line, snippet, call_context]).lower()
        if "sig_validation_failed" in source_text or "session key" in source_text:
            reasons.append("CAP-007: view-style/session-key call shape, not value-bearing ledger mutation")

    if "signature-without-nonce" in cid:
        signature_context = (
            _solidity_function_context_for_snippet(contract_context, snippet)
            or _solidity_function_context_for_snippet(source_context, snippet)
            or contract_context
            or source_context
        )
        if _bridge_signature_without_nonce_false_positive(signature_context, text):
            reasons.append(
                "CAP-021: proof/consensus signature recovery is not a bridge nonce replay check"
            )

    if "pausable-no-unpause-exposed" in cid or "missing-unpause" in cid:
        if _contract_exposes_effective_unpause(contract_context):
            reasons.append("CAP-018: same contract exposes unpause()")

    if "lzreceive-no-sender-check" in cid:
        call_context = (
            _solidity_function_context_for_snippet(contract_context, snippet)
            or _solidity_function_context_for_snippet(source_context, snippet)
        )
        if call_context:
            body = _first_solidity_function_body(call_context, ("lzReceive",))
            if body is not None and _is_revert_only_body(body):
                reasons.append("CAP-019: lzReceive is a deliberate revert tombstone")
            elif _cap019_validated_oapp_delivery(call_context, snippet):
                reasons.append("CAP-019: OApp lzReceive delivery follows source and nonce validation")

    if not reasons:
        return {"suppressed": False, "reasons": [], "score_penalty": 0.0}
    return {
        "suppressed": True,
        "reasons": reasons,
        "score_penalty": DOCUMENTED_FP_SCORE_PENALTY,
    }


def _has_solidity_role_guard(source: str) -> bool:
    """Best-effort check for an access-control guard in one Solidity function."""
    clean = _strip_comments(source)
    has_modifier_or_require_guard = bool(
        re.search(
            r"\bonly(?:Owner|Role|Admin|Governance|Governor|Upgrader|Guardian)\b"
            r"|\b(?:_checkOwner|_checkRole|hasRole)\s*\("
            r"|\brequire\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\))"
            r"[^;{}]*(?:owner|admin|role|governance|governor|upgrader)"
            r"|\brequire\s*\([^;{}]*(?:owner|admin|role|governance|governor|upgrader)"
            r"[^;{}]*(?:msg\.sender|_msgSender\s*\(\))",
            clean,
            re.I | re.S,
        )
    )
    if has_modifier_or_require_guard:
        return True
    has_if_revert_guard = bool(
        re.search(
            r"\bif\s*\([^)]*(?:msg\.sender|_msgSender\s*\(\))[^)]*!="
            r"[^)]*(?:owner|admin|governance|governor|upgrader)[^)]*\)\s*revert",
            clean,
            re.I | re.S,
        )
    )
    return has_if_revert_guard and _slither_segment_has_revert_call(clean)


def _slither_segment_has_revert_call(source: str) -> bool:
    module = _load_slither_predicates_module()
    if module is None:
        return True
    try:
        synthetic = _slither_synthetic_function_from_row(
            {"name": "", "signature": "function synthetic() external", "segment": source}
        )
        return bool(module.check(synthetic, "has_revert"))
    except Exception:
        return True


def _has_timelock_or_multisig_guard(source: str) -> bool:
    clean = _strip_comments(source)
    return bool(
        re.search(
            r"\b(?:onlyTimelock|onlyMultisig|onlyMultiSig|TimelockController|timelock|timeLock"
            r"|multisig|multiSig|GnosisSafe|Safe\(|threshold|quorum|eta|delay)\b",
            clean,
            re.I | re.S,
        )
    )


def _has_signature_recovery_shape(source: str) -> bool:
    clean = _strip_comments(source)
    return bool(
        re.search(
            r"\b(?:ecrecover|ECDSA\.recover|SignatureChecker\.isValidSignatureNow"
            r"|isValidSignature)\s*\(",
            clean,
            re.I | re.S,
        )
    )


def _bridge_signature_without_nonce_false_positive(source: str, text: str) -> bool:
    """Detect proof/consensus ecrecover shapes that are not bridge replay checks."""
    clean = _strip_comments(source)
    raw = "\n".join([source, text])
    has_recovery_shape = _has_signature_recovery_shape(clean) or bool(
        re.search(
            r"\b(?:recover(?:s|ed|ing)?\s+signer|signer\s+addresses?\s+via\s+ecrecover|"
            r"ECDSA\s+recovery|signature\s+recovery)\b",
            raw,
            re.I | re.S,
        )
    )
    if not has_recovery_shape:
        return False
    if re.search(
        r"\b(?:nonce|messageNonce|processedNonces|consumedNonces|executedNonces|"
        r"seenNonces|usedNonces|_?inboundNonce(?:s)?|sourceChain|srcChain|srcEid|"
        r"chainId|replay)\b",
        clean,
        re.I | re.S,
    ):
        return False
    return bool(
        re.search(
            r"(?:_?rawsignaturevalidation|recover signer|signature recovery|consensus|"
            r"authority|membership|validator|light client|beefy|proof verification|"
            r"signature validation)",
            raw,
            re.I | re.S,
        )
    )


def _has_deadline_guard(source: str) -> bool:
    clean = _strip_comments(source)
    has_require_or_assert_guard = bool(
        re.search(
            r"\b(?:require|assert)\s*\([^;{}]*(?:deadline|expiry|expiration|validUntil)"
            r"[^;{}]*(?:>=|>)\s*block\.timestamp"
            r"|\b(?:require|assert)\s*\([^;{}]*block\.timestamp\s*(?:<=|<)"
            r"[^;{}]*(?:deadline|expiry|expiration|validUntil)",
            clean,
            re.I | re.S,
        )
    )
    if has_require_or_assert_guard:
        return True
    has_if_revert_guard = bool(
        re.search(
            r"\bif\s*\([^)]*block\.timestamp\s*(?:>|>=)[^)]*"
            r"(?:deadline|expiry|expiration|validUntil)[^)]*\)\s*revert"
            r"|\bif\s*\([^)]*(?:deadline|expiry|expiration|validUntil)"
            r"[^)]*(?:<|<=)\s*block\.timestamp[^)]*\)\s*revert",
            clean,
            re.I | re.S,
        )
    )
    return has_if_revert_guard and _slither_segment_has_revert_call(clean)


def _has_allowance_spend(source: str) -> bool:
    clean = _strip_comments(source)
    return bool(
        re.search(
            r"\b_spendAllowance\s*\("
            r"|\b(?:allowance|allowances|_allowances)\s*(?:\[[^\]]+\]|\([^)]*\))"
            r"(?:\s*(?:\[[^\]]+\]))?\s*(?:-=|=\s*[^;]+-)"
            r"|\b_approve\s*\([^;{}]*(?:allowance|currentAllowance|allowed)"
            r"[^;{}]*-\s*(?:amount|assets|shares|value)",
            clean,
            re.I | re.S,
        )
    )


def _has_owner_only_erc4626_guard(source: str) -> bool:
    clean = _strip_comments(source)
    has_require_or_assert_guard = bool(
        re.search(
            r"\b(?:require|assert)\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\))"
            r"\s*==\s*owner",
            clean,
            re.I | re.S,
        )
    )
    if has_require_or_assert_guard:
        return True
    has_if_revert_guard = bool(
        re.search(
            r"\bif\s*\([^)]*(?:msg\.sender|_msgSender\s*\(\))\s*!=\s*owner"
            r"[^)]*\)\s*revert",
            clean,
            re.I | re.S,
        )
    )
    return has_if_revert_guard and _slither_segment_has_revert_call(clean)


def _has_claimed_reward_write(source: str) -> re.Match[str] | None:
    return re.search(
        r"\b(?:claimed|claimedRewards|rewardClaimed|hasClaimed|claims)"
        r"\s*(?:\[[^\]]+\]|\.[A-Za-z_][A-Za-z0-9_]*)+\s*=\s*true\b"
        r"|\b(?:claimed|claimedRewards|rewardClaimed|hasClaimed|claims)"
        r"\s*(?:\[[^\]]+\]|\.[A-Za-z_][A-Za-z0-9_]*)+\s*\+\+",
        _strip_comments(source),
        re.I | re.S,
    )


def _go_has_direct_keeper_msg_invocation(source: str) -> bool:
    clean = _strip_comments(source)
    direct = re.search(
        r"\b(?:keeper|keepers|k|msgServer|server|handler)\s*\.\s*"
        r"(?:Handle|Execute|Submit|Create|Update|Delete)[A-Za-z0-9_]*\s*"
        r"\(\s*ctx\s*,\s*(?:msg|sdkMsg|message)\b",
        clean,
        re.I | re.S,
    )
    if not direct:
        return False
    return not re.search(r"\b(?:BroadcastTxSync|RunTx|DeliverTx|CheckTx|AnteHandler)\s*\(", clean)


def _go_has_consensus_nondeterminism(source: str) -> bool:
    clean = _strip_comments(source)
    consensus_path = re.search(
        r"\b(?:DeliverTx|FinalizeBlock|BeginBlock|EndBlock|PrepareProposal|ProcessProposal)\b",
        clean,
        re.I,
    )
    if not consensus_path:
        return False
    if re.search(r"\b(?:time\.Now|rand\.|crypto/rand|go\s+func)\b", clean):
        return True
    has_map_range = re.search(r"\bfor\s+[^{}:=]+(?::=|=)\s+range\s+[A-Za-z_][A-Za-z0-9_]*", clean)
    return bool(has_map_range and "sort." not in clean and "slices.Sort" not in clean)


def _go_has_direct_keeper_handlemsg(source: str) -> bool:
    if _ast_function_has_call_without_call(
        source,
        lang="go",
        target_call_pattern=r"\.(?:keeper|msgServer)\.HandleMsg[A-Za-z0-9_]*\b",
        forbidden_call_pattern=r"\b(?:BroadcastTxSync|RunTx|DeliverTx|CheckTx|AnteHandler)\b",
    ):
        return True
    clean = _strip_comments(source)
    return bool(
        re.search(
            r"\b[A-Za-z_][A-Za-z0-9_]*\.(?:keeper|msgServer)\.HandleMsg[A-Za-z0-9_]*\s*\(",
            clean,
            re.I | re.S,
        )
    )


def _p1_predicate_cosmos_001(source: str, _text: str) -> bool:
    """INV-COSMOS-001: Msg execution path bypasses ante decorators by direct keeper dispatch."""
    return _go_has_direct_keeper_handlemsg(source)


def _p1_predicate_cosmos_002(source: str, _text: str) -> bool:
    """INV-COSMOS-002: ProcessProposal accepts tx set without pre-validation."""
    clean = _strip_comments(source)
    process_proposal = _first_go_function_segment(clean, ("ProcessProposal",))
    if process_proposal is None:
        return False

    if _ast_function_has_call_without_call(
        process_proposal,
        lang="go",
        target_call_pattern=r"\b(?:ResponseProcessProposal_ACCEPT|ProcessProposal_ACCEPT|abci\.ResponseProcessProposal|sdk\.ABCIResponse)\b",
        fn_names=("ProcessProposal",),
    ):
        has_request_validation = re.search(
            r"\b(?:len\s*\([^)]*\.Txs|req\.Txs\s*==\s*nil|request\.Txs\s*==\s*nil"
            r"|proposal\.Txs\s*==\s*nil|req\.Txs\s*!=\s*nil|len\(.*req\.Txs\)\s*[<>]=?\s*0"
            r"|len\(.*request\.Txs\)\s*[<>]=?\s*0)\b",
            process_proposal,
            re.I | re.S,
        )
        return not bool(has_request_validation)

    has_accept = re.search(
        r"\b(?:ResponseProcessProposal_ACCEPT|ProcessProposal_ACCEPT|abci\.ResponseProcessProposal|sdk\.ABCIResponse)",
        process_proposal,
        re.I,
    )
    if has_accept is None:
        return False

    has_request_validation = re.search(
        r"\b(?:len\s*\([^)]*\.Txs|req\.Txs\s*==\s*nil|request\.Txs\s*==\s*nil"
        r"|proposal\.Txs\s*==\s*nil|req\.Txs\s*!=\s*nil|len\(.*req\.Txs\)\s*[<>]=?\s*0"
        r"|len\(.*request\.Txs\)\s*[<>]=?\s*0)\b",
        process_proposal,
        re.I | re.S,
    )
    return not bool(has_request_validation)


def _p1_predicate_cosmos_003(source: str, _text: str) -> bool:
    """INV-COSMOS-003: RecvPacket continues while channel is not validated OPEN."""
    clean = _strip_comments(source)
    recv_packet = _first_go_function_segment(clean, ("RecvPacket", "OnRecvPacket"))
    if recv_packet is None:
        return False

    has_open_state_guard = re.search(
        r"\bif\b[^{}]{0,240}\b(?:channel|pkt|channelState)\.[A-Za-z0-9_]*\s*==\s*"
        r"(?:channeltypes\.|channel\.|ibcexported\.)?(?:OPEN|Open|STATE_OPEN)"
        r"|(?:channel|pkt|channelState)\.[A-Za-z0-9_]*\s*!?=\s*(?:channeltypes\.|channel\.|ibcexported\.)?(?:OPEN|Open|STATE_OPEN)",
        recv_packet,
        re.I | re.S,
    )
    if has_open_state_guard is None:
        return True
    return False


def _p1_predicate_cosmos_004(source: str, _text: str) -> bool:
    """INV-COSMOS-004: FeeCollector Send omits module-account existence validation."""
    clean = _strip_comments(source)
    if "send" not in clean.lower():
        return False
    if _ast_function_has_structural_call_without_call(
        clean,
        lang="go",
        structural_predicate="assignment_to_subscript_call",
        target_call_pattern=r"\b(?:SendCoinsFromModuleToAccount|SendCoinsToModule)\b",
        forbidden_call_pattern=r"\bGetModuleAccount(?:Address)?\b",
        fn_names=("Send", "SendCoins", "SendToModule"),
    ):
        return True
    fee_sender = _first_go_function_segment(clean, ("Send", "SendCoins", "SendToModule"))
    if fee_sender is None:
        return False

    if "sendcoinsfrommoduletoaccount" not in fee_sender.lower() and "sendcoinstomodule" not in fee_sender.lower():
        return False

    has_module_account_guard = re.search(
        r"\bGetModuleAccount(?:Address)?\s*\(",
        fee_sender,
        re.I,
    )
    return not bool(has_module_account_guard)


def _rust_strict_increase_guard_re(field_terms: tuple[str, ...]) -> re.Pattern[str]:
    joined = "|".join(re.escape(term) for term in field_terms)
    return re.compile(
        rf"\b(?:if|ensure!|assert!|require!)\s*!?\s*\(?[^;{{}}]*"
        rf"(?:{joined})[^;{{}}]*(?:>|>=)[^;{{}}]*(?:current|last|store|state|self)"
        rf"|\b(?:if|ensure!|assert!|require!)\s*!?\s*\(?[^;{{}}]*"
        rf"(?:current|last|store|state|self)[^;{{}}]*(?:<|<=)[^;{{}}]*(?:{joined})",
        re.I | re.S,
    )


def _rust_ast_missing_strict_increase_guard(source: str, field_terms: tuple[str, ...]) -> bool | None:
    engine = _ast_engine_for_source("rust", source)
    if engine is None:
        return None
    try:
        functions = list(engine.functions())
    except Exception:
        return None
    guard_re = _rust_strict_increase_guard_re(field_terms)
    assignment_re = re.compile(
        r"\b(?:store|state|self|oracle|client)\.[A-Za-z0-9_]*(?:period|epoch|height)"
        r"\s*=\s*(?:update|new|next|submitted|root|header|period|epoch|height)",
        re.I | re.S,
    )
    saw_relevant_assignment = False
    for fn in functions:
        try:
            if not engine.predicate_structural_match(fn, "assignment"):
                continue
        except Exception:
            continue
        assignments = _ast_function_assignment_texts(engine, fn)
        if not assignments:
            continue
        relevant = [
            text
            for text in assignments
            if any(term in text for term in field_terms) and assignment_re.search(text)
        ]
        if not relevant:
            continue
        saw_relevant_assignment = True
        body_text = "\n".join(relevant)
        try:
            body = engine.fn_body(fn)
            if body is not None:
                body_text = str(engine.text(body))
        except Exception:
            pass
        if not guard_re.search(body_text):
            return True
    if saw_relevant_assignment:
        return False
    return None


def _rust_has_missing_strict_increase_guard(source: str, field_terms: tuple[str, ...]) -> bool:
    clean = _strip_comments(source)
    if not any(term in clean for term in field_terms):
        return False
    ast_verdict = _rust_ast_missing_strict_increase_guard(clean, field_terms)
    if ast_verdict is not None:
        return ast_verdict
    has_assignment = re.search(
        r"\b(?:store|state|self|oracle|client)\.[A-Za-z0-9_]*(?:period|epoch|height)"
        r"\s*=\s*(?:update|new|next|submitted|root|header|period|epoch|height)",
        clean,
        re.I | re.S,
    )
    if not has_assignment:
        return False
    has_guard = _rust_strict_increase_guard_re(field_terms).search(clean)
    return not bool(has_guard)


def _slither_auth_010_function_violation(function: Any) -> bool | None:
    row = _slither_function_row(function)
    if not _slither_ast_check(function, "reads_tx_origin"):
        return None
    return _tx_origin_auth_decision(row["segment"])


def _p1_predicate_auth_001(source: str, _text: str) -> bool:
    """INV-AUTH-001: UUPS upgrade authorization exists but is not role-gated."""
    ir_verdict = _p1_predicate_solidity_function_slither(source, _slither_auth_001_function_violation)
    if ir_verdict is not None:
        return ir_verdict

    rows = _solidity_function_segments(source)
    for name in ("_authorizeUpgrade", "upgradeTo", "upgradeToAndCall"):
        row = next((item for item in rows if item["name"] == name), None)
        if row is None:
            continue
        module = _load_slither_predicates_module()
        if module is not None:
            try:
                synthetic = _slither_synthetic_function_from_row(row)
                if bool(module.check(synthetic, "has_only_owner_modifier")):
                    return False
                return not _has_solidity_role_guard(row.get("body", ""))
            except Exception:
                pass
        return not _has_solidity_role_guard(row["segment"])
    return False


def _p1_predicate_auth_002(source: str, _text: str) -> bool:
    """INV-AUTH-002: ERC-1271 magic-value check without signer/wallet binding."""
    clean = _strip_comments(source)
    has_1271_call = bool(
        re.search(
            r"\bIERC1271\s*\([^)]+\)\s*\.\s*isValidSignature\s*\("
            r"|\b[A-Za-z_][A-Za-z0-9_\.]*\s*\.\s*isValidSignature\s*\(",
            clean,
            re.I | re.S,
        )
    )
    if not has_1271_call:
        return False
    has_signer_binding = bool(
        re.search(
            r"\b(?:wallet|walletAddress|contractWallet|account)\b\s*==\s*"
            r"\b(?:claimedSigner|signer|owner)\b"
            r"|\b(?:claimedSigner|signer|owner)\b\s*==\s*"
            r"\b(?:wallet|walletAddress|contractWallet|account)\b",
            clean,
            re.I | re.S,
        )
    )
    return not has_signer_binding


def _p1_predicate_auth_003(source: str, _text: str) -> bool:
    """INV-AUTH-003: governance proposal bundle is mutable after propose()."""
    clean = _strip_comments(source)
    has_proposal_flow = (
        re.search(r"\bpropose\s*\(", clean, re.I) is not None
        and re.search(r"\bexecute\s*\(", clean, re.I) is not None
        and re.search(r"\b(targets|values|calldatas|proposal)\b", clean, re.I) is not None
    )
    if not has_proposal_flow:
        return False
    has_external_mutator = re.search(
        r"\bfunction\s+(?:set|update|edit|mutate)[A-Za-z0-9_]*"
        r"(?:Proposal|Targets|Values|Calldatas)[A-Za-z0-9_]*\s*\([^)]*\)"
        r"[^;{]*(?:external|public)",
        clean,
        re.I | re.S,
    ) is not None
    writes_bundle = re.search(
        r"\bproposals?\s*\[[^\]]+\]\s*\.\s*(?:targets|values|calldatas)"
        r"\s*(?:=|\.push\s*\()",
        clean,
        re.I | re.S,
    ) is not None
    return bool(has_external_mutator and writes_bundle)


def _p1_predicate_uni_002(source: str, _text: str) -> bool:
    """INV-UNI-002: EIP-712/EIP-2612 signature path lacks nonce advancement."""
    ir_verdict = _p1_predicate_solidity_function_slither(source, _slither_uni_002_function_violation)
    if ir_verdict is not None:
        return ir_verdict

    clean = _strip_comments(source)
    has_signature_path = re.search(
        r"\b(ecrecover|ECDSA\.recover|recover)\s*\("
        r"|\bpermit\s*\("
        r"|\b_hashTypedDataV4\s*\(",
        clean,
        re.I | re.S,
    ) is not None
    has_typed_domain = re.search(
        r"\b(domain_separator|domainseparator|DOMAIN_SEPARATOR|EIP712|permit)\b",
        clean,
        re.I | re.S,
    ) is not None
    nonce_bumped = re.search(
        r"\bnonces?\s*(?:\[[^\]]+\]|\([^)]+\)|\.[A-Za-z_][A-Za-z0-9_]*)"
        r"\s*(?:\+\+|\+=\s*1|=\s*[^;]+\+\s*1)",
        clean,
        re.I | re.S,
    ) is not None
    return bool(has_signature_path and has_typed_domain and not nonce_bumped)


def _p1_predicate_atom_004(source: str, _text: str) -> bool:
    """INV-ATOM-004: standalone permit without the authorized action bundled."""
    segment = _first_solidity_function_segment(source, ("permit",))
    if segment is None:
        return False
    has_action = re.search(
        r"\b(transferFrom|safeTransferFrom|deposit|mint|stake|withdraw)\s*\(",
        segment,
        re.I | re.S,
    ) is not None
    has_atomic_name = re.search(r"\b(?:permitAnd|withPermit)\w*\s*\(", segment, re.I) is not None
    return bool(not has_action and not has_atomic_name)


def _p1_predicate_bnd_004(source: str, _text: str) -> bool:
    """INV-BND-004: leverage path lacks a maxLeverage comparison."""
    segment = _first_solidity_function_segment(
        source,
        ("openPosition", "setLeverage", "increaseLeverage"),
    )
    target = segment or source
    has_leverage = re.search(r"\bleverage\b", target, re.I) is not None
    if not has_leverage:
        return False
    has_guard = re.search(
        r"\bleverage\s*<=\s*[^;{}]*max[_A-Za-z0-9]*Leverage"
        r"|\bmax[_A-Za-z0-9]*Leverage[^;{}]*>=\s*[^;{}]*leverage"
        r"|\brequire\s*\([^;{}]*leverage[^;{}]*max[_A-Za-z0-9]*Leverage",
        target,
        re.I | re.S,
    ) is not None
    return not has_guard


def _p1_predicate_bnd_008(source: str, _text: str) -> bool:
    """INV-BND-008: balance subtraction occurs without a preceding bounds guard."""
    clean = _strip_comments(source)
    has_subtract = re.search(
        r"\b(?:balance|balances)\s*(?:\[[^\]]+\])?\s*-=\s*amount\b"
        r"|\b(?:balance|balances)\s*(?:\[[^\]]+\])?\s*="
        r"\s*(?:balance|balances)\s*(?:\[[^\]]+\])?\s*-\s*amount\b",
        clean,
        re.I | re.S,
    ) is not None
    if not has_subtract:
        return False
    has_guard = re.search(
        r"\b(?:require|assert)\s*\([^;{}]*(?:balance|balances)"
        r"[^;{}]*>=\s*amount"
        r"|\bif\s*\([^)]*(?:balance|balances)[^)]*<\s*amount[^)]*\)\s*revert",
        clean,
        re.I | re.S,
    ) is not None
    return not has_guard


def _p1_predicate_auth_006(source: str, _text: str) -> bool:
    """INV-AUTH-006: emergency controls are single-actor, not timelock/multisig gated."""
    ir_verdict = _p1_predicate_solidity_function_slither(source, _slither_auth_006_function_violation)
    if ir_verdict is not None:
        return ir_verdict

    for row in _solidity_function_segments(source):
        name = row["name"].lower()
        segment = row["segment"]
        if not re.search(r"\b(?:external|public)\b", row["signature"], re.I):
            continue
        emergency_name = re.search(
            r"(?:pause|emergency|withdrawall|sweep|rescue|selfdestruct|destroy)",
            name,
            re.I,
        )
        emergency_effect = re.search(
            r"\b(?:_pause|pause|selfdestruct|suicide)\s*\("
            r"|\bpaused\s*=\s*true\b"
            r"|\b(?:withdrawAll|sweep|rescue)[A-Za-z0-9_]*\s*\(",
            segment,
            re.I | re.S,
        )
        if (emergency_name or emergency_effect) and not _has_timelock_or_multisig_guard(segment):
            return True
    return False


def _p1_predicate_auth_007(source: str, _text: str) -> bool:
    """INV-AUTH-007: Move capability acquire lacks signer owner assertion."""
    clean = _strip_comments(source)
    has_capability_acquire = re.search(
        r"\b(?:public\s+)?(?:entry\s+)?fun\b[\s\S]{0,260}\bacquires\s+[A-Za-z0-9_:]*Capability\b"
        r"|\bborrow_(?:global|global_mut)\s*<[^>]*Capability",
        clean,
        re.I,
    )
    if not has_capability_acquire:
        return False
    has_owner_assert = re.search(
        r"\bassert!\s*\([^;{}]*(?:signer::address_of|account::address_of)"
        r"[^;{}]*(?:==|!=)[^;{}]*(?:owner|admin|canonical|resource)",
        clean,
        re.I | re.S,
    )
    return not bool(has_owner_assert)


def _p1_predicate_auth_008(source: str, _text: str) -> bool:
    """INV-AUTH-008: Cosmos Msg execution bypasses ante-handler chain."""
    return _go_has_direct_keeper_msg_invocation(source)


def _p1_predicate_auth_009(source: str, _text: str) -> bool:
    """INV-AUTH-009: cancel/admin-burn path is not caller-authorized."""
    for row in _solidity_function_segments(source):
        name = row["name"].lower()
        segment = row["segment"]
        if "cancel" not in name and "burn" not in name:
            continue
        if not re.search(r"\b(?:external|public)\b", row["signature"], re.I):
            continue
        if not re.search(r"\b(?:timelock|proposal|proposer|bond|payout|burn|cancel)", segment, re.I):
            continue
        has_caller_guard = re.search(
            r"\b(?:require|assert)\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\))"
            r"[^;{}]*(?:==|!=)[^;{}]*(?:proposer|owner|admin|beneficiary|recipient)"
            r"|\bif\s*\([^)]*(?:msg\.sender|_msgSender\s*\(\))[^)]*(?:!=|==)"
            r"[^)]*(?:proposer|owner|admin|beneficiary|recipient)[^)]*\)\s*revert",
            segment,
            re.I | re.S,
        )
        if not has_caller_guard:
            return True
    return False


_TX_ORIGIN_AUTH_TARGET = (
    r"\b(?=[A-Za-z_])\w*"
    r"(?:owner|admin|governance|governor|guardian|upgrader|operator|authority|authorized|role)"
    r"\w*\b"
)


def _tx_origin_auth_decision(segment: str) -> bool:
    clean = _strip_comments_and_strings(segment)
    require_or_assert = (
        rf"\b(?:require|assert)\s*\([^;{{}}]*"
        rf"(?:\btx\.origin\b\s*==\s*{_TX_ORIGIN_AUTH_TARGET}|"
        rf"{_TX_ORIGIN_AUTH_TARGET}\s*==\s*\btx\.origin\b)"
        rf"[^;{{}}]*\)"
    )
    if_revert = (
        rf"\bif\s*\([^)]*"
        rf"(?:\btx\.origin\b\s*!=\s*{_TX_ORIGIN_AUTH_TARGET}|"
        rf"{_TX_ORIGIN_AUTH_TARGET}\s*!=\s*\btx\.origin\b)"
        rf"[^)]*\)\s*(?:{{\s*)?\brevert\b"
    )
    return bool(re.search(require_or_assert, clean, re.I | re.S) or re.search(if_revert, clean, re.I | re.S))


def _p1_predicate_auth_010(source: str, _text: str) -> bool:
    """INV-AUTH-010: authorization decision uses tx.origin."""
    ir_verdict = _p1_predicate_solidity_function_slither(source, _slither_auth_010_function_violation)
    if ir_verdict is not None:
        return ir_verdict

    rows = _solidity_function_segments(source)
    for row in rows:
        if _tx_origin_auth_decision(row["segment"]):
            return True
    return False


def _p1_predicate_uni_010(source: str, _text: str) -> bool:
    """INV-UNI-010: signed order fill lacks filled/cancelled order-hash write."""
    for row in _solidity_function_segments(source):
        name = row["name"].lower()
        segment = row["segment"]
        if not re.search(r"(?:fill|settle|execute|match).*order|order.*(?:fill|settle|execute|match)", name):
            continue
        if not re.search(r"\b(?:orderHash|hashOrder|maker|salt|nonce|Order)\b", segment):
            continue
        if not _has_signature_recovery_shape(segment):
            continue
        write_match = re.search(
            r"\b(?:filled|cancelled|canceled|filledOrCancelled|usedOrders|executedOrders)"
            r"\s*(?:\[[^\]]+\]|\.[A-Za-z_][A-Za-z0-9_]*)+\s*=\s*true\b",
            segment,
            re.I | re.S,
        )
        effect_match = re.search(
            r"\b(?:settle|transferFrom|safeTransferFrom|transfer|call|swap|mint)\s*\(",
            segment,
            re.I | re.S,
        )
        if write_match is None:
            return True
        if effect_match is not None and write_match.start() > effect_match.start():
            return True
    return False


def _p1_predicate_ord_003(source: str, _text: str) -> bool:
    """INV-ORD-003: Cosmos Msg flow invokes keeper handler directly."""
    return _go_has_direct_keeper_msg_invocation(source)


def _p1_predicate_ord_004(source: str, _text: str) -> bool:
    """INV-ORD-004: swap path has zero/unused min-output protection."""
    for row in _solidity_function_segments(source):
        name = row["name"].lower()
        segment = row["segment"]
        if "swap" not in name and not re.search(r"\b(?:swap|exactInput|exactOutput)\s*\(", segment):
            continue
        if re.search(
            r"\b(?:amountOutMinimum|amountOutMin|minAmountOut|minOutputAmount|minOutput)"
            r"\s*[:=]\s*0\b",
            segment,
            re.I,
        ):
            return True
        min_params = [
            pname
            for pname in _solidity_param_names(row["signature"], r"u?int")
            if re.search(r"(?:min.*out|amountoutmin|minimumoutput|minoutput)", pname, re.I)
        ]
        for pname in min_params:
            escaped = re.escape(pname)
            enforced = re.search(
                rf"\b(?:require|assert)\s*\([^;{{}}]*(?:amountOut|received|out)"
                rf"[^;{{}}]*(?:>=|>)\s*{escaped}\b"
                rf"|\b(?:amountOutMinimum|amountOutMin|minAmountOut|minOutputAmount)"
                rf"\s*[:=]\s*{escaped}\b",
                segment,
                re.I | re.S,
            )
            if not enforced:
                return True
    return False


def _p1_predicate_ord_006(source: str, _text: str) -> bool:
    """INV-ORD-006: bridge message dispatch occurs before source-side burn."""
    clean = _strip_comments(source)
    if not re.search(r"\b(?:bridge|dispatch|sendMessage|postRequest|lzSend|xcall)\b", clean, re.I):
        return False
    dispatch = re.search(r"\b(?:dispatch|sendMessage|postRequest|lzSend|xcall|sendPacket)\s*\(", clean, re.I)
    burn = re.search(r"\b(?:_burn|burn|burnFrom)\s*\(", clean, re.I)
    return bool(dispatch and (burn is None or burn.start() > dispatch.start()))


def _p1_predicate_ord_007(source: str, _text: str) -> bool:
    """INV-ORD-007: package global mutable pointer/interface lacks mutex/atomic."""
    clean = _strip_comments(source)
    if re.search(r"\b(?:sync\.Mutex|sync\.RWMutex|atomic\.)\b", clean):
        return False
    globals_found = re.findall(
        r"(?m)^var\s+(?:\(\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+"
        r"(?P<typ>\*?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?"
        r"|interface\s*\{|map\s*\[|\[\])",
        clean,
    )
    for name, typ in globals_found:
        if not (typ.startswith("*") or "interface" in typ or "map" in typ or typ.startswith("[]")):
            continue
        escaped = re.escape(name)
        has_set = re.search(
            rf"\bfunc\s+Set[A-Za-z0-9_]*\s*\([^)]*\)\s*\{{[^{{}}]*\b{escaped}\s*=",
            clean,
            re.S,
        )
        has_get = re.search(
            rf"\bfunc\s+Get[A-Za-z0-9_]*\s*\([^)]*\)[^{{}}]*\{{[^{{}}]*\breturn\s+{escaped}\b",
            clean,
            re.S,
        )
        if has_set and has_get:
            return True
    return False


def _p1_predicate_ord_009(source: str, text: str) -> bool:
    """INV-ORD-009: permit approval can land standalone from the action."""
    return _p1_predicate_atom_004(source, text)


def _p1_predicate_mon_001(source: str, _text: str) -> bool:
    """INV-MON-001: finalized period update lacks strict-increase guard."""
    return _rust_has_missing_strict_increase_guard(source, ("finalized_period", "finality_period"))


def _p1_predicate_mon_003(source: str, _text: str) -> bool:
    """INV-MON-003: totalSupply is directly written outside mint/burn."""
    for row in _solidity_function_segments(source):
        if row["name"].lower() in {"mint", "_mint", "burn", "_burn"}:
            continue
        if re.search(r"\b_?totalSupply\s*(?:=|\+=|-=|\+\+|--)", row["segment"]):
            return True
    return False


def _p1_predicate_mon_004(source: str, _text: str) -> bool:
    """INV-MON-004: epoch/round update lacks strict-increase guard."""
    return _rust_has_missing_strict_increase_guard(source, ("epoch", "round"))


def _p1_predicate_mon_006(source: str, _text: str) -> bool:
    """INV-MON-006: lastUpdate can be set backwards."""
    for row in _solidity_function_segments(source):
        segment = row["segment"]
        if not re.search(r"\blastUpdate\b\s*=", segment):
            continue
        if re.search(r"\blastUpdate\s*=\s*block\.timestamp\b", segment):
            continue
        has_guard = re.search(
            r"\b(?:require|assert)\s*\([^;{}]*(?:>=|>)\s*lastUpdate"
            r"|\b(?:require|assert)\s*\([^;{}]*lastUpdate\s*(?:<=|<)"
            r"|\b(?:require|assert)\s*\([^;{}]*(?:new|next|timestamp|time|lastUpdate)"
            r"[^;{}]*(?:>=|>)\s*lastUpdate"
            r"|\bif\s*\([^)]*(?:new|next|timestamp|time)[^)]*(?:<|<=)\s*lastUpdate"
            r"[^)]*\)\s*revert",
            segment,
            re.I | re.S,
        )
        if not has_guard:
            return True
    return False


def _p1_predicate_mon_008(source: str, _text: str) -> bool:
    """INV-MON-008: Go consensus path uses nondeterministic input."""
    return _go_has_consensus_nondeterminism(source)


def _p1_predicate_mon_010(source: str, _text: str) -> bool:
    """INV-MON-010: finalized height update lacks strict-increase guard."""
    return _rust_has_missing_strict_increase_guard(source, ("finalized_height", "last_finalized", "height"))


_TOTAL_SUPPLY_CALL_RE = re.compile(r"(?:\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?\btotalSupply\s*\(", re.I)


def _segment_calls_total_supply(segment: str) -> bool:
    return bool(_TOTAL_SUPPLY_CALL_RE.search(_strip_comments_and_strings(segment)))


def _total_supply_derived_names(segment: str) -> set[str]:
    clean = _strip_comments_and_strings(segment)
    derived: set[str] = set()
    assignment_re = re.compile(
        r"\b(?:u?int(?:8|16|32|64|96|128|160|224|256)?|int(?:8|16|32|64|96|128|160|224|256)?|var)?"
        r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);",
        re.I | re.S,
    )
    changed = True
    while changed:
        changed = False
        for match in assignment_re.finditer(clean):
            name = match.group(1)
            rhs = match.group(2)
            if name in derived:
                continue
            if _TOTAL_SUPPLY_CALL_RE.search(rhs) or any(
                re.search(rf"\b{re.escape(existing)}\b", rhs) for existing in derived
            ):
                derived.add(name)
                changed = True
    return derived


def _total_supply_ref_union(derived_names: set[str]) -> str:
    refs = [r"(?:\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?\btotalSupply\s*\([^)]*\)"]
    refs.extend(rf"\b{re.escape(name)}\b" for name in sorted(derived_names))
    return "(?:" + "|".join(refs) + ")"


def _total_supply_accounting_shape(segment: str) -> bool:
    clean = _strip_comments_and_strings(segment)
    if not _segment_calls_total_supply(clean):
        return False
    derived_names = _total_supply_derived_names(clean)
    ref_union = _total_supply_ref_union(derived_names)
    return bool(
        re.search(
            rf"\b(?:require|assert)\s*\([^;{{}}]*(?:{ref_union})[^;{{}}]*(?:>=|>|<=|<|==|!=)",
            clean,
            re.I | re.S,
        )
        or re.search(
            rf"\b(?:require|assert)\s*\([^;{{}}]*(?:>=|>|<=|<|==|!=)[^;{{}}]*(?:{ref_union})",
            clean,
            re.I | re.S,
        )
        or re.search(
            rf"\b(?:return|=)\s*[^;{{}}]*(?:{ref_union})[^;{{}}]*(?:/|\*)[^;{{}}]*;",
            clean,
            re.I | re.S,
        )
        or re.search(
            rf"\b(?:return|=)\s*[^;{{}}]*(?:/|\*)[^;{{}}]*(?:{ref_union})[^;{{}}]*;",
            clean,
            re.I | re.S,
        )
    )


def _slither_mon_011_function_match(function: Any) -> bool | None:
    row = _slither_function_row(function)
    if not (_slither_ast_check(function, "has_total_supply") or _segment_calls_total_supply(row["segment"])):
        return None
    return _total_supply_accounting_shape(row["segment"])


def _p1_predicate_mon_011(source: str, _text: str) -> bool:
    """INV-MON-011: totalSupply read is a live supply-accounting input."""
    ir_verdict = _p1_predicate_solidity_function_slither(source, _slither_mon_011_function_match)
    if ir_verdict is not None:
        return ir_verdict

    for row in _solidity_function_segments(source):
        if _total_supply_accounting_shape(row["segment"]):
            return True
    return False


def _p1_predicate_cust_001(source: str, _text: str) -> bool:
    """INV-CUST-001: ERC-20 transferFrom does not debit spender allowance."""
    segment = _first_solidity_function_segment(source, ("transferFrom",))
    if segment is None:
        return False
    if not re.search(r"\b(?:from|owner)\b[^;{}]*\bto\b[^;{}]*\b(?:amount|value)\b", segment, re.I | re.S):
        return False
    return not _has_allowance_spend(segment)


def _p1_predicate_cust_002(source: str, _text: str) -> bool:
    """INV-CUST-002: ERC-4626 withdraw/redeem lacks owner allowance/caller check."""
    for row in _solidity_function_segments(source, ("withdraw", "redeem")):
        segment = row["segment"]
        if not re.search(r"\bowner\b", row["signature"], re.I):
            continue
        has_allowance_or_owner_guard = (
            _has_allowance_spend(segment)
            or _has_owner_only_erc4626_guard(segment)
            or re.search(r"\b_preview(?:Withdraw|Redeem)\b", segment)
        )
        if not has_allowance_or_owner_guard:
            return True
    return False


def _p1_predicate_cust_003(source: str, _text: str) -> bool:
    """INV-CUST-003: ERC-721 transfer implementation does not clear approvals."""
    for row in _solidity_function_segments(source, ("_transfer", "transferFrom", "safeTransferFrom")):
        segment = row["segment"]
        has_erc721_transfer = re.search(
            r"\b(?:ownerOf|_owners|tokenId|keyManager|approval)\b",
            segment,
            re.I,
        ) and re.search(r"\b(?:from|owner)\b[^;{}]*\bto\b", segment, re.I | re.S)
        if not has_erc721_transfer:
            continue
        clears_approval = re.search(
            r"\b(?:delete\s+(?:keyManagerOf|approvals|_tokenApprovals|_operatorApprovals)"
            r"|_approve\s*\(\s*address\s*\(\s*0\s*\)"
            r"|approve\s*\(\s*address\s*\(\s*0\s*\))",
            segment,
            re.I | re.S,
        )
        if not clears_approval:
            return True
    return False


def _p1_predicate_cust_004(source: str, _text: str) -> bool:
    """INV-CUST-004: ERC-20 bool-returning transfer is ignored."""
    clean = _strip_comments(source)
    if re.search(r"\b(?:SafeERC20|safeTransfer|safeTransferFrom)\b", clean):
        return False
    for stmt in clean.split(";"):
        if not re.search(
            r"\b(?:IERC20\s*\([^)]+\)|[A-Za-z_][A-Za-z0-9_]*(?:Token|token|asset|erc20|underlying))"
            r"\s*\.\s*(?:transfer|transferFrom)\s*\(",
            stmt,
        ):
            continue
        if re.search(r"\b(?:require|assert|if|return)\s*\(", stmt):
            continue
        call_pos = re.search(r"\.\s*(?:transfer|transferFrom)\s*\(", stmt)
        if call_pos and "=" in stmt[: call_pos.start()]:
            continue
        return True
    return False


def _p1_predicate_cust_005(source: str, _text: str) -> bool:
    """INV-CUST-005: safeApprove lacks non-zero-to-non-zero rejection."""
    segment = _first_solidity_function_segment(source, ("safeApprove",))
    if segment is None or not re.search(r"\bapprove\s*\(", segment):
        return False
    has_zero_guard = re.search(
        r"\b(?:require|assert)\s*\([^;{}]*(?:allowance|value|amount)"
        r"[^;{}]*(?:==\s*0|0\s*==)"
        r"[^;{}]*(?:\|\||&&)[^;{}]*(?:allowance|value|amount)"
        r"[^;{}]*(?:==\s*0|0\s*==)",
        segment,
        re.I | re.S,
    )
    return not bool(has_zero_guard)


def _p1_predicate_cust_006(source: str, _text: str) -> bool:
    """INV-CUST-006: multisig executeTransaction lacks threshold confirmation gate."""
    segment = _first_solidity_function_segment(source, ("executeTransaction",))
    if segment is None:
        return False
    if not re.search(r"\b(?:confirmations|owners|threshold|required|multisig|multiSig)\b", source, re.I):
        return False
    has_threshold_gate = re.search(
        r"\b(?:require|assert)\s*\([^;{}]*(?:confirmations|confirmationCount|isConfirmed)"
        r"[^;{}]*(?:>=|==)[^;{}]*(?:threshold|required)"
        r"|\bisConfirmed\s*\(",
        segment,
        re.I | re.S,
    )
    return not bool(has_threshold_gate)


def _p1_predicate_cust_008(source: str, _text: str) -> bool:
    """INV-CUST-008: Move Capability is exposed without acquired-holder guard."""
    clean = _strip_comments(source)
    has_public_cap_helper = re.search(
        r"\bpublic\s+(?:entry\s+)?fun\b[\s\S]{0,320}"
        r"(?:acquires\s+[A-Za-z0-9_:]*Capability|borrow_(?:global|global_mut)\s*<[^>]*Capability)",
        clean,
        re.I,
    )
    if not has_public_cap_helper:
        return False
    has_holder_guard = re.search(
        r"\b(?:assert!|exists<)\s*\([^;{}]*(?:signer::address_of|account::address_of|holder|owner)",
        clean,
        re.I | re.S,
    )
    return not bool(has_holder_guard)


def _p1_predicate_cust_009(source: str, _text: str) -> bool:
    """INV-CUST-009: repayment is blocked by token whitelist/blacklist standing."""
    for row in _solidity_function_segments(source):
        if "repay" not in row["name"].lower():
            continue
        if re.search(
            r"\b(?:onlyWhitelisted|onlyAllowed|isWhitelisted|whitelist|blacklist|allowedToken)\b",
            row["segment"],
            re.I,
        ):
            return True
    return False


_SELF_BALANCE_SOURCE_RE = re.compile(
    r"address\s*\(\s*this\s*\)\s*\.\s*balance|\bselfbalance\s*\(\s*\)",
    re.I,
)


def _segment_reads_self_balance(segment: str) -> bool:
    return bool(_SELF_BALANCE_SOURCE_RE.search(_strip_comments_and_strings(segment)))


def _self_balance_derived_names(segment: str) -> set[str]:
    clean = _strip_comments_and_strings(segment)
    derived: set[str] = set()
    assignment_re = re.compile(
        r"\b(?:u?int(?:8|16|32|64|96|128|160|224|256)?|int(?:8|16|32|64|96|128|160|224|256)?|bool|bytes32|var)?"
        r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);",
        re.I | re.S,
    )
    changed = True
    while changed:
        changed = False
        for match in assignment_re.finditer(clean):
            name = match.group(1)
            rhs = match.group(2)
            if name in derived:
                continue
            if _SELF_BALANCE_SOURCE_RE.search(rhs):
                derived.add(name)
                changed = True
                continue
            if any(re.search(rf"\b{re.escape(existing)}\b", rhs) for existing in derived):
                derived.add(name)
                changed = True
    return derived


def _segment_uses_self_balance_guard(segment: str, derived_names: set[str]) -> bool:
    refs = [
        r"address\s*\(\s*this\s*\)\s*\.\s*balance",
        r"\bselfbalance\s*\(\s*\)",
    ]
    refs.extend(rf"\b{re.escape(name)}\b" for name in sorted(derived_names))
    ref_union = "(?:" + "|".join(refs) + ")"
    return bool(
        re.search(
            rf"\b(?:require|assert)\s*\([^;{{}}]*{ref_union}[^;{{}}]*(?:>=|>|<=|<|==|!=)",
            segment,
            re.I | re.S,
        )
        or re.search(
            rf"\b(?:require|assert)\s*\([^;{{}}]*(?:>=|>|<=|<|==|!=)[^;{{}}]*{ref_union}",
            segment,
            re.I | re.S,
        )
        or re.search(
            rf"\bif\s*\([^)]*{ref_union}[^)]*(?:>=|>|<=|<|==|!=)",
            segment,
            re.I | re.S,
        )
        or re.search(
            rf"\bif\s*\([^)]*(?:>=|>|<=|<|==|!=)[^)]*{ref_union}",
            segment,
            re.I | re.S,
        )
    )


def _segment_uses_self_balance_native_value(segment: str, derived_names: set[str]) -> bool:
    refs = [
        r"address\s*\(\s*this\s*\)\s*\.\s*balance",
        r"\bselfbalance\s*\(\s*\)",
    ]
    refs.extend(rf"\b{re.escape(name)}\b" for name in sorted(derived_names))
    ref_union = "(?:" + "|".join(refs) + ")"
    return bool(
        re.search(
            rf"\.\s*(?:call|deposit|wrap|depositETH|depositNative|mint)\s*\{{[^}}]*\bvalue\s*:\s*[^}}]*{ref_union}",
            segment,
            re.I | re.S,
        )
        or re.search(
            rf"\.\s*(?:transfer|send)\s*\(\s*{ref_union}\s*\)",
            segment,
            re.I | re.S,
        )
    )


def _cust_010_native_balance_accounting_shape(segment: str) -> bool:
    clean = _strip_comments_and_strings(segment)
    if not _segment_reads_self_balance(clean):
        return False
    derived_names = _self_balance_derived_names(clean)
    return _segment_uses_self_balance_guard(clean, derived_names) or _segment_uses_self_balance_native_value(
        clean,
        derived_names,
    )


def _slither_cust_010_function_match(function: Any) -> bool | None:
    row = _slither_function_row(function)
    if re.search(r"\b(?:view|pure)\b", row["signature"], re.I):
        return False
    if not (
        _slither_ast_check(function, "reads_self_balance")
        or _segment_reads_self_balance(row["segment"])
    ):
        return None
    return _cust_010_native_balance_accounting_shape(row["segment"])


def _p1_predicate_cust_010(source: str, _text: str) -> bool:
    """INV-CUST-010: native balance is a real custody/accounting input."""
    ir_verdict = _p1_predicate_solidity_function_slither(source, _slither_cust_010_function_match)
    if ir_verdict is not None:
        return ir_verdict

    for row in _solidity_function_segments(source):
        if re.search(r"\b(?:view|pure)\b", row["signature"], re.I):
            continue
        if _cust_010_native_balance_accounting_shape(row["segment"]):
            return True
    return False


def _p1_predicate_bnd_003(source: str, _text: str) -> bool:
    """INV-BND-003: Move stablecoin mint lacks per-issuer cap check."""
    clean = _strip_comments(source)
    if not re.search(r"\bpublic\s+(?:entry\s+)?fun\s+mint\b[\s\S]{0,500}\bamount\b", clean, re.I):
        return False
    has_cap_guard = re.search(r"\b(?:assert!|abort)\s*\([^;{}]*(?:cap|max|limit)[^;{}]*(?:>=|>)", clean, re.I | re.S)
    return not bool(has_cap_guard)


def _p1_predicate_bnd_005(source: str, _text: str) -> bool:
    """INV-BND-005: Move funding-rate update lacks max-delta clamp."""
    clean = _strip_comments(source)
    if not re.search(r"\b(?:set|update)_?funding_?rate\b[\s\S]{0,500}\bfunding_?rate\s*=", clean, re.I):
        return False
    has_delta_guard = re.search(r"\b(?:assert!|abort)\s*\([^;{}]*(?:MAX|MAX_FUNDING|delta|abs)[^;{}]*(?:<=|<)", clean, re.I | re.S)
    return not bool(has_delta_guard)


def _p1_predicate_bnd_010(source: str, _text: str) -> bool:
    """INV-BND-010: Go allocation from variable size lacks max cap."""
    clean = _strip_comments(source)
    make_match = re.search(
        r"\bmake\s*\(\s*\[\]\s*(?:byte|uint8|[A-Za-z_][A-Za-z0-9_]*)\s*,\s*"
        r"(?P<size>[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?)\s*\)",
        clean,
        re.S,
    )
    if not make_match:
        return False
    size = re.sub(r"\W+", "", make_match.group("size"))
    if not size:
        return False
    has_cap = re.search(
        rf"\bif\s+{re.escape(size)}\s*>\s*(?:max|Max|MAX)[A-Za-z0-9_]*\b"
        rf"|\bif\s+len\s*\([^)]*\)\s*>\s*(?:max|Max|MAX)[A-Za-z0-9_]*\b",
        clean,
        re.S,
    )
    return not bool(has_cap)


def _p1_predicate_con_004(source: str, _text: str) -> bool:
    """INV-CON-004: voting power accounting checks total bonded stake."""
    clean = _strip_comments_and_strings(source)
    voting_terms = r"(?:voting[_\s-]*power|validator[_\s-]*power|total[_\s-]*power)"
    bonded_terms = r"(?:total[_\s-]*bonded|bonded[_\s-]*stake|total[_\s-]*stake|total[_\s-]*collateral)"
    if not (re.search(voting_terms, clean, re.I) and re.search(bonded_terms, clean, re.I)):
        return False
    has_balance_check = re.search(
        rf"{voting_terms}[\s\S]{{0,160}}(?:==|!=|<=|>=|<|>)[\s\S]{{0,160}}{bonded_terms}"
        rf"|{bonded_terms}[\s\S]{{0,160}}(?:==|!=|<=|>=|<|>)[\s\S]{{0,160}}{voting_terms}",
        clean,
        re.I,
    )
    return not bool(has_balance_check)


def _p1_predicate_con_006(source: str, _text: str) -> bool:
    """INV-CON-006: insurance fund payout uses historical/non-spot measurement."""
    for row in _solidity_function_segments(source):
        if not _solidity_segment_is_external_entry(row):
            continue
        segment = _strip_comments_and_strings(row["segment"])
        segment_lower = segment.lower()
        if not any(
            token in segment_lower
            for token in (
                "insurancefund",
                "insurance_fund",
                "insurance-fund",
                "insurance fund",
                "backstop",
                "safetyfund",
                "safety_fund",
                "safety-fund",
                "safety fund",
            )
        ):
            continue
        if not re.search(r"\b(?:claim|draw|withdraw|payout|settle|distribute)\b", row["name"] + " " + segment, re.I):
            continue
        if not re.search(r"\b(?:slot0|getReserves|latestRoundData|latestAnswer|markPrice|indexPrice)\s*\(", segment, re.I):
            continue
        has_history_guard = re.search(
            r"\b(?:observe|consult|twap|timeWeighted|updatedAt|heartbeat|stale|"
            r"max[_\s-]*staleness|window|period|epoch)\b",
            segment,
            re.I,
        )
        if not has_history_guard:
            return True
    return False


def _p1_predicate_con_009(source: str, _text: str) -> bool:
    """INV-CON-009: reward claim transfers before marking user/epoch claimed."""
    for row in _solidity_function_segments(source):
        if "claim" not in row["name"].lower():
            continue
        segment = row["segment"]
        if not re.search(r"\b(?:reward|epoch)\b", segment, re.I):
            continue
        transfer = re.search(r"\b(?:safeTransfer|transfer)\s*\(", segment)
        if transfer is None:
            continue
        claimed_write = _has_claimed_reward_write(segment)
        if claimed_write is None or claimed_write.start() > transfer.start():
            return True
    return False


def _p1_predicate_fresh_005(source: str, _text: str) -> bool:
    """INV-FRESH-005: collateral pricing avoids self-priced LP pool reads."""
    for row in _solidity_function_segments(source):
        segment = _strip_comments_and_strings(row["segment"])
        if not re.search(r"\b(?:collateral|margin|health|ltv|liquidat)\w*\b", segment, re.I):
            continue
        if not re.search(
            r"\b[A-Za-z_][A-Za-z0-9_]*(?:pool|pair|amm|lp)[A-Za-z0-9_]*\s*\.\s*"
            r"(?:slot0|getReserves|get_dy|getVirtualPrice|price|quote)\s*\(",
            segment,
            re.I,
        ):
            continue
        has_independent_feed = re.search(
            r"\b(?:latestRoundData|chainlink|aggregator|oracleAdapter|externalOracle|"
            r"observe|consult|twap|updatedAt|heartbeat|max[_\s-]*staleness)\b",
            segment,
            re.I,
        )
        if not has_independent_feed:
            return True
    return False


def _p1_predicate_fresh_008(source: str, _text: str) -> bool:
    """INV-FRESH-008: light-client signature_slot lacks sync-period bound."""
    clean = _strip_comments(source)
    if not re.search(r"\bsignature_slot\b", clean) or not re.search(r"\b(?:sync_committee|period)\b", clean):
        return False
    has_period_guard = re.search(
        r"\b(?:if|ensure!|assert!|require!)\s*!?\s*\(?[^;{}]*signature_slot"
        r"[^;{}]*(?:>=|>|<=|<)[^;{}]*(?:period|start|end|sync_committee)"
        r"|\b(?:if|ensure!|assert!|require!)\s*!?\s*\(?[^;{}]*(?:period|start|end|sync_committee)"
        r"[^;{}]*(?:>=|>|<=|<)[^;{}]*signature_slot",
        clean,
        re.I | re.S,
    )
    return not bool(has_period_guard)


def _p1_predicate_fresh_010(source: str, _text: str) -> bool:
    """INV-FRESH-010: signature-bearing permit/order lacks deadline guard."""
    for row in _solidity_function_segments(source):
        segment = row["segment"]
        if not (
            _has_signature_recovery_shape(segment)
            or re.search(r"\b(?:permit|order|signature|sig)\b", segment, re.I)
        ):
            continue
        if not re.search(r"\b(?:permit|order|fill|execute|cancel)\b", row["name"], re.I):
            continue
        if not _has_deadline_guard(segment):
            return True
    return False


def _p1_predicate_det_001(source: str, _text: str) -> bool:
    """INV-DET-001: Go consensus path uses nondeterministic input."""
    return _go_has_consensus_nondeterminism(source)


def _p1_predicate_det_005(source: str, _text: str) -> bool:
    """INV-DET-005: consensus protobuf decode lacks canonical/deterministic check."""
    clean = _strip_comments(source)
    if not re.search(r"\b(?:Decode|Unmarshal|DeliverTx|ProcessProposal|FinalizeBlock)\b", clean):
        return False
    if not re.search(r"\b(?:proto\.Unmarshal|Unmarshal)\s*\(", clean):
        return False
    has_canonical_check = re.search(
        r"\b(?:Canonical|NonCanonical|Deterministic|ValidateBasic|RejectUnknown|unknown fields)\b",
        clean,
        re.I,
    )
    return not bool(has_canonical_check)


def _p1_predicate_det_008(source: str, _text: str) -> bool:
    """INV-DET-008: bridge-event id uses time/randomness instead of monotonic id."""
    clean = _strip_comments(source)
    if not re.search(r"\b(?:BridgeEvent|eventID|eventId|EventID|EventId|id)\b", clean):
        return False
    return bool(re.search(r"\b(?:time\.Now|rand\.|uuid\.New|UnixNano)\b", clean))


_BRIDGE_INBOUND_FUNCTIONS = {
    "handlemessage",
    "handlepostrequest",
    "lzreceive",
    "onaccept",
    "onmessage",
    "onrecvpacket",
    "receivemessage",
    "recvpacket",
}


def _solidity_segment_is_external_entry(row: dict[str, str]) -> bool:
    signature = row.get("signature", "")
    if re.search(r"\b(?:internal|private)\b", signature, re.I):
        return False
    return bool(re.search(r"\b(?:external|public)\b", signature, re.I))


def _is_bridge_inbound_segment(row: dict[str, str]) -> bool:
    name = row.get("name", "").lower()
    if name in _BRIDGE_INBOUND_FUNCTIONS:
        return True
    segment = row.get("segment", "")
    return bool(
        re.search(
            r"\b(?:sourceChain|srcChain|srcEid|srcAddress|nonce|payload|message)\b",
            segment,
            re.I,
        )
        and re.search(
            r"\b(?:bridge|crossChain|endpoint|gateway|host|ismp|layerzero|mailbox|packet|postRequest|xcall)\b",
            segment,
            re.I,
        )
    )


def _has_bridge_caller_guard(source: str) -> bool:
    clean = _strip_comments(source)
    return bool(
        _has_solidity_role_guard(clean)
        or re.search(
            r"\bonly(?:AuthorizedCaller|Bridge|Endpoint|Gateway|Host|Mailbox|OApp|Relayer|Remote|Router)\b"
            r"|\b(?:isAuthorizedCaller|_assertAuthorized|_checkAuthorized|_checkTrustedRemote|_validateSender)\s*\(",
            clean,
            re.I | re.S,
        )
        or re.search(
            r"\b(?:require|assert)\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\))"
            r"[^;{}]*(?:==|!=)[^;{}]*(?:bridge|endpoint|gateway|host|mailbox|router|trustedRemote|ismpHost|lzEndpoint)"
            r"|\b(?:require|assert)\s*\([^;{}]*(?:bridge|endpoint|gateway|host|mailbox|router|trustedRemote|ismpHost|lzEndpoint)"
            r"[^;{}]*(?:==|!=)[^;{}]*(?:msg\.sender|_msgSender\s*\(\))"
            r"|\bif\s*\([^)]*(?:msg\.sender|_msgSender\s*\(\))[^)]*!="
            r"[^)]*(?:bridge|endpoint|gateway|host|mailbox|router|trustedRemote|ismpHost|lzEndpoint)[^)]*\)\s*revert",
            clean,
            re.I | re.S,
        )
    )


def _p1_predicate_bridge_001(source: str, _text: str) -> bool:
    """INV-BRIDGE-001: inbound message handlers authenticate bridge caller."""
    ir_verdict = _p1_predicate_bridge_001_slither(source)
    if ir_verdict is not None:
        return ir_verdict

    for row in _solidity_function_segments(source):
        if not _solidity_segment_is_external_entry(row):
            continue
        if not _is_bridge_inbound_segment(row):
            continue
        if not _has_bridge_caller_guard(row["segment"]):
            return True
    return False


def _p1_predicate_bridge_002(source: str, _text: str) -> bool:
    """INV-BRIDGE-002: state-machine registration requires registrar authority."""
    ir_verdict = _p1_predicate_bridge_002_slither(source)
    if ir_verdict is not None:
        return ir_verdict

    registration_re = re.compile(
        r"\b(?:addChain|addClient|registerChain|registerStateMachine|setClient|setStateMachine)\s*\(",
        re.I,
    )
    for row in _solidity_function_segments(source):
        if not _solidity_segment_is_external_entry(row):
            continue
        name = row.get("name", "")
        if not (registration_re.search(name + "(") or registration_re.search(row["segment"])):
            continue
        if not _has_solidity_role_guard(row["segment"]):
            return True
    return False


def _p1_predicate_bridge_003(source: str, _text: str) -> bool:
    """INV-BRIDGE-003: commitment is consumed before external value/call effect."""
    ir_verdict = _p1_predicate_bridge_003_slither(source)
    if ir_verdict is not None:
        return ir_verdict

    call_re = re.compile(
        r"\.(?:call|delegatecall|send|staticcall|transfer)\s*(?:\{|\\?\()"
        r"|\b(?:sendValue|safeTransfer|safeTransferFrom)\s*\(",
        re.I | re.S,
    )
    consumed_re = re.compile(
        r"\b(?:consumed|processed|executed|fulfilled|spent|used)(?:Commitments?|Messages?|Packets?)?"
        r"\s*\[[^\]]+\]\s*=\s*true\b"
        r"|\bcommitments?\s*\[[^\]]+\]\s*\.\s*(?:consumed|processed|executed|used)\s*=\s*true\b"
        r"|\bdelete\s+commitments?\s*\[[^\]]+\]",
        re.I | re.S,
    )
    for row in _solidity_function_segments(source):
        segment = row["segment"]
        if not re.search(r"\bcommitments?\s*\[[^\]]+\]", segment, re.I | re.S):
            continue
        call = call_re.search(segment)
        if call is None:
            continue
        consumed_before_call = any(m.start() < call.start() for m in consumed_re.finditer(segment))
        if not consumed_before_call:
            return True
    return False


def _p1_predicate_bridge_004(source: str, _text: str) -> bool:
    """INV-BRIDGE-004: inbound messages track source-chain/nonce replay state."""
    ir_verdict = _p1_predicate_bridge_004_slither(source)
    if ir_verdict is not None:
        return ir_verdict

    replay_re = re.compile(
        r"\b(?:consumedNonces|executedMessages|executedNonces|processedMessages|processedNonces|"
        r"processedPackets|seenNonces|usedNonces|_?inboundNonce(?:s)?)\s*(?:\[[^\]]+\]\s*){1,3}"
        r"|\bkeccak256\s*\([^)]*(?:nonce|messageNonce)[^)]*(?:sourceChain|srcChain|srcEid|chainId)"
        r"|\bkeccak256\s*\([^)]*(?:sourceChain|srcChain|srcEid|chainId)[^)]*(?:nonce|messageNonce)",
        re.I | re.S,
    )
    for row in _solidity_function_segments(source):
        if not _solidity_segment_is_external_entry(row):
            continue
        if not _is_bridge_inbound_segment(row):
            continue
        segment = row["segment"]
        if not _bridge_004_segment_has_replay_key(segment):
            continue
        if replay_re.search(segment) is None and not _bridge_004_segment_tracks_commitment_hash(segment):
            return True
    return False


def _p1_predicate_bridge_005(source: str, _text: str) -> bool:
    """INV-BRIDGE-005: finality/state proofs enforce freshness windows."""
    ir_verdict = _p1_predicate_bridge_005_slither(source)
    if ir_verdict is not None:
        return ir_verdict

    proof_re = re.compile(r"\b(?:finalityProof|stateProof|proof)\b", re.I)
    height_re = re.compile(r"\b(?:finalityProof|stateProof|proof)\s*\.\s*(?:blockNumber|height|slot|timestamp)\b", re.I)
    freshness_re = re.compile(
        r"\bblock\.(?:number|timestamp)\b[^;{}]{0,220}(?:-|>|>=|<|<=)[^;{}]{0,220}"
        r"\b(?:finalityProof|stateProof|proof)\s*\.\s*(?:blockNumber|height|slot|timestamp)\b"
        r"|\b(?:finalityProof|stateProof|proof)\s*\.\s*(?:blockNumber|height|slot|timestamp)\b"
        r"[^;{}]{0,220}(?:-|>|>=|<|<=)[^;{}]{0,220}\bblock\.(?:number|timestamp)\b"
        r"|\b(?:FRESHNESS_WINDOW|FINALITY_WINDOW|MAX_PROOF_AGE|STALE_PROOF|STALE_SLOT)\b"
        r"[^;{}]{0,220}\b(?:finalityProof|stateProof|proof)\s*\.\s*(?:blockNumber|height|slot|timestamp)\b",
        re.I | re.S,
    )
    for row in _solidity_function_segments(source):
        if not _solidity_segment_is_external_entry(row):
            continue
        segment = row["segment"]
        if proof_re.search(segment) is None or height_re.search(segment) is None:
            continue
        if freshness_re.search(segment) is None:
            return True
    return False


def _p1_predicate_bridge_006(source: str, _text: str) -> bool:
    """INV-BRIDGE-006: bridge proof/replay digests bind source and destination domains."""
    ir_verdict = _p1_predicate_bridge_006_slither(source)
    if ir_verdict is not None:
        return ir_verdict

    for row in _solidity_function_segments(source):
        if not _solidity_segment_is_external_entry(row):
            continue
        if not _bridge_006_function_is_relevant(row):
            continue
        verdict = _bridge_006_digest_missing_domain_binding(row["segment"])
        if verdict is True:
            return True
    return False


def _p1_predicate_defi_001(source: str, _text: str) -> bool:
    """INV-DEFI-001: fee-on-transfer deposits credit observed balance delta."""
    ir_verdict = _p1_predicate_solidity_function_slither(source, _slither_defi_001_function_violation)
    if ir_verdict is not None:
        return ir_verdict

    for row in _solidity_function_segments(source):
        if not re.search(
            r"(?:addLiquidity|deposit|fill|fund|mint|pay|purchase|stake|supply)",
            row["name"],
            re.I,
        ):
            continue
        segment = row["segment"]
        if not re.search(
            r"\.\s*(?:safeTransferFrom|transferFrom)\s*\([^;{}]*address\s*\(\s*this\s*\)[^;{}]*\)",
            segment,
            re.I | re.S,
        ):
            continue
        has_delta_accounting = re.search(
            r"\b(?:balanceBefore|beforeBalance|preBalance|assetsBefore)\b"
            r"[\s\S]{0,260}\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)"
            r"|\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)"
            r"[\s\S]{0,260}\b(?:balanceAfter|afterBalance|postBalance|assetsAfter)\b"
            r"|\b(?:received|actualReceived|assetsReceived|delta)\s*=\s*"
            r"(?:balanceAfter|afterBalance|postBalance|assetsAfter)\s*-\s*"
            r"(?:balanceBefore|beforeBalance|preBalance|assetsBefore)",
            segment,
            re.I | re.S,
        )
        if not has_delta_accounting:
            return True
    return False


def _p1_predicate_defi_002(source: str, _text: str) -> bool:
    """INV-DEFI-002: rebasing assets use share/index accounting, not raw balances."""
    ir_verdict = _p1_predicate_solidity_function_slither(source, _slither_defi_002_function_violation)
    if ir_verdict is not None:
        return ir_verdict

    clean = _strip_comments(source)
    if not re.search(r"\b(?:rebase|rebasing|elastic|stETH|aToken|cToken|scaledBalance|gons)\b", clean, re.I):
        return False
    for row in _solidity_function_segments(source):
        if not re.search(r"\b(?:totalAssets|exchangeRate|previewRedeem|previewWithdraw|redeem|withdraw)\b", row["name"], re.I):
            continue
        segment = row["segment"]
        if not re.search(r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)", segment, re.I):
            continue
        has_share_index_accounting = re.search(
            r"\b(?:convertToAssets|convertToShares|getPooledEthByShares|getSharesByPooledEth|"
            r"scaledBalanceOf|liquidityIndex|sharePrice|exchangeRateStored|rebasingCreditsPerToken|"
            r"sharesOf|totalShares)\b",
            segment,
            re.I,
        )
        if not has_share_index_accounting:
            return True
    return False


def _p1_predicate_defi_003(source: str, _text: str) -> bool:
    """INV-DEFI-003: oracle pricing avoids spot-only or stale-feed reads."""
    ir_verdict = _p1_predicate_solidity_function_slither(source, _slither_defi_003_function_violation)
    if ir_verdict is not None:
        return ir_verdict

    price_function_re = re.compile(
        r"\b(?:getPrice|price|quote|consult|valueOf|assetValue|latestPrice|_price)\b",
        re.I,
    )
    spot_oracle_re = re.compile(
        r"\b(?:slot0|getReserves|latestAnswer|latestRoundData)\s*\(",
        re.I,
    )
    freshness_or_twap_re = re.compile(
        r"\b(?:observe|consult|TWAP|twap|timeWeighted|meanTick|secondsAgo|"
        r"updatedAt|answeredInRound|heartbeat|STALE|MAX_STALENESS|MAX_DELAY|"
        r"block\.timestamp\s*-\s*updatedAt)\b",
        re.I,
    )
    for row in _solidity_function_segments(source):
        if not price_function_re.search(row["name"]):
            continue
        segment = row["segment"]
        if spot_oracle_re.search(segment) is None:
            continue
        if freshness_or_twap_re.search(segment) is None:
            return True
    return False


_SAFE_APPROVE_CALL_RE = re.compile(
    r"\b(?:[A-Za-z_][A-Za-z0-9_]*|SafeERC20)\s*\.\s*safeApprove\s*\((?P<args>[^;{}]*)\)",
    re.I | re.S,
)


def _safe_approve_calls(segment: str) -> list[re.Match[str]]:
    return list(_SAFE_APPROVE_CALL_RE.finditer(_strip_comments_and_strings(segment)))


def _safe_approve_amount_arg_is_zero(args: str) -> bool:
    parts = [part.strip() for part in args.split(",") if part.strip()]
    if not parts:
        return False
    amount = re.sub(r"\s+", "", parts[-1])
    return amount in {"0", "uint256(0)", "uint(0)"}


def _safe_approve_workflow_shape(row: dict[str, str]) -> bool:
    if row["name"].lower() == "safeapprove":
        return False
    if not _solidity_segment_is_external_entry(row):
        return False
    segment = _strip_comments_and_strings(row["segment"])
    for match in _safe_approve_calls(segment):
        if _safe_approve_amount_arg_is_zero(match.group("args")):
            continue
        after = segment[match.end() :]
        if re.search(
            r"\.\s*(?:deposit|stake|supply|mint|swap|bridge|xcall|sendMessage|execute|repay|borrow|addLiquidity)"
            r"\s*\(",
            after,
            re.I | re.S,
        ):
            return True
    return False


def _slither_defi_004_function_match(function: Any) -> bool | None:
    row = _slither_function_row(function)
    if not (_slither_ast_check(function, "has_safe_approve") or _safe_approve_calls(row["segment"])):
        return None
    return _safe_approve_workflow_shape(row)


def _p1_predicate_defi_004(source: str, _text: str) -> bool:
    """INV-DEFI-004: caller-side safeApprove is part of an allowance workflow."""
    ir_verdict = _p1_predicate_solidity_function_slither(source, _slither_defi_004_function_match)
    if ir_verdict is not None:
        return ir_verdict

    for row in _solidity_function_segments(source):
        if _safe_approve_workflow_shape(row):
            return True
    return False


def _p1_predicate_erc4626_001(source: str, _text: str) -> bool:
    """INV-ERC4626-001: mutable ERC4626 entrypoints expose no slippage bound."""
    for row in _solidity_function_segments(source, ("deposit", "mint", "withdraw", "redeem")):
        if not _solidity_segment_is_external_entry(row):
            continue
        signature = row.get("signature", "")
        segment = row.get("segment", "")
        if not re.search(r"\b(?:deposit|mint|withdraw|redeem)\s*\(", signature, re.I):
            continue
        has_caller_bound = re.search(
            r"\b(?:min(?:Assets|Shares|Amount|Out)?|max(?:Assets|Shares|Amount|In)?|"
            r"minOut|maxIn|slippage|deadline)\b",
            signature + "\n" + segment,
            re.I,
        )
        if not has_caller_bound:
            return True
    return False


def _p1_predicate_return_bomb_001(source: str, _text: str) -> bool:
    """INV-RET-001: returndata is decoded/copied without a bounded cap."""
    clean = _strip_comments_and_strings(source)
    return bool(
        re.search(r"\breturndata\s*\.\s*length\b", clean, re.I)
        and re.search(r"\babi\s*\.\s*decode\s*\(\s*returndata\b", clean, re.I)
        and not re.search(
            r"\breturndata\s*\.\s*length\s*(?:<=|<)\s*(?:MAX_|max|[0-9])",
            clean,
            re.I,
        )
    )


def _p1_predicate_zk_001(source: str, _text: str) -> bool:
    """INV-ZK-001: Every signal MUST be constrained in at least one polynomial constraint."""
    clean = _strip_comments_and_strings(source)
    signals = _extract_identifiers(
        clean,
        r"\b(?:signal|var|var\s+private)\s+(?:\w+\s+)*(?P<id>[A-Za-z_][A-Za-z0-9_]*)\b",
    )
    if not signals:
        return False
    unconstrained = [sig for sig in signals if not re.search(rf"\b{re.escape(sig)}\b\s*(?:<==|===)", clean, re.S)]
    return bool(unconstrained)


def _p1_predicate_zk_002(source: str, _text: str) -> bool:
    """INV-ZK-002: Assigned witness values must be bound by unique constraints."""
    clean = _strip_comments_and_strings(source)
    assigned = _extract_identifiers(clean, r"\b(?P<id>[A-Za-z_][A-Za-z0-9_]*)\s*<--\s*")
    if not assigned:
        return False
    for name in assigned:
        constrained = (
            re.search(rf"\b(?:assert(?:_eq|_equal)?|enforce|constrain)\s*\([^;{{}}]*\b{re.escape(name)}\b", clean, re.S | re.I)
            or re.search(rf"\b{re.escape(name)}\b\s*(?:===|==)\s*[^\n;]+", clean, re.S)
        )
        if not constrained:
            return True
    return False


def _p1_predicate_zk_003(source: str, _text: str) -> bool:
    """INV-ZK-003: Trusted setup should not retain toxic-waste material."""
    clean = _strip_comments_and_strings(source)
    if not re.search(
        r"\b(?:ceremony|trusted[_-]?setup|powers?[\-_]?of[_-]?tau|phase[_ ]?2|toxic)\b",
        clean,
        re.I,
    ):
        return False
    if re.search(r"\b(?:tau|srs)\b", clean, re.I) is None:
        return False
    destroys = re.search(
        r"\b(?:drop|delete|clear|zeroize|shred|memset|memzero)\b",
        clean,
        re.I,
    )
    return not bool(destroys)


def _p1_predicate_move_001(source: str, _text: str) -> bool:
    """INV-MOVE-001: resource-account signer should be capability/owner checked."""
    clean = _strip_comments_and_strings(source)
    if _ast_function_has_call_without_call(
        clean,
        lang="move",
        target_call_pattern=r"\baccount::create_resource_account\b",
    ):
        if re.search(
            r"\bassert!\s*\([^;{{}}]*\b(signer::address_of|account::address_of)\b[^;{{}}]*(?:==|!=)[^;{{}}]*\b(?:admin|owner|creator|authority)\b",
            clean,
            re.I | re.S,
        ):
            return False
        return True
    if not re.search(r"\baccount::create_resource_account\b", clean, re.I):
        return False
    if re.search(
        r"\bassert!\s*\([^;{{}}]*\b(signer::address_of|account::address_of)\b[^;{{}}]*(?:==|!=)[^;{{}}]*\b(?:admin|owner|creator|authority)\b",
        clean,
        re.I | re.S,
    ):
        return False
    return True


def _p1_predicate_move_002(source: str, _text: str) -> bool:
    """INV-MOVE-002: user-controlled struct should not store raw Capability<T>."""
    clean = _strip_comments_and_strings(source)
    for struct_block in re.finditer(
        r"\bstruct\s+[A-Za-z_][A-Za-z0-9_]*\s+has\s+[A-Za-z0-9_,\s]+\s*\{[^{}]*\}",
        clean,
        re.I | re.S,
    ):
        block = struct_block.group(0)
        if re.search(r"\b(?:\b[A-Za-z_][A-Za-z0-9_]*\s*:\s*Capability<)", block, re.I):
            return True
    return False


def _p1_predicate_move_003(source: str, _text: str) -> bool:
    """INV-MOVE-003: Dynamic-field key derivation should hash user input."""
    clean = _strip_comments_and_strings(source)
    if _ast_function_has_call_without_call(
        clean,
        lang="move",
        target_call_pattern=r"\bdof::add\s*\(",
        forbidden_call_pattern=r"\bsha3_256\s*\(",
    ):
        return True
    if not re.search(r"\bdof::add\s*\(", clean):
        return False
    if re.search(r"\bsha3_256\s*\(", clean):
        return False
    return True


def _p1_predicate_sol_001(source: str, _text: str) -> bool:
    """INV-SOL-001: PDA seed tuple should include distinguishing identifiers."""
    clean = _strip_comments(source)
    prefix_hits: dict[str, int] = {}
    for m in re.finditer(
        r"\bfind_program_address\s*\(\s*&?\[?(?P<seed>[^\]]+)\]",
        clean,
        re.I,
    ):
        seed = m.group("seed").strip()
        if not re.fullmatch(r"b[\"'][^\"']+[\"']", seed, re.S):
            continue
        prefix_hits[seed] = prefix_hits.get(seed, 0) + 1
    return any(count >= 2 for count in prefix_hits.values())


def _p1_predicate_sol_002(source: str, _text: str) -> bool:
    """INV-SOL-002: CPI invoke_signed should verify target program-id."""
    clean = _strip_comments_and_strings(source)
    positions = [m.end() for m in re.finditer(r"\binvoke_signed\s*\(", clean)]
    if not positions:
        return False
    for pos in positions:
        window = clean[max(0, pos - 250): min(len(clean), pos + 350)]
        has_guard = (
            re.search(r"\brequire_keys_eq!\s*\(", window)
            or re.search(
                r"\brequire!\s*\([^;{{}}]*(?:program|program_id|target|owner)\b[^;{{}}]*(?:==|!=)[^;{{}}]*(?:key|id|expected)\b",
                window,
                re.S | re.I,
            )
        )
        if not has_guard:
            return True
    return False


def _p1_predicate_sol_003(source: str, _text: str) -> bool:
    """INV-SOL-003: Sysvar reads should bound slot freshness."""
    clean = _strip_comments_and_strings(source)
    if not re.search(r"\bClock::get\(\)\?", clean, re.I):
        return False
    has_freshness = False
    for clock_match in re.finditer(r"\bclock\.slot\b", clean):
        window = clean[max(0, clock_match.start() - 220): clock_match.end() + 220]
        if not re.search(r"\b(?:if|require|assert|assert!)\b", window, re.I):
            continue
        if not re.search(r"(?:>=|>|==|!=|<=|<)", window):
            continue
        if not re.search(
            r"\b(?:self\.|state\.)?(?:last_update_slot|last_update|fresh|stale|threshold|window|STALE)",
            window,
            re.I,
        ):
            continue
        has_freshness = True
        break
    return not bool(has_freshness)


def _first_rust_function_segment(source: str, names: tuple[str, ...]) -> str | None:
    """Extract the first implemented Rust function declaration + body for a function name."""
    clean = _strip_comments(source)
    for name in names:
        pattern = re.compile(
            rf"\bfn\s+{re.escape(name)}\s*(?:<[^>]*>)?\s*\(",
            re.S,
        )
        for match in pattern.finditer(clean):
            open_brace = clean.find("{", match.end())
            if open_brace < 0:
                continue
            close_brace = _find_matching_brace(clean, open_brace)
            if close_brace is None:
                continue
            return clean[match.start() : close_brace + 1]
    return None


def _has_trivial_pallet_weight_expr(expr: str) -> bool:
    """Heuristic for simple pallet::weight expressions that are not input-dependent."""
    compact = re.sub(r"\s+", "", expr)
    if not compact:
        return False
    if re.fullmatch(r"[0-9_]+", compact):
        return True
    if re.fullmatch(
        r"Weight::from_parts\([0-9_]+,[0-9_]+\)",
        compact,
    ):
        return True
    if re.fullmatch(
        r"Weight::from_ref_time\([0-9_]+\)\.saturating_add\(Weight::from_proof_size\([0-9_]+\)\)",
        compact,
    ):
        return True
    if re.fullmatch(r"Weight::zero\(\)", compact):
        return True
    return bool(re.fullmatch(r"[0-9_()+*/%<>!&.,:;-]*", compact))


def _has_unbounded_loop_segment(source: str) -> bool:
    clean = _strip_comments(source)
    return (
        bool(re.search(r"\bwhile\s+[^;{}]*\{", clean))
        or bool(re.search(r"\bloop\s*\{", clean))
        or bool(re.search(r"\bfor\s+[^\n{}:]*in\s+\w+\.into_iter\s*\(", clean))
        or bool(
            re.search(
                r"\bfor\s+[^\n{}:]*in\s+.*\.\.\.",
                clean,
            )
        )
    )


def _p1_predicate_l2_001(source: str, _text: str) -> bool:
    """INV-L2-001: forced inclusion exists without bounded max-delay checks."""
    clean = _strip_comments(source)
    has_forced_inclusion = bool(
        re.search(
            r"\b(?:forceInclusion|enqueueL2Tx|force_inclusion|enqueue_l2_tx)\b",
            clean,
        )
    )
    if not has_forced_inclusion:
        return False
    has_delay_guard = bool(
        re.search(
            r"\b(?:require|assert|if)\s*\([^)]*(?:max[_-]?(?:delay|block)|challenge[_-]?period|force[_-]?delay)[^)]*\)",
            clean,
        )
    )
    has_block_delay_cap = bool(
        re.search(
            r"\b(?:max_delay_blocks|maxDelayBlocks|maxDelay|DELAY_MAX|CHALLENGE_PERIOD|maxDelayed|maxBlockDelay)\b",
            clean,
        )
    )
    return not bool(has_delay_guard or has_block_delay_cap)


def _p1_predicate_l2_002(source: str, _text: str) -> bool:
    """INV-L2-002: output commitment lacks proof verification before state-root commitment."""
    segment = _first_solidity_function_segment(
        source,
        ("proveBlock", "submitOutput"),
    )
    candidate = segment or source
    has_submit_fn = bool(
        re.search(r"\b(?:proveBlock|submitOutput)\b", candidate),
    )
    if not has_submit_fn:
        return False
    verify_match = re.search(r"\b(?:verifyProof|checkProof)\s*\(", candidate)
    commit_match = re.search(
        r"\b(?:stateRoot|outputRoot|outputProposal)\s*[:=]{1,2}\s*[^;\n]*[;\n)]",
        candidate,
    )
    if not commit_match:
        return False
    if not verify_match:
        return True
    return verify_match.start() > commit_match.start()


def _p1_predicate_l2_003(source: str, _text: str) -> bool:
    """INV-L2-003: confirmOutput path has no challenge-window boundary check."""
    clean = _strip_comments(source)
    has_confirm = bool(re.search(r"\bconfirmOutput\b", clean))
    if not has_confirm:
        return False
    has_challenge_window = bool(
        re.search(
            r"\bblock\.timestamp\b.*(?:outputProposal|proposal)\b.*(?:CHALLENGE|challenge)[_\- ]*(?:PERIOD|period)",
            clean,
            re.I | re.S,
        )
    )
    has_generic_timestamp_guard = bool(
        re.search(
            r"\bconfirmOutput\b.*\bblock\s*\.\s*timestamp\b",
            clean,
            re.I | re.S,
        )
    )
    if has_challenge_window or has_generic_timestamp_guard:
        return False
    return True


def _p1_predicate_l2_004(source: str, _text: str) -> bool:
    """INV-L2-004: L2 bridge-like contract has no forced-withdraw escape hatch."""
    clean = _strip_comments(source)
    has_l2_anchor = bool(
        re.search(
            r"\b(?:L2|rollup|forceInclusion|enqueueL2Tx|proveBlock|submitOutput|confirmOutput|stateRoot|outputRoot)\b",
            clean,
        )
    )
    if not has_l2_anchor:
        return False
    has_exit_hatch = bool(
        re.search(
            r"\b(?:forceWithdraw|emergencyExit|escapeHatch|circuitBreaker|exitQueue)\b",
            clean,
        )
    )
    return not has_exit_hatch


def _p1_predicate_sub_001(source: str, _text: str) -> bool:
    """INV-SUB-001: pallet::weight is constant/trivial while body has unbounded loop."""
    clean = _strip_comments(source)
    for attr_match in re.finditer(
        r"#\s*\[pallet::weight\s*\((?P<expr>[^]]+)\)\]",
        clean,
    ):
        expr = attr_match.group("expr")
        if not _has_trivial_pallet_weight_expr(expr):
            continue
        fn_start = clean.find("fn", attr_match.end())
        if fn_start < 0:
            continue
        fn_match = re.search(
            r"\b(?:pub\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
            clean[fn_start:],
        )
        if not fn_match:
            continue
        fn_name = fn_match.group(1)
        segment = _first_rust_function_segment(clean, (fn_name,))
        if not segment:
            continue
        if _has_unbounded_loop_segment(segment):
            return True
    return False


def _p1_predicate_sub_002(source: str, _text: str) -> bool:
    """INV-SUB-002: fork_choice implementation ignores last finalized block input."""
    segment = _first_rust_function_segment(source, ("fork_choice",))
    if not segment:
        return False
    if not re.search(r"\blast[_-]?finalized", segment, re.I):
        return True
    return False


def _p1_predicate_sub_003(source: str, _text: str) -> bool:
    """INV-SUB-003: collate_block path does not validate parachain block."""
    segment = _first_rust_function_segment(source, ("collate_block",))
    if not segment:
        return False
    return re.search(r"\bvalidate_block\s*\(", segment) is None


def _p1_predicate_ln_001(source: str, _text: str) -> bool:
    """INV-LN-001: HTLC timeout race due to missing lock-time ordering guard."""
    clean = _strip_comments(source)
    if not re.search(r"\bhtlcSuccessTx\b|\bhtlcsuccess\b", clean, re.I):
        return False
    if not re.search(r"\bhtlcTimeoutTx\b|\btimeoutTx\b|\brefund\b", clean, re.I):
        return False
    guarded = bool(
        re.search(
            r"\b(?:require|assert|if)\b[^{;\n]*\bn[_A-Za-z]*\s*(?:lock|time)[A-Za-z0-9_]*\s*[<>]=?\s*[^;\n]*\brefund[_]?maturity\b[^;\n]*(?:-|\bminus\b)\s*[A-Za-z_][A-Za-z0-9_]*",
            clean,
            re.I,
        )
        or re.search(
            r"\b(?:require|assert|if)\b[^{;\n]*\brefund[_]?maturity\b[^;\n]*(?:-|\bminus\b)\s*[A-Za-z_][A-Za-z0-9_]*[^;\n]*\bn[_A-Za-z]*(?:lock|time)[A-Za-z0-9_]*",
            clean,
            re.I,
        )
    )
    no_guarded_timeout = not guarded
    return no_guarded_timeout


def _p1_predicate_ln_002(source: str, _text: str) -> bool:
    """INV-LN-002: threshold/FROST setup misses signer/attacker overlap enumeration."""
    clean = _strip_comments(source)
    if not re.search(r"\b(?:frost|threshold)\b", clean, re.I):
        return False
    if not re.search(r"\brequired[_-]?signers\b", clean, re.I):
        return False
    if not re.search(r"\battacker[s]?\b|\badversary\b|\bbad\b", clean, re.I):
        return False
    overlap_check = bool(
        re.search(
            r"\brequired[_-]?signers\b[^\n;{}]*(?:\.intersect|\bintersect|\bintersection|\s+&\s+|\bcontains\b)[^\n;{}]*\b(?:attacker[s]?|adversary|party)\b",
            clean,
            re.I,
        )
        or re.search(
            r"\bfor\b[^\n{}]*\b(?:attacker[s]?|adversary|party)\b[^\n{}]*\b(?:required[_-]?signers|signers)\b",
            clean,
            re.I,
        )
    )
    return not overlap_check


def _p1_predicate_ln_003(source: str, _text: str) -> bool:
    """INV-LN-003: watchtower misses full txid scan over block inputs."""
    clean = _strip_comments(source)
    if not re.search(r"\bwatchtower\b|\bmonitor_watchtower\b", clean, re.I):
        return False
    if not re.search(r"\b(?:block\.(?:Txs|txs)|block_txs|watched_outpoints)\b", clean, re.I):
        return False
    has_iteration = bool(
        re.search(
            r"\b(for|range)\b[^\n{}]*\b(?:block\.(?:Txs|txs)|block_txs)\b",
            clean,
            re.I,
        )
        or re.search(
            r"\bfor\b[^\n{}]*\b(?:watch(?:tower|er)_?outpoints?)\b[^\n{}]*\b(?:in|of)\b",
            clean,
            re.I,
        )
    )
    return not has_iteration


def _p1_predicate_ln_004(source: str, _text: str) -> bool:
    """INV-LN-004: force-close/rollback path must verify revocation key."""
    clean = _strip_comments(source)
    if not re.search(r"\bforce\s*close\b|\bforceClose\b|\bmutual\s+close\b", clean, re.I):
        return False
    return not bool(
        re.search(
            r"\b(?:check|verify|validate|require|assert)\b[^\n;{}]*\b(?:revocation[_-]?key)\b",
            clean,
            re.I,
        )
        or re.search(
            r"\b(?:revocation[_-]?key)\b[^\n;]*\b(?:check|verify|validate|require|assert)\b",
            clean,
            re.I,
        )
    )


P1_INVARIANT_PREDICATES: dict[str, Callable[[str, str], bool]] = {
    "INV-BRIDGE-001": _p1_predicate_bridge_001,
    "INV-BRIDGE-002": _p1_predicate_bridge_002,
    "INV-BRIDGE-003": _p1_predicate_bridge_003,
    "INV-BRIDGE-004": _p1_predicate_bridge_004,
    "INV-BRIDGE-005": _p1_predicate_bridge_005,
    "INV-BRIDGE-006": _p1_predicate_bridge_006,
    "INV-COSMOS-001": _p1_predicate_cosmos_001,
    "INV-COSMOS-002": _p1_predicate_cosmos_002,
    "INV-COSMOS-003": _p1_predicate_cosmos_003,
    "INV-COSMOS-004": _p1_predicate_cosmos_004,
    "INV-AUTH-001": _p1_predicate_auth_001,
    "INV-AUTH-002": _p1_predicate_auth_002,
    "INV-AUTH-003": _p1_predicate_auth_003,
    "INV-AUTH-006": _p1_predicate_auth_006,
    "INV-AUTH-007": _p1_predicate_auth_007,
    "INV-AUTH-008": _p1_predicate_auth_008,
    "INV-AUTH-009": _p1_predicate_auth_009,
    "INV-AUTH-010": _p1_predicate_auth_010,
    "INV-ATOM-004": _p1_predicate_atom_004,
    "INV-BND-003": _p1_predicate_bnd_003,
    "INV-BND-004": _p1_predicate_bnd_004,
    "INV-BND-005": _p1_predicate_bnd_005,
    "INV-BND-008": _p1_predicate_bnd_008,
    "INV-BND-010": _p1_predicate_bnd_010,
    "INV-CON-004": _p1_predicate_con_004,
    "INV-CON-006": _p1_predicate_con_006,
    "INV-CON-009": _p1_predicate_con_009,
    "INV-CUST-001": _p1_predicate_cust_001,
    "INV-CUST-002": _p1_predicate_cust_002,
    "INV-CUST-003": _p1_predicate_cust_003,
    "INV-CUST-004": _p1_predicate_cust_004,
    "INV-CUST-005": _p1_predicate_cust_005,
    "INV-CUST-006": _p1_predicate_cust_006,
    "INV-CUST-008": _p1_predicate_cust_008,
    "INV-CUST-009": _p1_predicate_cust_009,
    "INV-CUST-010": _p1_predicate_cust_010,
    "INV-DEFI-001": _p1_predicate_defi_001,
    "INV-DEFI-002": _p1_predicate_defi_002,
    "INV-DEFI-003": _p1_predicate_defi_003,
    "INV-DEFI-004": _p1_predicate_defi_004,
    "INV-ERC4626-001": _p1_predicate_erc4626_001,
    "INV-RET-001": _p1_predicate_return_bomb_001,
    "INV-DET-001": _p1_predicate_det_001,
    "INV-DET-005": _p1_predicate_det_005,
    "INV-DET-008": _p1_predicate_det_008,
    "INV-FRESH-005": _p1_predicate_fresh_005,
    "INV-L2-001": _p1_predicate_l2_001,
    "INV-L2-002": _p1_predicate_l2_002,
    "INV-L2-003": _p1_predicate_l2_003,
    "INV-L2-004": _p1_predicate_l2_004,
    "INV-LN-001": _p1_predicate_ln_001,
    "INV-LN-002": _p1_predicate_ln_002,
    "INV-LN-003": _p1_predicate_ln_003,
    "INV-LN-004": _p1_predicate_ln_004,
    "INV-MOVE-001": _p1_predicate_move_001,
    "INV-MOVE-002": _p1_predicate_move_002,
    "INV-MOVE-003": _p1_predicate_move_003,
    "INV-FRESH-008": _p1_predicate_fresh_008,
    "INV-FRESH-010": _p1_predicate_fresh_010,
    "INV-SOL-001": _p1_predicate_sol_001,
    "INV-SOL-002": _p1_predicate_sol_002,
    "INV-SOL-003": _p1_predicate_sol_003,
    "INV-SUB-001": _p1_predicate_sub_001,
    "INV-SUB-002": _p1_predicate_sub_002,
    "INV-SUB-003": _p1_predicate_sub_003,
    "INV-MON-001": _p1_predicate_mon_001,
    "INV-MON-003": _p1_predicate_mon_003,
    "INV-MON-004": _p1_predicate_mon_004,
    "INV-MON-006": _p1_predicate_mon_006,
    "INV-MON-008": _p1_predicate_mon_008,
    "INV-MON-010": _p1_predicate_mon_010,
    "INV-MON-011": _p1_predicate_mon_011,
    "INV-ZK-001": _p1_predicate_zk_001,
    "INV-ZK-002": _p1_predicate_zk_002,
    "INV-ZK-003": _p1_predicate_zk_003,
    "INV-ORD-003": _p1_predicate_ord_003,
    "INV-ORD-004": _p1_predicate_ord_004,
    "INV-ORD-006": _p1_predicate_ord_006,
    "INV-ORD-007": _p1_predicate_ord_007,
    "INV-ORD-009": _p1_predicate_ord_009,
    "INV-UNI-002": _p1_predicate_uni_002,
    "INV-UNI-010": _p1_predicate_uni_010,
}


FUNCTION_SCOPED_P1_INVARIANTS: set[str] = {
    "INV-BRIDGE-001",
    "INV-BRIDGE-002",
    "INV-BRIDGE-003",
    "INV-BRIDGE-004",
    "INV-BRIDGE-005",
    "INV-BRIDGE-006",
    "INV-COSMOS-001",
    "INV-COSMOS-002",
    "INV-COSMOS-003",
    "INV-COSMOS-004",
    "INV-AUTH-006",
    "INV-AUTH-009",
    "INV-AUTH-010",
    "INV-ATOM-004",
    "INV-BND-004",
    "INV-BND-008",
    "INV-CON-004",
    "INV-CON-006",
    "INV-CON-009",
    "INV-CUST-001",
    "INV-CUST-002",
    "INV-CUST-004",
    "INV-CUST-005",
    "INV-CUST-006",
    "INV-CUST-009",
    "INV-CUST-010",
    "INV-FRESH-005",
    "INV-DEFI-001",
    "INV-DEFI-002",
    "INV-DEFI-003",
    "INV-DEFI-004",
    "INV-ERC4626-001",
    "INV-RET-001",
    "INV-FRESH-010",
    "INV-MON-003",
    "INV-MON-006",
    "INV-MON-011",
    "INV-ORD-004",
    "INV-ORD-006",
    "INV-ORD-009",
    "INV-L2-001",
    "INV-L2-002",
    "INV-L2-003",
    "INV-L2-004",
    "INV-SUB-001",
    "INV-SUB-002",
    "INV-SUB-003",
    "INV-UNI-002",
    "INV-UNI-010",
    "INV-LN-001",
    "INV-LN-002",
    "INV-LN-003",
    "INV-LN-004",
}


def _semantic_p1_matches(
    cluster_id: str,
    *,
    matched_p1: list[str],
    file_line: str,
    snippet: str,
    source_context: str,
    source_contract_context: str = "",
) -> list[str]:
    """Return P1 IDs whose specific invariant predicate is present in source.

    Category-level matches remain useful as topical recall, but they are not
    semantic evidence. A semantic hit must show the code shape named by the
    invariant, not merely a broad category token such as Ownable/ECDSA.
    """
    if not matched_p1:
        return []
    cid = cluster_id.lower()
    predicate_source = source_contract_context or source_context
    function_source = (
        _solidity_function_context_for_snippet(predicate_source, snippet)
        or _solidity_function_context_for_snippet(source_context, snippet)
        or source_context
    )
    text = "\n".join([file_line, snippet, predicate_source]).lower()

    semantic: list[str] = []
    for inv_id in matched_p1:
        iid = str(inv_id)
        predicate = P1_INVARIANT_PREDICATES.get(iid)
        candidate_source = (
            function_source
            if iid in FUNCTION_SCOPED_P1_INVARIANTS and function_source
            else predicate_source
        )
        candidate = _PredicateSource(
            candidate_source,
            source_context=source_context,
            contract_source=predicate_source,
            snippet=snippet,
            file_line=file_line,
        )
        if predicate is not None and predicate(candidate, text):
            semantic.append(iid)

    if not semantic and "external-call-before-state-update" in cid:
        # The detector may have source shape, but P1 remains topical unless
        # one of the explicitly keyed invariant predicates above matched.
        return []
    return semantic


def _p1_match_tier(
    *,
    matched_p1: list[str],
    semantic_p1: list[str],
) -> str:
    if semantic_p1:
        return "SEMANTIC-MATCH"
    if matched_p1:
        return "TOPICAL-MATCH"
    return "NO-MATCH"


def _p1_semantic_invariant_gaps(
    cluster_id: str,
    *,
    p1_index: dict[str, list[str]],
    matched_p1: list[str],
    semantic_p1: list[str],
    file_hint: str | None = None,
) -> list[dict[str, Any]]:
    """Explain why an entry lacks source-supported P1 invariant evidence."""
    p1_cat, _ = _resolve_cluster_category(cluster_id)
    lang = _cluster_lang(cluster_id, file_hint=file_hint)
    if semantic_p1:
        return []
    if matched_p1:
        return [
            {
                "status": "topical-only",
                "category": p1_cat,
                "language": lang,
                "matched_topical_invariant_ids": matched_p1[:5],
                "reason": (
                    "P1 category matched, but source context did not show the "
                    "semantic shape required for a source-supported invariant hit."
                ),
            }
        ]
    if p1_cat:
        checked_keys = [f"{p1_cat}|{lang}"]
        if lang != "any":
            checked_keys.append(f"{p1_cat}|any")
        available_keys = sorted(k for k in p1_index if k.startswith(f"{p1_cat}|"))
        return [
            {
                "status": "catalog-gap",
                "category": p1_cat,
                "language": lang,
                "checked_keys": checked_keys,
                "available_keys": available_keys[:8],
                "reason": (
                    "Cluster resolved to a P1 category, but no invariant ID "
                    "matched the target language/cross-language buckets."
                ),
            }
        ]
    return [
        {
            "status": "unmapped-cluster",
            "category": None,
            "language": lang,
            "reason": (
                "Cluster slug did not resolve to a P1 category; extend "
                "CLUSTER_TOKEN_TO_CATEGORY or CLUSTER_KEYWORD_TO_CATEGORY."
            ),
        }
    ]


# ---------------------------------------------------------------------------
# Engagement-prescreen tool dynamic loader (since file name has a hyphen).
# ---------------------------------------------------------------------------

def _load_engagement_prescreen() -> Any:
    """Dynamically import `tools/engagement-prescreen.py` as a module."""
    here = Path(__file__).resolve().parent
    tool_path = here / "engagement-prescreen.py"
    if not tool_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(
        "_engagement_prescreen_for_p5", tool_path
    )
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def _load_p4_triager_precheck() -> Any:
    """Dynamically import the existing P4 local precheck helper.

    The simulator module imports ``lib.triager_precheck_schema`` relative to
    the tools directory when run as a script. During dynamic import from this
    file we add that directory to sys.path temporarily so we reuse the P4
    worker implementation instead of copying its rules.
    """
    here = Path(__file__).resolve().parent
    tool_path = here / "triager-pre-filing-simulator.py"
    if not tool_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(
        "_triager_pre_filing_simulator_for_p5", tool_path
    )
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    inserted = False
    here_str = str(here)
    if here_str not in sys.path:
        sys.path.insert(0, here_str)
        inserted = True
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    finally:
        if inserted:
            try:
                sys.path.remove(here_str)
            except ValueError:
                pass
    return mod


def _load_bug_bounty_oos_index_helper() -> Any:
    """Dynamically import the BUG_BOUNTY.md OOS index helper."""
    here = Path(__file__).resolve().parent
    tool_path = here / "bug_bounty_oos_index.py"
    if not tool_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(
        "_bug_bounty_oos_index_for_p5", tool_path
    )
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def _build_bug_bounty_oos_index(workspace: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build and persist the workspace BUG_BOUNTY.md OOS index."""
    helper = _load_bug_bounty_oos_index_helper()
    if helper is None or not hasattr(helper, "build_and_write_index"):
        return {}, {
            "available": False,
            "state": "helper-unavailable",
            "index_path": "",
            "source_paths": [],
            "indexed_rows": 0,
            "entries_matched": 0,
            "entries_downranked": 0,
            "high_confidence_matches": 0,
            "high_confidence_threshold": 0.7,
        }
    try:
        index = helper.build_and_write_index(workspace)
    except Exception as exc:  # noqa: BLE001
        return {}, {
            "available": False,
            "state": "index-error",
            "error": str(exc),
            "index_path": "",
            "source_paths": [],
            "indexed_rows": 0,
            "entries_matched": 0,
            "entries_downranked": 0,
            "high_confidence_matches": 0,
            "high_confidence_threshold": float(
                getattr(helper, "HIGH_CONFIDENCE_THRESHOLD", 0.7)
            ),
        }
    return index, {
        "available": True,
        "state": "indexed",
        "index_path": str(index.get("index_path") or ""),
        "source_paths": list(index.get("source_paths") or []),
        "indexed_rows": int(index.get("row_count") or 0),
        "index_hash": str(index.get("index_hash") or ""),
        "entries_matched": 0,
        "entries_downranked": 0,
        "high_confidence_matches": 0,
        "high_confidence_threshold": float(
            index.get("high_confidence_threshold")
            or getattr(helper, "HIGH_CONFIDENCE_THRESHOLD", 0.7)
        ),
    }


def _apply_bug_bounty_oos_cross_check(
    entries: list[dict[str, Any]],
    index: dict[str, Any],
) -> dict[str, Any]:
    """Annotate and downrank entries matched by BUG_BOUNTY.md OOS rows."""
    helper = _load_bug_bounty_oos_index_helper()
    if helper is None or not hasattr(helper, "annotate_candidates"):
        for entry in entries:
            entry.setdefault("bug_bounty_oos_match", None)
        return {
            "entries_considered": len(entries),
            "entries_matched": 0,
            "entries_downranked": 0,
            "high_confidence_matches": 0,
            "state": "helper-unavailable",
        }
    stats = helper.annotate_candidates(entries, index)
    threshold = float(
        stats.get("high_confidence_threshold")
        or getattr(helper, "HIGH_CONFIDENCE_THRESHOLD", 0.7)
    )
    downranked = 0
    for entry in entries:
        match = entry.get("bug_bounty_oos_match")
        if not isinstance(match, dict):
            entry["bug_bounty_oos_match"] = None
            continue
        if float(match.get("confidence") or 0.0) < threshold:
            continue
        previous = str(entry.get("hunt_priority") or "")
        entry["hunt_priority_before_bug_bounty_oos"] = previous
        if previous != BUG_BOUNTY_OOS_PRIORITY:
            downranked += 1
        entry["hunt_priority"] = BUG_BOUNTY_OOS_PRIORITY
        entry["bug_bounty_oos_downranked"] = True
    return {
        **stats,
        "entries_considered": len(entries),
        "entries_downranked": downranked,
        "state": "completed",
    }


# ---------------------------------------------------------------------------
# Workspace artifact readers (best-effort, degrade gracefully).
# ---------------------------------------------------------------------------

def _read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _read_audit_pin(workspace: Path) -> dict[str, Any]:
    """Best-effort audit-pin extraction.

    Sources tried in order:
      - .auditooor/commit_lifecycle_ledger.json -> primary_repo + sha + pinned_at
      - INTAKE_BASELINE.json -> assets_in_scope summary
    """
    pin: dict[str, Any] = {
        "primary_repo": None,
        "sha": None,
        "pinned_at": None,
        "freshness_status": "unknown",
    }
    ledger_path = workspace / ".auditooor" / "commit_lifecycle_ledger.json"
    ledger = _read_json(ledger_path)
    if isinstance(ledger, dict):
        for key in ("primary_repo", "repo", "target_repo"):
            if ledger.get(key):
                pin["primary_repo"] = str(ledger[key])
                break
        for key in ("audit_pin_sha", "audit_pin", "sha", "head_sha"):
            if ledger.get(key):
                pin["sha"] = str(ledger[key])
                break
        for key in ("pinned_at", "audit_pin_date", "timestamp"):
            if ledger.get(key):
                pin["pinned_at"] = str(ledger[key])
                break
    # Validate: SHA must be a 40-char hex; reject 'main' / branch names.
    if pin["sha"] is not None and not re.fullmatch(r"[0-9a-f]{40}", pin["sha"]):
        pin["sha"] = None
    if pin["sha"] is None:
        # Fall back to grepping known intake artifacts for a 40-char hex.
        fallback_candidates = [
            workspace / "BOOTSTRAP_ITER7.md",
            workspace / "INTAKE_BASELINE.md",
            workspace / "BRAIN_PRIMING_REPORT.md",
        ]
        # Plus a small scan of .auditooor/*.md briefs (capped).
        auditooor_dir = workspace / ".auditooor"
        if auditooor_dir.is_dir():
            md_files = sorted(auditooor_dir.glob("*.md"))[:20]
            fallback_candidates.extend(md_files)
        for candidate in fallback_candidates:
            if candidate.is_file():
                text = _read_text(candidate)
                m = re.search(r"\b([0-9a-f]{40})\b", text)
                if m:
                    pin["sha"] = m.group(1)
                    break
    pin["report_generated"] = _dt.datetime.now(_dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    if pin["sha"] is not None:
        pin["freshness_status"] = "fresh"
    return pin


def _read_intake_baseline(workspace: Path) -> dict[str, Any]:
    """Extract files_indexed + languages + assets_in_scope summary."""
    intake_json = _read_json(workspace / "INTAKE_BASELINE.json")
    if not isinstance(intake_json, dict):
        return {
            "files_indexed": 0,
            "languages": [],
            "assets_in_scope": [],
        }
    ext_counts: dict[str, int] = intake_json.get("file_extension_counts") or {}
    files_indexed = sum(int(v) for v in ext_counts.values() if isinstance(v, int))
    langs: set[str] = set()
    lang_map = {
        ".go": "go",
        ".rs": "rust",
        ".sol": "solidity",
        ".ts": "ts",
        ".tsx": "ts",
        ".js": "js",
        ".py": "python",
        ".move": "move",
        ".cairo": "cairo",
    }
    for ext, count in ext_counts.items():
        if not isinstance(count, int) or count < 5:
            continue
        if ext in lang_map:
            langs.add(lang_map[ext])
    return {
        "files_indexed": files_indexed,
        "languages": sorted(langs),
        "assets_in_scope": list(intake_json.get("assets_in_scope") or []),
    }


def _read_engage_report(workspace: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse engage_report into a flat hits list with cluster annotation.

    MVP1.1 (P5-MVP1.1-MD-FALLBACK, 2026-05-23): prefer ``engage_report.json``
    when present; fall back to parsing ``engage_report.md`` so workspaces
    (polymarket, morpho) that ship only the human-readable artifact still
    get ranked candidates instead of a silent 0-result. The .md schema is
    stable - cluster headings ``### Cluster: <slug> (<n> hits)`` and rows
    ``- **[<SEV>] `<slug>`** -- `<file:line>``` (em-dash or double-hyphen)
    with an optional indented ``snippet:`` continuation line.

    Returns:
        (hits, source_meta) where source_meta carries:
            - ``source``: one of ``json``, ``md``, ``none``.
            - ``engage_report_md_fallback``: True when the .md fallback fired.
            - ``json_present`` / ``md_present``: booleans for telemetry.
            - ``json_path`` / ``md_path``: resolved paths (or None).
    """
    json_path = workspace / "engage_report.json"
    md_path = workspace / "engage_report.md"
    meta: dict[str, Any] = {
        "source": "none",
        "engage_report_md_fallback": False,
        "json_present": json_path.is_file(),
        "md_present": md_path.is_file(),
        "json_path": str(json_path) if json_path.is_file() else None,
        "md_path": str(md_path) if md_path.is_file() else None,
    }

    # Layer 1: engage_report.json (canonical).
    engage = _read_json(json_path)
    if isinstance(engage, dict):
        clusters = engage.get("clusters") or []
        flat: list[dict[str, Any]] = []
        for cluster in clusters:
            if not isinstance(cluster, dict):
                continue
            slug = str(cluster.get("detector_slug") or "")
            cluster_hits = cluster.get("hits") or []
            if not isinstance(cluster_hits, list):
                continue
            for hit in cluster_hits:
                if not isinstance(hit, dict):
                    continue
                flat.append(
                    {
                        "cluster_id": slug,
                        "cluster_size": int(cluster.get("hit_count") or len(cluster_hits)),
                        "file_path": str(hit.get("file_path") or ""),
                        "severity": str(hit.get("severity") or "LOW").upper(),
                        "snippet": str(hit.get("snippet") or "").strip(),
                    }
                )
        if flat:
            meta["source"] = "json"
            return flat, meta
        # JSON was present but empty -> fall through to .md fallback below.

    # Layer 2: engage_report.md fallback.
    md_hits = _parse_engage_report_md(md_path)
    if md_hits:
        meta["source"] = "md"
        meta["engage_report_md_fallback"] = True
        return md_hits, meta

    return [], meta


# Cluster heading: '### Cluster: `<slug>` (<n> hits)' (backtick or unbacktick)
_RE_CLUSTER_HEADING = re.compile(
    r"^###\s+Cluster:\s*`?(?P<slug>[A-Za-z0-9_.:\-\/]+)`?\s*(?:\((?P<count>\d+)\s+hits?\))?"
)

# Row: '- **[<SEV>] `<slug>`** -- `<file:line>`' (em-dash, en-dash, or hyphen-hyphen).
# Real-world emit uses em-dash (U+2014) per repo memory; we accept both safely.
_RE_HIT_ROW = re.compile(
    r"^-\s*\*\*\[(?P<sev>HIGH|MEDIUM|LOW|INFO|INFORMATIONAL|CRITICAL)\]\s*"
    r"`(?P<slug>[A-Za-z0-9_.:\-\/]+)`\*\*\s*"
    r"(?:[—–]|--|-)\s*"
    r"`(?P<file_line>[^`]+)`"
)

# Snippet continuation: '  - snippet: `...`' (continuation indent, may use
# backticks or bare text after the colon).
_RE_SNIPPET = re.compile(r"^\s+-\s*snippet:\s*`?(?P<snippet>[^\n`]+?)`?\s*$")


def _parse_engage_report_md(md_path: Path) -> list[dict[str, Any]]:
    """Parse engage_report.md into JSON-equivalent flat hits.

    Reads cluster headings + bullet rows + optional ``snippet:`` continuation
    lines and emits the same record shape ``_read_engage_report()`` would
    have produced from the .json variant.
    """
    if not md_path.is_file():
        return []
    try:
        text = md_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    # First pass: bucket lines by cluster heading + count hits per cluster.
    lines = text.splitlines()
    # cluster_id -> declared hit_count (from the heading) or None.
    declared_counts: dict[str, int] = {}
    # cluster_id -> tally of rows attributed to it (we use declared count
    # when present, otherwise the tally).
    tallied_counts: dict[str, int] = {}
    # Track rows to attach a snippet to (most-recent row pointer).
    flat: list[dict[str, Any]] = []
    current_cluster: str | None = None
    last_row_idx: int | None = None
    in_clusters_section = False
    in_mining_section = False

    for raw in lines:
        line = raw.rstrip("\n")
        # Section gates: only parse rows under '## Clusters'; ignore the
        # '## No close historical match (best mining candidates)' tail
        # since those rows duplicate the cluster rows.
        if line.startswith("## "):
            in_clusters_section = line.strip().startswith("## Clusters")
            in_mining_section = "best mining candidates" in line.lower()
            current_cluster = None
            last_row_idx = None
            continue
        if not in_clusters_section or in_mining_section:
            continue

        # Cluster heading.
        m = _RE_CLUSTER_HEADING.match(line)
        if m:
            current_cluster = m.group("slug")
            count_str = m.group("count")
            if count_str is not None:
                declared_counts[current_cluster] = int(count_str)
            tallied_counts.setdefault(current_cluster, 0)
            last_row_idx = None
            continue

        # Hit row.
        row_m = _RE_HIT_ROW.match(line)
        if row_m:
            slug = row_m.group("slug")
            sev = row_m.group("sev").upper()
            # Normalize INFORMATIONAL -> INFO for consistency w/ json shape.
            if sev == "INFORMATIONAL":
                sev = "INFO"
            file_line = row_m.group("file_line").strip()
            cluster_id = current_cluster or slug
            tallied_counts[cluster_id] = tallied_counts.get(cluster_id, 0) + 1
            flat.append(
                {
                    "cluster_id": cluster_id,
                    "cluster_size": 0,  # patched in second pass below
                    "file_path": file_line,
                    "severity": sev,
                    "snippet": "",
                }
            )
            last_row_idx = len(flat) - 1
            continue

        # Snippet continuation attached to the most recent row.
        if last_row_idx is not None:
            snip_m = _RE_SNIPPET.match(line)
            if snip_m:
                flat[last_row_idx]["snippet"] = snip_m.group("snippet").strip()

    # Second pass: stamp cluster_size from declared count when present,
    # otherwise from the tally.
    for entry in flat:
        cid = entry["cluster_id"]
        entry["cluster_size"] = declared_counts.get(cid) or tallied_counts.get(cid, 0)

    return flat


def _read_prior_concerns(workspace: Path) -> set[str]:
    """Return the set of detector slugs / topical phrases mentioned in PRIOR_CONCERNS.md."""
    text = _read_text(workspace / "PRIOR_CONCERNS.md")
    if not text:
        return set()
    out: set[str] = set()
    # Heuristic: extract bullet-style topic phrases.
    for m in re.finditer(r"\b(go\.[A-Za-z0-9_.]+|x/[a-z_]+|[A-Za-z0-9_]+/[A-Za-z0-9_]+\.go)", text):
        out.add(m.group(1))
    # Also pick up "designed-by-design" key terms.
    if re.search(r"acknowledged.by.design|known.issue|design.choice", text, re.IGNORECASE):
        out.add("__acknowledged_by_design_present__")
    return out


def _read_severity_rubric(workspace: Path) -> dict[str, Any]:
    """Best-effort SEVERITY.md parse: surfaces accepted severity tiers."""
    text = _read_text(workspace / "SEVERITY.md")
    if not text:
        return {"tiers_listed": [], "raw_present": False}
    tiers = []
    for tier in ("Critical", "High", "Medium", "Low", "Informational"):
        if re.search(rf"\b{tier}\b", text):
            tiers.append(tier)
    return {"tiers_listed": tiers, "raw_present": True}


def _read_existing_submissions(workspace: Path) -> set[str]:
    """Enumerate cluster_ids implicit in existing submissions.

    We grep filed/staging/paste_ready/superseded for detector slugs already
    cited. Used to flag 'coverage gaps' (clusters with NO existing finding).
    """
    out: set[str] = set()
    subs_root = workspace / "submissions"
    if not subs_root.is_dir():
        return out
    for status in ("paste_ready", "staging", "filed", "held", "superseded"):
        status_dir = subs_root / status
        if not status_dir.is_dir():
            continue
        for md_path in status_dir.rglob("*.md"):
            try:
                text = md_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # Cheap heuristic: detector slug pattern go.* / rust.* / sol.*.
            for m in re.finditer(r"\b((?:go|rust|sol|crypto)\.[a-z0-9_.]+)\b", text):
                out.add(m.group(1))
            # CAP-001 (2026-05-24): also pick up descriptive kebab-case
            # detector slugs (e.g. ``division-by-zero``,
            # ``external-call-before-state-update``) when surrounded by
            # backticks. This is the slug shape Hyperbridge / EVM engage
            # reports emit; the dotted pattern above misses them.
            for m in re.finditer(r"`([a-z][a-z0-9]+(?:-[a-z0-9]+){2,})`", text):
                out.add(m.group(1))
    return out


def _read_exploit_queue(workspace: Path) -> list[dict[str, Any]]:
    """Optional .auditooor/exploit_queue.json read."""
    eq = _read_json(workspace / ".auditooor" / "exploit_queue.json")
    if isinstance(eq, dict):
        items = eq.get("queue") or eq.get("items") or []
        if isinstance(items, list):
            return items
    if isinstance(eq, list):
        return eq
    return []


# ---------------------------------------------------------------------------
# Engage-severity ranking (corpus-fit composition).
# ---------------------------------------------------------------------------

def _compute_engage_severity(workspace: Path) -> dict[str, Any]:
    """Invoke engagement-prescreen.prescreen() to get corpus_fit_score.

    Returns a dict containing corpus_fit_score + per-language scaffolding
    when the L0.4 tool is available, otherwise a neutral-default dict so
    the report still composes.
    """
    mod = _load_engagement_prescreen()
    if mod is None or not hasattr(mod, "prescreen"):
        return {
            "corpus_fit_score": 0,
            "verdict": "UNAVAILABLE",
            "available": False,
            "reason": "tools/engagement-prescreen.py not available",
        }
    try:
        result = mod.prescreen(
            target_meta={},
            workspace_path=workspace,
            workspace_name=workspace.name,
        )
        return {
            "corpus_fit_score": int(result.get("corpus_fit_score") or 0),
            "verdict": str(result.get("verdict") or "UNAVAILABLE"),
            "available": True,
            "inferred_languages": list(
                (result.get("inferred_target_meta") or {}).get("languages") or []
            ),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "corpus_fit_score": 0,
            "verdict": "UNAVAILABLE",
            "available": False,
            "reason": f"engagement-prescreen error: {exc}",
        }


def _rank_score(
    hit: dict[str, Any],
    *,
    engage_severity: dict[str, Any],
    prior_concerns: set[str],
) -> float:
    """Composite per-hit score in [0, 100].

    Combines:
      - severity weight (LOW=30, MEDIUM=60, HIGH=100)
      - cluster_size_bonus (-log scaled; large clusters of identical LOW
        hits get diminishing returns to avoid swamping)
      - corpus_fit_score from engagement-prescreen (workspace-level boost)
      - prior_concerns hit: -15 (already-known shapes ranked lower)
    """
    sev = SEVERITY_WEIGHT.get(hit["severity"], 30)
    # Cluster-size signal: prefer SMALL focused clusters over 400-hit noise.
    cluster_size = max(int(hit.get("cluster_size") or 1), 1)
    if cluster_size <= 5:
        cluster_bonus = 15
    elif cluster_size <= 20:
        cluster_bonus = 8
    elif cluster_size <= 100:
        cluster_bonus = 0
    else:
        cluster_bonus = -10
    # Path-based exposure heuristic: in-tree under external/ or repos/ is
    # real code; share/cantina-*-evidence/ is throw-away test scaffolding.
    file_path = hit.get("file_path", "")
    if re.search(r"/share/[^/]*cantina[^/]*evidence", file_path):
        path_penalty = -25
    elif re.search(r"_test\.(go|rs|sol|ts|py)$|/tests?/", file_path):
        path_penalty = -10
    elif file_path.startswith("external/") or file_path.startswith("repos/"):
        path_penalty = 5
    else:
        path_penalty = 0
    # Corpus-fit boost (workspace-level): more corpus = more confidence.
    fit_boost = 0.0
    if engage_severity.get("available"):
        fit_boost = float(engage_severity.get("corpus_fit_score") or 0) * 0.15
    # Prior-concerns penalty.
    cluster_id = hit.get("cluster_id", "")
    prior_penalty = -15 if cluster_id in prior_concerns else 0
    score = sev + cluster_bonus + path_penalty + fit_boost + prior_penalty
    return max(0.0, min(100.0, score))


def _bucket_for(score: float) -> str:
    if score >= HIGH_PRIORITY_THRESHOLD:
        return "HIGH-PRIORITY-HUNT"
    if score >= MEDIUM_PRIORITY_THRESHOLD:
        return "MEDIUM-PRIORITY"
    return "LOW-PRIORITY"


def _bucket_with_composability(score: float, composability_score: int) -> tuple[str, str, bool]:
    """Return (final_bucket, score_bucket, bumped) for P5 ranking.

    Score differentiators may run after initial composability enrichment, so
    bucket promotion has to be recomputed from the new score instead of being
    overwritten by score-only bucketing.
    """
    score_bucket = _bucket_for(score)
    if composability_score < COMPOSABILITY_BUMP_THRESHOLD:
        return score_bucket, score_bucket, False
    if score_bucket == "LOW-PRIORITY":
        return "MEDIUM-PRIORITY", score_bucket, True
    if score_bucket == "MEDIUM-PRIORITY":
        return "HIGH-PRIORITY-HUNT", score_bucket, True
    return score_bucket, score_bucket, False


def _compute_stddev(values: list[float]) -> float:
    """Sample standard deviation (population formula). Returns 0.0 for n<2."""
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    var = sum((x - mean) ** 2 for x in values) / len(values)
    return var ** 0.5


def _band_file_path(file_line: str) -> str:
    return file_line.split(":", 1)[0] if ":" in file_line else file_line


def _band_line_no(file_line: str) -> int | None:
    _path, line_no = _split_file_line(file_line)
    return line_no


def _load_bearingness_score(entry: dict[str, Any]) -> float:
    text = " ".join(
        str(entry.get(k) or "")
        for k in ("file_line", "cluster_id", "snippet", "source_context_excerpt")
    ).lower()
    score = 0.0
    if re.search(r"\b(core|vault|gateway|bridge|host|manager|account|oracle|router|pool|escrow)\b", text):
        score += 0.25
    if re.search(r"\b(withdraw|deposit|transfer|mint|burn|settle|execute|permit|initialize|liquidate)\b", text):
        score += 0.25
    if re.search(r"\b(balance|balances|allowance|owner|admin|nonce|debt|collateral|shares|supply)\b", text):
        score += 0.2
    if re.search(r"\b(call\s*\{|delegatecall|transferfrom|safeTransfer|safeTransferFrom|sendValue)\b", text, re.I):
        score += 0.2
    if re.search(r"\b(test|mock|fixture|script|example|vendor|node_modules)\b|/tests?/", text):
        score -= 0.45
    return max(0.0, min(1.0, score))


def _line_locality_scores(entries: list[dict[str, Any]]) -> dict[int, float]:
    by_file: dict[str, list[tuple[int, int]]] = {}
    for idx, entry in enumerate(entries):
        line_no = _band_line_no(str(entry.get("file_line") or ""))
        if line_no is None:
            continue
        by_file.setdefault(_band_file_path(str(entry.get("file_line") or "")), []).append((idx, line_no))

    out = {idx: 0.0 for idx in range(len(entries))}
    for rows in by_file.values():
        if len(rows) == 1:
            continue
        for idx, line_no in rows:
            nearest = min(abs(line_no - other_line) for other_idx, other_line in rows if other_idx != idx)
            if nearest <= 3:
                out[idx] = 1.0
            elif nearest <= 10:
                out[idx] = 0.75
            elif nearest <= 30:
                out[idx] = 0.45
            elif nearest <= 80:
                out[idx] = 0.2
    return out


def _invariant_match_strength(entry: dict[str, Any]) -> float:
    semantic = len(entry.get("semantic_p1_invariants") or [])
    topical = len(entry.get("topical_p1_invariants") or [])
    accepted_sourceproof = len(entry.get("accepted_p1_source_proof_matches") or [])
    tier = entry.get("p1_match_tier")
    if tier == "SEMANTIC-MATCH":
        return min(1.0, 0.5 + semantic * 0.1 + accepted_sourceproof * 0.2)
    if tier == "TOPICAL-MATCH":
        return min(0.2, topical * 0.04)
    return 0.0


def _p3_match_strength(entry: dict[str, Any]) -> float:
    p3s = entry.get("matched_anti_patterns") or []
    real = [p for p in p3s if not str(p).startswith("no-P3-match:")]
    if not real:
        return 0.0
    return min(1.0, 0.35 + len(real) * 0.12)


def _fp_penalty_strength(entry: dict[str, Any]) -> float:
    suppression = entry.get("false_positive_suppression") or {}
    if suppression.get("suppressed"):
        penalty = float(suppression.get("score_penalty") or DOCUMENTED_FP_SCORE_PENALTY)
        return min(1.0, penalty / max(DOCUMENTED_FP_SCORE_PENALTY, 1.0))
    return 0.0


def _high_fp_detector_risk(entry: dict[str, Any]) -> float:
    """Return ranking risk for detector families with documented high-FP history."""
    if _fp_penalty_strength(entry) > 0:
        return 1.0
    cid = str(entry.get("cluster_id") or "").lower()
    high_fp_tokens = (
        "inverted-verify-return",
        "division-by-zero",
        "erc-2771",
        "msgsender-forgery",
        "external-call-before-state-update",
        "pausable-no-unpause-exposed",
        "missing-unpause",
        "lzreceive-no-sender-check",
        "constructor-no-zero-address-check",
    )
    if not any(token in cid for token in high_fp_tokens):
        return 0.0
    if entry.get("p1_match_tier") == "SEMANTIC-MATCH":
        return 0.1
    if entry.get("accepted_p1_source_proof_matches"):
        return 0.1
    return 0.45


def _topical_only_uncertainty(entry: dict[str, Any]) -> float:
    if entry.get("p1_match_tier") != "TOPICAL-MATCH":
        return 0.0
    topical = len(entry.get("topical_p1_invariants") or [])
    return min(1.0, 0.25 + topical * 0.05)


def _apply_score_band_differentiator(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """CAP-014 deterministic tie closure within identical score bands.

    The differentiator uses only local evidence already present in the report:
    file/function load-bearingness, proximity to other detector hits in the
    same file, semantic P1 strength, real P3 match count/confidence, and
    documented false-positive penalties. Deltas are derived from per-entry
    evidence magnitude, not ordinal position inside the tied band.
    """
    if not entries:
        return {"applied": False, "reason": "no_entries", "bands_split": 0}

    bands: dict[float, list[int]] = {}
    for idx, entry in enumerate(entries):
        bands.setdefault(float(entry.get("engage_severity_score") or 0.0), []).append(idx)
    tied_bands = {score: idxs for score, idxs in bands.items() if len(idxs) > 1}
    if not tied_bands:
        return {"applied": False, "reason": "no_tied_score_bands", "bands_split": 0}

    locality = _line_locality_scores(entries)
    bands_split = 0
    entries_adjusted = 0
    entries_scored = 0
    scores_before = [float(e.get("engage_severity_score") or 0.0) for e in entries]
    for _score, idxs in tied_bands.items():
        raw_rows: list[tuple[int, float, dict[str, float]]] = []
        for idx in idxs:
            entry = entries[idx]
            components = {
                "load_bearingness": _load_bearingness_score(entry),
                "line_locality": locality.get(idx, 0.0),
                "invariant_match_strength": _invariant_match_strength(entry),
                "p3_match_strength": _p3_match_strength(entry),
                "documented_fp_penalty": _fp_penalty_strength(entry),
                "high_fp_detector_risk": _high_fp_detector_risk(entry),
                "topical_only_uncertainty": _topical_only_uncertainty(entry),
            }
            raw = (
                components["load_bearingness"] * 0.24
                + components["line_locality"] * 0.14
                + components["invariant_match_strength"] * 0.3
                + components["p3_match_strength"] * 0.2
                - components["documented_fp_penalty"] * 0.38
                - components["high_fp_detector_risk"] * 0.24
                - components["topical_only_uncertainty"] * 0.12
            )
            raw_rows.append((idx, max(-1.0, min(1.0, raw)), components))

        distinct_scores: set[float] = set()
        for idx, raw, components in raw_rows:
            delta = BAND_DIFFERENTIATOR_MAX_DELTA * raw
            entry = entries[idx]
            base_score = float(entry.get("engage_severity_score") or 0.0)
            new_score = round(max(0.0, min(100.0, base_score + delta)), 2)
            distinct_scores.add(new_score)
            entry["engage_severity_score"] = new_score
            final_bucket, score_bucket, bucket_bumped = _bucket_with_composability(
                new_score,
                int(entry.get("composability_score") or 0),
            )
            entry["hunt_priority"] = final_bucket
            entry["hunt_priority_base"] = score_bucket
            entry["composability_bucket_bumped"] = bucket_bumped
            entry["band_differentiator"] = {
                "applied": True,
                "delta": round(delta, 2),
                "evidence_score": round(raw, 3),
                "components": {k: round(v, 3) for k, v in components.items()},
            }
            entries_scored += 1
            if new_score != round(base_score, 2):
                entries_adjusted += 1
        if len(distinct_scores) > 1:
            bands_split += 1

    scores_after = [float(e.get("engage_severity_score") or 0.0) for e in entries]
    if entries_adjusted == 0:
        return {
            "applied": False,
            "reason": "no_meaningful_differentiator_signal",
            "bands_split": 0,
            "entries_scored": entries_scored,
            "entries_adjusted": 0,
            "top30_unique_scores_before": len({round(s, 2) for s in scores_before[:30]}),
            "top30_unique_scores_after": len({round(s, 2) for s in scores_after[:30]}),
            "max_delta": BAND_DIFFERENTIATOR_MAX_DELTA,
            "max_abs_delta": BAND_DIFFERENTIATOR_MAX_DELTA,
        }
    return {
        "applied": entries_adjusted > 0,
        "reason": "tied_score_bands_split",
        "bands_split": bands_split,
        "entries_scored": entries_scored,
        "entries_adjusted": entries_adjusted,
        "top30_unique_scores_before": len({round(s, 2) for s in scores_before[:30]}),
        "top30_unique_scores_after": len({round(s, 2) for s in scores_after[:30]}),
        "max_delta": BAND_DIFFERENTIATOR_MAX_DELTA,
        "max_abs_delta": BAND_DIFFERENTIATOR_MAX_DELTA,
    }


def _apply_stddev_tiebreaker(
    entries: list[dict[str, Any]],
    *,
    coverage_gaps: set[str],
    threshold: float = SCORE_STDDEV_TIEBREAKER_THRESHOLD,
) -> dict[str, Any]:
    """CAP-001 stddev tiebreaker for ranking-collapse cases.

    When the top-30 score stddev falls below ``threshold`` the ranking
    signal has collapsed (every entry looks identical to the operator).
    Apply 3 tiebreaker signals to spread the scores back out by up to
    +/- 15 points each:

      (a) detector-density per cluster: SMALL focused clusters (1-2 hits)
          rank higher than LARGE swept clusters (>=10 hits). Adds +/- up
          to 10 points.
      (b) prior-coverage delta: clusters NOT yet covered by an existing
          submission rank higher than already-hunted clusters. Adds +/-
          up to 8 points (passed in via ``coverage_gaps``).
      (c) cross-cluster file-overlap: files surfaced by >=2 distinct
          detector clusters carry stronger cumulative evidence and
          score higher. Adds +/- up to 6 points.
      (d) source-context quality: documented false-positive suppressions
          score down, semantic P1 matches score up, purely topical P1
          matches score slightly down.

    Mutates each entry dict in-place by overwriting
    ``engage_severity_score`` and re-bucketing ``hunt_priority`` based
    on the new score. Returns a diagnostic dict for telemetry.
    """
    if not entries:
        return {
            "applied": False,
            "reason": "no_entries",
            "stddev_before": 0.0,
            "stddev_after": 0.0,
        }
    raw_scores = [float(e.get("engage_severity_score") or 0.0) for e in entries]
    stddev_before = _compute_stddev(raw_scores)
    if stddev_before >= threshold:
        return {
            "applied": False,
            "reason": "stddev_above_threshold",
            "stddev_before": round(stddev_before, 3),
            "stddev_after": round(stddev_before, 3),
            "threshold": threshold,
        }

    # Pre-compute cluster-size + file-overlap signals.
    cluster_sizes: dict[str, int] = {}
    file_to_clusters: dict[str, set[str]] = {}
    for e in entries:
        cid = e.get("cluster_id") or ""
        cluster_sizes[cid] = max(cluster_sizes.get(cid, 0), int(e.get("cluster_size") or 0))
        fp = e.get("file_line") or ""
        # File path only (strip :line suffix) for overlap counting.
        fp_only = fp.split(":", 1)[0] if ":" in fp else fp
        file_to_clusters.setdefault(fp_only, set()).add(cid)

    for e in entries:
        cid = e.get("cluster_id") or ""
        base_score = float(e.get("engage_severity_score") or 0.0)

        # (a) detector-density per cluster.
        size = cluster_sizes.get(cid, 0)
        if size <= 2:
            density_delta = 10.0
        elif size <= 5:
            density_delta = 5.0
        elif size <= 10:
            density_delta = 0.0
        elif size <= 25:
            density_delta = -5.0
        else:
            density_delta = -10.0

        # (b) prior-coverage delta.
        coverage_delta = 8.0 if cid in coverage_gaps else -4.0

        # (c) cross-cluster file-overlap.
        fp = e.get("file_line") or ""
        fp_only = fp.split(":", 1)[0] if ":" in fp else fp
        n_overlaps = len(file_to_clusters.get(fp_only, set()))
        if n_overlaps >= 3:
            overlap_delta = 6.0
        elif n_overlaps == 2:
            overlap_delta = 3.0
        else:
            overlap_delta = 0.0

        suppression = e.get("false_positive_suppression") or {}
        if suppression.get("suppressed"):
            detector_quality_delta = -DOCUMENTED_FP_SCORE_PENALTY
        elif e.get("p1_match_tier") == "SEMANTIC-MATCH":
            detector_quality_delta = 10.0
        elif e.get("p1_match_tier") == "TOPICAL-MATCH":
            detector_quality_delta = -3.0
        else:
            detector_quality_delta = 0.0

        new_score = max(
            0.0,
            min(
                100.0,
                base_score
                + density_delta
                + coverage_delta
                + overlap_delta
                + detector_quality_delta,
            ),
        )
        e["engage_severity_score"] = round(new_score, 2)
        final_bucket, score_bucket, bucket_bumped = _bucket_with_composability(
            new_score,
            int(e.get("composability_score") or 0),
        )
        e["hunt_priority"] = final_bucket
        e["hunt_priority_base"] = score_bucket
        e["composability_bucket_bumped"] = bucket_bumped
        e["tiebreaker_applied"] = True
        e["tiebreaker_deltas"] = {
            "density": round(density_delta, 2),
            "coverage": round(coverage_delta, 2),
            "overlap": round(overlap_delta, 2),
            "detector_quality": round(detector_quality_delta, 2),
        }

    new_scores = [float(e.get("engage_severity_score") or 0.0) for e in entries]
    stddev_after = _compute_stddev(new_scores)
    return {
        "applied": True,
        "reason": "stddev_below_threshold",
        "stddev_before": round(stddev_before, 3),
        "stddev_after": round(stddev_after, 3),
        "threshold": threshold,
        "score_spread_before": round(max(raw_scores) - min(raw_scores), 2),
        "score_spread_after": round(max(new_scores) - min(new_scores), 2),
    }


# ---------------------------------------------------------------------------
# P4 local triager precheck composition.
# ---------------------------------------------------------------------------

def _entry_triager_draft(entry: dict[str, Any]) -> str:
    """Render a report entry into a short local-precheck draft."""
    p1_gaps = entry.get("p1_semantic_invariant_gaps") or []
    lines = [
        f"# Live target candidate: {entry.get('cluster_id', 'unknown')}",
        "",
        f"Claimed severity: {entry.get('severity_from_engage') or 'unknown'}",
        f"Hunt priority: {entry.get('hunt_priority') or 'unknown'}",
        f"Engage severity score: {entry.get('engage_severity_score')}",
        f"File: {entry.get('file_line') or ''}",
        f"Detector cluster: {entry.get('cluster_id') or ''}",
        f"Detector snippet: {entry.get('snippet') or ''}",
        "",
        "P1 semantic invariants:",
        ", ".join(entry.get("semantic_p1_invariants") or []) or "none",
        "",
        "P1 semantic invariant gaps:",
        json.dumps(p1_gaps, sort_keys=True) if p1_gaps else "none",
        "",
        "P3 anti-pattern IDs:",
        ", ".join(entry.get("matched_anti_patterns") or []) or "none",
        "",
        "Local source context:",
        "```",
        str(entry.get("source_context_excerpt") or "")[:4000],
        "```",
        "",
        (
            "This draft is generated for deterministic local P4 precheck only. "
            "It is not a filed finding and does not request provider-backed "
            "simulation or triager clearance."
        ),
    ]
    return "\n".join(lines)


def _normalize_p4_precheck_packet(
    packet: dict[str, Any],
    *,
    budget_rank: int,
) -> dict[str, Any]:
    """Keep useful P4 local output while preserving the provider boundary."""
    local_rules_status = dict(packet.get("local_rules_status") or {})
    provider_status = dict(packet.get("provider_status") or {})
    capability_boundary = dict(packet.get("capability_boundary") or {})

    for row in (local_rules_status, provider_status, capability_boundary):
        row["provider_backed"] = False
        row["provider_call_made"] = False
        row["predicted_verdict_supported"] = False
    capability_boundary["triager_verdict_or_clearance"] = False

    matched_patterns: list[dict[str, Any]] = []
    for row in list(packet.get("matched_patterns") or [])[:8]:
        if not isinstance(row, dict):
            continue
        matched_patterns.append(
            {
                "id": row.get("id"),
                "name": row.get("name"),
                "severity": row.get("severity"),
                "outcome_class": row.get("outcome_class"),
                "outcome_class_key": row.get("outcome_class_key"),
                "score": row.get("score"),
                "matched_terms": list(row.get("matched_terms") or [])[:8],
            }
        )

    warnings: list[dict[str, Any]] = []
    for row in list(packet.get("warnings") or [])[:8]:
        if isinstance(row, dict):
            warnings.append(row)

    disposition = packet.get("disposition_evidence")
    if isinstance(disposition, dict):
        disposition = dict(disposition)
        disposition["provider_backed"] = False
        disposition["provider_call_made"] = False
        disposition["predicted_provider_verdict"] = None

    source_refs: list[str] = []
    generated_ref = f"generated:p5_live_target_entry:{budget_rank:03d}"
    for raw_ref in list(packet.get("source_refs") or [])[:12]:
        ref = str(raw_ref)
        if "auditooor-p5-p4-" in ref:
            ref = generated_ref
        source_refs.append(ref)

    return {
        "status": "completed",
        "budget_rank": budget_rank,
        "schema": packet.get("schema"),
        "mode": packet.get("mode", "rules_mvp"),
        "local_rules_status": local_rules_status,
        "provider_status": provider_status,
        "provider_backed": False,
        "provider_call_made": False,
        "predicted_verdict_supported": False,
        "predicted_verdict": None,
        "triager_verdict_or_clearance": False,
        "recommended_action": packet.get("recommended_action"),
        "warnings": warnings,
        "matched_patterns": matched_patterns,
        "class_votes": dict(packet.get("class_votes") or {}),
        "silent_kill_predictions": list(packet.get("silent_kill_predictions") or [])[:8],
        "silent_kill_summary": dict(packet.get("silent_kill_summary") or {}),
        "disposition_evidence": disposition,
        "capability_boundary": capability_boundary,
        "source_refs": sorted(dict.fromkeys(source_refs)),
        "advisory_only": True,
    }


def _p4_budget_skipped_status(
    *,
    budget_requested: int,
    reason: str,
    budget_rank: int | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "status": "budget-skipped",
        "budget_requested": budget_requested,
        "reason": reason,
        "provider_backed": False,
        "provider_call_made": False,
        "predicted_verdict_supported": False,
        "predicted_verdict": None,
        "triager_verdict_or_clearance": False,
    }
    if budget_rank is not None:
        out["budget_rank"] = budget_rank
    return out


def _p4_integration_gap_status(reason: str) -> dict[str, Any]:
    return {
        "status": "integration-gap",
        "reason": reason,
        "provider_backed": False,
        "provider_call_made": False,
        "predicted_verdict_supported": False,
        "predicted_verdict": None,
        "triager_verdict_or_clearance": False,
    }


def _apply_p4_triager_prechecks(
    entries: list[dict[str, Any]],
    *,
    workspace: Path,
    triager_precheck_budget: int,
) -> dict[str, Any]:
    """Attach P4 local rules precheck output to budgeted ranked entries."""
    try:
        budget_requested = int(triager_precheck_budget)
    except (TypeError, ValueError):
        budget_requested = 0
    budget_requested = max(0, budget_requested)

    stats: dict[str, Any] = {
        "available": False,
        "state": "not_run",
        "budget_requested": budget_requested,
        "entries_considered": len(entries),
        "entries_prechecked": 0,
        "entries_budget_skipped": 0,
        "entries_failed": 0,
        "provider_backed": False,
        "provider_call_made": False,
        "predicted_verdict_supported": False,
        "triager_verdict_or_clearance": False,
        "source_ref": "tools/triager-pre-filing-simulator.py::build_precheck",
    }

    if not entries:
        stats["state"] = "no_entries"
        return stats

    if budget_requested <= 0:
        for idx, entry in enumerate(entries, start=1):
            entry["p4_triager_precheck"] = _p4_budget_skipped_status(
                budget_requested=budget_requested,
                budget_rank=idx,
                reason="triager_precheck_budget <= 0",
            )
        stats["state"] = "budget_zero"
        stats["entries_budget_skipped"] = len(entries)
        return stats

    p4_mod = _load_p4_triager_precheck()
    if p4_mod is None or not hasattr(p4_mod, "build_precheck"):
        reason = "P4 local precheck helper unavailable"
        for entry in entries:
            entry["p4_triager_precheck"] = _p4_integration_gap_status(reason)
        stats["state"] = "integration_gap"
        stats["integration_gap"] = reason
        return stats

    stats["available"] = True
    budget_remaining = budget_requested
    for idx, entry in enumerate(entries, start=1):
        if budget_remaining <= 0:
            entry["p4_triager_precheck"] = _p4_budget_skipped_status(
                budget_requested=budget_requested,
                budget_rank=idx,
                reason="triager_precheck_budget exhausted",
            )
            stats["entries_budget_skipped"] += 1
            continue

        draft_text = _entry_triager_draft(entry)
        try:
            with tempfile.TemporaryDirectory(prefix="auditooor-p5-p4-") as tmp_dir:
                draft_path = Path(tmp_dir) / f"p5-entry-{idx:03d}.md"
                draft_path.write_text(draft_text, encoding="utf-8")
                packet = p4_mod.build_precheck(
                    draft_path,
                    workspace,
                    severity=str(entry.get("severity_from_engage") or "").title() or None,
                )
        except Exception as exc:  # noqa: BLE001
            entry["p4_triager_precheck"] = {
                **_p4_integration_gap_status(f"P4 local precheck error: {exc}"),
                "budget_rank": idx,
            }
            stats["entries_failed"] += 1
            budget_remaining -= 1
            continue

        if not isinstance(packet, dict):
            entry["p4_triager_precheck"] = {
                **_p4_integration_gap_status("P4 local precheck returned non-object"),
                "budget_rank": idx,
            }
            stats["entries_failed"] += 1
            budget_remaining -= 1
            continue

        entry["p4_triager_precheck"] = _normalize_p4_precheck_packet(
            packet,
            budget_rank=idx,
        )
        stats["entries_prechecked"] += 1
        budget_remaining -= 1

    stats["state"] = "completed" if stats["entries_failed"] == 0 else "completed_with_errors"
    return stats


# ---------------------------------------------------------------------------
# Report assembly.
# ---------------------------------------------------------------------------

def build_report(
    workspace: Path,
    *,
    top_n: int = 50,
    triager_precheck_budget: int = 10,
    strict: bool = False,
) -> dict[str, Any]:
    """Assemble the live-target-intelligence report (MVP3).

    Args:
        workspace: workspace root.
        top_n: ranked-hunt-list cap.
        triager_precheck_budget: number of top-ranked entries to run through
            the rules-only P4 local precheck.
        strict: if True, fail-closed when required artifacts are missing.

    Returns:
        Dict matching ``auditooor.live_target_intelligence.v3``.
    """
    errors: list[str] = []
    if not workspace.is_dir():
        msg = f"workspace_not_found: {workspace}"
        if strict:
            raise FileNotFoundError(msg)
        errors.append(msg)

    audit_pin = _read_audit_pin(workspace)
    intake = _read_intake_baseline(workspace)
    hits, engage_report_source = _read_engage_report(workspace)
    prior_concerns = _read_prior_concerns(workspace)
    severity_rubric = _read_severity_rubric(workspace)
    existing_submissions = _read_existing_submissions(workspace)
    engage_severity = _compute_engage_severity(workspace)
    # MVP1.1 (P5-MVP1.1-MD-FALLBACK): annotate engage_severity with the
    # engage_report source + .md-fallback marker so operators can tell a
    # parser-gap zero from a data zero.
    engage_severity["engage_report_source"] = engage_report_source.get("source", "none")
    engage_severity["engage_report_md_fallback"] = bool(
        engage_report_source.get("engage_report_md_fallback")
    )
    engage_severity["engage_report_json_present"] = bool(
        engage_report_source.get("json_present")
    )
    engage_severity["engage_report_md_present"] = bool(
        engage_report_source.get("md_present")
    )

    # MVP2 compose: load P1 + P3 catalogs once, reuse per-entry.
    p1_index = _load_p1_invariants()
    p3_index = _load_p3_patterns()
    shape_cluster_candidates = _load_shape_cluster_predicate_candidates(workspace)
    bug_bounty_oos_index, bug_bounty_oos_stats = _build_bug_bounty_oos_index(workspace)

    if not hits and strict:
        raise FileNotFoundError(
            "engage_report.json AND engage_report.md missing or empty at "
            f"{workspace}/engage_report.{{json,md}}"
        )
    if not hits:
        errors.append("engage_report_missing_or_empty")

    # Score every hit, rank, top-N.
    enriched: list[dict[str, Any]] = []
    per_cluster_seen: dict[str, int] = {}
    for hit in hits:
        cluster_id = hit["cluster_id"]
        seen = per_cluster_seen.get(cluster_id, 0)
        if seen >= MAX_ENTRIES_PER_CLUSTER:
            continue
        per_cluster_seen[cluster_id] = seen + 1
        score = _rank_score(
            hit,
            engage_severity=engage_severity,
            prior_concerns=prior_concerns,
        )
        base_bucket = _bucket_for(score)
        # MVP2 compose: real P3 anti-pattern IDs (or documented no-match
        # sentinel) + real P1 invariant_ids from the corpus catalog.
        # CAP-003: pass the file_path as file_hint so the matcher can
        # derive language from extension when the cluster slug carries
        # no lang prefix (descriptive kebab-case slugs).
        file_hint = hit.get("file_path") or ""
        source_context = _source_context(workspace, file_hint)
        source_contract_context = _source_contract_context(workspace, file_hint)
        fp_suppression = _detector_false_positive_suppression(
            cluster_id,
            file_line=file_hint,
            snippet=hit.get("snippet") or "",
            source_context=source_context,
            source_contract_context=source_contract_context,
        )
        if fp_suppression.get("suppressed"):
            score = max(0.0, score - float(fp_suppression.get("score_penalty") or 0.0))
            base_bucket = _bucket_for(score)
        matched_p3 = _match_p3_for_cluster(cluster_id, p3_index=p3_index, file_hint=file_hint)
        matched_p3 = _filter_live_target_p3_matches(
            matched_p3,
            file_hint=file_hint,
            snippet=hit.get("snippet") or "",
            source_context=source_context,
            source_contract_context=source_contract_context,
        )
        if fp_suppression.get("suppressed"):
            matched_p3 = [
                pid for pid in matched_p3
                if pid.startswith("no-P3-match:")
            ]
        matched_p1 = _match_p1_for_cluster(cluster_id, p1_index=p1_index, file_hint=file_hint)
        semantic_p1 = _semantic_p1_matches(
            cluster_id,
            matched_p1=matched_p1,
            file_line=file_hint,
            snippet=hit.get("snippet") or "",
            source_context=source_context,
            source_contract_context=source_contract_context,
        )
        accepted_source_proof_p1 = _accepted_p1_source_proof_matches(workspace, file_hint)
        for accepted_match in accepted_source_proof_p1:
            inv_id = str(accepted_match.get("invariant_id") or "")
            if not inv_id:
                continue
            if inv_id not in matched_p1:
                matched_p1.append(inv_id)
            if inv_id not in semantic_p1:
                semantic_p1.append(inv_id)
        shape_cluster_predicate_matches = _shape_cluster_predicate_semantic_matches(
            workspace,
            cluster_id=cluster_id,
            file_line=file_hint,
            snippet=hit.get("snippet") or "",
            source_context=source_context,
            source_contract_context=source_contract_context,
            candidates_by_cluster=shape_cluster_candidates,
            matched_p1=matched_p1,
        )
        for shape_candidate in shape_cluster_predicate_matches:
            inv_id = str(shape_candidate.get("invariant_id") or "")
            if not inv_id:
                continue
            if inv_id not in matched_p1:
                matched_p1.append(inv_id)
            if inv_id not in semantic_p1:
                semantic_p1.append(inv_id)
        topical_p1 = [pid for pid in matched_p1 if pid not in set(semantic_p1)]
        p1_match_tier = _p1_match_tier(
            matched_p1=matched_p1,
            semantic_p1=semantic_p1,
        )
        p1_semantic_gaps = _p1_semantic_invariant_gaps(
            cluster_id,
            p1_index=p1_index,
            matched_p1=matched_p1,
            semantic_p1=semantic_p1,
            file_hint=file_hint,
        )
        if p1_match_tier == "SEMANTIC-MATCH":
            score = min(100.0, score + 6.0)
            base_bucket = _bucket_for(score)
        elif p1_match_tier == "TOPICAL-MATCH":
            score = max(0.0, score - 2.0)
            base_bucket = _bucket_for(score)
        # composability_score counts REAL anchors (excludes ``no-P3-match:``
        # sentinels) so the bump rewards genuine corpus depth, not gap
        # documentation.
        real_p3 = [pid for pid in matched_p3 if not pid.startswith("no-P3-match")]
        composability_score = len(real_p3) + len(semantic_p1)
        bumped_bucket, score_bucket, bucket_bumped = _bucket_with_composability(
            score,
            composability_score,
        )
        enriched.append(
            {
                "file_line": hit["file_path"],
                "cluster_id": cluster_id,
                "cluster_size": hit["cluster_size"],
                "severity_from_engage": hit["severity"],
                "snippet": hit["snippet"][:200],
                "engage_severity_score": round(score, 2),
                "hunt_priority": bumped_bucket,
                "hunt_priority_base": score_bucket,
                "matched_anti_patterns": matched_p3 if matched_p3 else [],
                "p1_invariant_hits": matched_p1,
                "matched_p1_invariants": matched_p1,  # MVP2 canonical field name
                "semantic_p1_invariants": semantic_p1,
                "topical_p1_invariants": topical_p1,
                "p1_match_tier": p1_match_tier,
                "p1_semantic_invariant_gaps": p1_semantic_gaps,
                "accepted_p1_source_proof_matches": accepted_source_proof_p1,
                "shape_cluster_predicate_matches": shape_cluster_predicate_matches,
                "composability_score": composability_score,
                "composability_bucket_bumped": bucket_bumped,
                "p4_triager_precheck": _p4_budget_skipped_status(
                    budget_requested=triager_precheck_budget,
                    reason="P4 precheck assigned after final ranking",
                ),
                "false_positive_suppression": fp_suppression,
                "source_context_excerpt": source_context[:2000],
            }
        )

    enriched.sort(key=lambda e: e["engage_severity_score"], reverse=True)
    prioritized = enriched[:top_n]

    # Coverage gaps: clusters with NO existing submission citation.
    clusters_in_report = {h["cluster_id"] for h in hits if h["cluster_id"]}
    coverage_gaps = sorted(clusters_in_report - existing_submissions)

    # CAP-001 stddev tiebreaker: re-spread prioritized entries when the
    # top-N score distribution has collapsed to near-uniform values
    # (e.g. hyperbridge 2026-05-24 had all 30 entries scored 51.9).
    band_differentiator_diagnostics = _apply_score_band_differentiator(prioritized)
    if band_differentiator_diagnostics.get("applied"):
        prioritized.sort(key=lambda e: e["engage_severity_score"], reverse=True)
    tiebreaker_diagnostics = _apply_stddev_tiebreaker(
        prioritized,
        coverage_gaps=set(coverage_gaps),
    )
    # Re-sort by the new score so the operator sees the updated ranking.
    if tiebreaker_diagnostics.get("applied"):
        prioritized.sort(key=lambda e: e["engage_severity_score"], reverse=True)
    bug_bounty_oos_apply_stats = _apply_bug_bounty_oos_cross_check(
        prioritized,
        bug_bounty_oos_index,
    )
    bug_bounty_oos_stats.update(bug_bounty_oos_apply_stats)
    # Prior-audit deltas: clusters whose detector slug appears in PRIOR_CONCERNS.
    prior_audit_deltas = sorted(clusters_in_report & prior_concerns)

    p4_precheck_stats = _apply_p4_triager_prechecks(
        prioritized,
        workspace=workspace,
        triager_precheck_budget=triager_precheck_budget,
    )
    for entry in prioritized:
        entry.pop("source_context_excerpt", None)

    # Operator action queue: top HIGH-PRIORITY-HUNT subset of prioritized.
    action_queue = [
        {
            "rank": idx + 1,
            "file_line": item["file_line"],
            "cluster_id": item["cluster_id"],
            "engage_severity_score": item["engage_severity_score"],
            "hunt_priority": item["hunt_priority"],
            "next_step": "PoC build + V3-grade evidence per R40",
        }
        for idx, item in enumerate(prioritized)
        if item["hunt_priority"] == "HIGH-PRIORITY-HUNT"
    ][: min(top_n, 25)]

    # Provenance.
    workspace_state_blob = json.dumps(
        {
            "files_indexed": intake["files_indexed"],
            "hits_count": len(hits),
            "audit_pin_sha": audit_pin.get("sha"),
            "tool_version": TOOL_VERSION,
            "bug_bounty_oos_index_hash": bug_bounty_oos_index.get("index_hash"),
            "bug_bounty_oos_index_rows": bug_bounty_oos_index.get("row_count", 0),
        },
        sort_keys=True,
    )
    workspace_state_hash = hashlib.sha256(workspace_state_blob.encode("utf-8")).hexdigest()

    # MVP2 compose stats.
    composability_scores = [e["composability_score"] for e in prioritized]
    bumped_count = sum(1 for e in prioritized if e.get("composability_bucket_bumped"))
    p1_tier_counts = {
        "SEMANTIC-MATCH": sum(1 for e in prioritized if e.get("p1_match_tier") == "SEMANTIC-MATCH"),
        "TOPICAL-MATCH": sum(1 for e in prioritized if e.get("p1_match_tier") == "TOPICAL-MATCH"),
        "NO-MATCH": sum(1 for e in prioritized if e.get("p1_match_tier") == "NO-MATCH"),
    }
    p1_semantic_gap_counts: dict[str, int] = {}
    for entry in prioritized:
        gaps = entry.get("p1_semantic_invariant_gaps") or []
        if not gaps:
            p1_semantic_gap_counts["none"] = p1_semantic_gap_counts.get("none", 0) + 1
            continue
        for gap in gaps:
            status = str((gap or {}).get("status") or "unknown")
            p1_semantic_gap_counts[status] = p1_semantic_gap_counts.get(status, 0) + 1
    suppressed_fp_count = sum(
        1 for e in prioritized
        if (e.get("false_positive_suppression") or {}).get("suppressed")
    )
    shape_cluster_semantic_count = sum(
        len(e.get("shape_cluster_predicate_matches") or [])
        for e in prioritized
    )
    summary_card = {
        "files_indexed": intake["files_indexed"],
        "languages": intake["languages"],
        "engage_report_hit_count": len(hits),
        "clusters_count": len({h["cluster_id"] for h in hits}),
        "ranked_hunt_list_size": len(prioritized),
        "score_tiebreaker": tiebreaker_diagnostics,
        "score_band_differentiator": band_differentiator_diagnostics,
        "top30_unique_score_count": len(
            {float(e.get("engage_severity_score") or 0.0) for e in prioritized[:30]}
        ),
        "hunt_priority_distribution": {
            "HIGH-PRIORITY-HUNT": sum(
                1 for e in prioritized if e["hunt_priority"] == "HIGH-PRIORITY-HUNT"
            ),
            "MEDIUM-PRIORITY": sum(
                1 for e in prioritized if e["hunt_priority"] == "MEDIUM-PRIORITY"
            ),
            "LOW-PRIORITY": sum(
                1 for e in prioritized if e["hunt_priority"] == "LOW-PRIORITY"
            ),
            BUG_BOUNTY_OOS_PRIORITY: sum(
                1 for e in prioritized if e["hunt_priority"] == BUG_BOUNTY_OOS_PRIORITY
            ),
        },
        "coverage_gap_count": len(coverage_gaps),
        "prior_audit_delta_count": len(prior_audit_deltas),
        "operator_action_queue_size": len(action_queue),
        "engage_severity": engage_severity,
        "severity_rubric": severity_rubric,
        "composability": {
            "p1_corpus_size": sum(len(v) for v in p1_index.values()),
            "p3_catalog_size": sum(len(v) for v in p3_index.values()),
            "composability_score_max": max(composability_scores) if composability_scores else 0,
            "composability_score_min": min(composability_scores) if composability_scores else 0,
            "composability_score_avg": (
                round(sum(composability_scores) / len(composability_scores), 2)
                if composability_scores else 0
            ),
            "entries_bucket_bumped": bumped_count,
            "composability_bump_threshold": COMPOSABILITY_BUMP_THRESHOLD,
            "p1_match_tier_counts": p1_tier_counts,
            "p1_semantic_gap_counts": p1_semantic_gap_counts,
            "documented_fp_suppressed_entries": suppressed_fp_count,
            "shape_cluster_predicate_semantic_matches": shape_cluster_semantic_count,
        },
        "p4_triager_precheck": p4_precheck_stats,
        "bug_bounty_oos": bug_bounty_oos_stats,
    }

    return {
        "schema": SCHEMA,
        "tool_version": TOOL_VERSION,
        "workspace": str(workspace),
        "audit_pin": audit_pin,
        "summary_card": summary_card,
        "entry_points": prioritized,
        "prioritized_hunt_list": prioritized,
        "coverage_gaps": coverage_gaps,
        "prior_audit_deltas": prior_audit_deltas,
        "operator_action_queue": action_queue,
        "bug_bounty_oos_index": {
            "schema": bug_bounty_oos_index.get("schema"),
            "index_path": bug_bounty_oos_stats.get("index_path", ""),
            "source_paths": bug_bounty_oos_stats.get("source_paths", []),
            "row_count": bug_bounty_oos_stats.get("indexed_rows", 0),
            "index_hash": bug_bounty_oos_stats.get("index_hash", ""),
        },
        "provenance": {
            "tool_version": TOOL_VERSION,
            "tool_path": "tools/live-target-intelligence-report.py",
            "workspace_state_hash": workspace_state_hash,
            "generated_at_utc": _dt.datetime.now(_dt.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "mvp_phase": "MVP3",
            "schema_v1_compatibility": (
                "v3 is a superset of v1/v2: all v1 fields preserved; v2 adds "
                "matched_p1_invariants, composability_score, "
                "composability_bucket_bumped, hunt_priority_base; v3 adds "
                "p1_semantic_invariant_gaps, accepted_p1_source_proof_matches, "
                "shape_cluster_predicate_matches, and rules-only "
                "p4_triager_precheck."
            ),
            "deferred_to_mvp2": [],  # all delivered in this build
            "deferred_to_mvp3": (
                [p4_precheck_stats.get("integration_gap")]
                if p4_precheck_stats.get("integration_gap")
                else []
            ),
        },
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Markdown rendering.
# ---------------------------------------------------------------------------

def render_markdown(report: dict[str, Any]) -> str:
    out: list[str] = []
    workspace = report.get("workspace", "")
    ws_name = Path(workspace).name if workspace else "unknown"
    pin = report.get("audit_pin", {}) or {}
    summary = report.get("summary_card", {}) or {}
    out.append(f"# Live-Target Intelligence Report - {ws_name}")
    out.append("")
    out.append(f"- Workspace: `{workspace}`")
    mvp_label = (report.get("provenance") or {}).get("mvp_phase", "MVP1")
    out.append(f"- Tool: `{report.get('tool_version', 'unknown')}` ({mvp_label})")
    out.append(f"- Generated: `{pin.get('report_generated', '?')}`")
    if pin.get("sha"):
        out.append(f"- Audit pin: `{pin['sha']}` ({pin.get('freshness_status', '?')})")
    if pin.get("primary_repo"):
        out.append(f"- Primary repo: `{pin['primary_repo']}`")
    out.append("")
    out.append("## Summary card")
    out.append("")
    out.append(f"- Files indexed: **{summary.get('files_indexed', 0):,}**")
    langs = summary.get("languages") or []
    out.append(f"- Languages: **{', '.join(langs) if langs else 'unknown'}**")
    out.append(f"- Engage-report hits: **{summary.get('engage_report_hit_count', 0)}**")
    out.append(f"- Detector clusters: **{summary.get('clusters_count', 0)}**")
    es = summary.get("engage_severity") or {}
    er_source = es.get("engage_report_source", "none")
    if er_source == "md":
        out.append(
            "- Engage-report source: **engage_report.md** (MVP1.1 fallback - "
            "engage_report.json was missing or empty)"
        )
    elif er_source == "json":
        out.append("- Engage-report source: engage_report.json")
    else:
        out.append(
            "- Engage-report source: **none** (both .json and .md missing or empty)"
        )
    if es.get("available"):
        out.append(
            f"- Engagement corpus-fit score: **{es.get('corpus_fit_score', 0)}** "
            f"({es.get('verdict', '?')})"
        )
    else:
        reason = es.get("reason", "engagement-prescreen unavailable")
        out.append(f"- Engagement corpus-fit score: UNAVAILABLE ({reason})")
    dist = summary.get("hunt_priority_distribution") or {}
    out.append(
        f"- Hunt-priority distribution: HIGH={dist.get('HIGH-PRIORITY-HUNT', 0)} / "
        f"MED={dist.get('MEDIUM-PRIORITY', 0)} / LOW={dist.get('LOW-PRIORITY', 0)} / "
        f"NEEDS-EXT={dist.get(BUG_BOUNTY_OOS_PRIORITY, 0)}"
    )
    out.append(f"- Coverage gaps: **{summary.get('coverage_gap_count', 0)}** "
               f"clusters with no existing finding")
    out.append(f"- Prior-audit deltas: **{summary.get('prior_audit_delta_count', 0)}** "
               f"clusters acknowledged in prior audits (R47/R53 risk)")
    bb_oos = summary.get("bug_bounty_oos") or {}
    if bb_oos:
        out.append(
            f"- BUG_BOUNTY OOS cross-check: **{bb_oos.get('indexed_rows', 0)}** rows "
            f"from **{len(bb_oos.get('source_paths') or [])}** file(s); "
            f"matched=**{bb_oos.get('entries_matched', 0)}**; "
            f"downranked=**{bb_oos.get('entries_downranked', 0)}**"
        )
    out.append("")
    # MVP2 composability summary
    comp = (summary.get("composability") or {})
    if comp:
        out.append("## Composability (MVP2)")
        out.append("")
        out.append(f"- P1 invariant library: **{comp.get('p1_corpus_size', 0)}** entries")
        out.append(f"- P3 anti-pattern catalog: **{comp.get('p3_catalog_size', 0)}** entries")
        out.append(
            f"- Composability score: min=**{comp.get('composability_score_min', 0)}** "
            f"avg=**{comp.get('composability_score_avg', 0)}** "
            f"max=**{comp.get('composability_score_max', 0)}**"
        )
        out.append(
            f"- Entries bucket-bumped via composability "
            f"(threshold >= **{comp.get('composability_bump_threshold', 3)}**): "
            f"**{comp.get('entries_bucket_bumped', 0)}**"
        )
        tiers = comp.get("p1_match_tier_counts") or {}
        out.append(
            f"- P1 match tiers: semantic=**{tiers.get('SEMANTIC-MATCH', 0)}** / "
            f"topical=**{tiers.get('TOPICAL-MATCH', 0)}** / "
            f"none=**{tiers.get('NO-MATCH', 0)}**"
        )
        gap_counts = comp.get("p1_semantic_gap_counts") or {}
        if gap_counts:
            gap_bits = ", ".join(
                f"{key}={value}" for key, value in sorted(gap_counts.items())
            )
            out.append(f"- P1 semantic invariant gaps: **{gap_bits}**")
        out.append(
            f"- Documented detector false-positive suppressions: "
            f"**{comp.get('documented_fp_suppressed_entries', 0)}**"
        )
        out.append("")
    gate = report.get("semantic_gate_application") or {}
    if gate:
        out.append("## Semantic Gate")
        out.append("")
        out.append(
            f"- Semantic promotions: **{gate.get('semantic_promotions', 0)}**; "
            f"false-positive records: **{gate.get('false_positive_records', 0)}**; "
            f"topical records: **{gate.get('topical_records', 0)}**"
        )
        out.append(
            f"- Dry-run verdicts skipped: **{gate.get('dry_run_verdicts_skipped', 0)}**; "
            f"unmatched verdicts: **{gate.get('unmatched_verdicts', 0)}**"
        )
        if gate.get("false_positive_policy"):
            out.append(f"- False-positive policy: {gate['false_positive_policy']}")
        out.append("")
    p4 = summary.get("p4_triager_precheck") or {}
    if p4:
        out.append("## P4 triager precheck (MVP3)")
        out.append("")
        out.append(
            f"- State: **{p4.get('state', 'unknown')}**; "
            f"rules helper available: **{bool(p4.get('available'))}**"
        )
        out.append(
            f"- Budget: **{p4.get('budget_requested', 0)}**; "
            f"entries prechecked: **{p4.get('entries_prechecked', 0)}**; "
            f"budget-skipped: **{p4.get('entries_budget_skipped', 0)}**"
        )
        out.append(
            "- Provider-backed simulation: **false**; provider call made: "
            "**false**; predicted verdict supported: **false**"
        )
        if p4.get("integration_gap"):
            out.append(f"- Integration gap: {p4['integration_gap']}")
        out.append("")
    out.append("## Hunt prioritization")
    out.append("")
    entries = report.get("prioritized_hunt_list") or []
    if not entries:
        out.append(
            "_(no entries - engage_report.json AND engage_report.md missing or empty)_"
        )
    else:
        out.append("| rank | score | comp | priority | file:line | cluster | p1 tier | p1 | p3 | bug bounty OOS | p4 |")
        out.append("|----:|----:|----:|---|---|---|---|---|---|---|---|")
        for idx, ent in enumerate(entries):
            p1s = ent.get("matched_p1_invariants") or ent.get("p1_invariant_hits") or []
            p3s = ent.get("matched_anti_patterns") or []
            p1_str = ", ".join(p1s[:3]) + (f" (+{len(p1s)-3})" if len(p1s) > 3 else "")
            p3_str = ", ".join(p3s[:2]) + (f" (+{len(p3s)-2})" if len(p3s) > 2 else "")
            bb_match = ent.get("bug_bounty_oos_match") or {}
            if bb_match:
                bb_phrase = str(bb_match.get("phrase") or "")[:80]
                bb_oos_str = (
                    f"{bb_match.get('clause_id', '?')} "
                    f"({bb_match.get('confidence', 0)}): {bb_phrase}"
                )
            else:
                bb_oos_str = ""
            p4_precheck = ent.get("p4_triager_precheck") or {}
            p4_status = str(p4_precheck.get("status") or "unknown")
            p4_action = str(p4_precheck.get("recommended_action") or "")
            p4_str = p4_status if not p4_action else f"{p4_status}: {p4_action}"
            bump_marker = " *" if ent.get("composability_bucket_bumped") else ""
            out.append(
                f"| {idx + 1} | {ent['engage_severity_score']} | "
                f"{ent.get('composability_score', 0)}{bump_marker} | "
                f"{ent['hunt_priority']} | `{ent['file_line']}` | "
                f"`{ent['cluster_id']}` | {ent.get('p1_match_tier', 'NO-MATCH')} | "
                f"{p1_str} | {p3_str} | {bb_oos_str} | {p4_str} |"
            )
        out.append("")
        out.append("_`*` = entry bucket-bumped via composability_score >= threshold._")
    out.append("")
    out.append("## Coverage gaps")
    out.append("")
    gaps = report.get("coverage_gaps") or []
    if not gaps:
        out.append("_(no gaps - every cluster has an existing submission)_")
    else:
        out.append("Clusters present in engage_report with no submission citation:")
        out.append("")
        for g in gaps[:20]:
            out.append(f"- `{g}`")
    out.append("")
    out.append("## Prior-audit deltas (R47 / R53 risk)")
    out.append("")
    deltas = report.get("prior_audit_deltas") or []
    if not deltas:
        out.append("_(no clusters acknowledged in PRIOR_CONCERNS.md)_")
    else:
        for d in deltas[:20]:
            out.append(f"- `{d}` - flagged in PRIOR_CONCERNS.md; supersede check required.")
    out.append("")
    out.append("## Operator action queue")
    out.append("")
    queue = report.get("operator_action_queue") or []
    if not queue:
        out.append("_(no HIGH-PRIORITY-HUNT entries; nothing actionable at top)_")
    else:
        for item in queue:
            out.append(
                f"- **Rank {item['rank']}** (score {item['engage_severity_score']}) - "
                f"`{item['file_line']}` ({item['cluster_id']}) - {item['next_step']}"
            )
    out.append("")
    out.append("## Provenance")
    out.append("")
    prov = report.get("provenance", {}) or {}
    out.append(f"- Tool: `{prov.get('tool_path', '?')}`")
    out.append(f"- Tool version: `{prov.get('tool_version', '?')}`")
    out.append(f"- Workspace state hash: `{prov.get('workspace_state_hash', '?')}`")
    out.append(f"- MVP phase: **{prov.get('mvp_phase', '?')}**")
    deferred_mvp2 = ", ".join(prov.get("deferred_to_mvp2") or []) or "(none)"
    deferred_mvp3 = ", ".join(prov.get("deferred_to_mvp3") or []) or "(none)"
    out.append(f"- Deferred to MVP2: {deferred_mvp2}")
    out.append(f"- Deferred to MVP3: {deferred_mvp3}")
    out.append("")
    errs = report.get("errors") or []
    if errs:
        out.append("## Errors")
        out.append("")
        for e in errs:
            out.append(f"- {e}")
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Staleness check + CLI.
# ---------------------------------------------------------------------------

def _is_stale(output_path: Path, threshold_seconds: int = DEFAULT_STALENESS_SECONDS) -> bool:
    if not output_path.is_file():
        return True
    age = _dt.datetime.now().timestamp() - output_path.stat().st_mtime
    return age > threshold_seconds


def _report_tool_version(report: dict[str, Any]) -> str:
    provenance = report.get("provenance") if isinstance(report, dict) else {}
    if not isinstance(provenance, dict):
        provenance = {}
    for candidate in (provenance.get("tool_version"), report.get("tool_version")):
        value = str(candidate or "").strip()
        if value:
            return value
    return ""


def live_target_report_freshness(
    report: Any,
    *,
    expected_tool_version: str = TOOL_VERSION,
    expected_schema: str = SCHEMA,
) -> dict[str, Any]:
    """Validate whether an existing LIVE_TARGET_REPORT JSON is current.

    CAP-007/CAP-015 precision fixes changed the semantics of suppressed false
    positives and semantic invariant matches. A cached report from an older
    tool version must therefore be treated as stale even if its file mtime is
    fresh.
    """
    base = {
        "freshness_basis": "schema_and_provenance_tool_version",
        "expected_schema": expected_schema,
        "expected_tool_version": expected_tool_version,
        "report_schema": "",
        "report_tool_version": "",
        "safe_to_treat_as_current": False,
    }
    if not isinstance(report, dict):
        return {**base, "status": "invalid_report_payload"}

    schema = str(report.get("schema") or "").strip()
    tool_version = _report_tool_version(report)
    base.update({"report_schema": schema, "report_tool_version": tool_version})
    if schema != expected_schema:
        return {**base, "status": "stale_schema"}
    if not tool_version:
        return {**base, "status": "missing_tool_version"}
    if tool_version != expected_tool_version:
        return {**base, "status": "stale_tool_version"}
    return {**base, "status": "current", "safe_to_treat_as_current": True}


def live_target_report_json_freshness(
    json_path: Path,
    *,
    staleness_threshold_seconds: int | None = None,
) -> dict[str, Any]:
    base = {
        "path": str(json_path),
        "expected_tool_version": TOOL_VERSION,
        "expected_schema": SCHEMA,
        "report_tool_version": "",
        "report_schema": "",
        "safe_to_treat_as_current": False,
    }
    if not json_path.is_file():
        return {
            **base,
            "status": "missing_json",
            "freshness_basis": "missing_live_target_report_json",
        }
    try:
        payload = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            **base,
            "status": "invalid_json",
            "freshness_basis": "parse_live_target_report_json",
        }

    freshness = live_target_report_freshness(payload)
    freshness = {**freshness, "path": str(json_path)}
    if not freshness.get("safe_to_treat_as_current"):
        return freshness

    if staleness_threshold_seconds is not None:
        age = _dt.datetime.now().timestamp() - json_path.stat().st_mtime
        if age > staleness_threshold_seconds:
            return {
                **freshness,
                "status": "stale_mtime",
                "age_seconds": round(age, 3),
                "staleness_threshold_seconds": staleness_threshold_seconds,
                "safe_to_treat_as_current": False,
                "freshness_basis": "mtime_and_schema_and_provenance_tool_version",
            }
    return freshness


def _freshness_json_path(output_md: Path | None, output_json_arg: str | None) -> Path | None:
    if output_json_arg:
        return Path(output_json_arg).resolve()
    if output_md and output_md.name == "LIVE_TARGET_REPORT.md":
        return output_md.with_suffix(".json")
    return None


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="P5 MVP1 - live-target intelligence report"
    )
    p.add_argument("--workspace", required=True, help="workspace root (e.g. /Users/wolf/audits/dydx)")
    p.add_argument("--output", default=None, help="markdown output path")
    p.add_argument("--output-json", default=None, help="optional JSON output path")
    p.add_argument("--top-n", type=int, default=50)
    p.add_argument("--triager-precheck-budget", type=int, default=10,
                   help="run rules-only P4 local precheck for top N entries")
    p.add_argument("--if-stale-only", action="store_true",
                   help="skip generation if output mtime <1h (or env-tunable)")
    p.add_argument("--staleness-threshold-seconds", type=int,
                   default=DEFAULT_STALENESS_SECONDS,
                   help="staleness threshold in seconds (default 3600)")
    p.add_argument("--strict", action="store_true",
                   help="fail closed on missing engage_report / workspace")
    p.add_argument("--json", action="store_true", help="emit JSON to stdout")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    workspace = Path(args.workspace).resolve()
    output_md = Path(args.output).resolve() if args.output else None

    if args.if_stale_only and output_md and not _is_stale(
        output_md, args.staleness_threshold_seconds
    ):
        freshness_json = _freshness_json_path(output_md, args.output_json)
        if freshness_json is not None:
            freshness = live_target_report_json_freshness(
                freshness_json,
                staleness_threshold_seconds=args.staleness_threshold_seconds,
            )
            if not freshness.get("safe_to_treat_as_current"):
                sys.stdout.write(
                    "[live-target-intel] refresh (not-current): "
                    f"{freshness_json} status={freshness.get('status')} "
                    f"expected={freshness.get('expected_tool_version')} "
                    f"found={freshness.get('report_tool_version') or 'none'}\n"
                )
            else:
                sys.stdout.write(
                    f"[live-target-intel] skip (fresh): {output_md}\n"
                )
                return 0
        else:
            # No JSON freshness surface was requested; preserve the legacy
            # markdown mtime-only skip behavior for non-standard output paths.
            sys.stdout.write(
                f"[live-target-intel] skip (fresh): {output_md}\n"
            )
            return 0

    try:
        report = build_report(
            workspace,
            top_n=args.top_n,
            triager_precheck_budget=args.triager_precheck_budget,
            strict=args.strict,
        )
    except FileNotFoundError as e:
        sys.stderr.write(f"[live-target-intel] FAIL strict: {e}\n")
        return 2

    if args.json:
        sys.stdout.write(json.dumps(report, indent=2) + "\n")
    md = render_markdown(report)
    if output_md is not None:
        output_md.parent.mkdir(parents=True, exist_ok=True)
        output_md.write_text(md, encoding="utf-8")
        sys.stdout.write(f"[live-target-intel] wrote {output_md}\n")
    elif not args.json:
        sys.stdout.write(md + "\n")
    if args.output_json:
        json_path = Path(args.output_json).resolve()
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        sys.stdout.write(f"[live-target-intel] wrote {json_path}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
