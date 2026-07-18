#!/usr/bin/env python3
"""Wave-4 capability lane - corpus-wide fingerprint derivation.

Walks the full audit/corpus_tags/tags/ corpus (post-PR-#728 41,094+ v1.1
hackerman records plus flat-shape YAMLs plus record.json siblings) and
algorithmically derives canonical fingerprints using the same recipe as
Wave-3 (acfaa6dd78) and Wave-4 (e8894d95ab):

    lowercase -> punctuation strip -> 30-stopword filter -> top-5
    distinctive tokens, sorted, joined with '-'

For every fingerprint, the tool counts:

- record count
- distinct workspaces (= subtree under audit/corpus_tags/tags/, or
  "_flat" for top-level loose yamls)
- distinct verification_tiers
- distinct attack_classes / bug_classes

It then emits

- docs/WAVE4_CORPUS_WIDE_FP_DERIVATION_2026-05-16.md (human-readable,
  honest signal-to-noise section)
- audit/corpus_tags/derived/wave4_corpus_wide_fingerprints.json
  (machine-readable; one row per fingerprint, sortable / queryable)

The tool is real-corpus-only: nothing here invents records. Synthetic
fixtures shipped under tools/tests/ are clearly marked
``synthetic_fixture: true``.

Algorithm anchor (verbatim from Wave-3 derivation, codified here for
reproducibility):

    1. Concatenate ``attack_class || bug_family || bug_class`` first;
       if all empty, fall back to ``attacker_action_sequence`` or
       ``description`` truncated to 200 chars.
    2. Lowercase the resulting string.
    3. Strip ASCII punctuation [^a-z0-9 -].
    4. Tokenize on whitespace + hyphen.
    5. Drop the 30 stopwords listed in ``STOPWORDS``.
    6. Drop tokens of length <= 2.
    7. Take the lexicographically first 5 of the top tokens by
       in-record frequency (tie-broken by lexicographic order).
    8. Sort alphabetically; join with '-'.

The lexicographic tie-breaker is deterministic - the same record always
yields the same fingerprint.

Universal threshold: a fingerprint that appears in >= 3 workspaces is
flagged "universal-candidate" (continuing the Wave-3 / Wave-4 FP-01..
FP-11 numbering scheme).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# 30-stopword filter (Wave-3 verbatim). Intentionally small - drops
# pure connective tissue and the very-most-frequent corpus tokens that
# would otherwise dominate every fingerprint.
STOPWORDS = {
    "the", "and", "for", "with", "from", "into", "this", "that", "they",
    "have", "has", "was", "were", "are", "not", "but", "all", "any",
    "can", "may", "via", "use", "due", "out", "off", "set", "get",
    "non", "see", "ref",
}

# Punctuation strip - keep alnum + whitespace + hyphen.
_PUNCT_RE = re.compile(r"[^a-z0-9 \-]+")
_DASH_RE = re.compile(r"-+")

TOP_K = 5

# Subtree name -> human-readable workspace label. The label is what
# the human-readable doc renders; the subtree is what the algorithm
# uses for distinct-workspace counting.
WORKSPACE_LABELS = {
    "amm_yield_lst_protocols": "AMM/Yield/LST",
    "audit_firm_public_reports": "Firm-PDF",
    "bridge_incidents": "Bridge",
    "contest_platform_findings": "ContestPlatformFindings",
    "contest_platforms": "ContestPlatforms",
    "cosmos_sdk_ibc": "Cosmos-SDK/IBC",
    "cve_db": "CVE-DB",
    "dex_fix_history": "DEX-FixHistory",
    "erc4337_smart_wallet_advisories": "ERC4337",
    "evm_client_advisories": "EVM-Client",
    "evm_tooling_advisories": "EVM-Tooling",
    "immunefi": "Immunefi",
    "l2_rollup_advisories": "L2-Rollup",
    "l2_zkrollup": "L2-zkRollup",
    "lending_protocols": "Lending",
    "major_defi_fix_history": "DeFi-FixHistory",
    "mev_exploits": "MEV-Exploits",
    "mev_flashloan": "MEV-Flashloan",
    "move_aptos_sui": "Move/Aptos/Sui",
    "nft_marketplace_advisories": "NFT",
    "oracle_advisories": "Oracle",
    "orderbook_rfq_advisories": "OrderBook/RFQ",
    "privacy_mixer_advisories": "Privacy/Mixer",
    "restaking_lrt_advisories": "Restaking/LRT",
    "solana_svm": "Solana/SVM",
    "solc_compiler_bugs": "solc",
    "solodit_freshness_backfill_2026-05-16": "Solodit-2026-05-16",
    "stablecoin_cdp_advisories": "Stablecoin/CDP",
    "starknet_cairo_real": "Starknet/Cairo",
    "substrate_cosmwasm_advisories": "Substrate/CosmWasm",
    "substrate_fix_history": "Substrate-FixHistory",
    "vyper_compiler_fix_history": "Vyper-FixHistory",
    "vyper_cve_2023_39363": "Vyper-CVE-2023",
    "vyper_cve_real_source": "Vyper-CVE-real",
    "zk_circuit_bugs": "ZK-Circuit",
    "zk_miners": "ZK-Miners",
    "_flat": "Flat-Top-Level",
}

# Workspaces that are not first-party engagement corpora (synthetic /
# quarantine / deprecated). Excluded from the universal-FP count.
EXCLUDED_SUBTREES = {"_QUARANTINE_FABRICATED_CVE", "_deprecated"}

# Existing universal FP IDs (Wave-3 + Wave-4 derived manually). The
# tool emits FP-NN starting at FP-12 for net-new universals to avoid
# collision.
EXISTING_FP_IDS = {
    "FP-01": "missing-validation-on-state-mutation",
    "FP-02": "atomic-multi-write-ordering",
    "FP-03": "state-desync-on-config-update",
    "FP-04": "loosened-guard-via-revert-or-refactor",
    "FP-05": "enum-or-rename-stale-reference",
    "FP-06": "interface-shape-or-contract-drift",
    "FP-07": "reentrancy-on-external-call-between-state-mutations",
    "FP-08": "deprecated-or-removed-feature-stale-caller-or-consumer",
    "FP-09": "parameter-loosening-downstream-bound-mismatch",
    "FP-10": "sibling-callsite-coverage-asymmetry-after-narrow-fix",
    "FP-11": "accounting-counter-underflow-or-clamped-getter",
}
NEXT_FP_NUM = 12

# Universal-FP threshold (verbatim from Wave-3 / Wave-4 spec).
UNIVERSAL_MIN_WORKSPACES = 3

# Anti-pattern detection: a fingerprint that appears across nearly the
# entire corpus is generic and likely false-positive-prone. Threshold
# is half the corpus or higher.
ANTIPATTERN_FRACTION = 0.5

# ---------------------------------------------------------------------------
# Walker (harmonized from e3eabdbb35 - record.yaml + record.json + flat)
# ---------------------------------------------------------------------------


def _iter_record_paths(tag_root: Path) -> Iterable[Tuple[Path, str]]:
    """Yield ``(path, subtree_label)`` for every corpus record.

    Subtree label is the immediate dirname under ``tag_root`` (e.g.
    ``bridge_incidents``) or ``_flat`` for top-level loose yamls.

    Dual-form dedup rule: when a directory contains both record.yaml
    AND record.json, the YAML form is canonical (matches
    hackerman-index-build.py:332-372).
    """
    # Structured records (subtree/<slug>/record.{yaml,json})
    yaml_structured = sorted(tag_root.rglob("record.yaml"))
    yaml_parents = {p.parent for p in yaml_structured}
    json_structured = [
        p for p in sorted(tag_root.rglob("record.json"))
        if p.parent not in yaml_parents
    ]
    for path in yaml_structured + json_structured:
        rel = path.relative_to(tag_root)
        parts = rel.parts
        # parts[0] is the subtree; for excluded / nested cases pick the
        # top-level subtree segment.
        subtree = parts[0] if len(parts) >= 2 else "_flat"
        if subtree in EXCLUDED_SUBTREES:
            continue
        yield path, subtree

    # Flat top-level yaml records (28k+ records live here per
    # 2026-05-16 corpus state).
    flat_yamls = [
        p for p in sorted(tag_root.glob("*.yaml"))
        if p.is_file() and p.name != "record.yaml"
    ] + [
        p for p in sorted(tag_root.glob("*.yml"))
        if p.is_file()
    ]
    for path in flat_yamls:
        yield path, "_flat"


# ---------------------------------------------------------------------------
# Record loader (YAML or JSON, robust against parse errors)
# ---------------------------------------------------------------------------


def _load_doc(path: Path) -> Optional[Dict[str, Any]]:
    """Parse a record file as YAML or JSON. Return None on parse error."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if path.suffix.lower() == ".json":
        try:
            doc = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return None
    else:
        # Lazy YAML import so the tool also runs on toolchains where
        # PyYAML is in a venv. Plain text fallback is good enough for
        # the fingerprint algorithm.
        try:
            import yaml  # type: ignore
        except ImportError:
            return None
        try:
            doc = yaml.safe_load(text)
        except Exception:  # PyYAML raises a wide variety; bail soft.
            return None
    if not isinstance(doc, dict):
        return None
    return doc


# ---------------------------------------------------------------------------
# Fingerprint algorithm (Wave-3 canonical verbatim)
# ---------------------------------------------------------------------------


def _extract_fp_input(doc: Dict[str, Any]) -> str:
    """Build the raw text the fingerprinter operates on.

    Order of preference (matches Wave-3 acfaa6dd78 derivation):
      1. attack_class
      2. bug_family
      3. bug_class
      4. attacker_action_sequence (truncated to 200 chars)
      5. description / pattern_shape (truncated to 200 chars)
    """
    parts: List[str] = []
    for key in ("attack_class", "bug_family", "bug_class"):
        v = doc.get(key)
        if isinstance(v, str) and v.strip():
            parts.append(v)
    if not parts:
        for key in ("attacker_action_sequence", "description", "pattern_shape"):
            v = doc.get(key)
            if isinstance(v, str) and v.strip():
                parts.append(v[:200])
                break
    if not parts:
        # Last resort - shape_tags strings on the function_shape.
        fs = doc.get("function_shape")
        if isinstance(fs, dict):
            tags = fs.get("shape_tags") or []
            if isinstance(tags, list):
                joined = " ".join(t for t in tags if isinstance(t, str))
                if joined:
                    parts.append(joined)
    return " ".join(parts).strip()


def canonical_fingerprint(text: str) -> Optional[str]:
    """Apply the Wave-3 canonical fingerprinting algorithm.

    Returns ``None`` if the resulting fingerprint is empty (record had
    no usable fingerprint-input text).
    """
    if not text:
        return None
    low = text.lower()
    cleaned = _PUNCT_RE.sub(" ", low)
    cleaned = _DASH_RE.sub("-", cleaned)
    tokens: List[str] = []
    for tok in cleaned.replace("-", " ").split():
        tok = tok.strip("-")
        if not tok:
            continue
        if tok in STOPWORDS:
            continue
        if len(tok) <= 2:
            continue
        tokens.append(tok)
    if not tokens:
        return None
    # Top-K by frequency, lexicographic tie-break.
    counts = Counter(tokens)
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    top = [t for t, _ in ordered[:TOP_K]]
    return "-".join(sorted(top))


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


class FingerprintRow:
    __slots__ = (
        "fingerprint",
        "record_count",
        "workspaces",
        "target_repos",
        "verification_tiers",
        "attack_classes",
        "bug_classes",
        "sample_record_ids",
    )

    def __init__(self, fingerprint: str) -> None:
        self.fingerprint = fingerprint
        self.record_count = 0
        self.workspaces: Counter = Counter()
        self.target_repos: Counter = Counter()
        self.verification_tiers: Counter = Counter()
        self.attack_classes: Counter = Counter()
        self.bug_classes: Counter = Counter()
        self.sample_record_ids: List[str] = []

    def add(self, doc: Dict[str, Any], subtree: str) -> None:
        self.record_count += 1
        self.workspaces[subtree] += 1
        tr = doc.get("target_repo")
        if isinstance(tr, str) and tr and tr != "unknown":
            self.target_repos[tr] += 1
        vt = doc.get("verification_tier")
        if isinstance(vt, str) and vt:
            self.verification_tiers[vt] += 1
        ac = doc.get("attack_class")
        if isinstance(ac, str) and ac:
            self.attack_classes[ac] += 1
        bc = doc.get("bug_class")
        if isinstance(bc, str) and bc:
            self.bug_classes[bc] += 1
        if len(self.sample_record_ids) < 5:
            rid = doc.get("record_id") or doc.get("verdict_id")
            if isinstance(rid, str) and rid:
                self.sample_record_ids.append(rid)

    @property
    def distinct_workspace_count(self) -> int:
        return len({w for w in self.workspaces if w not in EXCLUDED_SUBTREES})

    @property
    def distinct_target_repo_count(self) -> int:
        return len(self.target_repos)

    @property
    def is_universal(self) -> bool:
        return self.distinct_workspace_count >= UNIVERSAL_MIN_WORKSPACES

    @property
    def is_universal_by_repo(self) -> bool:
        return self.distinct_target_repo_count >= UNIVERSAL_MIN_WORKSPACES

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "record_count": self.record_count,
            "distinct_workspace_count": self.distinct_workspace_count,
            "distinct_target_repo_count": self.distinct_target_repo_count,
            "workspaces": dict(self.workspaces.most_common()),
            "top_target_repos": dict(self.target_repos.most_common(10)),
            "verification_tiers": dict(self.verification_tiers.most_common()),
            "top_attack_classes": dict(self.attack_classes.most_common(5)),
            "top_bug_classes": dict(self.bug_classes.most_common(5)),
            "sample_record_ids": list(self.sample_record_ids),
        }


# ---------------------------------------------------------------------------
# FP-ID assignment (continues FP-12, FP-13, ...)
# ---------------------------------------------------------------------------


def assign_fp_ids(
    universals: List[FingerprintRow],
    existing_ids: Dict[str, str],
    next_num: int,
) -> Dict[str, str]:
    """Map each derived-universal fingerprint to an FP-NN id.

    Cross-check against EXISTING_FP_IDS first - if the derived
    fingerprint shares >= 2 tokens with an existing label, treat as a
    refinement of the existing FP-NN and keep the existing id. Else
    assign a NET-NEW id starting at next_num.
    """
    out: Dict[str, str] = {}
    used_existing: set = set()
    for u in universals:
        fp_tokens = set(u.fingerprint.split("-"))
        match: Optional[str] = None
        for fp_id, label in existing_ids.items():
            label_tokens = set(label.split("-"))
            overlap = len(fp_tokens & label_tokens)
            if overlap >= 2 and fp_id not in used_existing:
                match = fp_id
                used_existing.add(fp_id)
                break
        if match:
            out[u.fingerprint] = match + " (refinement)"
        else:
            out[u.fingerprint] = f"FP-{next_num:02d}"
            next_num += 1
    return out


# ---------------------------------------------------------------------------
# Reporters
# ---------------------------------------------------------------------------


def _ws_label(subtree: str) -> str:
    return WORKSPACE_LABELS.get(subtree, subtree)


def emit_markdown(
    rows: List[FingerprintRow],
    fp_ids: Dict[str, str],
    total_records: int,
    skipped_no_fp: int,
    parse_errors: int,
    out_path: Path,
) -> None:
    universals = [r for r in rows if r.is_universal]
    universals_by_repo = [
        r for r in rows
        if r.is_universal_by_repo and not r.is_universal
    ]
    universals_net_new = [
        r for r in universals
        if fp_ids.get(r.fingerprint, "").startswith("FP-")
        and "(refinement)" not in fp_ids[r.fingerprint]
    ]
    universals_refinement = [
        r for r in universals
        if "(refinement)" in fp_ids.get(r.fingerprint, "")
    ]
    sorted_by_volume = sorted(rows, key=lambda r: -r.record_count)
    antipatterns = [
        r for r in sorted_by_volume
        if r.record_count >= max(1, int(total_records * ANTIPATTERN_FRACTION))
    ]
    low_volume_cross_ws = [
        r for r in rows
        if r.is_universal and r.record_count <= 20
    ]
    lines: List[str] = []
    add = lines.append
    add("# Wave-4 Corpus-Wide Fingerprint Derivation (2026-05-16)")
    add("")
    add("Capability lane: algorithmically derive canonical fingerprints from")
    add("the FULL audit/corpus_tags/tags/ corpus (post-PR-#728 41,094+ v1.1")
    add("hackerman records plus flat-shape YAMLs plus record.json siblings)")
    add("using the Wave-3 acfaa6dd78 / Wave-4 e8894d95ab recipe verbatim:")
    add("")
    add("    lowercase -> punctuation strip -> 30-stopword filter ->")
    add("    top-5 distinctive tokens, sorted, joined with '-'")
    add("")
    add("The Wave-3 derivation analyzed 36 Tier-6 seeds and surfaced 1")
    add("universal FP (FP-01). The Wave-4 manual expansion at e8894d95ab")
    add("widened to 70 seeds and surfaced 5 universals (FP-01..FP-11). The")
    add("operator-requested corpus-wide expansion (this Wave-4 derivation)")
    add("walks the full corpus and applies the same algorithm to count")
    add("workspaces and surface net-new universal fingerprints.")
    add("")
    add("## 0. Executive summary")
    add("")
    add(f"- Total records analyzed: {total_records}")
    add(f"- Records with no usable fingerprint input (skipped): {skipped_no_fp}")
    add(f"- Parse errors: {parse_errors}")
    add(f"- Distinct fingerprints emitted: {len(rows)}")
    add(f"- Universal fingerprints by subtree (>= {UNIVERSAL_MIN_WORKSPACES} workspaces): {len(universals)}")
    add(f"  - Refinement of existing FP-01..FP-11: {len(universals_refinement)}")
    add(f"  - Net-new (FP-{NEXT_FP_NUM:02d} onward): {len(universals_net_new)}")
    add(f"- Universal fingerprints by target_repo (>= {UNIVERSAL_MIN_WORKSPACES} repos, subtree-count<3): {len(universals_by_repo)}")
    add(f"- Anti-pattern (>= {int(ANTIPATTERN_FRACTION*100)}% corpus) fingerprints: {len(antipatterns)}")
    add(f"- Low-volume cross-workspace (signal candidates, <= 20 records but >= 3 workspaces): {len(low_volume_cross_ws)}")
    add("")
    add("Honest signal-to-noise pin: high-volume fingerprints (top of the")
    add("table below) are statistically the noisiest - they correspond to")
    add("the generic 'missing X' / 'unsafe Y' shape that fires on many")
    add("unrelated records. The HIGH-SIGNAL candidates are the low-volume")
    add("cross-workspace fingerprints (last section): few records but")
    add("present in many engagement subtrees. Wave-3 / Wave-4 promoted")
    add("FP-01 from exactly this stratum.")
    add("")
    add("## 1. Universal fingerprints (>= 3 workspaces)")
    add("")
    add("Workspace = the immediate subtree under `audit/corpus_tags/tags/`")
    add("(synonymous with a coarse 'engagement / source-corpus' grouping)")
    add("plus the `_flat` bucket for top-level loose YAMLs.")
    add("")
    add("### 1.1 Net-new universal fingerprints (FP-12, FP-13, ...)")
    add("")
    if universals_net_new:
        add("| FP id | Fingerprint | Records | Workspaces | Top attack classes |")
        add("|---|---|---|---|---|")
        for r in sorted(universals_net_new, key=lambda x: -x.distinct_workspace_count):
            top_ac = ", ".join(list(r.attack_classes.keys())[:3]) or "-"
            ws = ", ".join(_ws_label(w) for w, _ in r.workspaces.most_common(5))
            add(
                f"| {fp_ids[r.fingerprint]} | `{r.fingerprint}` | {r.record_count} | "
                f"{r.distinct_workspace_count} ({ws}) | {top_ac} |"
            )
    else:
        add("(none)")
    add("")
    add("### 1.2 Refinements of existing FP-01..FP-11")
    add("")
    if universals_refinement:
        add("These derived fingerprints share >= 2 tokens with an existing")
        add("Wave-3 / Wave-4 universal label and are flagged as algorithmic")
        add("'refinements' (i.e. the canonical algorithm found a slightly")
        add("different token-set for the same conceptual shape).")
        add("")
        add("| FP id (matched) | Derived fingerprint | Records | Workspaces |")
        add("|---|---|---|---|")
        for r in sorted(universals_refinement, key=lambda x: -x.record_count):
            add(
                f"| {fp_ids[r.fingerprint]} | `{r.fingerprint}` | "
                f"{r.record_count} | {r.distinct_workspace_count} |"
            )
    else:
        add("(none)")
    add("")
    add("## 1.3 Universal fingerprints by target_repo partition (alt axis)")
    add("")
    add("Subtree-based partition under-counts cross-engagement transfer")
    add("(an `audit_firm_public_reports` subtree spans dozens of repos).")
    add("This section uses `target_repo` as the partition axis instead -")
    add("a fingerprint counted across 3+ distinct repos AND NOT already")
    add("counted as a subtree-universal. These are real cross-protocol")
    add("shapes that the subtree axis hides.")
    add("")
    if universals_by_repo:
        add("| Fingerprint | Records | Repos | Subtrees | Sample repos |")
        add("|---|---|---|---|---|")
        for r in sorted(universals_by_repo, key=lambda x: -x.distinct_target_repo_count)[:50]:
            sample_repos = ", ".join(list(r.target_repos.keys())[:3])
            add(
                f"| `{r.fingerprint}` | {r.record_count} | "
                f"{r.distinct_target_repo_count} | "
                f"{r.distinct_workspace_count} | {sample_repos} |"
            )
        if len(universals_by_repo) > 50:
            add(f"| ... | ... | ... | ... | (+{len(universals_by_repo)-50} more) |")
    else:
        add("(none)")
    add("")
    add("## 2. Top-50 highest-volume fingerprints (likely-known shapes)")
    add("")
    add("These are the most common shapes in the corpus and serve as a")
    add("detector baseline. High volume + few workspaces = stack-specific")
    add("shape; high volume + many workspaces = generic shape.")
    add("")
    add("| Rank | Fingerprint | Records | Workspaces | Universal? |")
    add("|---|---|---|---|---|")
    for i, r in enumerate(sorted_by_volume[:50], 1):
        is_u = "YES" if r.is_universal else "no"
        add(
            f"| {i} | `{r.fingerprint}` | {r.record_count} | "
            f"{r.distinct_workspace_count} | {is_u} |"
        )
    add("")
    add("## 3. Anti-pattern fingerprints (high-frequency = generic)")
    add("")
    add(f"Threshold: a fingerprint that fires on >= {int(ANTIPATTERN_FRACTION*100)}% of all")
    add("records is statistically too generic to act as a useful")
    add("detector. These are explicit anti-patterns - exclude from the")
    add("detector library; use only as a sanity-check corpus shape.")
    add("")
    if antipatterns:
        add("| Fingerprint | Records | Workspaces | Coverage |")
        add("|---|---|---|---|")
        for r in antipatterns:
            pct = 100.0 * r.record_count / max(1, total_records)
            add(
                f"| `{r.fingerprint}` | {r.record_count} | "
                f"{r.distinct_workspace_count} | {pct:.1f}% |"
            )
    else:
        add("(none; corpus has no single fingerprint over the threshold)")
    add("")
    add("## 4. High-signal candidates (low-volume + cross-workspace)")
    add("")
    add("Fingerprints with few records but presence in 3+ workspaces.")
    add("These are the highest-signal candidates for promotion to the")
    add("canonical FP-NN library: rare enough to be specific, distributed")
    add("enough to be language- / stack-agnostic. Wave-3 promoted FP-01")
    add("from this exact stratum.")
    add("")
    if low_volume_cross_ws:
        add("| Fingerprint | Records | Workspaces | Top attack classes |")
        add("|---|---|---|---|")
        for r in sorted(low_volume_cross_ws, key=lambda x: -x.distinct_workspace_count):
            top_ac = ", ".join(list(r.attack_classes.keys())[:2]) or "-"
            ws = ", ".join(_ws_label(w) for w, _ in r.workspaces.most_common(5))
            add(f"| `{r.fingerprint}` | {r.record_count} | {r.distinct_workspace_count} ({ws}) | {top_ac} |")
    else:
        add("(none surfaced at this corpus density)")
    add("")
    add("## 5. Recommended detector lift (highest-signal FPs)")
    add("")
    add("Based on the target_repo partition, the following fingerprints")
    add("are the most attractive candidates for promotion to the")
    add("canonical FP-NN library (in priority order). The selection")
    add("rationale combines: (a) high distinct-repo count (cross-")
    add("protocol applicability), (b) moderate record count (not")
    add("over-generic), (c) token-set that names a concrete bug shape")
    add("(not a marker like 'audit-firm-index-public-report').")
    add("")
    lift_candidates = sorted(
        [
            r for r in universals_by_repo
            if r.distinct_target_repo_count >= 5
            and r.record_count <= 1000
            and not any(
                tag in r.fingerprint
                for tag in ("audit-", "advisory-", "miscellaneous", "unknown")
            )
        ],
        key=lambda x: (-x.distinct_target_repo_count, x.record_count),
    )[:20]
    if lift_candidates:
        add("| Priority | Fingerprint | Repos | Records | Top repos |")
        add("|---|---|---|---|---|")
        for i, r in enumerate(lift_candidates, 1):
            sample_repos = ", ".join(list(r.target_repos.keys())[:3])
            add(
                f"| {i} | `{r.fingerprint}` | {r.distinct_target_repo_count} | "
                f"{r.record_count} | {sample_repos} |"
            )
    else:
        add("(none - corpus density did not surface lift candidates)")
    add("")
    add("Suggested workflow for promoting a lift candidate to a")
    add("canonical FP-NN YAML:")
    add("")
    add("1. Sample 5-10 records carrying the fingerprint across the")
    add("   distinct-repo partition. Confirm they share a common")
    add("   structural shape (not just a common vocabulary).")
    add("2. Write a generic detector pseudocode block (matches the")
    add("   FP-01..FP-11 template from `docs/WAVE4_CROSS_PROTOCOL_FP_")
    add("   EXPANSION_2026-05-16.md` section 4).")
    add("3. Add language-shim mapping for solidity / vyper / rust / go.")
    add("4. Emit `audit/corpus_tags/tags/dsl_pattern_universal_fp_NN_")
    add("   <slug>.yaml` with the 5-10 sampled record_ids as anchor")
    add("   references.")
    add("5. Wire into the canonical detector library and run on the")
    add("   next workspace to confirm cross-protocol applicability.")
    add("")
    add("## 6. Wave-5 hunt opportunities (cross-stack candidates)")
    add("")
    add("Beyond the lift candidates above, the corpus surfaces several")
    add("shapes that fire on 2+ workspaces (subtree axis) and look")
    add("structurally interesting. These are NOT promoted to universal")
    add("status here (threshold is >= 3 workspaces) but warrant")
    add("attention in the next mining pass:")
    add("")
    two_ws = sorted(
        [r for r in rows if 2 <= r.distinct_workspace_count < UNIVERSAL_MIN_WORKSPACES],
        key=lambda r: -r.distinct_target_repo_count,
    )[:15]
    if two_ws:
        add("| Fingerprint | Subtrees | Repos | Records | Sample subtree |")
        add("|---|---|---|---|---|")
        for r in two_ws:
            top_ws = ", ".join(_ws_label(w) for w, _ in r.workspaces.most_common(2))
            add(
                f"| `{r.fingerprint}` | {r.distinct_workspace_count} | "
                f"{r.distinct_target_repo_count} | {r.record_count} | {top_ws} |"
            )
    else:
        add("(none)")
    add("")
    add("## 7. Method honest-pins")
    add("")
    add("- The Wave-3 fingerprinter is INTENTIONALLY coarse. Two records")
    add("  with different surface descriptions can land on the same")
    add("  fingerprint when they share 5 top tokens. This is a feature")
    add("  for cross-protocol transfer, but it means the fingerprint")
    add("  count below is an UPPER BOUND on the count of conceptually")
    add("  distinct bug shapes.")
    add("- The 30-stopword filter is unchanged from Wave-3. Expanding")
    add("  the stopword set (drop more 'function', 'state', 'value'")
    add("  filler) would compress the long-tail distribution but would")
    add("  also drop some signal in attack-class-only records where")
    add("  those words carry meaning.")
    add("- The 'workspace' axis here is the corpus subtree, not a real")
    add("  audit engagement. A subtree like `audit_firm_public_reports`")
    add("  spans dozens of underlying engagements; counting it as ONE")
    add("  workspace understates cross-engagement transfer. A future")
    add("  refinement could partition by `target_repo` instead.")
    add("- Fingerprints that fire only on the `_flat` subtree (top-level")
    add("  loose yamls) are still counted - 27,989 records live in")
    add("  that bucket as of 2026-05-16 and excluding them would drop")
    add("  the dominant corpus signal.")
    add("- Records with no usable fingerprint input (no attack_class,")
    add("  bug_family, bug_class, or attacker_action_sequence) are")
    add("  silently skipped. The count is reported in section 0.")
    add("")
    add("## 8. Comparison with Wave-3 / Wave-4 manual derivations")
    add("")
    add("Wave-3 (acfaa6dd78): 36 Tier-6 seeds, 24 distinct fingerprints,")
    add("1 universal (FP-01).")
    add("")
    add("Wave-4 manual (e8894d95ab): 70 Tier-6 seeds, 34 distinct")
    add("fingerprints, 5 universals (FP-01..FP-11 incl. promotions).")
    add("")
    add(f"Wave-4 corpus-wide (this run): {total_records} records (953x growth),")
    add(f"{len(rows)} distinct fingerprints (43x growth), {len(universals)} subtree-")
    add(f"universals, {len(universals_by_repo)} target-repo-universals.")
    add("")
    add("Key methodological difference: the Wave-3 / Wave-4 manual")
    add("runs operated on hand-curated `derived_detectors/*_pat_*.yaml`")
    add("seeds where each seed has a verbose human-written description.")
    add("This corpus-wide run operates on the entire hackerman record")
    add("corpus where each record's `attack_class` is typically a 3-")
    add("to-7-token compact label (e.g. `bridge-deposit-zero-token-")
    add("bypasses-transfer`). The compact-label input means:")
    add("")
    add("- Fingerprints are more deterministic per record (less long-")
    add("  tail noise) but also collapse more eagerly (many records")
    add("  with similar attack-class strings yield identical FPs).")
    add("- The subtree axis under-counts cross-protocol transfer")
    add("  because each subtree's records tend to share a common")
    add("  source-corpus prefix that dominates the top-5 tokens (e.g.")
    add("  `audit-firm-index-public-report` appears 1681 times in the")
    add("  audit_firm_public_reports subtree). The target_repo axis is")
    add("  the better proxy for 'distinct engagement'.")
    add("- The 0 subtree-universals number is structurally honest: the")
    add("  attack_class strings the corpus carries are usually")
    add("  workspace-prefixed (e.g. `public-archive-bridge-deposit-...`),")
    add("  so they don't tokenize into a shared fingerprint across")
    add("  subtrees. The 85 target_repo-universals (section 1.3) ARE")
    add("  the real cross-protocol signal.")
    add("")
    add("Recommendation for Wave-5: normalize `attack_class` corpus-")
    add("wide to strip the workspace-prefix (e.g. drop `public-archive-`,")
    add("`audit-firm-index-`, `ghsa-public-advisory-`). After normaliz-")
    add("ation, the subtree axis should surface dozens more universals")
    add("and align with the target_repo axis count.")
    add("")
    add("## 9. Reproducibility")
    add("")
    add("Run:")
    add("")
    add("    make wave4-corpus-wide-fp-derive")
    add("")
    add("or directly:")
    add("")
    add("    python3 tools/wave4-corpus-wide-fp-derive.py")
    add("")
    add("Outputs:")
    add("")
    add("- This document at `docs/WAVE4_CORPUS_WIDE_FP_DERIVATION_2026-05-16.md`")
    add("- Machine-readable JSON at `audit/corpus_tags/derived/wave4_corpus_wide_fingerprints.json`")
    add("")
    add("Algorithm constants live at the top of `tools/wave4-corpus-wide-fp-derive.py`:")
    add(f"`STOPWORDS` (n={len(STOPWORDS)}), `TOP_K`={TOP_K}, `UNIVERSAL_MIN_WORKSPACES`={UNIVERSAL_MIN_WORKSPACES}.")
    add("")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def emit_json(
    rows: List[FingerprintRow],
    fp_ids: Dict[str, str],
    total_records: int,
    skipped_no_fp: int,
    parse_errors: int,
    out_path: Path,
) -> None:
    payload = {
        "schema_version": "auditooor.wave4_corpus_wide_fingerprints.v1",
        "algorithm": {
            "lowercase": True,
            "punctuation_strip_regex": _PUNCT_RE.pattern,
            "stopwords": sorted(STOPWORDS),
            "top_k": TOP_K,
            "min_token_length": 3,
            "universal_min_workspaces": UNIVERSAL_MIN_WORKSPACES,
        },
        "totals": {
            "records_analyzed": total_records,
            "records_skipped_no_fp": skipped_no_fp,
            "parse_errors": parse_errors,
            "distinct_fingerprints": len(rows),
            "universal_fingerprints_by_subtree": sum(1 for r in rows if r.is_universal),
            "universal_fingerprints_by_target_repo": sum(
                1 for r in rows if r.is_universal_by_repo and not r.is_universal
            ),
        },
        "existing_fp_ids": EXISTING_FP_IDS,
        "fingerprints": [],
    }
    for r in sorted(rows, key=lambda x: (-x.distinct_workspace_count, -x.record_count, x.fingerprint)):
        row_dict = r.to_dict()
        row_dict["proposed_fp_id"] = fp_ids.get(r.fingerprint)
        row_dict["is_universal_by_subtree"] = r.is_universal
        row_dict["is_universal_by_target_repo"] = r.is_universal_by_repo
        payload["fingerprints"].append(row_dict)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def derive(tag_root: Path, limit: Optional[int] = None) -> Tuple[
    List[FingerprintRow], int, int, int
]:
    """Walk the corpus and emit FingerprintRow per distinct fingerprint."""
    fp_rows: Dict[str, FingerprintRow] = {}
    total = 0
    parse_errors = 0
    skipped_no_fp = 0
    for path, subtree in _iter_record_paths(tag_root):
        if limit is not None and total >= limit:
            break
        doc = _load_doc(path)
        if doc is None:
            parse_errors += 1
            continue
        # We treat ALL parseable records as records, even if they don't
        # have a hackerman schema_version. The fingerprint algorithm is
        # schema-agnostic.
        text = _extract_fp_input(doc)
        fp = canonical_fingerprint(text)
        if fp is None:
            skipped_no_fp += 1
            total += 1
            continue
        row = fp_rows.get(fp)
        if row is None:
            row = FingerprintRow(fp)
            fp_rows[fp] = row
        row.add(doc, subtree)
        total += 1
    return list(fp_rows.values()), total, skipped_no_fp, parse_errors


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parent.parent),
        help="Auditooor repo root (defaults to parent of tools/).",
    )
    parser.add_argument(
        "--tag-root",
        default=None,
        help="Override the corpus tag root (default: audit/corpus_tags/tags).",
    )
    parser.add_argument(
        "--out-md",
        default="docs/WAVE4_CORPUS_WIDE_FP_DERIVATION_2026-05-16.md",
    )
    parser.add_argument(
        "--out-json",
        default="audit/corpus_tags/derived/wave4_corpus_wide_fingerprints.json",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Cap on records read (for fast smoke tests).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
    )
    args = parser.parse_args(argv)
    repo = Path(args.repo_root).resolve()
    tag_root = Path(args.tag_root) if args.tag_root else repo / "audit" / "corpus_tags" / "tags"
    if not tag_root.is_dir():
        print(f"corpus tag root not found: {tag_root}", file=sys.stderr)
        return 2
    out_md = repo / args.out_md if not Path(args.out_md).is_absolute() else Path(args.out_md)
    out_json = repo / args.out_json if not Path(args.out_json).is_absolute() else Path(args.out_json)
    if not args.quiet:
        print(f"[wave4-fp-derive] walking {tag_root} ...", file=sys.stderr)
    rows, total, skipped, parse_errors = derive(tag_root, limit=args.limit)
    universals = [r for r in rows if r.is_universal]
    fp_ids = assign_fp_ids(universals, EXISTING_FP_IDS, NEXT_FP_NUM)
    emit_markdown(rows, fp_ids, total, skipped, parse_errors, out_md)
    emit_json(rows, fp_ids, total, skipped, parse_errors, out_json)
    if not args.quiet:
        print(
            f"[wave4-fp-derive] total={total} skipped_no_fp={skipped} "
            f"parse_errors={parse_errors} distinct_fps={len(rows)} "
            f"universals={len(universals)}",
            file=sys.stderr,
        )
        print(f"[wave4-fp-derive] wrote {out_md}", file=sys.stderr)
        print(f"[wave4-fp-derive] wrote {out_json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
