#!/usr/bin/env python3
"""Wave-2 PR-B cross-firm duplicate-finding detector.

When multiple audit firms (Trail of Bits / Sherlock / Pashov / Zellic /
Cyfrin / Spearbit / ChainSecurity / OpenZeppelin) audit the SAME protocol
and report the SAME bug class, the W2.4 firm-PDF parsers each emit a
distinct record under
``audit/corpus_tags/tags/firm-<firm>-audits/<protocol-slug>/<finding>.yaml``.
Without dedup, downstream corpus-stats / hacker-brief / pattern-mining
tooling counts these as N independent findings and inflates the corpus.

This tool surfaces candidate cross-firm dupe clusters via a two-stage
fuzzy-match:

1.  CHEAP FILTER - group records by
    ``(protocol_normalized, attack_class)``. Records that disagree on
    either axis cannot be the same finding.
2.  EXPENSIVE COMPARE - within each cheap-filter bucket, compute
    pairwise Jaccard similarity on the title-keyword sets (lowercase +
    strip punctuation + remove stopwords + top-5 distinctive tokens).
    Pairs with Jaccard >= ``--min-similarity`` (default 0.6) AND the
    same normalised severity are candidate cross-firm dupes.

Mirrors the W2.6 cosmos-sdk dedup pattern (PR #726 commit ``8fa397589f``):
detect first, mutate later via a separate operator-driven step. This
tool emits CANDIDATES ONLY - it does NOT rewrite, delete, or merge any
record on disk.

Output schema: ``auditooor.wave2_cross_firm_dedup_detector.v1``.

CLI::

    python3 tools/wave2-cross-firm-dedup-detector.py \\
        --workspace . \\
        --json \\
        --min-similarity 0.6 \\
        --min-cluster-size 2

Real-source-only / M14-trap discipline:

* Walks ``audit/corpus_tags/tags/firm-*-audits/`` recursively under the
  workspace; no external network.
* Reads YAML records (``record.yaml`` preferred; falls back to any
  ``*.yaml`` under the per-finding directory).
* Records flagged ``synthetic_fixture: true`` in ``record_extensions``
  are tagged in the cluster output (a synthetic-only cluster is
  honestly labelled), but they are NOT silently dropped - the
  operator inspects the cluster list and decides.
* Does NOT modify ``tools/calibration/llm_budget_log.jsonl``.
* Does NOT modify any record under the corpus tree.

Per ``CLAUDE.md`` formatting rules: ASCII hyphens only, no em-dashes /
en-dashes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import yaml  # type: ignore
except ImportError as exc:  # pragma: no cover - fail loud on missing dep
    print(
        f"[wave2-cross-firm-dedup-detector] PyYAML required: {exc}",
        file=sys.stderr,
    )
    sys.exit(2)


SCHEMA_ID = "auditooor.wave2_cross_firm_dedup_detector.v1"

# Real corpus layout (W3.9 path-mismatch fix).
#
# The W2.4 firm-PDF parsers do NOT emit ``tags/firm-<firm>-audits/...``.
# They emit one record per audit report under
# ``audit/corpus_tags/tags/audit_firm_public_reports/<firm>__<slug>-<hash>/record.yaml``
# where ``<firm>`` is a firm-publication slug such as
# ``trailofbits-publications`` / ``pashov-audits`` / ``spearbit-portfolio`` /
# ``zellic-publications`` / ``cyfrin-audit-reports`` / ``sherlock-reports`` /
# ``chainsecurity-audits`` / ``openzeppelin-contracts-audits``.
#
# The legacy glob ``firm-*-audits`` matched nothing on the real corpus, so
# this tool silently scanned 0 records. ``FIRM_REPORTS_SUBTREE`` /
# ``LEGACY_FIRM_SUBTREE_GLOB`` below are both honoured: the legacy
# per-firm-subtree layout still works for synthetic test fixtures, and the
# real ``audit_firm_public_reports`` layout is now discovered too.
FIRM_REPORTS_SUBTREE = "audit_firm_public_reports"
LEGACY_FIRM_SUBTREE_GLOB = "firm-*-audits"
# Backwards-compat alias (some callers / tests import the old name).
FIRM_SUBTREE_GLOB = LEGACY_FIRM_SUBTREE_GLOB

# Firm-publication-repo suffixes stripped to obtain the canonical firm slug.
_FIRM_SLUG_SUFFIXES = (
    "-publications",
    "-audit-reports",
    "-contracts-audits",
    "-audits",
    "-reports",
    "-portfolio",
)

# Token normalisation -------------------------------------------------------

_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "can",
        "for",
        "from",
        "if",
        "in",
        "into",
        "is",
        "it",
        "may",
        "no",
        "not",
        "of",
        "on",
        "or",
        "the",
        "to",
        "via",
        "when",
        "which",
        "with",
        "without",
        "this",
        "that",
        "these",
        "those",
        "but",
        "due",
        "such",
        "any",
        "all",
        "its",
        "their",
        "has",
        "have",
        "had",
        "do",
        "does",
        "did",
        "been",
        "being",
        "was",
        "were",
        "will",
        "would",
        "should",
        "could",
        "than",
        "then",
        "so",
        "also",
    }
)

_TOP_TOKENS = 5

_PUNCT_RE = re.compile(r"[^a-z0-9\s]+")
_WS_RE = re.compile(r"\s+")
_PROTOCOL_NORMALISE_RE = re.compile(r"[^a-z0-9]+")


def _normalise_protocol(value: Optional[str]) -> str:
    if not value:
        return ""
    s = str(value).strip().lower()
    s = _PROTOCOL_NORMALISE_RE.sub("-", s).strip("-")
    return s


def _normalise_severity(value: Optional[str]) -> str:
    if not value:
        return ""
    s = str(value).strip().lower()
    # Common verbatim variants -> canonical.
    if s.startswith("crit"):
        return "critical"
    if s.startswith("high"):
        return "high"
    if s.startswith("med"):
        return "medium"
    if s.startswith("low"):
        return "low"
    if s.startswith("info") or s == "informational":
        return "informational"
    if s.startswith("gas"):
        return "gas"
    return s


def _title_keywords(title: Optional[str]) -> Tuple[str, ...]:
    """Extract top-N distinctive title tokens.

    Lowercase, strip punctuation, drop stopwords, drop length<=2 tokens,
    keep first N unique tokens in order of appearance (preserves the
    finding-title's leading subject signal).
    """
    if not title:
        return ()
    s = str(title).lower()
    s = _PUNCT_RE.sub(" ", s)
    s = _WS_RE.sub(" ", s).strip()
    seen: List[str] = []
    seen_set: set = set()
    for tok in s.split(" "):
        if len(tok) <= 2:
            continue
        if tok in _STOPWORDS:
            continue
        if tok in seen_set:
            continue
        seen.append(tok)
        seen_set.add(tok)
        if len(seen) >= _TOP_TOKENS:
            break
    return tuple(seen)


def _attack_class(record: Dict[str, Any]) -> str:
    val = record.get("attack_class") or record.get("bug_class") or ""
    return str(val).strip().lower()


def _bug_family(record: Dict[str, Any]) -> str:
    val = (
        record.get("bug_family")
        or record.get("bug_class")
        or record.get("attack_class")
        or ""
    )
    return str(val).strip().lower()


def _protocol(record: Dict[str, Any]) -> str:
    for key in ("protocol", "target_component", "target_repo"):
        v = record.get(key)
        if v and str(v).strip().lower() not in {"", "unknown"}:
            return _normalise_protocol(v)
    return ""


def _severity(record: Dict[str, Any]) -> str:
    v = (
        record.get("severity")
        or record.get("severity_at_finding")
        or record.get("severity_verbatim")
        or ""
    )
    return _normalise_severity(v)


def _record_source_url(record: Dict[str, Any]) -> str:
    return str(record.get("record_source_url") or "")


def _verification_tier_rank(record: Dict[str, Any]) -> int:
    """Higher = more verified. Tier-2-verified > tier-1 > unknown."""
    tier = str(record.get("verification_tier") or "").lower()
    if "tier-3" in tier:
        return 3
    if "tier-2" in tier:
        return 2
    if "tier-1" in tier:
        return 1
    if "tier-0" in tier:
        return 0
    return -1


def _incident_date(record: Dict[str, Any]) -> str:
    """Best-effort incident-date extraction for tie-break.

    Returns an ISO-ish string or empty. Earlier wins on tie-break, so
    empty (sorted last when reversed) is OK.
    """
    for key in ("incident_date", "year", "audit_date", "report_date"):
        v = record.get(key)
        if v:
            return str(v)
    return ""


def _canonical_firm_slug(raw: str) -> str:
    """Collapse a firm-publication-repo slug to a canonical firm name.

    ``trailofbits-publications`` -> ``trailofbits``
    ``pashov-audits``           -> ``pashov``
    ``cyfrin-audit-reports``    -> ``cyfrin``
    ``openzeppelin-contracts-audits`` -> ``openzeppelin``
    Unknown shapes pass through unchanged.
    """
    s = raw.strip().lower()
    for suf in _FIRM_SLUG_SUFFIXES:
        if s.endswith(suf):
            return s[: -len(suf)]
    return s


def _firm_from_path(yaml_path: Path) -> str:
    """Extract the canonical firm slug from either corpus layout.

    Layout A (real corpus, W3.9 fix):
        ``.../audit_firm_public_reports/<firm>__<slug>-<hash>/record.yaml``
        firm = canonicalised text before the ``__`` separator.
    Layout B (legacy / synthetic fixtures):
        ``.../tags/firm-<firm>-audits/<slug>/<finding>.yaml``
        firm = text between ``firm-`` and ``-audits``.
    """
    parts = yaml_path.parts
    for idx, part in enumerate(parts):
        # Layout B (legacy per-firm subtree).
        if part.startswith("firm-") and part.endswith("-audits"):
            return part[len("firm-"):-len("-audits")]
        # Layout A (audit_firm_public_reports/<firm>__<slug>).
        if part == FIRM_REPORTS_SUBTREE and idx + 1 < len(parts):
            report_dir = parts[idx + 1]
            if "__" in report_dir:
                return _canonical_firm_slug(report_dir.split("__", 1)[0])
    return "unknown"


def _is_synthetic(record: Dict[str, Any]) -> bool:
    ext = record.get("record_extensions") or {}
    if isinstance(ext, dict):
        if ext.get("synthetic_fixture") is True:
            return True
    if record.get("synthetic_fixture") is True:
        return True
    return False


# Record discovery / loading ------------------------------------------------


def _iter_firm_yaml_paths(
    tags_root: Path,
    firms_filter: Optional[set] = None,
) -> Iterable[Path]:
    """Yield every firm-audit YAML record, deterministic order.

    Discovers BOTH corpus layouts (W3.9 path-mismatch fix):

    * Layout A - the real corpus: ``audit_firm_public_reports/<firm>__<slug>/``.
    * Layout B - legacy / synthetic fixtures: ``firm-<firm>-audits/<slug>/``.

    ``firms_filter`` is matched against the canonical firm slug
    (``_firm_from_path``), so callers can pass ``trailofbits`` regardless of
    which layout the records physically live in.
    """
    if not tags_root.is_dir():
        return
    seen: set = set()

    def _emit(firm_dir: Path) -> Iterable[Path]:
        for yaml_path in sorted(firm_dir.rglob("*.yaml")):
            if not yaml_path.is_file():
                continue
            if firms_filter is not None:
                if _firm_from_path(yaml_path) not in firms_filter:
                    continue
            rp = yaml_path.resolve()
            if rp in seen:
                continue
            seen.add(rp)
            yield yaml_path

    # Layout A: audit_firm_public_reports/<firm>__<slug>/record.yaml.
    reports_root = tags_root / FIRM_REPORTS_SUBTREE
    if reports_root.is_dir():
        for report_dir in sorted(reports_root.iterdir()):
            if not report_dir.is_dir():
                continue
            yield from _emit(report_dir)

    # Layout B: legacy firm-<firm>-audits/ subtrees (synthetic fixtures).
    for firm_dir in sorted(tags_root.glob(LEGACY_FIRM_SUBTREE_GLOB)):
        if not firm_dir.is_dir():
            continue
        yield from _emit(firm_dir)


def _load_record(yaml_path: Path) -> Optional[Dict[str, Any]]:
    try:
        text = yaml_path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    return data


# Clustering ----------------------------------------------------------------


def _jaccard(a: Sequence[str], b: Sequence[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    if union == 0:
        return 0.0
    return inter / union


def _cluster_id(protocol_norm: str, attack_class: str, record_ids: Sequence[str]) -> str:
    src = "|".join([protocol_norm, attack_class, *sorted(record_ids)])
    return hashlib.sha256(src.encode("utf-8")).hexdigest()[:16]


def build_record_view(yaml_path: Path, record: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a raw YAML record into the dedup-view dict."""
    rid = (
        record.get("record_id")
        or record.get("id")
        or str(yaml_path)
    )
    return {
        "record_id": str(rid),
        "yaml_path": str(yaml_path),
        "firm": _firm_from_path(yaml_path),
        "protocol_normalized": _protocol(record),
        "attack_class": _attack_class(record),
        "bug_family": _bug_family(record),
        "severity_normalized": _severity(record),
        "title": str(record.get("title") or ""),
        "title_keywords": list(_title_keywords(record.get("title"))),
        "verification_tier": str(record.get("verification_tier") or ""),
        "verification_tier_rank": _verification_tier_rank(record),
        "incident_date": _incident_date(record),
        "record_source_url": _record_source_url(record),
        "synthetic_fixture": _is_synthetic(record),
    }


def collect_records(
    tags_root: Path,
    firms_filter: Optional[set] = None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for yaml_path in _iter_firm_yaml_paths(tags_root, firms_filter=firms_filter):
        record = _load_record(yaml_path)
        if record is None:
            continue
        view = build_record_view(yaml_path, record)
        if not view["protocol_normalized"] or not view["attack_class"]:
            # Cannot participate in cheap-filter; skip but count below.
            view["_skipped_reason"] = "missing_protocol_or_attack_class"
        out.append(view)
    return out


def build_clusters(
    records: List[Dict[str, Any]],
    *,
    min_similarity: float = 0.6,
    min_cluster_size: int = 2,
) -> List[Dict[str, Any]]:
    """Two-stage cluster build: cheap-filter then Jaccard pairwise."""
    bucketed: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        if r.get("_skipped_reason"):
            continue
        key = (r["protocol_normalized"], r["attack_class"])
        bucketed[key].append(r)

    clusters: List[Dict[str, Any]] = []
    for (protocol_norm, attack_class), bucket in bucketed.items():
        if len(bucket) < min_cluster_size:
            continue
        # Union-find on Jaccard+severity edges.
        parent = list(range(len(bucket)))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: int, b: int) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        sim_pairs: Dict[Tuple[int, int], float] = {}
        for i, j in combinations(range(len(bucket)), 2):
            ri, rj = bucket[i], bucket[j]
            if ri["severity_normalized"] != rj["severity_normalized"]:
                continue
            sim = _jaccard(ri["title_keywords"], rj["title_keywords"])
            if sim >= min_similarity:
                union(i, j)
                key_pair = (i, j) if i < j else (j, i)
                sim_pairs[key_pair] = sim

        groups: Dict[int, List[int]] = defaultdict(list)
        for idx in range(len(bucket)):
            groups[find(idx)].append(idx)

        for root, members in groups.items():
            if len(members) < min_cluster_size:
                continue
            member_records = [bucket[m] for m in sorted(members)]
            # Mean pairwise similarity within this group.
            group_pairs = [
                sim_pairs[(a, b) if a < b else (b, a)]
                for a, b in combinations(sorted(members), 2)
                if ((a, b) if a < b else (b, a)) in sim_pairs
            ]
            mean_sim = sum(group_pairs) / len(group_pairs) if group_pairs else 0.0

            # Canonical record: highest verification_tier_rank,
            # ties broken by earliest incident_date (asc), then
            # record_id (asc) for full determinism.
            canon = sorted(
                member_records,
                key=lambda r: (
                    -r["verification_tier_rank"],
                    r["incident_date"] or "9999",
                    r["record_id"],
                ),
            )[0]

            record_ids = sorted(r["record_id"] for r in member_records)
            firms_involved = sorted({r["firm"] for r in member_records})
            cluster_synth = all(r["synthetic_fixture"] for r in member_records)

            clusters.append(
                {
                    "cluster_id": _cluster_id(protocol_norm, attack_class, record_ids),
                    "protocol_normalized": protocol_norm,
                    "attack_class": attack_class,
                    "severity_normalized": member_records[0]["severity_normalized"],
                    "record_ids": record_ids,
                    "yaml_paths": sorted(r["yaml_path"] for r in member_records),
                    "firms_involved": firms_involved,
                    "cluster_size": len(member_records),
                    "similarity_score": round(mean_sim, 4),
                    "recommended_canonical": {
                        "record_id": canon["record_id"],
                        "firm": canon["firm"],
                        "yaml_path": canon["yaml_path"],
                        "verification_tier": canon["verification_tier"],
                        "incident_date": canon["incident_date"],
                    },
                    "synthetic_fixture_only": cluster_synth,
                    "title_keywords_union": sorted(
                        {t for r in member_records for t in r["title_keywords"]}
                    ),
                }
            )

    # Stable cluster order: by size desc, then similarity desc, then id asc.
    clusters.sort(
        key=lambda c: (-c["cluster_size"], -c["similarity_score"], c["cluster_id"])
    )
    return clusters


def firm_intersection_matrix(
    clusters: List[Dict[str, Any]],
) -> Dict[str, int]:
    """Pairwise count of clusters in which a given firm-pair both appear."""
    counts: Dict[Tuple[str, str], int] = defaultdict(int)
    for c in clusters:
        firms = c["firms_involved"]
        for a, b in combinations(sorted(set(firms)), 2):
            counts[(a, b)] += 1
    return {f"{a}__x__{b}": n for (a, b), n in sorted(counts.items())}


def overall_status(cluster_count: int) -> str:
    if cluster_count == 0:
        return "PASS"
    if cluster_count > 10:
        return "WARNING"
    return "INFO"


# CLI driver ----------------------------------------------------------------


def run_detect(
    workspace: Path,
    *,
    min_similarity: float = 0.6,
    min_cluster_size: int = 2,
    firms_filter: Optional[set] = None,
    cluster_cap: int = 50,
    verbose: bool = False,
) -> Dict[str, Any]:
    tags_root = workspace / "audit" / "corpus_tags" / "tags"
    records = collect_records(tags_root, firms_filter=firms_filter)
    firms_scanned = sorted({r["firm"] for r in records})
    clusters = build_clusters(
        records,
        min_similarity=min_similarity,
        min_cluster_size=min_cluster_size,
    )
    total_dupes = sum(max(c["cluster_size"] - 1, 0) for c in clusters)
    status = overall_status(len(clusters))
    payload = {
        "schema": SCHEMA_ID,
        "workspace": str(workspace.resolve()),
        "tags_root": str(tags_root),
        "min_similarity": min_similarity,
        "min_cluster_size": min_cluster_size,
        "firms_filter": sorted(firms_filter) if firms_filter else [],
        "total_firm_records_scanned": len(records),
        "firms_scanned": firms_scanned,
        "cluster_count": len(clusters),
        "clusters": clusters[:cluster_cap],
        "clusters_truncated": len(clusters) > cluster_cap,
        "total_estimated_dupes": total_dupes,
        "firm_intersection_matrix": firm_intersection_matrix(clusters),
        "overall_status": status,
    }
    if verbose:
        skipped = sum(1 for r in records if r.get("_skipped_reason"))
        payload["verbose"] = {
            "records_with_missing_cheap_filter_fields": skipped,
        }
    return payload


def parse_firms(arg: Optional[str]) -> Optional[set]:
    if not arg:
        return None
    parts = [p.strip() for p in arg.split(",") if p.strip()]
    return set(parts) if parts else None


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Wave-2 PR-B cross-firm duplicate-finding candidate detector. "
            "Read-only; emits a candidate list for operator review."
        )
    )
    p.add_argument(
        "--workspace",
        default=".",
        help="Workspace root containing audit/corpus_tags/tags/.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON payload to stdout (default: human summary).",
    )
    p.add_argument(
        "--min-similarity",
        type=float,
        default=0.6,
        help="Title-keyword Jaccard threshold for clustering (default 0.6).",
    )
    p.add_argument(
        "--min-cluster-size",
        type=int,
        default=2,
        help="Minimum members in a candidate cluster (default 2).",
    )
    p.add_argument(
        "--firms",
        default=None,
        help="Comma-separated list of firm slugs to restrict the scan to.",
    )
    p.add_argument(
        "--cluster-cap",
        type=int,
        default=50,
        help="Maximum clusters embedded in the JSON output (default 50).",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Include extra diagnostic counters in the JSON output.",
    )
    args = p.parse_args(argv)

    workspace = Path(args.workspace).resolve()
    firms_filter = parse_firms(args.firms)

    payload = run_detect(
        workspace,
        min_similarity=args.min_similarity,
        min_cluster_size=args.min_cluster_size,
        firms_filter=firms_filter,
        cluster_cap=args.cluster_cap,
        verbose=args.verbose,
    )

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"schema: {payload['schema']}")
        print(f"workspace: {payload['workspace']}")
        print(f"firms_scanned: {payload['firms_scanned']}")
        print(
            f"total_firm_records_scanned: {payload['total_firm_records_scanned']}"
        )
        print(f"cluster_count: {payload['cluster_count']}")
        print(
            f"total_estimated_dupes: {payload['total_estimated_dupes']}"
        )
        print(
            f"min_similarity: {payload['min_similarity']}    "
            f"min_cluster_size: {payload['min_cluster_size']}"
        )
        print(f"overall_status: {payload['overall_status']}")
        if payload["clusters"]:
            print("top clusters:")
            for c in payload["clusters"][:5]:
                print(
                    f"  cluster_id={c['cluster_id']}    "
                    f"size={c['cluster_size']}    "
                    f"sim={c['similarity_score']}    "
                    f"firms={c['firms_involved']}    "
                    f"protocol={c['protocol_normalized']}    "
                    f"attack_class={c['attack_class']}"
                )
        if payload["clusters_truncated"]:
            print(
                f"(cluster list truncated to first {args.cluster_cap}; "
                f"total clusters: {payload['cluster_count']})"
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
