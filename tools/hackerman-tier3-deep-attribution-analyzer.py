#!/usr/bin/env python3
"""hackerman-tier3-deep-attribution-analyzer.

Investigative-only analyzer for tier-3-synthetic-taxonomy-anchored records.

Walks the tier-3 cohort surfaced by
`tools/hackerman-stratify-verification-tier.py` (or the candidate JSONL
written by it) and classifies each `source_audit_ref` prefix into one of
three deep-attribution buckets:

  - "genuinely-synthetic"
      The record is a DSL fan-out, regex-derived taxonomy slice, or
      compiler-bug fixture. Even with deeper source attribution it would
      remain a tier-3 / tier-4 anchor because the specific incident is
      templated.

  - "deeper-attribution-possible"
      The record cites a real-world URL, audit-firm PDF, public
      post-mortem, or canonical bug-tracker entry in `source_audit_ref`
      or `required_preconditions`. With a stratifier-prefix-table
      extension the record could be promoted to tier-2.

  - "unknown-needs-investigation"
      Heuristics are ambiguous; flagged for human review.

Outputs (NEVER modifies records):

  - `.auditooor/tier3_prefix_analysis.jsonl`
      One JSON object per prefix bucket.

  - `docs/HACKERMAN_TIER3_PROMOTION_CANDIDATES_<YYYY-MM-DD>.md`
      Top-20 prefixes by record count, classification, recommended
      action per prefix.

Usage:

    python3 tools/hackerman-tier3-deep-attribution-analyzer.py \
        [--candidates .auditooor/verification-tier-candidates.jsonl] \
        [--out-jsonl .auditooor/tier3_prefix_analysis.jsonl] \
        [--out-doc docs/HACKERMAN_TIER3_PROMOTION_CANDIDATES_2026-05-16.md] \
        [--dry-run]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


REPO_ROOT_GUESS = Path(__file__).resolve().parent.parent
DEFAULT_CANDIDATES = (
    REPO_ROOT_GUESS / ".auditooor" / "verification-tier-candidates.jsonl"
)
DEFAULT_TAGS_DIR = REPO_ROOT_GUESS / "audit" / "corpus_tags" / "tags"
DEFAULT_OUT_JSONL = REPO_ROOT_GUESS / ".auditooor" / "tier3_prefix_analysis.jsonl"


# --------------------------------------------------------------------------- #
# Classification heuristics
# --------------------------------------------------------------------------- #

# Prefixes whose records are intrinsically synthetic: DSL fan-out, regex
# slice, compiler-bug fixture. Promotion is NOT meaningful even with deep
# source attribution because the record body is templated.
GENUINELY_SYNTHETIC_PREFIXES = frozenset({
    "corpus-mined",         # regex-derived slice over markdown corpus
    "corpus-txt",           # regex-derived slice over text corpus
    "solc-compiler",        # bugs.json fixture; canonical but templated
    "sig-extract",          # function-signature shape extraction
    "dsl-pattern",
    "canonical-dsl",
    "solidity-fork-pattern",
    "vyper-fork-pattern",
})

# Prefixes whose source_audit_ref values typically contain a real URL or
# canonical public-archive identifier. With a stratifier-prefix-table
# extension (e.g. `zk-auditor:` → tier-2) these records can be promoted.
DEEPER_ATTRIBUTION_POSSIBLE_PREFIXES = frozenset({
    "zk-auditor",           # audit-firm reports (asymmetric-research,
                            # veridise, zellic, etc.)
    "zk-contest",           # cantina/code4rena zk-targeted contests
    "zkbugs",               # zksecurity/zkbugs dataset (real github URLs)
    "zkbugs-catalog",       # zksecurity/zkbugs catalog (real github URLs)
    "zkbugtracker",         # 0xPARC zk-bug-tracker (real github URLs)
    "l2-zkrollup",          # L2 rollup incident references
    "mev-exploits",         # MEV writeups (blocknative, flashbots, etc.)
    "mev-flashloan",        # Flash-loan attack canonical classes
    "bridge-incident",      # Bridge-incident post-mortems (Ronin, Wormhole)
    "starknet-cairo-corpus", # Starknet audit PDFs (ChainSecurity, etc.)
    "movebit",              # Movebit audit reports (Aptos / Sui)
    "solana-svm",           # Solana SVM writeups (Neodyme, Sec3, etc.)
    "vyper-39363",          # CVE-2023-39363 family (real CVE)
    "cve-db",               # CVE database entries (real CVE IDs)
})

# URL / canonical-id markers that indicate a record CAN be promoted even
# if its prefix isn't in DEEPER_ATTRIBUTION_POSSIBLE_PREFIXES.
URL_SIGNAL_RE = re.compile(
    r"https?://|"
    r"github\.com/|"
    r"raw\.githubusercontent\.com/|"
    r"cve-\d{4}-\d{4,}|"
    r"sol-\d{4}-\d+",
    re.IGNORECASE,
)

# Bug-tracker / public-archive host patterns commonly found in
# required_preconditions of tier-3 records.
PUBLIC_ARCHIVE_HOST_RE = re.compile(
    r"(rekt\.news|"
    r"blog\.openzeppelin\.com|"
    r"blog\.trailofbits\.com|"
    r"blog\.soliditylang\.org|"
    r"medium\.com|"
    r"hackmd\.io|"
    r"docs\.aave\.com|"
    r"blocknative\.com|"
    r"code4rena\.com|"
    r"sherlock\.xyz|"
    r"cantina\.xyz|"
    r"immunefi\.com)",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- #
# Record I/O
# --------------------------------------------------------------------------- #


TOP_LEVEL_SCALAR_RE = re.compile(r"^([a-z_][a-z0-9_]*):\s*(.*)$", re.IGNORECASE)


def _unquote(val: str) -> str:
    val = val.strip()
    if not val:
        return ""
    if (val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'"):
        return val[1:-1]
    return val


def load_record_fields(path: Path) -> Dict[str, Any]:
    """Load a small set of top-level scalars / lists from a hackerman
    record. Supports both YAML and JSON record forms.

    Returns a dict containing whichever of {record_id, source_audit_ref,
    required_preconditions, attacker_action_sequence,
    source_extraction_method, source_extraction_confidence} were found.
    """
    fields: Dict[str, Any] = {}
    if not path.exists():
        return fields
    if path.suffix.lower() == ".json":
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return fields
        if not isinstance(payload, dict):
            return fields
        for key in (
            "record_id",
            "source_audit_ref",
            "required_preconditions",
            "attacker_action_sequence",
            "source_extraction_method",
            "source_extraction_confidence",
        ):
            v = payload.get(key)
            if v is not None:
                fields[key] = v
        return fields
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            in_preconditions = False
            preconds: List[str] = []
            for raw_line in fh:
                line = raw_line.rstrip("\n")
                if not line:
                    continue
                if line.startswith("  - ") and in_preconditions:
                    preconds.append(_unquote(line[4:]))
                    continue
                if line.startswith(" ") or line.startswith("\t"):
                    continue
                in_preconditions = False
                m = TOP_LEVEL_SCALAR_RE.match(line)
                if not m:
                    continue
                key = m.group(1).strip().lower()
                val = _unquote(m.group(2))
                if key == "required_preconditions":
                    in_preconditions = True
                    if val and val != "":
                        # inline form (rare)
                        preconds.append(val)
                    continue
                if key in {
                    "record_id",
                    "source_audit_ref",
                    "attacker_action_sequence",
                    "source_extraction_method",
                    "source_extraction_confidence",
                }:
                    fields.setdefault(key, val)
            if preconds:
                fields["required_preconditions"] = preconds
    except OSError:
        return fields
    return fields


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #


def extract_prefix(record_id: str) -> str:
    """Extract the prefix slug from a record_id.

    Heuristic: take the substring before the first ':'. Falls back to
    the first 30 characters.
    """
    if not record_id:
        return ""
    if ":" in record_id:
        return record_id.split(":", 1)[0]
    return record_id[:30]


def has_url_signal(record_fields: Dict[str, Any]) -> bool:
    """Return True iff the record cites a real-world URL / canonical CVE
    or solc-bugs identifier in source_audit_ref, attacker_action_sequence,
    or required_preconditions."""
    candidates: List[str] = []
    saf = record_fields.get("source_audit_ref")
    if isinstance(saf, str):
        candidates.append(saf)
    aas = record_fields.get("attacker_action_sequence")
    if isinstance(aas, str):
        candidates.append(aas)
    preconds = record_fields.get("required_preconditions")
    if isinstance(preconds, list):
        for p in preconds:
            if isinstance(p, str):
                candidates.append(p)
    elif isinstance(preconds, str):
        candidates.append(preconds)
    for c in candidates:
        if URL_SIGNAL_RE.search(c) or PUBLIC_ARCHIVE_HOST_RE.search(c):
            return True
    return False


def classify_prefix(
    prefix: str, sample_record_fields: List[Dict[str, Any]]
) -> Tuple[str, str]:
    """Classify a prefix into one of:

      - "genuinely-synthetic"
      - "deeper-attribution-possible"
      - "unknown-needs-investigation"

    Returns (classification, reason).
    """
    if prefix in GENUINELY_SYNTHETIC_PREFIXES:
        return (
            "genuinely-synthetic",
            f"prefix '{prefix}' is a DSL/regex/compiler fixture; templated body",
        )
    if prefix in DEEPER_ATTRIBUTION_POSSIBLE_PREFIXES:
        return (
            "deeper-attribution-possible",
            f"prefix '{prefix}' is recognised as a real-archive cohort",
        )
    # Heuristic over sample records: if a majority cite URL / canonical
    # IDs, lean toward "deeper-attribution-possible". Otherwise
    # "unknown".
    if not sample_record_fields:
        return ("unknown-needs-investigation", "no samples available")
    url_hits = sum(1 for f in sample_record_fields if has_url_signal(f))
    if url_hits >= max(1, len(sample_record_fields) // 2 + 1):
        return (
            "deeper-attribution-possible",
            f"{url_hits}/{len(sample_record_fields)} samples cite real URLs / canonical IDs",
        )
    if url_hits == 0:
        return (
            "unknown-needs-investigation",
            "no URL / canonical ID found in sampled records",
        )
    return (
        "unknown-needs-investigation",
        f"only {url_hits}/{len(sample_record_fields)} samples cite URLs (below majority)",
    )


# --------------------------------------------------------------------------- #
# Aggregation pipeline
# --------------------------------------------------------------------------- #


def iter_tier3_candidates(candidates_path: Path) -> Iterable[Dict[str, Any]]:
    """Yield records from a verification-tier-candidates JSONL that are
    classified tier-3-synthetic-taxonomy-anchored."""
    if not candidates_path.exists():
        return
    with candidates_path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if rec.get("verification_tier") != "tier-3-synthetic-taxonomy-anchored":
                continue
            yield rec


def build_prefix_groups(
    candidates_path: Path,
    repo_root: Path,
    sample_size: int = 3,
) -> Dict[str, Dict[str, Any]]:
    """Group tier-3 candidates by prefix, sampling up to `sample_size`
    records per prefix (loading their YAML/JSON bodies)."""
    groups: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "count": 0,
            "sample_files": [],
            "sample_records": [],
            "example_record_ids": [],
        }
    )
    for cand in iter_tier3_candidates(candidates_path):
        record_id = cand.get("record_id", "")
        prefix = extract_prefix(record_id)
        g = groups[prefix]
        g["count"] += 1
        if len(g["sample_files"]) < sample_size:
            rel_file = cand.get("file", "")
            full_path = repo_root / rel_file if rel_file else None
            fields = load_record_fields(full_path) if full_path else {}
            g["sample_files"].append(rel_file)
            g["sample_records"].append(fields)
            g["example_record_ids"].append(record_id)
    return dict(groups)


def classify_all(groups: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run the classifier over every prefix group. Returns a list of
    bucket dicts, one per prefix, sorted descending by count."""
    rows: List[Dict[str, Any]] = []
    for prefix, g in groups.items():
        classification, reason = classify_prefix(prefix, g["sample_records"])
        promotion_candidate_count = 0
        if classification == "deeper-attribution-possible":
            promotion_candidate_count = g["count"]
        elif classification == "unknown-needs-investigation":
            # Conservative: count URL-bearing samples and scale to total
            n_samples = len(g["sample_records"])
            if n_samples > 0:
                hit_ratio = sum(
                    1 for f in g["sample_records"] if has_url_signal(f)
                ) / n_samples
                promotion_candidate_count = int(round(g["count"] * hit_ratio))
        rows.append({
            "prefix": prefix,
            "count": g["count"],
            "classification": classification,
            "reason": reason,
            "promotion_candidate_count": promotion_candidate_count,
            "example_record_ids": g["example_record_ids"],
            "sample_files": g["sample_files"],
        })
    rows.sort(key=lambda r: (-r["count"], r["prefix"]))
    return rows


# --------------------------------------------------------------------------- #
# Output writers
# --------------------------------------------------------------------------- #


def write_jsonl(rows: List[Dict[str, Any]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


def recommended_action(row: Dict[str, Any]) -> str:
    cls = row["classification"]
    prefix = row["prefix"]
    if cls == "genuinely-synthetic":
        return "no-action; keep tier-3 (templated synthetic body)"
    if cls == "deeper-attribution-possible":
        return (
            f"extend stratifier-prefix-table to recognise '{prefix}:' "
            f"and inspect a 10-record sample to confirm tier-2 fit"
        )
    return (
        f"manual review of 3 sampled records under '{prefix}:' to decide "
        f"between genuinely-synthetic vs deeper-attribution-possible"
    )


def write_doc(
    rows: List[Dict[str, Any]],
    out_path: Path,
    total_tier3: int,
    top_n: int = 20,
) -> None:
    today = _dt.date.today().isoformat()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    top = rows[:top_n]
    promo_total = sum(r["promotion_candidate_count"] for r in rows)
    lines: List[str] = []
    lines.append(f"# Hackerman tier-3 promotion candidates ({today})")
    lines.append("")
    lines.append(
        "Investigative-only analysis of the tier-3-synthetic-taxonomy-"
        "anchored cohort emitted by `tools/hackerman-stratify-verification-"
        "tier.py`. NO records are modified by this analyzer."
    )
    lines.append("")
    lines.append(f"- Total tier-3 records: {total_tier3}")
    lines.append(f"- Distinct prefixes: {len(rows)}")
    lines.append(
        f"- Estimated promotion-candidate records "
        f"(across all prefixes): {promo_total}"
    )
    lines.append("")
    lines.append(f"## Top-{top_n} tier-3 prefixes by record count")
    lines.append("")
    lines.append(
        "| # | prefix | count | classification | "
        "promotion-candidates | recommended action |"
    )
    lines.append("|---|--------|-------|----------------|-----------------------|--------------------|")
    for i, r in enumerate(top, start=1):
        lines.append(
            f"| {i} | `{r['prefix']}` | {r['count']} | "
            f"{r['classification']} | {r['promotion_candidate_count']} | "
            f"{recommended_action(r)} |"
        )
    lines.append("")
    lines.append("## Per-prefix detail")
    lines.append("")
    for r in top:
        lines.append(f"### `{r['prefix']}` ({r['count']} records)")
        lines.append("")
        lines.append(f"- Classification: **{r['classification']}**")
        lines.append(f"- Reason: {r['reason']}")
        lines.append(
            f"- Promotion-candidate count: {r['promotion_candidate_count']}"
        )
        lines.append(f"- Recommended action: {recommended_action(r)}")
        lines.append("- Example record_ids:")
        for rid in r["example_record_ids"]:
            lines.append(f"  - `{rid}`")
        lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "1. Read `.auditooor/verification-tier-candidates.jsonl` and "
        "filter to `verification_tier = tier-3-synthetic-taxonomy-anchored`."
    )
    lines.append(
        "2. Group records by the prefix slug of `record_id` (text before "
        "the first `:`)."
    )
    lines.append(
        "3. For each prefix, sample up to 3 records and load their "
        "top-level fields."
    )
    lines.append(
        "4. Classify the prefix as one of `genuinely-synthetic`, "
        "`deeper-attribution-possible`, or `unknown-needs-investigation` "
        "using the curated prefix tables in the analyzer plus a "
        "URL/canonical-ID heuristic over sampled records."
    )
    lines.append("")
    lines.append("## Disclaimer")
    lines.append("")
    lines.append(
        "Heuristic classification is conservative. A record flagged "
        "`deeper-attribution-possible` is a CANDIDATE only; the "
        "stratifier-prefix-table extension agent (Wave-2) is the "
        "system-of-record for actual tier promotion."
    )
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Analyze tier-3 records for deep-attribution promotion candidates."
    )
    p.add_argument(
        "--candidates",
        type=Path,
        default=DEFAULT_CANDIDATES,
        help="Path to verification-tier-candidates.jsonl (default: %(default)s)",
    )
    p.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT_GUESS,
        help="Repository root used to resolve relative record paths",
    )
    p.add_argument(
        "--out-jsonl",
        type=Path,
        default=DEFAULT_OUT_JSONL,
        help="Output JSONL path (default: %(default)s)",
    )
    p.add_argument(
        "--out-doc",
        type=Path,
        default=None,
        help="Output Markdown doc path (default: docs/HACKERMAN_TIER3_PROMOTION_CANDIDATES_<YYYY-MM-DD>.md)",
    )
    p.add_argument(
        "--top-n",
        type=int,
        default=20,
        help="Number of top prefixes to include in the doc (default: 20)",
    )
    p.add_argument(
        "--sample-size",
        type=int,
        default=3,
        help="Records sampled per prefix for URL heuristic (default: 3)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print summary to stdout but do not write outputs",
    )
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    candidates = args.candidates
    if not candidates.exists():
        print(
            f"[error] candidates JSONL not found at {candidates}; "
            f"run tools/hackerman-stratify-verification-tier.py first",
            file=sys.stderr,
        )
        return 2
    groups = build_prefix_groups(
        candidates, args.repo_root, sample_size=args.sample_size
    )
    rows = classify_all(groups)
    total_tier3 = sum(r["count"] for r in rows)

    if args.dry_run:
        print(f"[dry-run] tier-3 records: {total_tier3}; prefixes: {len(rows)}")
        for r in rows[: args.top_n]:
            print(
                f"  {r['count']:>6}  {r['prefix']:<32}  "
                f"{r['classification']}  (promo-candidates={r['promotion_candidate_count']})"
            )
        return 0

    out_doc = args.out_doc or (
        args.repo_root
        / "docs"
        / f"HACKERMAN_TIER3_PROMOTION_CANDIDATES_{_dt.date.today().isoformat()}.md"
    )
    write_jsonl(rows, args.out_jsonl)
    write_doc(rows, out_doc, total_tier3, top_n=args.top_n)
    print(f"[ok] wrote {args.out_jsonl} ({len(rows)} prefix rows)")
    print(f"[ok] wrote {out_doc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
