#!/usr/bin/env python3
"""hackerman-detector-seed-extractor (PREVIEW ONLY).

Walk the Hackerman corpus per-directory record bundles under
``audit/corpus_tags/tags/<bucket>/<slug>/record.{json,yaml}`` and emit a
*preview* JSONL of candidate detector seeds extracted from real-source
records (verification_tier-1 + tier-2 only). Synthetic / fixture /
quarantine tiers (tier-3, tier-4, tier-5) are skipped per operator hard
rule.

Two seed families are extracted:

  1. Regex seed (``shape_tag_literal``): any literal substring drawn from
     a record's ``function_shape.shape_tags`` array that recurs >=3 times
     across *distinct* tier-1/tier-2 records. The recurrence threshold
     keeps single-record noise out of the preview.

  2. AST seed (``diff_style_shape``): scan ``code_snippet_pre_fix`` /
     ``code_snippet_post_fix`` fields (when present) for diff-style
     directive lines (``+ ...`` / ``- ...`` introducing a token-level
     change). One record per seed is fine here because diff structure is
     itself a structural signal. Currently rarely populated in the
     corpus; tool emits zero AST seeds for buckets that lack the
     fields, which is the expected behavior and surfaces a gap to the
     operator.

The output artifact lands at ``.auditooor/candidate_detectors.jsonl``
(gitignored - see ``.gitignore`` entry for ``.auditooor/``). It is a
PREVIEW only. This tool does NOT write to ``Makefile``,
``tools/audit-deep-runner.py``, or anything that participates in
``make audit``. The operator reviews the JSONL and decides whether to
promote any seed to a real detector.

The companion markdown preview at
``docs/HACKERMAN_DETECTOR_SEEDS_PREVIEW_<DATE>.md`` (default:
2026-05-16) shows the top-50 candidate seeds by recurrence count,
grouped by ``attack_class``. The markdown is operator-readable; the
JSONL is the machine artifact.

Usage:

    # Preview run (writes JSONL + markdown)
    python3 tools/hackerman-detector-seed-extractor.py

    # Dry-run (computes seeds, prints summary, writes nothing)
    python3 tools/hackerman-detector-seed-extractor.py --dry-run

    # Limit how many top seeds appear in the markdown (default 50)
    python3 tools/hackerman-detector-seed-extractor.py --top-n 100

Exit codes:

    0 - preview generated (or dry-run completed)
    2 - corpus tree missing / unreadable / no tier-1/2 records found
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SCHEMA = "auditooor.hackerman_detector_seed_extractor.v1"
HACKERMAN_V1_SCHEMA = "auditooor.hackerman_record.v1"

REPO_ROOT_GUESS = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT_GUESS / "audit" / "corpus_tags" / "tags"
DEFAULT_OUTPUT_JSONL = REPO_ROOT_GUESS / ".auditooor" / "candidate_detectors.jsonl"
DEFAULT_DOCS_PATH = REPO_ROOT_GUESS / "docs" / "HACKERMAN_DETECTOR_SEEDS_PREVIEW_2026-05-16.md"

REAL_SOURCE_TIERS = (
    "tier-1-verified-realtime-api",
    "tier-2-verified-public-archive",
)
SKIPPED_TIERS = (
    "tier-3-synthetic-taxonomy-anchored",
    "tier-4-bundled-fixture",
    "tier-5-quarantine",
)

# Tier-classification regexes/markers mirror
# tools/hackerman-stratify-verification-tier.py, extended with
# real-source prefixes used by the newer per-directory record bundles
# (zk_circuit_bugs, dex_fix_history, cosmos_sdk_ibc, etc.) that the
# stratifier predated.
QUARANTINE_PATH_MARKERS = (
    "_QUARANTINE_FABRICATED_CVE",
    "_QUARANTINE_FABRICATED",
    "quarantine_fabricated",
)

TIER1_SUBSTRINGS = (
    "api.github.com",
    "nvd.nist.gov",
    "cve.mitre.org",
    "ghsa-",
    "immunefi-public:",
    "immunefi-live:",
    "cantina-live:",
    "historic:",
    "critical:",
    "cve_db:",
    # Newer per-dir bundle prefixes - real upstream advisories / fix
    # history with concrete SHAs or canonical zk-bug ids:
    "zkbugs:",
    "dex-fix-history:",
)

TIER1_GIT_SHA_RE = re.compile(r"^(?:git-mining|github):[^@]+@[0-9a-f]{8,}")

TIER2_PREFIXES = (
    "prior-audit:",
    "findings-go:",
)
SOLODIT_NUMERIC_RE = re.compile(r"^solodit-spec:[^:]*?:?(\d+):")

TIER3_PREFIXES = (
    "corpus-mined:",
    "corpus-txt:",
)

TIER4_PREFIXES = (
    "solidity-fork-pattern:",
    "dsl-pattern:",
    "dsl_pattern",
    "canonical-dsl:",
)
TIER4_TARGET_REPO_MARKERS = (
    "unknown/dsl-synthetic",
)

# Diff-style directive line: `+ <token>` or `- <token>` plus identifier-ish
# content. Used to extract AST-style seeds from code_snippet_pre/post_fix.
DIFF_LINE_RE = re.compile(r"^[+\-]\s+([A-Za-z_][\w.\-]{2,}\b.*)$")

# Lowercased tags we never want to surface as detector seeds: too noisy,
# too generic, or trivially tautological with the bucket name itself.
STOPLIST_SHAPE_TAGS = frozenset(
    {
        # Bucket/dir tags that just label the corpus origin
        "ghsa-real",
        "src-ghsa",
        "src-git-fix-history",
        "src-zkbugs",
        "impact-soundness",
        # Generic language/platform marker tags
        "rust",
        "go",
        "solidity",
        "typescript",
        "python",
        "javascript",
        # Generic ecosystem markers
        "evm",
        "consensus",
        "rpc",
    }
)


# --------------------------------------------------------------------------- #
# Tier classification (mirrors stratifier; extended for new real-source
# bundles)
# --------------------------------------------------------------------------- #


def classify_tier(record: Dict[str, Any]) -> Tuple[str, str]:
    """Return (tier_key, reason). Tier-1/tier-2 are 'real-source' per the
    operator hard rule; tier-3/4/5 are skipped."""
    record_id = str(record.get("record_id") or "")
    source_ref = str(record.get("source_audit_ref") or "")
    extract_method = str(record.get("source_extraction_method") or "").lower()
    target_repo = str(record.get("target_repo") or "").lower()
    record_tier = str(record.get("record_tier") or "")
    haystack = f"{record_id}\n{source_ref}".lower()

    # tier-5 quarantine first (operator hard exclusion)
    for marker in QUARANTINE_PATH_MARKERS:
        if marker.lower() in haystack:
            return ("tier-5-quarantine", f"quarantine-path-marker:{marker}")

    # tier-1: live API / canonical CVE / real-SHA git mining / new real-source prefixes
    for sub in TIER1_SUBSTRINGS:
        if sub.lower() in haystack:
            return ("tier-1-verified-realtime-api", f"tier1-marker:{sub}")
    if TIER1_GIT_SHA_RE.match(source_ref) or TIER1_GIT_SHA_RE.match(record_id):
        return ("tier-1-verified-realtime-api", "git-mining-with-sha")

    # tier-2: public archive prefixes
    for pref in TIER2_PREFIXES:
        if record_id.startswith(pref) or source_ref.startswith(pref):
            return ("tier-2-verified-public-archive", f"tier2-prefix:{pref}")
    if SOLODIT_NUMERIC_RE.match(record_id) or SOLODIT_NUMERIC_RE.match(source_ref):
        return ("tier-2-verified-public-archive", "solodit-numeric-id")

    # tier-4: bundled fixtures
    for pref in TIER4_PREFIXES:
        if record_id.startswith(pref) or source_ref.startswith(pref):
            return ("tier-4-bundled-fixture", f"tier4-prefix:{pref}")
    if extract_method == "dsl-synthetic":
        return ("tier-4-bundled-fixture", "extraction-method-dsl-synthetic")
    for marker in TIER4_TARGET_REPO_MARKERS:
        if marker in target_repo:
            return ("tier-4-bundled-fixture", f"target-repo-synthetic:{marker}")

    # tier-3: corpus-mined regex fan-outs
    for pref in TIER3_PREFIXES:
        if record_id.startswith(pref) or source_ref.startswith(pref):
            return ("tier-3-synthetic-taxonomy-anchored", f"tier3-prefix:{pref}")

    # Solodit named drafts fallback -> tier-2
    if record_id.startswith("solodit-spec:") or source_ref.startswith("solodit-spec:"):
        return ("tier-2-verified-public-archive", "solodit-spec-fallback")

    # local-workspace / submission-derived legacy -> tier-2
    if record_tier in {"local-workspace", "submission-derived", "dydx-filed"}:
        return ("tier-2-verified-public-archive", f"record-tier:{record_tier}")
    # W2.7.a (2026-05-16): off-GitHub miners may emit
    # record_tier=tier-2-verified-public-archive directly. Passthrough.
    if record_tier == "tier-2-verified-public-archive":
        return ("tier-2-verified-public-archive", "record-tier:tier-2-verified-public-archive")
    if record_id.startswith("legacy:") or record_id.startswith("solidity-pattern:"):
        return ("tier-2-verified-public-archive", "legacy-workspace-derived")

    if extract_method == "regex-derived":
        return ("tier-3-synthetic-taxonomy-anchored", "extraction-method-regex-derived")

    return ("tier-3-synthetic-taxonomy-anchored", "fallback-unknown-prefix")


def is_real_source_tier(tier_key: str) -> bool:
    return tier_key in REAL_SOURCE_TIERS


# --------------------------------------------------------------------------- #
# Record loading
# --------------------------------------------------------------------------- #


# Minimal YAML scalar/list extractor. Sufficient for the canonical
# hackerman-v1 record shape. Avoids a hard PyYAML dependency.
TOP_SCALAR_RE = re.compile(r"^([a-z_][a-z0-9_]*):\s*(.*)$", re.IGNORECASE)


def _unquote(val: str) -> str:
    val = val.strip()
    if not val:
        return ""
    if (val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'"):
        return val[1:-1]
    return val


def parse_record_yaml_minimal(path: Path) -> Dict[str, Any]:
    """Parse the subset of fields we need from a canonical hackerman-v1
    YAML record. Handles top-level scalars + the
    ``function_shape.shape_tags`` list + best-effort code_snippet fields.
    """
    fields: Dict[str, Any] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return fields
    lines = text.splitlines()
    i = 0
    in_function_shape = False
    in_shape_tags = False
    shape_tags: List[str] = []
    code_pre: List[str] = []
    code_post: List[str] = []
    in_code_pre = False
    in_code_post = False
    while i < len(lines):
        line = lines[i]
        if not line or line.lstrip().startswith("#"):
            i += 1
            continue
        # Detect end of nested blocks: a non-indented line resets context.
        is_top = not (line.startswith(" ") or line.startswith("\t"))
        if is_top:
            in_function_shape = False
            in_shape_tags = False
            in_code_pre = False
            in_code_post = False
            m = TOP_SCALAR_RE.match(line)
            if m:
                key = m.group(1).strip().lower()
                val = _unquote(m.group(2))
                if key == "function_shape" and not val:
                    in_function_shape = True
                elif key in {"code_snippet_pre_fix"} and not val:
                    in_code_pre = True
                elif key in {"code_snippet_post_fix"} and not val:
                    in_code_post = True
                elif val != "":
                    # only set scalars once
                    fields.setdefault(key, val)
        else:
            stripped = line.strip()
            if in_function_shape:
                if stripped.startswith("shape_tags:"):
                    in_shape_tags = True
                elif in_shape_tags and stripped.startswith("- "):
                    shape_tags.append(_unquote(stripped[2:]))
                elif in_shape_tags and not stripped.startswith("- "):
                    in_shape_tags = False
            elif in_code_pre:
                code_pre.append(stripped)
            elif in_code_post:
                code_post.append(stripped)
        i += 1
    if shape_tags:
        fields["function_shape"] = {"shape_tags": shape_tags}
    if code_pre:
        fields["code_snippet_pre_fix"] = "\n".join(code_pre)
    if code_post:
        fields["code_snippet_post_fix"] = "\n".join(code_post)
    return fields


def parse_record_json(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def load_record(record_path: Path) -> Optional[Dict[str, Any]]:
    """Load a hackerman-v1 record from either layout:

    * Per-directory bundle: ``record_path`` is a directory containing
      ``record.json`` (preferred) or ``record.yaml``.
    * Flat file: ``record_path`` is a ``<slug>.json`` / ``<slug>.yaml``
      file placed directly under the bucket directory.

    Prefers JSON over YAML when both exist in a bundle dir. Returns
    None if nothing parseable / empty.
    """
    json_path: Optional[Path] = None
    yaml_path: Optional[Path] = None
    if record_path.is_dir():
        cand_json = record_path / "record.json"
        cand_yaml = record_path / "record.yaml"
        json_path = cand_json if cand_json.exists() else None
        yaml_path = cand_yaml if cand_yaml.exists() else None
    else:
        # Flat-file layout: <bucket>/<slug>.{json,yaml}
        suffix = record_path.suffix.lower()
        if suffix == ".json":
            json_path = record_path
        elif suffix in (".yaml", ".yml"):
            yaml_path = record_path

    record: Dict[str, Any] = {}
    used_path: Optional[Path] = None
    if json_path is not None:
        record = parse_record_json(json_path)
        if record:
            used_path = json_path
    if (not record) and yaml_path is not None:
        record = parse_record_yaml_minimal(yaml_path)
        if record:
            used_path = yaml_path
    if not record:
        return None
    record["_record_path"] = str(used_path or record_path)
    return record


def iter_record_bundles(tags_dir: Path) -> Iterable[Path]:
    """Yield hackerman-record paths from BOTH on-disk corpus layouts:

    1. Per-directory bundle: ``tags/<bucket>/<slug>/record.{json,yaml}``
       (yields the ``<slug>/`` directory).
    2. Flat file: ``tags/<bucket>/<slug>.{json,yaml}`` (yields the file
       itself).

    The flat-file layout is the dominant on-disk shape (~59k records,
    including every newly-ingested own-finding / prior-audit / solodit /
    github-advisory record); the original walk only saw the ~18k bundle
    records, silently dropping the rest. ``load_record`` handles both
    path kinds.

    Quarantine-marker buckets are skipped at this layer (they are also
    caught by the tier-5 classifier downstream, but skipping at the walk
    layer keeps the scan honest).
    """
    if not tags_dir.exists():
        return
    for bucket in sorted(p for p in tags_dir.iterdir() if p.is_dir()):
        if any(m in bucket.name for m in QUARANTINE_PATH_MARKERS):
            continue
        for entry in sorted(bucket.iterdir()):
            if entry.is_dir():
                if (entry / "record.json").exists() or (entry / "record.yaml").exists():
                    yield entry
            elif entry.is_file() and entry.suffix.lower() in (".json", ".yaml", ".yml"):
                yield entry


# --------------------------------------------------------------------------- #
# Seed extraction
# --------------------------------------------------------------------------- #


def extract_diff_seeds(code_snippet: str) -> List[str]:
    """Return diff-style directive tokens captured from a code snippet
    (deduplicated, lowercased, max 32 chars each)."""
    if not code_snippet:
        return []
    out: List[str] = []
    seen: set = set()
    for line in code_snippet.splitlines():
        m = DIFF_LINE_RE.match(line)
        if not m:
            continue
        tok = m.group(1).strip()
        if len(tok) > 80:
            tok = tok[:80]
        key = tok.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(tok)
    return out


def extract_seeds(
    tags_dir: Path,
    *,
    min_recurrence: int = 3,
) -> Dict[str, Any]:
    """Walk the corpus tree, classify, and extract candidate seeds.

    Returns a dict containing:
      - regex_seeds: list of {seed, count, attack_classes, source_records}
      - ast_seeds: list of {seed, attack_class, source_record}
      - stats: tier distribution + scan counters
    """
    tier_counter: Counter = Counter()
    scanned = 0
    real_source = 0
    skipped_synthetic = 0

    # shape_tag literal -> sources/attack_classes
    shape_tag_counts: Counter = Counter()
    shape_tag_attack_classes: Dict[str, Counter] = defaultdict(Counter)
    shape_tag_sources: Dict[str, List[str]] = defaultdict(list)

    ast_seed_rows: List[Dict[str, str]] = []

    for slug_dir in iter_record_bundles(tags_dir):
        scanned += 1
        record = load_record(slug_dir)
        if record is None:
            continue
        tier_key, _reason = classify_tier(record)
        tier_counter[tier_key] += 1
        if not is_real_source_tier(tier_key):
            skipped_synthetic += 1
            continue
        real_source += 1
        record_path = record.get("_record_path", str(slug_dir))
        try:
            record_rel = str(Path(record_path).resolve().relative_to(tags_dir.parent.parent.parent.resolve()))
        except Exception:
            record_rel = record_path
        attack_class = str(record.get("attack_class") or "").strip().lower() or "unknown"

        # Regex seeds: shape_tag literal substrings, dedup-per-record
        shape_tags = (record.get("function_shape") or {}).get("shape_tags") or []
        seen_in_record: set = set()
        for tag in shape_tags:
            tag_norm = str(tag).strip().lower()
            if not tag_norm or tag_norm in seen_in_record:
                continue
            seen_in_record.add(tag_norm)
            if tag_norm in STOPLIST_SHAPE_TAGS:
                continue
            # Skip overly short tokens (1-2 chars)
            if len(tag_norm) < 3:
                continue
            shape_tag_counts[tag_norm] += 1
            shape_tag_attack_classes[tag_norm][attack_class] += 1
            if len(shape_tag_sources[tag_norm]) < 6:
                shape_tag_sources[tag_norm].append(record_rel)

        # AST seeds: diff-style scan on code_snippet_pre_fix / post_fix
        for code_key in ("code_snippet_pre_fix", "code_snippet_post_fix"):
            snippet = record.get(code_key)
            if not snippet:
                continue
            diffs = extract_diff_seeds(str(snippet))
            for d in diffs:
                ast_seed_rows.append(
                    {
                        "seed": d,
                        "seed_kind": "ast_diff_directive",
                        "code_field": code_key,
                        "attack_class": attack_class,
                        "source_record": record_rel,
                        "tier": tier_key,
                    }
                )

    # Filter shape_tag seeds by recurrence
    regex_seed_rows: List[Dict[str, Any]] = []
    for tag, count in shape_tag_counts.items():
        if count < min_recurrence:
            continue
        regex_seed_rows.append(
            {
                "seed": tag,
                "seed_kind": "shape_tag_literal",
                "recurrence_count": count,
                "attack_class_distribution": dict(shape_tag_attack_classes[tag]),
                "source_records_sample": shape_tag_sources[tag],
                "tier_floor": "tier-1-or-tier-2",
            }
        )
    regex_seed_rows.sort(key=lambda r: (-r["recurrence_count"], r["seed"]))

    return {
        "regex_seeds": regex_seed_rows,
        "ast_seeds": ast_seed_rows,
        "stats": {
            "scanned_bundles": scanned,
            "real_source_records": real_source,
            "skipped_synthetic_records": skipped_synthetic,
            "tier_distribution": dict(tier_counter),
            "min_recurrence_threshold": min_recurrence,
            "distinct_regex_seeds": len(regex_seed_rows),
            "distinct_ast_seeds": len(ast_seed_rows),
        },
    }


# --------------------------------------------------------------------------- #
# Emitters
# --------------------------------------------------------------------------- #


def emit_jsonl(report: Dict[str, Any], out_path: Path) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows_written = 0
    with out_path.open("w", encoding="utf-8") as fh:
        for r in report["regex_seeds"]:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
            rows_written += 1
        for r in report["ast_seeds"]:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
            rows_written += 1
    return rows_written


def render_markdown(report: Dict[str, Any], top_n: int = 50) -> str:
    stats = report["stats"]
    regex_seeds = report["regex_seeds"]
    ast_seeds = report["ast_seeds"]

    # Group regex seeds by dominant attack_class
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in regex_seeds[:top_n]:
        # dominant attack class = max-count entry
        ac_dist = r["attack_class_distribution"] or {"unknown": 1}
        dom = max(ac_dist.items(), key=lambda kv: kv[1])[0]
        grouped[dom].append(r)

    lines: List[str] = []
    lines.append("# Hackerman Detector Seeds - PREVIEW (operator-review only)")
    lines.append("")
    lines.append(f"- Generated by: `tools/hackerman-detector-seed-extractor.py`")
    lines.append(f"- Generated at: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} UTC")
    lines.append(f"- Schema: `{SCHEMA}`")
    lines.append(f"- JSONL preview artifact: `.auditooor/candidate_detectors.jsonl` (gitignored)")
    lines.append(f"- Operator hard rule: tier-1 + tier-2 real-source records ONLY; tier-3/4/5 skipped.")
    lines.append("")
    lines.append("> STATUS: PREVIEW. This artifact does NOT feed `make audit` or")
    lines.append("> `tools/audit-deep-runner.py`. Detector-pattern auto-generation is")
    lines.append("> queued for AFTER the current roadmap closes.")
    lines.append("")
    lines.append("## Scan stats")
    lines.append("")
    lines.append(f"- Bundles scanned: **{stats['scanned_bundles']}**")
    lines.append(f"- Real-source (tier-1 + tier-2) retained: **{stats['real_source_records']}**")
    lines.append(f"- Synthetic / fixture / quarantine skipped: **{stats['skipped_synthetic_records']}**")
    lines.append(f"- Min recurrence threshold (regex seeds): **{stats['min_recurrence_threshold']}**")
    lines.append(f"- Distinct regex seeds: **{stats['distinct_regex_seeds']}**")
    lines.append(f"- Distinct AST seeds: **{stats['distinct_ast_seeds']}**")
    lines.append("")
    lines.append("### Tier distribution (full scan)")
    lines.append("")
    lines.append("| Tier | Count |")
    lines.append("|------|-------|")
    for t, c in sorted(stats["tier_distribution"].items()):
        lines.append(f"| `{t}` | {c} |")
    lines.append("")

    # Top-N regex seeds, grouped
    lines.append(f"## Top-{top_n} regex seed candidates (grouped by dominant attack_class)")
    lines.append("")
    if not grouped:
        lines.append("_No regex seeds met the recurrence threshold. Increase corpus size or lower threshold._")
        lines.append("")
    for ac in sorted(grouped.keys()):
        rows = grouped[ac]
        lines.append(f"### attack_class: `{ac}` ({len(rows)} seeds)")
        lines.append("")
        lines.append("| Seed | Recurrence | Attack-class distribution | Sample source records |")
        lines.append("|------|-----------:|---------------------------|-----------------------|")
        for r in rows:
            ac_dist_str = ", ".join(
                f"{k}:{v}" for k, v in sorted(r["attack_class_distribution"].items(), key=lambda kv: -kv[1])
            )
            sample_str = "<br>".join(f"`{s}`" for s in r["source_records_sample"][:3])
            lines.append(f"| `{r['seed']}` | {r['recurrence_count']} | {ac_dist_str} | {sample_str} |")
        lines.append("")

    # AST seeds preview (one section, no recurrence filter)
    lines.append("## AST seed candidates (diff-style directives)")
    lines.append("")
    if not ast_seeds:
        lines.append("_No AST seeds extracted. The corpus currently lacks populated_")
        lines.append("_`code_snippet_pre_fix` / `code_snippet_post_fix` fields. This is_")
        lines.append("_expected for the GHSA/zkbugs/dex-fix-history buckets that mirror_")
        lines.append("_advisory metadata rather than diffs. Future ETL waves that capture_")
        lines.append("_real diff hunks will populate this section._")
        lines.append("")
    else:
        lines.append("| Seed | Field | Attack class | Source record |")
        lines.append("|------|-------|--------------|---------------|")
        for r in ast_seeds[:top_n]:
            lines.append(
                f"| `{r['seed']}` | `{r['code_field']}` | `{r['attack_class']}` | `{r['source_record']}` |"
            )
        lines.append("")

    lines.append("## Provenance discipline")
    lines.append("")
    lines.append("Every seed row in the JSONL carries `source_records_sample` (regex seeds)")
    lines.append("or `source_record` (AST seeds) so the operator can audit the literal")
    lines.append("upstream advisory / fix-history commit that introduced the seed.")
    lines.append("")
    lines.append("Hard rules enforced:")
    lines.append("")
    lines.append("1. Only `tier-1-verified-realtime-api` + `tier-2-verified-public-archive` records")
    lines.append("   contribute to the seed pool. Tier-3/4/5 records are dropped at the tier check.")
    lines.append("2. Quarantine-bucket directories (`_QUARANTINE_*`) are skipped at the walk layer.")
    lines.append("3. The JSONL is gitignored (`.auditooor/candidate_detectors.jsonl`); ONLY the tool")
    lines.append("   and this markdown are committed.")
    lines.append("4. The tool does NOT touch `Makefile`, `tools/audit-deep-runner.py`, or any")
    lines.append("   wiring that feeds `make audit`. Promotion to a real detector is a separate")
    lines.append("   operator-gated step in a future roadmap wave.")
    lines.append("")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--tags-dir",
        type=Path,
        default=DEFAULT_TAGS_DIR,
        help="Root tags directory (default: audit/corpus_tags/tags)",
    )
    parser.add_argument(
        "--output-jsonl",
        type=Path,
        default=DEFAULT_OUTPUT_JSONL,
        help="Output JSONL preview path (default: .auditooor/candidate_detectors.jsonl)",
    )
    parser.add_argument(
        "--output-docs",
        type=Path,
        default=DEFAULT_DOCS_PATH,
        help="Output markdown preview path (default: docs/HACKERMAN_DETECTOR_SEEDS_PREVIEW_2026-05-16.md)",
    )
    parser.add_argument(
        "--min-recurrence",
        type=int,
        default=3,
        help="Minimum recurrence count to retain a regex seed (default: 3)",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=50,
        help="How many top regex seeds to render in the markdown preview (default: 50)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute seeds + print stats, but write no artifact",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON summary to stdout",
    )
    args = parser.parse_args(argv)

    if not args.tags_dir.exists():
        print(f"[seed-extractor] tags directory missing: {args.tags_dir}", file=sys.stderr)
        return 2

    report = extract_seeds(args.tags_dir, min_recurrence=args.min_recurrence)

    if report["stats"]["real_source_records"] == 0:
        print("[seed-extractor] no tier-1/tier-2 records found; aborting", file=sys.stderr)
        return 2

    if not args.dry_run:
        rows = emit_jsonl(report, args.output_jsonl)
        md = render_markdown(report, top_n=args.top_n)
        args.output_docs.parent.mkdir(parents=True, exist_ok=True)
        args.output_docs.write_text(md, encoding="utf-8")
        if not args.json:
            print(f"[seed-extractor] wrote {rows} rows to {args.output_jsonl}")
            print(f"[seed-extractor] wrote markdown preview to {args.output_docs}")
    if args.json:
        summary = {
            "schema": SCHEMA,
            "stats": report["stats"],
            "top_attack_classes_by_seed_count": _top_attack_classes(report, n=10),
            "output_jsonl": None if args.dry_run else str(args.output_jsonl),
            "output_docs": None if args.dry_run else str(args.output_docs),
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        s = report["stats"]
        print(
            f"[seed-extractor] scanned={s['scanned_bundles']} "
            f"real_source={s['real_source_records']} "
            f"regex_seeds={s['distinct_regex_seeds']} "
            f"ast_seeds={s['distinct_ast_seeds']}"
        )
        top = _top_attack_classes(report, n=3)
        print(f"[seed-extractor] top-3 attack classes by seed count: {top}")

    return 0


def _top_attack_classes(report: Dict[str, Any], n: int = 3) -> List[Tuple[str, int]]:
    counts: Counter = Counter()
    for r in report["regex_seeds"]:
        for ac, c in r["attack_class_distribution"].items():
            counts[ac] += c
    return counts.most_common(n)


if __name__ == "__main__":
    sys.exit(main())
