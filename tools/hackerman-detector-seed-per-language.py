#!/usr/bin/env python3
"""hackerman-detector-seed-per-language (PREVIEW ONLY).

Per-language sibling of ``tools/hackerman-detector-seed-extractor.py``.
The base extractor emits a global top-N seed list across the entire
tier-1 + tier-2 corpus. This tool groups records by ``target_language``
(solidity / vyper / rust / go / circom / move / cairo / noir / leo /
typescript-onchain / python-onchain / huff / assembly / unknown) and
emits a per-language top-N detector seed preview plus a sample fixture
record for each seed.

The output is operator-readable; nothing wires into ``make audit`` or
``tools/audit-deep-runner.py``. The JSONL artifact lands at
``.auditooor/detector_seeds_per_language.jsonl`` (gitignored). The
companion markdown preview surfaces cross-language pattern reuse
opportunities so the operator can decide which seeds to promote to
real detectors in a future roadmap wave.

Two seed families are extracted per language (mirrors the base tool):

  1. Regex seed (``shape_tag_literal``): any literal substring drawn from
     a record's ``function_shape.shape_tags`` array that recurs >=N times
     within a single language bucket. Threshold defaults to 2 (relaxed
     vs the global tool's 3, because per-language buckets are smaller).

  2. AST seed (``diff_style_shape``): scan ``code_snippet_pre_fix`` /
     ``code_snippet_post_fix`` for diff-style directive lines.

The cross-language reuse heuristic picks regex seeds that appear in
>=2 distinct languages and ranks by sum of recurrence across the
languages they appear in.

Usage::

    # Preview run (writes JSONL + markdown)
    python3 tools/hackerman-detector-seed-per-language.py

    # Dry-run (computes seeds, prints summary, writes nothing)
    python3 tools/hackerman-detector-seed-per-language.py --dry-run

    # Adjust top-N per language (default 20)
    python3 tools/hackerman-detector-seed-per-language.py --top-n 30

Exit codes::

    0 - preview generated (or dry-run completed)
    2 - corpus tree missing / unreadable / no tier-1/2 records found
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SCHEMA = "auditooor.hackerman_detector_seed_per_language.v1"

REPO_ROOT_GUESS = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT_GUESS / "audit" / "corpus_tags" / "tags"
DEFAULT_OUTPUT_JSONL = REPO_ROOT_GUESS / ".auditooor" / "detector_seeds_per_language.jsonl"
DEFAULT_DOCS_PATH = (
    REPO_ROOT_GUESS
    / "docs"
    / "HACKERMAN_DETECTOR_SEEDS_PER_LANGUAGE_PREVIEW_2026-05-16.md"
)

# We import the base extractor as a module (its filename contains
# hyphens so we must use importlib).
_BASE_TOOL_PATH = (
    Path(__file__).resolve().parent / "hackerman-detector-seed-extractor.py"
)


def _import_base_tool() -> Any:
    name = "_hackerman_detector_seed_extractor_base"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, str(_BASE_TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


BASE = _import_base_tool()


# Canonical language labels we want to surface in the preview. Anything
# not in this set is bucketed as ``unknown`` (with the raw value preserved
# in a debug column). Quoted YAML variants ("solidity") are folded to
# their unquoted form via lowercase + strip-quotes-and-whitespace.
KNOWN_LANGUAGES = (
    "solidity",
    "vyper",
    "rust",
    "go",
    "circom",
    "move",
    "cairo",
    "noir",
    "leo",
    "typescript-onchain",
    "python-onchain",
    "huff",
    "assembly",
    "cairo-zk",
)


def normalize_language(raw: Any) -> str:
    """Fold YAML-quoted / case-variant language values to the canonical
    lowercase label. Unknown values bucket to ``unknown``.
    """
    if raw is None:
        return "unknown"
    s = str(raw).strip()
    # Strip a surrounding pair of quotes (the minimal YAML parser
    # captures `target_language: "solidity"` with quotes intact).
    if len(s) >= 2 and (
        (s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'")
    ):
        s = s[1:-1].strip()
    s = s.lower()
    if not s:
        return "unknown"
    if s in KNOWN_LANGUAGES:
        return s
    return "unknown"


# --------------------------------------------------------------------------- #
# Per-language seed extraction
# --------------------------------------------------------------------------- #


def extract_per_language_seeds(
    tags_dir: Path,
    *,
    min_recurrence: int = 2,
) -> Dict[str, Any]:
    """Walk the corpus, classify tier + language, extract per-language
    seeds.

    Returns a dict containing::

      per_language: {
        <language>: {
          regex_seeds: [...],
          ast_seeds: [...],
          stats: {scanned, real_source, distinct_regex, distinct_ast},
        }
      }
      cross_language_reuse: [
        {seed, languages: [lang...], total_recurrence, per_language_counts}
      ]
      global_stats: {scanned_bundles, real_source_records, tier_distribution,
                      languages_seen}
    """
    tier_counter: Counter = Counter()
    scanned = 0
    real_source = 0
    skipped_synthetic = 0

    # Per-language tag accumulators
    per_lang_tag_counts: Dict[str, Counter] = defaultdict(Counter)
    per_lang_tag_attack_classes: Dict[str, Dict[str, Counter]] = defaultdict(
        lambda: defaultdict(Counter)
    )
    per_lang_tag_sources: Dict[str, Dict[str, List[str]]] = defaultdict(
        lambda: defaultdict(list)
    )
    # Per-language AST seeds (one row per diff-directive occurrence)
    per_lang_ast_seeds: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    # Per-language scan counters
    per_lang_scanned: Counter = Counter()
    per_lang_real_source: Counter = Counter()

    for slug_dir in BASE.iter_record_bundles(tags_dir):
        scanned += 1
        record = BASE.load_record(slug_dir)
        if record is None:
            continue
        tier_key, _reason = BASE.classify_tier(record)
        tier_counter[tier_key] += 1
        if not BASE.is_real_source_tier(tier_key):
            skipped_synthetic += 1
            continue
        real_source += 1
        lang = normalize_language(record.get("target_language"))
        per_lang_scanned[lang] += 1
        per_lang_real_source[lang] += 1
        record_path = record.get("_record_path", str(slug_dir))
        try:
            record_rel = str(
                Path(record_path)
                .resolve()
                .relative_to(tags_dir.parent.parent.parent.resolve())
            )
        except Exception:
            record_rel = record_path
        attack_class = (
            str(record.get("attack_class") or "").strip().lower() or "unknown"
        )

        shape_tags = (record.get("function_shape") or {}).get("shape_tags") or []
        seen_in_record: set = set()
        for tag in shape_tags:
            tag_norm = str(tag).strip().lower()
            if not tag_norm or tag_norm in seen_in_record:
                continue
            seen_in_record.add(tag_norm)
            if tag_norm in BASE.STOPLIST_SHAPE_TAGS:
                continue
            if len(tag_norm) < 3:
                continue
            per_lang_tag_counts[lang][tag_norm] += 1
            per_lang_tag_attack_classes[lang][tag_norm][attack_class] += 1
            if len(per_lang_tag_sources[lang][tag_norm]) < 6:
                per_lang_tag_sources[lang][tag_norm].append(record_rel)

        for code_key in ("code_snippet_pre_fix", "code_snippet_post_fix"):
            snippet = record.get(code_key)
            if not snippet:
                continue
            diffs = BASE.extract_diff_seeds(str(snippet))
            for d in diffs:
                per_lang_ast_seeds[lang].append(
                    {
                        "seed": d,
                        "seed_kind": "ast_diff_directive",
                        "code_field": code_key,
                        "attack_class": attack_class,
                        "source_record": record_rel,
                        "tier": tier_key,
                        "target_language": lang,
                    }
                )

    per_language: Dict[str, Any] = {}
    for lang in sorted(per_lang_tag_counts.keys() | per_lang_ast_seeds.keys()):
        rows: List[Dict[str, Any]] = []
        for tag, count in per_lang_tag_counts.get(lang, Counter()).items():
            if count < min_recurrence:
                continue
            rows.append(
                {
                    "seed": tag,
                    "seed_kind": "shape_tag_literal",
                    "target_language": lang,
                    "recurrence_count": count,
                    "attack_class_distribution": dict(
                        per_lang_tag_attack_classes[lang][tag]
                    ),
                    "source_records_sample": per_lang_tag_sources[lang][tag],
                    "tier_floor": "tier-1-or-tier-2",
                }
            )
        rows.sort(key=lambda r: (-r["recurrence_count"], r["seed"]))
        ast_rows = per_lang_ast_seeds.get(lang, [])
        per_language[lang] = {
            "regex_seeds": rows,
            "ast_seeds": ast_rows,
            "stats": {
                "real_source_records": per_lang_real_source[lang],
                "distinct_regex_seeds": len(rows),
                "distinct_ast_seeds": len(ast_rows),
            },
        }

    # Cross-language reuse: seeds that appear in >=2 distinct languages.
    cross_seed_per_lang: Dict[str, Dict[str, int]] = defaultdict(dict)
    for lang, payload in per_language.items():
        for r in payload["regex_seeds"]:
            cross_seed_per_lang[r["seed"]][lang] = r["recurrence_count"]
    cross_language_reuse: List[Dict[str, Any]] = []
    for seed, lang_counts in cross_seed_per_lang.items():
        if len(lang_counts) < 2:
            continue
        cross_language_reuse.append(
            {
                "seed": seed,
                "languages": sorted(lang_counts.keys()),
                "language_count": len(lang_counts),
                "total_recurrence": sum(lang_counts.values()),
                "per_language_counts": dict(lang_counts),
            }
        )
    cross_language_reuse.sort(
        key=lambda r: (-r["language_count"], -r["total_recurrence"], r["seed"])
    )

    return {
        "per_language": per_language,
        "cross_language_reuse": cross_language_reuse,
        "global_stats": {
            "scanned_bundles": scanned,
            "real_source_records": real_source,
            "skipped_synthetic_records": skipped_synthetic,
            "tier_distribution": dict(tier_counter),
            "languages_seen": sorted(per_language.keys()),
            "min_recurrence_threshold": min_recurrence,
        },
    }


# --------------------------------------------------------------------------- #
# Emitters
# --------------------------------------------------------------------------- #


def emit_jsonl(report: Dict[str, Any], out_path: Path, *, top_n: int = 20) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows_written = 0
    with out_path.open("w", encoding="utf-8") as fh:
        for lang in sorted(report["per_language"].keys()):
            payload = report["per_language"][lang]
            for r in payload["regex_seeds"][:top_n]:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
                rows_written += 1
            for r in payload["ast_seeds"][:top_n]:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
                rows_written += 1
        for r in report["cross_language_reuse"]:
            row = dict(r)
            row["seed_kind"] = "cross_language_reuse"
            fh.write(json.dumps(row, sort_keys=True) + "\n")
            rows_written += 1
    return rows_written


def render_markdown(report: Dict[str, Any], top_n: int = 20) -> str:
    gs = report["global_stats"]
    per_lang = report["per_language"]
    cross = report["cross_language_reuse"]

    lines: List[str] = []
    lines.append(
        "# Hackerman Detector Seeds - Per-Language PREVIEW (operator-review only)"
    )
    lines.append("")
    lines.append(
        "- Generated by: `tools/hackerman-detector-seed-per-language.py`"
    )
    lines.append(
        f"- Generated at: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} UTC"
    )
    lines.append(f"- Schema: `{SCHEMA}`")
    lines.append(
        "- JSONL preview artifact: `.auditooor/detector_seeds_per_language.jsonl` (gitignored)"
    )
    lines.append(
        "- Sibling tool: `tools/hackerman-detector-seed-extractor.py` (global top-N variant)"
    )
    lines.append("")
    lines.append(
        "> STATUS: PREVIEW. This artifact does NOT feed `make audit` or"
    )
    lines.append(
        "> `tools/audit-deep-runner.py`. Detector-pattern auto-generation is"
    )
    lines.append("> queued for a future roadmap wave; operator-gated.")
    lines.append("")

    # Global scan stats
    lines.append("## Global scan stats")
    lines.append("")
    lines.append(f"- Bundles scanned: **{gs['scanned_bundles']}**")
    lines.append(
        f"- Real-source (tier-1 + tier-2) retained: **{gs['real_source_records']}**"
    )
    lines.append(
        f"- Synthetic / fixture / quarantine skipped: **{gs['skipped_synthetic_records']}**"
    )
    lines.append(
        f"- Min recurrence threshold (per-language regex seeds): **{gs['min_recurrence_threshold']}**"
    )
    lines.append(
        f"- Distinct languages observed: **{len(gs['languages_seen'])}**"
    )
    lines.append(f"- Top-N rendered per language: **{top_n}**")
    lines.append("")
    lines.append("### Tier distribution (full scan)")
    lines.append("")
    lines.append("| Tier | Count |")
    lines.append("|------|-------|")
    for t, c in sorted(gs["tier_distribution"].items()):
        lines.append(f"| `{t}` | {c} |")
    lines.append("")

    # Language record counts
    lines.append("### Records per language (real-source only)")
    lines.append("")
    lines.append("| Language | Real-source records | Distinct regex seeds | Distinct AST seeds |")
    lines.append("|----------|---------------------:|---------------------:|--------------------:|")
    for lang in sorted(per_lang.keys()):
        s = per_lang[lang]["stats"]
        lines.append(
            f"| `{lang}` | {s['real_source_records']} | "
            f"{s['distinct_regex_seeds']} | {s['distinct_ast_seeds']} |"
        )
    lines.append("")

    # Per-language top-N tables
    for lang in sorted(per_lang.keys()):
        payload = per_lang[lang]
        rows = payload["regex_seeds"][:top_n]
        lines.append(f"## Language: `{lang}` - top-{top_n} regex seed candidates")
        lines.append("")
        lines.append(
            f"- Real-source records in this language: **{payload['stats']['real_source_records']}**"
        )
        lines.append(
            f"- Distinct regex seeds (over recurrence threshold): **{payload['stats']['distinct_regex_seeds']}**"
        )
        lines.append(
            f"- Distinct AST seeds: **{payload['stats']['distinct_ast_seeds']}**"
        )
        lines.append("")
        if not rows:
            lines.append(
                "_No regex seeds met the recurrence threshold for this language. "
                "Likely a small or shape-tag-sparse bucket; raise corpus size or "
                "lower threshold to surface preview seeds._"
            )
            lines.append("")
            continue
        lines.append(
            "| Seed | Recurrence | Top attack class | Sample fixture record |"
        )
        lines.append(
            "|------|-----------:|------------------|-----------------------|"
        )
        for r in rows:
            ac_dist = r["attack_class_distribution"] or {"unknown": 1}
            top_ac = max(ac_dist.items(), key=lambda kv: kv[1])[0]
            sample = (
                r["source_records_sample"][0]
                if r["source_records_sample"]
                else "(no sample)"
            )
            lines.append(
                f"| `{r['seed']}` | {r['recurrence_count']} | `{top_ac}` | `{sample}` |"
            )
        lines.append("")

    # Cross-language reuse opportunities
    lines.append("## Cross-language pattern reuse opportunities")
    lines.append("")
    lines.append(
        "Regex seeds that surface in >=2 distinct language buckets are candidates"
    )
    lines.append(
        "for a shared detector implementation across the language adapters. The"
    )
    lines.append(
        "table below ranks by language-count first, then by total recurrence."
    )
    lines.append("")
    if not cross:
        lines.append("_No cross-language regex-seed overlap detected. This is_")
        lines.append("_expected for shape-tag schemas that already encode language_")
        lines.append("_into the tag literal (e.g. `sherlock-solidity`). Tag-normalization_")
        lines.append("_(stripping language prefixes) is a future enhancement._")
        lines.append("")
    else:
        lines.append(
            "| Seed | Languages | Lang count | Total recurrence | Per-language counts |"
        )
        lines.append(
            "|------|-----------|-----------:|-----------------:|---------------------|"
        )
        for r in cross[: top_n * 2]:
            langs_str = ", ".join(f"`{l}`" for l in r["languages"])
            per_lang_str = ", ".join(
                f"{l}:{c}"
                for l, c in sorted(
                    r["per_language_counts"].items(), key=lambda kv: -kv[1]
                )
            )
            lines.append(
                f"| `{r['seed']}` | {langs_str} | "
                f"{r['language_count']} | {r['total_recurrence']} | {per_lang_str} |"
            )
        lines.append("")

    # Structural-vs-metadata commentary (operator-readable)
    lines.append("## Structural-vs-metadata triage hints")
    lines.append("")
    lines.append(
        "Not every cross-language seed maps to a real structural detector. The"
    )
    lines.append(
        "top of the reuse table is dominated by **corpus-metadata** tags that"
    )
    lines.append(
        "leak verification-tier provenance into the shape_tag array (e.g."
    )
    lines.append(
        "`verification_tier:tier-1-verified-realtime-api`,"
    )
    lines.append(
        "`fix-commit-shape-unclassified`, `diff-derived-pattern`)."
    )
    lines.append(
        "These should be filtered out before any detector-promotion decision."
    )
    lines.append("")
    lines.append(
        "Structural seeds the operator should actually look at first:"
    )
    lines.append("")
    lines.append(
        "1. **zk-circuit underconstraint family** - `vuln-under-constrained`,"
    )
    lines.append(
        "   `rootcause-missing-input-constraints`,"
    )
    lines.append(
        "   `rootcause-wrong-translation-of-logic-into-constraints`,"
    )
    lines.append(
        "   `rootcause-assigned-but-unconstrained` all reuse across"
    )
    lines.append(
        "   `circom` + `rust` (Halo2/zkSync) + `cairo-zk`. A single shared"
    )
    lines.append("   detector spec with three language adapters is a clear win.")
    lines.append("")
    lines.append(
        "2. **EVM reentrancy family** - `external-call-reentrancy` + `reentrancy`"
    )
    lines.append(
        "   reuse across `solidity` + `vyper`. Slither's reentrancy detector"
    )
    lines.append(
        "   already covers solidity; a vyper adapter (or vyper-specific Slither"
    )
    lines.append(
        "   port) closes the missing surface. AMM/yield buckets where vyper is"
    )
    lines.append(
        "   prevalent (Curve, Yearn) make this high-leverage."
    )
    lines.append("")
    lines.append(
        "3. **DEX-AMM domain shape** - `dex-amm` reuse across `solidity`"
    )
    lines.append(
        "   + `vyper` is a domain marker, but the underlying bug families it"
    )
    lines.append(
        "   tags (price oracle manipulation, slippage drift, invariant rebalance"
    )
    lines.append(
        "   skew) are themselves cross-language. Operator review: walk the"
    )
    lines.append(
        "   sampled records to recover the concrete shape inside `dex-amm` and"
    )
    lines.append("   promote those rather than the umbrella tag.")
    lines.append("")
    lines.append(
        "4. **CosmWasm wasmd surface** - `pkg-github.com/cosmwasm/wasmd` reuse"
    )
    lines.append(
        "   across `go` + `rust` reflects the dual-language footprint of"
    )
    lines.append(
        "   wasmd integrations (host go + contract rust). Detectors that"
    )
    lines.append(
        "   reason about VM <-> host boundary mismatches benefit from a"
    )
    lines.append("   coordinated two-adapter approach.")
    lines.append("")
    lines.append(
        "5. **Consensus / L1-client surface** - `domain-l1-client`,"
    )
    lines.append(
        "   `domain-consensus` reuse across `go` + `rust` + `typescript-onchain`"
    )
    lines.append(
        "   reflects the polyglot reality of modern L1 clients (geth/erigon in"
    )
    lines.append(
        "   go, reth in rust, optimism contracts in solidity, op-node in go,"
    )
    lines.append(
        "   client-side libs in TS). Cross-client divergence detectors are the"
    )
    lines.append("   target capability here.")
    lines.append("")
    lines.append(
        "Stop-tags that are NOT structural and should be filtered before any"
    )
    lines.append("detector-spec authoring:")
    lines.append("")
    lines.append("- `verification_tier:*` - provenance metadata, not shape.")
    lines.append(
        "- `diff-derived-pattern`, `diff-derived-rollback`,"
    )
    lines.append(
        "  `fix-commit-shape-unclassified` - ETL-derived audit markers."
    )
    lines.append(
        "- `behavior-rollback-of-prior-change` - bug-history marker, not"
    )
    lines.append("  a shape (although correlated with high-FP areas)."
    )
    lines.append(
        "- `zkbugs-config`, `codegen`, `semantic-analysis`, `type-system-bug`,"
    )
    lines.append(
        "  `compiler-other`, `abi-codec-bug` - bucket-origin markers; the real"
    )
    lines.append(
        "  structural shapes live one layer down in the per-record"
    )
    lines.append("  `function_shape.raw_signature` field, not the tag list.")
    lines.append("")

    # Provenance & rules section
    lines.append("## Provenance discipline")
    lines.append("")
    lines.append(
        "Every seed row in the JSONL carries `source_records_sample` (regex seeds)"
    )
    lines.append(
        "or `source_record` (AST seeds) so the operator can audit the literal"
    )
    lines.append(
        "upstream advisory / fix-history commit that introduced the seed. The"
    )
    lines.append(
        "cross-language reuse rows carry `per_language_counts` for the same"
    )
    lines.append("provenance roll-up.")
    lines.append("")
    lines.append("Hard rules enforced:")
    lines.append("")
    lines.append(
        "1. Only `tier-1-verified-realtime-api` + `tier-2-verified-public-archive`"
    )
    lines.append(
        "   records contribute to the per-language seed pools. Tier-3/4/5 records"
    )
    lines.append(
        "   are dropped at the tier-classification step (mirrors the global tool)."
    )
    lines.append(
        "2. Quarantine-bucket directories (`_QUARANTINE_*`) are skipped at the walk layer."
    )
    lines.append(
        "3. The JSONL is gitignored (`.auditooor/detector_seeds_per_language.jsonl`);"
    )
    lines.append("   only the tool, this markdown, and the test live in version control.")
    lines.append(
        "4. The tool does NOT touch `Makefile`, `tools/audit-deep-runner.py`, or any"
    )
    lines.append(
        "   wiring that feeds `make audit`. Promotion to a real per-language detector"
    )
    lines.append("   is a separate operator-gated step in a future roadmap wave.")
    lines.append("")
    lines.append("## How to consume this preview")
    lines.append("")
    lines.append(
        "Pick a per-language section above and walk the top-N rows. For each row:"
    )
    lines.append("")
    lines.append(
        "1. Open the sample fixture record at the cited path and read the raw"
    )
    lines.append(
        "   shape_tag list to understand the surrounding context (the seed is one"
    )
    lines.append("   tag of many)."
    )
    lines.append(
        "2. Decide whether the seed is a real structural shape (e.g. `delegatecall`)"
    )
    lines.append(
        "   or a corpus-metadata artifact (e.g. a finding id prefix). Only structural"
    )
    lines.append("   shapes should advance to detector promotion."
    )
    lines.append(
        "3. If the seed appears in the Cross-Language Reuse table, it is a"
    )
    lines.append(
        "   higher-leverage candidate - one detector spec, multiple language adapters."
    )
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
        help="Output JSONL preview path (default: .auditooor/detector_seeds_per_language.jsonl)",
    )
    parser.add_argument(
        "--output-docs",
        type=Path,
        default=DEFAULT_DOCS_PATH,
        help=(
            "Output markdown preview path "
            "(default: docs/HACKERMAN_DETECTOR_SEEDS_PER_LANGUAGE_PREVIEW_2026-05-16.md)"
        ),
    )
    parser.add_argument(
        "--min-recurrence",
        type=int,
        default=2,
        help="Minimum recurrence count to retain a per-language regex seed (default: 2)",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=20,
        help="How many top regex seeds to render per language in the markdown (default: 20)",
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
        print(
            f"[seed-per-lang] tags directory missing: {args.tags_dir}",
            file=sys.stderr,
        )
        return 2

    report = extract_per_language_seeds(
        args.tags_dir, min_recurrence=args.min_recurrence
    )

    if report["global_stats"]["real_source_records"] == 0:
        print(
            "[seed-per-lang] no tier-1/tier-2 records found; aborting",
            file=sys.stderr,
        )
        return 2

    if not args.dry_run:
        rows = emit_jsonl(report, args.output_jsonl, top_n=args.top_n)
        md = render_markdown(report, top_n=args.top_n)
        args.output_docs.parent.mkdir(parents=True, exist_ok=True)
        args.output_docs.write_text(md, encoding="utf-8")
        if not args.json:
            print(
                f"[seed-per-lang] wrote {rows} rows to {args.output_jsonl}"
            )
            print(
                f"[seed-per-lang] wrote markdown preview to {args.output_docs}"
            )

    if args.json:
        summary = {
            "schema": SCHEMA,
            "global_stats": report["global_stats"],
            "languages_seen": report["global_stats"]["languages_seen"],
            "top_cross_language_seeds": [
                {
                    "seed": r["seed"],
                    "languages": r["languages"],
                    "language_count": r["language_count"],
                    "total_recurrence": r["total_recurrence"],
                }
                for r in report["cross_language_reuse"][:5]
            ],
            "output_jsonl": None if args.dry_run else str(args.output_jsonl),
            "output_docs": None if args.dry_run else str(args.output_docs),
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        gs = report["global_stats"]
        print(
            f"[seed-per-lang] scanned={gs['scanned_bundles']} "
            f"real_source={gs['real_source_records']} "
            f"languages={len(gs['languages_seen'])} "
            f"cross_language_seeds={len(report['cross_language_reuse'])}"
        )
        for lang in gs["languages_seen"]:
            s = report["per_language"][lang]["stats"]
            print(
                f"[seed-per-lang]   {lang}: records={s['real_source_records']} "
                f"regex_seeds={s['distinct_regex_seeds']} "
                f"ast_seeds={s['distinct_ast_seeds']}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
