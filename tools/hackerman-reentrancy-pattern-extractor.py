#!/usr/bin/env python3
"""hackerman-reentrancy-pattern-extractor (PREVIEW ONLY).

Walk the Hackerman corpus per-directory record bundles under
``audit/corpus_tags/tags/<bucket>/<slug>/record.{json,yaml}`` and emit a
*preview* JSONL clustering of re-entrancy variant records drawn from
tier-1 and tier-2 verified-source tiers. Synthetic / fixture / quarantine
tiers (tier-3, tier-4, tier-5) are skipped per operator hard rule.

Re-entrancy variants captured (matched against the record's
``attack_class`` and ``bug_class`` fields, plus ``function_shape.shape_tags``):

  * external-call-reentrancy             (canonical ``call -> state-update`` swap)
  * cross-function-reentrancy            (read-only / sibling-function variant)
  * read-only-reentrancy                 (view-function inconsistent state)
  * erc777-reentrancy                    (token-callback hook reentrancy)
  * callback-reentrancy / hook-reentrancy (generic callback-injected reentrancy)
  * flashloan-callback-reentrancy        (flashloan callback hook abuse)

For each matching record the extractor captures:

  * ``record_id`` (provenance)
  * ``record_path`` (relative to repo root)
  * ``attack_class`` / ``bug_class``
  * ``shape_tags`` (from ``function_shape.shape_tags``)
  * ``raw_signature`` (from ``function_shape.raw_signature``)
  * ``fix_pattern`` short summary
  * ``fix_anti_pattern_avoided`` short summary
  * ``code_snippet_pre_fix`` diff-style tokens (when populated)
  * ``code_snippet_post_fix`` diff-style tokens (when populated)
  * ``severity_at_finding`` + ``target_language`` + ``target_repo``
  * ``tier_key`` (tier-1 / tier-2)

Two derived cluster summaries are emitted alongside the per-record
detail rows:

  1. ``variant_counts``: count of records per re-entrancy variant.
  2. ``pre_fix_shape_signals`` / ``post_fix_shape_signals``: counter of
     normalized shape-tag literals / fix-pattern keyword signals
     ("nonReentrant", "checks-effects-interactions", "external call",
     "state update", etc.) observed across the matched records.

The output JSONL lands at ``.auditooor/reentrancy_patterns_preview.jsonl``
(``.auditooor/`` is gitignored). The companion markdown preview at
``docs/HACKERMAN_REENTRANCY_PATTERNS_PREVIEW_<DATE>.md`` (default:
2026-05-16) shows the top variants by record count plus the dominant
pre-fix / post-fix shape signals.

This tool is **PREVIEW ONLY**. It does NOT write to ``Makefile``,
``tools/audit-deep-runner.py``, or anything that participates in
``make audit``. The operator reviews the JSONL and decides whether to
promote any variant cluster to a real detector.

Usage:
    python3 tools/hackerman-reentrancy-pattern-extractor.py \
        --tags-dir audit/corpus_tags/tags \
        --out .auditooor/reentrancy_patterns_preview.jsonl \
        --markdown docs/HACKERMAN_REENTRANCY_PATTERNS_PREVIEW_2026-05-16.md

Exit codes:
    0  success (JSONL + markdown emitted)
    2  bad arguments / missing tags dir
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# Re-entrancy variant taxonomy
# --------------------------------------------------------------------------- #

# Canonical variant keys. Each entry maps to a set of substring matchers
# applied case-insensitively against ``attack_class``, ``bug_class``, and
# the ``function_shape.shape_tags`` array.
REENTRANCY_VARIANTS: Dict[str, Tuple[str, ...]] = {
    "external-call-reentrancy": (
        "external-call-reentrancy",
        "external call reentrancy",
    ),
    "cross-function-reentrancy": (
        "cross-function-reentrancy",
        "cross function reentrancy",
        "sibling-function-reentrancy",
    ),
    "read-only-reentrancy": (
        "read-only-reentrancy",
        "readonly-reentrancy",
        "view-function-reentrancy",
    ),
    "erc777-reentrancy": (
        "erc777-reentrancy",
        "erc-777-reentrancy",
        "erc777 callback",
        "tokensreceived",
    ),
    "callback-reentrancy": (
        "callback-reentrancy",
        "hook-reentrancy",
        "callback-hook-reentrancy",
    ),
    "flashloan-callback-reentrancy": (
        "flashloan-callback-reentrancy",
        "flashloan-callback-mismatch",
        "flash-loan-reentrancy",
    ),
    "generic-reentrancy": (
        # Fallback: a record whose attack_class / bug_class literally
        # contains "reentran" but does not match any of the more specific
        # variants above. Kept last so specific variants win.
        "reentrancy",
        "re-entrancy",
        "reentran",
    ),
}


# Shape-tag / fix-pattern keyword signals we track for cluster summary.
# These are matched case-insensitively as substrings against shape tags
# and against the fix_pattern / fix_anti_pattern_avoided prose.
PRE_FIX_SHAPE_SIGNALS: Tuple[str, ...] = (
    "external call before state update",
    "call before effects",
    "missing nonreentrant",
    "missing reentrancy guard",
    "missing checks-effects-interactions",
    "no reentrancy guard",
    "state update after call",
    "untrusted external call",
    "callback into",
    "low-level call",
    "delegatecall",
    "transfer(",
    "send(",
    ".call{value:",
    "checks-effects-interactions violated",
    "hook called before",
    "tokensreceived",
    "onerc777received",
)

POST_FIX_SHAPE_SIGNALS: Tuple[str, ...] = (
    "nonreentrant",
    "reentrancyguard",
    "checks-effects-interactions",
    "state update before call",
    "effects before interactions",
    "reentrancylock",
    "mutex",
    "_status = _entered",
    "require(!_locked",
    "reentrancyguardupgradeable",
    "vault-reentrancy",
    "ensurenotinvaultcontext",
    "lock acquired",
)


# --------------------------------------------------------------------------- #
# Tier classification
# --------------------------------------------------------------------------- #

# Re-implemented locally rather than imported from the seed-extractor so
# this preview tool stays standalone. Mirrors the canonical taxonomy.

TIER1_SUBSTRINGS: Tuple[str, ...] = (
    "tier-1",
    "verified-realtime-api",
    "ghsa-",
    "cve-",
    "rustsec-",
    "lhf-",
    "imf-",
    "code4rena-",
    "c4-",
    "sherlock-",
    "cantina-",
    "spearbit-",
    "trail-of-bits-",
    "trailofbits-",
    "openzeppelin-audit-",
    "consensys-",
    "halborn-",
    "quantstamp-",
    "chainsecurity-",
    "abdk-",
    "zellic-",
    "audit-report-",
    "public-audit-",
)

TIER2_PREFIXES: Tuple[str, ...] = (
    "solodit:",
    "solodit-",
    "solodit_",
    "public-archive-",
    "bridge-incident-",
    "mev-extraction-",
)

TIER3_PREFIXES: Tuple[str, ...] = (
    "regex-",
    "synthetic-",
    "corpus-mined-",
    "fanout-",
)

TIER4_PREFIXES: Tuple[str, ...] = (
    "fixture-",
    "bundled-",
    "test-fixture-",
)

QUARANTINE_PATH_MARKERS: Tuple[str, ...] = (
    "_QUARANTINE",
    "quarantine",
    "fabricated",
)

REAL_SOURCE_TIERS: Tuple[str, ...] = (
    "tier-1-verified-realtime-api",
    "tier-2-verified-public-archive",
)

TIER1_GIT_SHA_RE = re.compile(r"^[a-f0-9]{8,40}(?::|$|\s)")
SOLODIT_NUMERIC_RE = re.compile(r"^\d{3,8}$")


def classify_tier(record: Dict[str, Any]) -> Tuple[str, str]:
    record_id = str(record.get("record_id") or "")
    source_ref = str(record.get("source_audit_ref") or "")
    extract_method = str(record.get("source_extraction_method") or "").lower()
    record_tier = str(record.get("record_tier") or "")
    haystack = f"{record_id}\n{source_ref}".lower()

    for marker in QUARANTINE_PATH_MARKERS:
        if marker.lower() in haystack:
            return ("tier-5-quarantine", f"quarantine:{marker}")

    for sub in TIER1_SUBSTRINGS:
        if sub.lower() in haystack:
            return ("tier-1-verified-realtime-api", f"tier1:{sub}")
    if TIER1_GIT_SHA_RE.match(source_ref) or TIER1_GIT_SHA_RE.match(record_id):
        return ("tier-1-verified-realtime-api", "git-sha")

    for pref in TIER2_PREFIXES:
        if record_id.startswith(pref) or source_ref.startswith(pref):
            return ("tier-2-verified-public-archive", f"tier2:{pref}")
    if SOLODIT_NUMERIC_RE.match(record_id) or SOLODIT_NUMERIC_RE.match(source_ref):
        return ("tier-2-verified-public-archive", "solodit-numeric")

    for pref in TIER4_PREFIXES:
        if record_id.startswith(pref) or source_ref.startswith(pref):
            return ("tier-4-bundled-fixture", f"tier4:{pref}")
    if extract_method == "dsl-synthetic":
        return ("tier-4-bundled-fixture", "dsl-synthetic")

    for pref in TIER3_PREFIXES:
        if record_id.startswith(pref) or source_ref.startswith(pref):
            return ("tier-3-synthetic-taxonomy-anchored", f"tier3:{pref}")

    if record_tier == "public-corpus":
        # Public corpus records are real-source; defer to verification_tier
        # shape-tag (added downstream by classify_record).
        return ("tier-1-verified-realtime-api", "public-corpus")

    if extract_method == "regex-derived":
        return ("tier-3-synthetic-taxonomy-anchored", "regex-derived")

    return ("tier-3-synthetic-taxonomy-anchored", "fallback")


def classify_record(record: Dict[str, Any]) -> Tuple[str, str]:
    """Return (tier_key, reason). Honors any verification_tier marker
    present in function_shape.shape_tags - those override the heuristic
    classify_tier when present."""
    shape = record.get("function_shape") or {}
    tags = shape.get("shape_tags") or []
    for t in tags:
        if not isinstance(t, str):
            continue
        if "verification_tier:tier-1" in t:
            return ("tier-1-verified-realtime-api", "shape-tag")
        if "verification_tier:tier-2" in t:
            return ("tier-2-verified-public-archive", "shape-tag")
        if "verification_tier:tier-3" in t:
            return ("tier-3-synthetic-taxonomy-anchored", "shape-tag")
        if "verification_tier:tier-4" in t:
            return ("tier-4-bundled-fixture", "shape-tag")
        if "verification_tier:tier-5" in t:
            return ("tier-5-quarantine", "shape-tag")
    return classify_tier(record)


def is_real_source_tier(tier_key: str) -> bool:
    return tier_key in REAL_SOURCE_TIERS


# --------------------------------------------------------------------------- #
# Record loading
# --------------------------------------------------------------------------- #

TOP_SCALAR_RE = re.compile(r"^([a-z_][a-z0-9_]*):\s*(.*)$", re.IGNORECASE)


def _unquote(val: str) -> str:
    val = val.strip()
    if not val:
        return ""
    if (val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'"):
        return val[1:-1]
    return val


def parse_record_yaml_minimal(path: Path) -> Dict[str, Any]:
    """Parse the subset of fields we need from a hackerman-v1 YAML record.
    Avoids a hard PyYAML dependency."""
    fields: Dict[str, Any] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return fields
    lines = text.splitlines()
    in_function_shape = False
    in_shape_tags = False
    in_code_pre = False
    in_code_post = False
    shape_tags: List[str] = []
    raw_sig: Optional[str] = None
    code_pre: List[str] = []
    code_post: List[str] = []
    for line in lines:
        if not line or line.lstrip().startswith("#"):
            continue
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
                elif key == "code_snippet_pre_fix" and not val:
                    in_code_pre = True
                elif key == "code_snippet_post_fix" and not val:
                    in_code_post = True
                elif val != "":
                    fields.setdefault(key, val)
        else:
            stripped = line.strip()
            if in_function_shape:
                if stripped.startswith("shape_tags:"):
                    in_shape_tags = True
                elif stripped.startswith("raw_signature:"):
                    raw_sig = _unquote(stripped.split(":", 1)[1])
                elif in_shape_tags and stripped.startswith("- "):
                    shape_tags.append(_unquote(stripped[2:]))
                elif in_shape_tags and not stripped.startswith("- "):
                    in_shape_tags = False
            elif in_code_pre:
                code_pre.append(stripped)
            elif in_code_post:
                code_post.append(stripped)
    if shape_tags or raw_sig:
        fs: Dict[str, Any] = {}
        if shape_tags:
            fs["shape_tags"] = shape_tags
        if raw_sig:
            fs["raw_signature"] = raw_sig
        fields["function_shape"] = fs
    if code_pre:
        fields["code_snippet_pre_fix"] = "\n".join(code_pre)
    if code_post:
        fields["code_snippet_post_fix"] = "\n".join(code_post)
    return fields


def parse_record_json(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
        return {}
    except (OSError, json.JSONDecodeError):
        return {}


def load_record(record_dir: Path) -> Optional[Dict[str, Any]]:
    """Prefer record.json (already-structured) over record.yaml."""
    json_path = record_dir / "record.json"
    yaml_path = record_dir / "record.yaml"
    record: Dict[str, Any] = {}
    if json_path.exists():
        record = parse_record_json(json_path)
    if (not record) and yaml_path.exists():
        record = parse_record_yaml_minimal(yaml_path)
    if not record:
        return None
    record["_record_path"] = str(json_path if json_path.exists() else yaml_path)
    return record


def iter_record_bundles(tags_dir: Path) -> Iterable[Path]:
    if not tags_dir.exists():
        return
    for bucket in sorted(p for p in tags_dir.iterdir() if p.is_dir()):
        if any(m in bucket.name for m in QUARANTINE_PATH_MARKERS):
            continue
        for slug in sorted(p for p in bucket.iterdir() if p.is_dir()):
            if (slug / "record.json").exists() or (slug / "record.yaml").exists():
                yield slug


# --------------------------------------------------------------------------- #
# Variant matching
# --------------------------------------------------------------------------- #


def match_variant(record: Dict[str, Any]) -> Optional[str]:
    """Return the most-specific re-entrancy variant key matched by the
    record, or None if the record is not a re-entrancy finding.

    Specific variants are checked first (in REENTRANCY_VARIANTS order);
    the ``generic-reentrancy`` fallback only fires when no specific
    variant matches but the record clearly mentions reentrancy.
    """
    ac = (record.get("attack_class") or "").lower()
    bc = (record.get("bug_class") or "").lower()
    shape = record.get("function_shape") or {}
    tags = shape.get("shape_tags") or []
    tag_blob = " ".join(t.lower() for t in tags if isinstance(t, str))
    haystack = f"{ac} | {bc} | {tag_blob}"

    for variant, needles in REENTRANCY_VARIANTS.items():
        for needle in needles:
            if needle in haystack:
                return variant
    return None


# --------------------------------------------------------------------------- #
# Shape-signal scoring
# --------------------------------------------------------------------------- #

DIFF_LINE_RE = re.compile(r"^[+-]\s*([^\s].{0,200})$")


def extract_diff_tokens(code_snippet: str) -> List[str]:
    """Return diff-style directive tokens captured from a code snippet."""
    if not code_snippet:
        return []
    out: List[str] = []
    seen: set = set()
    for line in code_snippet.splitlines():
        m = DIFF_LINE_RE.match(line)
        if not m:
            continue
        tok = m.group(1).strip()
        if len(tok) > 200:
            tok = tok[:200]
        key = tok.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(tok)
    return out


def score_signals(text: str, signals: Tuple[str, ...]) -> List[str]:
    """Return the list of signals from ``signals`` that appear in
    ``text`` (case-insensitive substring match)."""
    lt = text.lower()
    return [s for s in signals if s.lower() in lt]


# --------------------------------------------------------------------------- #
# Cluster extraction
# --------------------------------------------------------------------------- #


def extract_clusters(tags_dir: Path) -> Dict[str, Any]:
    """Walk all real-source records, filter to re-entrancy variants, and
    return a structured cluster report."""
    rows: List[Dict[str, Any]] = []
    variant_counts: Counter = Counter()
    pre_signals_counter: Counter = Counter()
    post_signals_counter: Counter = Counter()
    target_lang_counter: Counter = Counter()
    severity_counter: Counter = Counter()
    tier_counter: Counter = Counter()
    skipped_non_real: int = 0
    skipped_non_reentrancy: int = 0
    scanned: int = 0

    for slug_dir in iter_record_bundles(tags_dir):
        record = load_record(slug_dir)
        if record is None:
            continue
        scanned += 1
        tier_key, _ = classify_record(record)
        if not is_real_source_tier(tier_key):
            skipped_non_real += 1
            continue
        variant = match_variant(record)
        if variant is None:
            skipped_non_reentrancy += 1
            continue

        variant_counts[variant] += 1
        tier_counter[tier_key] += 1

        shape = record.get("function_shape") or {}
        tags = shape.get("shape_tags") or []
        raw_sig = shape.get("raw_signature") or ""

        fix_pattern = record.get("fix_pattern") or ""
        anti_pattern = record.get("fix_anti_pattern_avoided") or ""
        code_pre = record.get("code_snippet_pre_fix") or ""
        code_post = record.get("code_snippet_post_fix") or ""

        # Score pre-fix shape signals against anti-pattern prose + pre-fix
        # code snippet + shape tags.
        pre_haystack = " | ".join(
            [anti_pattern, code_pre, " ".join(t for t in tags if isinstance(t, str))]
        )
        pre_signals = score_signals(pre_haystack, PRE_FIX_SHAPE_SIGNALS)
        for s in pre_signals:
            pre_signals_counter[s] += 1

        post_haystack = " | ".join(
            [fix_pattern, code_post, " ".join(t for t in tags if isinstance(t, str))]
        )
        post_signals = score_signals(post_haystack, POST_FIX_SHAPE_SIGNALS)
        for s in post_signals:
            post_signals_counter[s] += 1

        lang = record.get("target_language") or "unknown"
        target_lang_counter[lang] += 1

        sev = record.get("severity_at_finding") or "unknown"
        severity_counter[sev] += 1

        row = {
            "record_id": record.get("record_id"),
            "record_path": record.get("_record_path"),
            "variant": variant,
            "tier_key": tier_key,
            "attack_class": record.get("attack_class"),
            "bug_class": record.get("bug_class"),
            "target_language": lang,
            "target_repo": record.get("target_repo"),
            "target_component": record.get("target_component"),
            "severity_at_finding": sev,
            "shape_tags": [t for t in tags if isinstance(t, str)],
            "raw_signature": raw_sig,
            "fix_pattern_summary": (fix_pattern or "")[:240],
            "fix_anti_pattern_summary": (anti_pattern or "")[:240],
            "pre_fix_signals": pre_signals,
            "post_fix_signals": post_signals,
            "pre_fix_diff_tokens": extract_diff_tokens(code_pre),
            "post_fix_diff_tokens": extract_diff_tokens(code_post),
        }
        rows.append(row)

    return {
        "summary": {
            "scanned_records": scanned,
            "matched_records": len(rows),
            "skipped_non_real_source": skipped_non_real,
            "skipped_non_reentrancy": skipped_non_reentrancy,
            "variant_counts": dict(variant_counts.most_common()),
            "tier_counts": dict(tier_counter.most_common()),
            "target_language_counts": dict(target_lang_counter.most_common()),
            "severity_counts": dict(severity_counter.most_common()),
            "pre_fix_shape_signal_counts": dict(pre_signals_counter.most_common()),
            "post_fix_shape_signal_counts": dict(post_signals_counter.most_common()),
        },
        "rows": rows,
    }


# --------------------------------------------------------------------------- #
# Emission
# --------------------------------------------------------------------------- #


def emit_jsonl(report: Dict[str, Any], out_path: Path) -> int:
    """Write JSONL: first line = summary envelope; subsequent lines = per-record rows."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with out_path.open("w", encoding="utf-8") as fh:
        envelope = {"_kind": "summary", **report["summary"]}
        fh.write(json.dumps(envelope, sort_keys=True) + "\n")
        written += 1
        for row in report["rows"]:
            fh.write(json.dumps({"_kind": "record", **row}, sort_keys=True) + "\n")
            written += 1
    return written


def render_markdown(report: Dict[str, Any], top_n: int = 30) -> str:
    summary = report["summary"]
    rows = report["rows"]
    lines: List[str] = []
    lines.append("# Hackerman Re-entrancy Patterns Preview - 2026-05-16")
    lines.append("")
    lines.append(
        "PREVIEW only. Derived from real-source corpus records under "
        "`audit/corpus_tags/tags/**/record.{json,yaml}` (tier-1 + tier-2). "
        "Not wired into `make audit`. JSONL artifact lives under "
        "`.auditooor/reentrancy_patterns_preview.jsonl` (gitignored)."
    )
    lines.append("")
    lines.append("## Scan envelope")
    lines.append("")
    lines.append(f"- Records scanned: **{summary['scanned_records']}**")
    lines.append(f"- Records matched (re-entrancy variant): **{summary['matched_records']}**")
    lines.append(f"- Records skipped (not real-source tier): {summary['skipped_non_real_source']}")
    lines.append(f"- Records skipped (not re-entrancy): {summary['skipped_non_reentrancy']}")
    lines.append("")

    lines.append("## Variant counts (top by record count)")
    lines.append("")
    lines.append("| Variant | Records |")
    lines.append("|---|---|")
    for variant, count in summary["variant_counts"].items():
        lines.append(f"| `{variant}` | {count} |")
    lines.append("")

    lines.append("## Tier breakdown")
    lines.append("")
    lines.append("| Tier | Records |")
    lines.append("|---|---|")
    for tier, count in summary["tier_counts"].items():
        lines.append(f"| `{tier}` | {count} |")
    lines.append("")

    lines.append("## Target-language breakdown")
    lines.append("")
    lines.append("| Language | Records |")
    lines.append("|---|---|")
    for lang, count in summary["target_language_counts"].items():
        lines.append(f"| `{lang}` | {count} |")
    lines.append("")

    lines.append("## Severity-at-finding breakdown")
    lines.append("")
    lines.append("| Severity | Records |")
    lines.append("|---|---|")
    for sev, count in summary["severity_counts"].items():
        lines.append(f"| `{sev}` | {count} |")
    lines.append("")

    lines.append("## Common pre-fix shape signals")
    lines.append("")
    lines.append(
        "Pre-fix signals are matched against the record's "
        "`fix_anti_pattern_avoided` prose plus any `code_snippet_pre_fix` "
        "diff body plus the `function_shape.shape_tags` literals. They "
        "describe the *vulnerable* shape that introduced the bug."
    )
    lines.append("")
    if summary["pre_fix_shape_signal_counts"]:
        lines.append("| Signal | Occurrences |")
        lines.append("|---|---|")
        for signal, count in summary["pre_fix_shape_signal_counts"].items():
            lines.append(f"| `{signal}` | {count} |")
    else:
        lines.append("_No pre-fix shape signals matched - corpus records lacked "
                     "`fix_anti_pattern_avoided` / `code_snippet_pre_fix` text "
                     "containing the tracked literals. Gap surfaced for "
                     "operator review._")
    lines.append("")

    lines.append("## Common post-fix shape signals")
    lines.append("")
    lines.append(
        "Post-fix signals are matched against `fix_pattern` prose plus any "
        "`code_snippet_post_fix` diff body plus shape tags. They describe "
        "the *patched* shape (the protection added)."
    )
    lines.append("")
    if summary["post_fix_shape_signal_counts"]:
        lines.append("| Signal | Occurrences |")
        lines.append("|---|---|")
        for signal, count in summary["post_fix_shape_signal_counts"].items():
            lines.append(f"| `{signal}` | {count} |")
    else:
        lines.append("_No post-fix shape signals matched - corpus records lacked "
                     "`fix_pattern` / `code_snippet_post_fix` text containing the "
                     "tracked literals. Gap surfaced for operator review._")
    lines.append("")

    lines.append(f"## Top {top_n} matched records")
    lines.append("")
    lines.append("| Variant | Repo | Lang | Severity | Component | Tier |")
    lines.append("|---|---|---|---|---|---|")
    for row in rows[:top_n]:
        comp = (row.get("target_component") or "")[:60]
        lines.append(
            f"| `{row['variant']}` | `{row.get('target_repo') or ''}` | "
            f"`{row.get('target_language') or ''}` | "
            f"`{row.get('severity_at_finding') or ''}` | "
            f"`{comp}` | `{row.get('tier_key') or ''}` |"
        )
    lines.append("")

    lines.append("## Provenance / how to regenerate")
    lines.append("")
    lines.append(
        "```bash\n"
        "python3 tools/hackerman-reentrancy-pattern-extractor.py \\\n"
        "    --tags-dir audit/corpus_tags/tags \\\n"
        "    --out .auditooor/reentrancy_patterns_preview.jsonl \\\n"
        "    --markdown docs/HACKERMAN_REENTRANCY_PATTERNS_PREVIEW_2026-05-16.md\n"
        "```"
    )
    lines.append("")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _default_repo_root() -> Path:
    here = Path(__file__).resolve().parent
    return here.parent


def main(argv: Optional[List[str]] = None) -> int:
    repo_root = _default_repo_root()
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--tags-dir",
        default=str(repo_root / "audit" / "corpus_tags" / "tags"),
        help="Directory containing per-bucket record bundles.",
    )
    parser.add_argument(
        "--out",
        default=str(repo_root / ".auditooor" / "reentrancy_patterns_preview.jsonl"),
        help="JSONL output path (gitignored by default via .auditooor/).",
    )
    parser.add_argument(
        "--markdown",
        default=str(
            repo_root / "docs" / "HACKERMAN_REENTRANCY_PATTERNS_PREVIEW_2026-05-16.md"
        ),
        help="Markdown preview output path (committed).",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=30,
        help="Number of top records to render in the markdown table.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress stdout chatter.",
    )
    args = parser.parse_args(argv)

    tags_dir = Path(args.tags_dir)
    if not tags_dir.exists():
        sys.stderr.write(
            f"error: --tags-dir not found: {tags_dir}\n"
            "       (expected audit/corpus_tags/tags/ under repo root)\n"
        )
        return 2

    report = extract_clusters(tags_dir)
    out_path = Path(args.out)
    n = emit_jsonl(report, out_path)

    md_path = Path(args.markdown)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_text = render_markdown(report, top_n=args.top_n)
    md_path.write_text(md_text, encoding="utf-8")

    if not args.quiet:
        s = report["summary"]
        sys.stdout.write(
            f"hackerman-reentrancy-pattern-extractor: scanned={s['scanned_records']} "
            f"matched={s['matched_records']} variants={len(s['variant_counts'])} "
            f"jsonl_rows={n} jsonl={out_path} md={md_path}\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
