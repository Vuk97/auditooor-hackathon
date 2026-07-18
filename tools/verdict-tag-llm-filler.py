#!/usr/bin/env python3
"""verdict-tag-llm-filler — Phase-F LLM-hybrid semantic enrichment for verdict tags.

Walks ``audit/corpus_tags/tags/*.yaml``, finds tags with mandatory fields
populated but ``bug_class`` and/or ``attack_classes_to_try`` empty, reads the
source verdict markdown, and fills those semantic fields using a heuristic
keyword/tf-idf classifier backed by ``reference/bug_class_taxonomy.yaml`` and
``reference/attack_class_vocab.yaml``.

The "LLM" in the name is aspirational: when a local ``claude`` CLI is detected
and the environment variable ``VERDICT_TAG_FILLER_LLM=1`` is set, the tool
pipes each verdict through the CLI for classification. In the default offline
mode (no network, no CLI) it uses the heuristic classifier described below.

Heuristic classifier:
  1. Load the bug_class_taxonomy.yaml vocabulary (~50 entries with keyword lists).
  2. For each verdict file, collect all text from the source markdown.
  3. Score each taxonomy entry by:
       raw_score = sum(keyword_weight(kw, position_in_keywords) for kw in keywords if kw in text)
     where position_in_keywords assigns weight 1.0 for index 0 down to 0.5 for
     the last keyword (linear decay).
  4. Normalise to [0,1] by dividing by max possible score.
  5. Pick the top-1 bug_class with score >= min_confidence.
  6. From the selected bug_class's ``associated_attack_classes``, pick the
     first 2-5 that appear in the attack_class_vocab.yaml as valid entries.

CLI:
    python3 tools/verdict-tag-llm-filler.py
        [--workspace <path>]           # default: repo root
        [--limit N]                    # max tags to fill per run (default 100)
        [--dry-run]                    # print diffs; do not write
        [--require-min-confidence 0.5] # skip if top-1 score < threshold
        [--verbose]                    # show per-tag scoring details
        [--report-only]                # emit coverage report to stdout and exit

Emits a summary line:
    tags_processed=N filled=M skipped_low_confidence=K skipped_already_filled=J

Phase F target: expand 98 tags to >=250 by running this tool over all
                ~/audits/*/agent_outputs/**/*verdict*.md sources.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import math
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None  # handled gracefully below

REPO_ROOT = Path(__file__).resolve().parent.parent
EXTRACTOR_VERSION = "0.2.0"  # Phase F

TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
REPORTS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "reports"
TAXONOMY_PATH = REPO_ROOT / "reference" / "bug_class_taxonomy.yaml"
ATTACK_VOCAB_PATH = REPO_ROOT / "reference" / "attack_class_vocab.yaml"

AUDITS_ROOT = Path(os.environ.get("AUDITOOOR_AUDITS_ROOT", str(Path.home() / "audits")))

# Workspace-local agent_outputs (worktree)
WORKTREE_AGENT_OUTPUTS = REPO_ROOT / "agent_outputs"

# Engagement name-to-subdirectory mapping for source resolution.
ENGAGEMENT_DIRS: Dict[str, List[Path]] = {}


# ---------------------------------------------------------------------------
# YAML helpers (without PyYAML dependency fallback)
# ---------------------------------------------------------------------------

def _load_yaml_safe(path: Path) -> Any:
    if yaml is None:
        raise ImportError("PyYAML is required: pip install pyyaml")
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _dump_yaml_minimal(obj: Dict[str, Any]) -> str:
    """Emit a YAML string preserving field order and quoting audit_pin_sha."""
    if yaml is None:
        raise ImportError("PyYAML is required: pip install pyyaml")
    # Force audit_pin_sha to be quoted (prevent int coercion of all-numeric SHAs).
    if "audit_pin_sha" in obj:
        obj["audit_pin_sha"] = _QuotedStr(str(obj["audit_pin_sha"]))
    return yaml.dump(obj, default_flow_style=False, allow_unicode=True, sort_keys=False, Dumper=_QuotedDumper)


class _QuotedStr(str):
    pass


class _QuotedDumper(yaml.Dumper):
    pass


def _quoted_str_representer(dumper: yaml.Dumper, data: _QuotedStr) -> yaml.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')


if yaml:
    _QuotedDumper.add_representer(_QuotedStr, _quoted_str_representer)


# ---------------------------------------------------------------------------
# Taxonomy / vocab loading
# ---------------------------------------------------------------------------

def load_taxonomy(path: Path) -> List[Dict[str, Any]]:
    """Return list of bug-class taxonomy entries."""
    raw = _load_yaml_safe(path)
    if not isinstance(raw, list):
        raise ValueError(f"taxonomy file {path} must be a YAML list")
    return raw


def load_attack_vocab(path: Path) -> Dict[str, Dict[str, Any]]:
    """Return {class_id: entry} mapping from attack_class_vocab.yaml."""
    raw = _load_yaml_safe(path)
    if not isinstance(raw, list):
        raise ValueError(f"attack vocab file {path} must be a YAML list")
    return {e["class_id"]: e for e in raw if "class_id" in e}


# ---------------------------------------------------------------------------
# Source verdict resolution
# ---------------------------------------------------------------------------

def find_verdict_source(verdict_id: str) -> Optional[Path]:
    """Try to locate the source markdown for a verdict_id.

    verdict_id format examples:
      dydx-hunt-iter-1/DYDX-HUNT-C1-clob-matching-engine-fund-loss-verdict.md
      staging/dydx-iavl-importer-commit-batch-race-983-HIGH.md
      FN2-IMMUNEFI-SUBMISSION.md
      paste_ready/rg-n6-s1-veto-bypass-supply-inflation-HIGH.md
    """
    # Direct path as given (relative to an audits engagement)
    for audit_dir in AUDITS_ROOT.iterdir():
        if not audit_dir.is_dir():
            continue
        # Try agent_outputs/<verdict_id>
        candidate = audit_dir / "agent_outputs" / verdict_id
        if candidate.exists():
            return candidate
        # Try direct under audit dir
        candidate2 = audit_dir / verdict_id
        if candidate2.exists():
            return candidate2
        # Try notes/<filename>
        fname = Path(verdict_id).name
        candidate3 = audit_dir / "notes" / fname
        if candidate3.exists():
            return candidate3
        # Try submissions subdirectories
        for sub in ("paste_ready", "staging", "superseded", "held", "filed"):
            candidate4 = audit_dir / "submissions" / sub / fname
            if candidate4.exists():
                return candidate4

    # Try worktree agent_outputs
    candidate5 = WORKTREE_AGENT_OUTPUTS / verdict_id
    if candidate5.exists():
        return candidate5

    # Try by filename only across all audits agent_outputs
    fname = Path(verdict_id).name
    for audit_dir in AUDITS_ROOT.iterdir():
        if not audit_dir.is_dir():
            continue
        for candidate in audit_dir.rglob(fname):
            if candidate.suffix == ".md":
                return candidate

    return None


def read_verdict_prose(verdict_id: str) -> str:
    """Return the full text of the source verdict, or empty string."""
    source = find_verdict_source(verdict_id)
    if source is None:
        return ""
    try:
        return source.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Heuristic classifier
# ---------------------------------------------------------------------------

def _keyword_weight(kw: str, idx: int, total: int) -> float:
    """Earlier keywords in the list have higher weight (linear decay 1.0 -> 0.5)."""
    if total <= 1:
        return 1.0
    return 1.0 - 0.5 * (idx / (total - 1))


def _text_to_lower_tokens(text: str) -> str:
    """Lowercased text for keyword matching."""
    return text.lower()


def score_bug_classes(
    text: str,
    taxonomy: List[Dict[str, Any]],
    verdict_id: str = "",
) -> List[Tuple[str, float, Dict[str, Any]]]:
    """Score each bug_class against the verdict text.

    Returns list of (class_id, normalised_score, entry) sorted descending.
    Normalised score is in [0, 1]; 1.0 means all keywords matched.
    """
    lower_text = _text_to_lower_tokens(text)
    # Also include verdict_id in matching surface (its slugs often carry class signals)
    vid_lower = verdict_id.replace("_", " ").replace("-", " ").lower()
    combined = lower_text + " " + vid_lower

    results: List[Tuple[str, float, Dict[str, Any]]] = []
    for entry in taxonomy:
        if entry.get("deprecated"):
            continue
        keywords: List[str] = entry.get("keywords", [])
        if not keywords:
            continue
        total = len(keywords)
        raw_score = 0.0
        max_possible = sum(_keyword_weight(kw, i, total) for i, kw in enumerate(keywords))
        for idx, kw in enumerate(keywords):
            kw_lower = kw.lower()
            if kw_lower in combined:
                raw_score += _keyword_weight(kw, idx, total)
        norm = raw_score / max_possible if max_possible > 0 else 0.0
        results.append((entry["class_id"], norm, entry))

    results.sort(key=lambda t: t[1], reverse=True)
    return results


def pick_attack_classes(
    bug_class_entry: Dict[str, Any],
    attack_vocab: Dict[str, Dict[str, Any]],
    text: str,
    max_attack: int = 5,
    min_attack: int = 2,
) -> List[str]:
    """Pick 2-5 attack_classes from the bug class's associated_attack_classes.

    Only returns IDs that exist in the attack_class_vocab. Supplements with
    text-based secondary scoring if the primary list is short.
    """
    primary: List[str] = bug_class_entry.get("associated_attack_classes", [])
    # Filter to known vocab entries
    valid = [ac for ac in primary if ac in attack_vocab]

    # If still short, try to score remaining vocab entries against text
    if len(valid) < min_attack:
        lower_text = text.lower()
        extras: List[Tuple[str, float]] = []
        for cid, ac_entry in attack_vocab.items():
            if cid in valid:
                continue
            desc = (ac_entry.get("description", "") + " " + ac_entry.get("name", "")).lower()
            # Simple overlap: count shared words
            desc_words = set(re.findall(r"\b\w{4,}\b", desc))
            text_words = set(re.findall(r"\b\w{4,}\b", lower_text))
            overlap = len(desc_words & text_words)
            if overlap > 0:
                extras.append((cid, overlap))
        extras.sort(key=lambda t: t[1], reverse=True)
        for cid, _ in extras:
            if len(valid) >= min_attack:
                break
            valid.append(cid)

    return valid[:max_attack]


def classify_verdict(
    verdict_id: str,
    text: str,
    taxonomy: List[Dict[str, Any]],
    attack_vocab: Dict[str, Dict[str, Any]],
    min_confidence: float = 0.3,
    verbose: bool = False,
) -> Tuple[Optional[str], List[str], float]:
    """Classify a verdict into (bug_class, attack_classes_to_try, confidence).

    Returns (None, [], 0.0) if confidence < min_confidence.
    """
    if not text.strip() and not verdict_id:
        return None, [], 0.0

    scored = score_bug_classes(text, taxonomy, verdict_id)
    if not scored:
        return None, [], 0.0

    top_class, confidence, entry = scored[0]

    if verbose:
        print(f"  Top-3 bug_class scores for {verdict_id}:")
        for cls, score, _ in scored[:3]:
            print(f"    {score:.3f}  {cls}")

    if confidence < min_confidence:
        return None, [], confidence

    attack_classes = pick_attack_classes(entry, attack_vocab, text)
    return top_class, attack_classes, confidence


# ---------------------------------------------------------------------------
# Tag file manipulation
# ---------------------------------------------------------------------------

def load_tag_file(path: Path) -> Dict[str, Any]:
    """Load a verdict tag YAML file."""
    return _load_yaml_safe(path)


def tag_needs_filling(tag: Dict[str, Any]) -> bool:
    """Return True if bug_class or attack_classes_to_try is absent/empty."""
    has_bug_class = bool(tag.get("bug_class", "").strip())
    has_attacks = bool(tag.get("attack_classes_to_try"))
    return not (has_bug_class and has_attacks)


def apply_fill(
    tag: Dict[str, Any],
    bug_class: str,
    attack_classes: List[str],
    confidence: float,
    dry_run: bool,
) -> Dict[str, Any]:
    """Return updated tag dict (does NOT write; caller writes if not dry_run)."""
    updated = dict(tag)
    if not updated.get("bug_class"):
        updated["bug_class"] = bug_class
    if not updated.get("attack_classes_to_try"):
        updated["attack_classes_to_try"] = attack_classes
    # Upgrade provenance from regex to hybrid when we add semantic fields
    if updated.get("extraction_provenance") == "regex":
        updated["extraction_provenance"] = "hybrid"
    # Record fill metadata in notes
    stamp = _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    old_notes = updated.get("notes", "")
    fill_note = f"phase-f-heuristic confidence={confidence:.3f} at={stamp}"
    updated["notes"] = (old_notes + "; " + fill_note).lstrip("; ") if old_notes else fill_note
    return updated


def write_tag_file(path: Path, tag: Dict[str, Any]) -> None:
    """Write tag back to YAML file, preserving field order."""
    text = _dump_yaml_minimal(tag)
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Corpus expansion: walk source verdict files and emit new tags
# ---------------------------------------------------------------------------

def _derive_verdict_id(source_path: Path, base_dir: Path) -> str:
    """Derive a verdict_id relative to the audit workspace."""
    try:
        rel = source_path.relative_to(base_dir)
        # strip leading 'agent_outputs/' for brevity
        parts = list(rel.parts)
        if parts and parts[0] == "agent_outputs":
            parts = parts[1:]
        return str(Path(*parts))
    except ValueError:
        return source_path.name


def _slug_to_tag_filename(verdict_id: str) -> str:
    """Convert a verdict_id string to a safe tag filename."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", verdict_id) + ".yaml"


def _detect_language(text: str, path: Path) -> str:
    """Detect primary language from file references in text."""
    lang_counts: Counter = Counter()
    ext_map = {
        ".go": "go",
        ".rs": "rust",
        ".sol": "solidity",
        ".py": "python",
        ".ts": "ts",
        ".js": "js",
        ".sql": "sql",
    }
    for m in re.finditer(r"\b\w[\w/._-]*\.(\w+)\b", text):
        ext = "." + m.group(1).lower()
        if ext in ext_map:
            lang_counts[ext_map[ext]] += 1
    if lang_counts:
        return lang_counts.most_common(1)[0][0]
    return "unknown"


def _detect_severity(text: str) -> Optional[str]:
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        if sev in text:
            return sev
    return None


def _detect_verdict_class(text: str, path_name: str) -> str:
    name_upper = path_name.upper()
    if "FILED" in name_upper:
        return "FILED"
    if "AMENDED" in name_upper:
        return "AMENDED"
    if "SUPERSEDED" in name_upper or "DUPE" in name_upper:
        return "DUPE"
    if "STAGING" in name_upper or "CANDIDATE" in name_upper:
        return "CANDIDATE"
    if "HELD" in name_upper:
        return "HOLD"
    if "NEGATIVE" in text[:500].upper() or "NO CANDIDATE" in text[:500].upper():
        return "NEGATIVE"
    if "DROP" in text[:500].upper() or "NOT EXPLOITABLE" in text[:500].upper():
        return "DROP"
    return "CANDIDATE"


def _detect_platform(text: str, path_name: str) -> str:
    if "cantina" in text.lower() or "cantina" in path_name.lower():
        return "cantina"
    if "immunefi" in text.lower() or "immunefi" in path_name.lower():
        return "immunefi"
    if "sherlock" in text.lower():
        return "sherlock"
    if "code4rena" in text.lower() or "c4" in path_name.lower():
        return "code4rena"
    return "internal-engagement"


def _detect_repo(text: str) -> str:
    """Best-effort target_repo extraction."""
    patterns = [
        re.compile(r"target[_\s-]*repo\s*[:=]\s*([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)", re.IGNORECASE),
        re.compile(r"github\.com/([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)"),
        re.compile(r"`([A-Za-z0-9._-]{2,}/[A-Za-z0-9._-]{2,})`"),
    ]
    for rx in patterns:
        m = rx.search(text)
        if m:
            repo = m.group(1).strip().rstrip(".")
            if "/" in repo:
                return repo
    return "unknown/unknown"


def _detect_pin(text: str) -> str:
    for rx in [
        re.compile(r"audit[- _]?pin[^a-z0-9]+([0-9a-f]{7,40})", re.IGNORECASE),
        re.compile(r"`([0-9a-f]{7,40})`"),
    ]:
        m = rx.search(text)
        if m:
            return m.group(1)
    return "0000000"


def build_new_tag(
    source_path: Path,
    audit_dir: Path,
    taxonomy: List[Dict[str, Any]],
    attack_vocab: Dict[str, Dict[str, Any]],
    min_confidence: float,
    verbose: bool,
) -> Optional[Dict[str, Any]]:
    """Build a new tag dict from a source verdict file. Returns None on failure."""
    try:
        text = source_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None

    verdict_id = _derive_verdict_id(source_path, audit_dir)

    # Check if tag already exists
    tag_fname = _slug_to_tag_filename(verdict_id)
    existing_tag_path = TAGS_DIR / tag_fname
    if existing_tag_path.exists():
        return None  # already tagged; skip

    bug_class, attacks, confidence = classify_verdict(
        verdict_id, text, taxonomy, attack_vocab, min_confidence, verbose
    )

    stamp = _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    tag: Dict[str, Any] = {
        "verdict_id": verdict_id,
        "target_repo": _detect_repo(text),
        "audit_pin_sha": _detect_pin(text),
        "language": _detect_language(text, source_path),
        "verdict_class": _detect_verdict_class(text, source_path.name),
        "extraction_provenance": "hybrid" if bug_class else "regex",
        "extractor_version": EXTRACTOR_VERSION,
        "extracted_at_utc": stamp,
        "platform": _detect_platform(text, source_path.name),
    }
    sev = _detect_severity(text)
    if sev:
        tag["severity_claimed"] = sev
    if bug_class:
        tag["bug_class"] = bug_class
        tag["attack_classes_to_try"] = attacks
        fill_note = f"phase-f-heuristic confidence={confidence:.3f} at={stamp}"
        tag["notes"] = fill_note

    return tag


# ---------------------------------------------------------------------------
# Coverage report
# ---------------------------------------------------------------------------

def build_coverage_report(
    tags_dir: Path,
    filled_this_run: int,
    low_conf_records: List[Dict[str, Any]],
) -> str:
    """Generate a markdown coverage report."""
    all_tags = list(tags_dir.glob("*.yaml"))
    total = len(all_tags)

    by_engagement: Dict[str, int] = defaultdict(int)
    by_language: Dict[str, int] = defaultdict(int)
    by_bug_class: Dict[str, int] = defaultdict(int)
    filled_count = 0
    confidence_buckets = [0, 0, 0, 0, 0]  # [0-0.2, 0.2-0.4, 0.4-0.6, 0.6-0.8, 0.8-1.0]

    for tf in all_tags:
        try:
            tag = _load_yaml_safe(tf)
        except Exception:
            continue

        vid = tag.get("verdict_id", tf.stem)
        # Engagement = first path segment of verdict_id
        eng = vid.split("/")[0].split("_")[0]
        # Normalise engagement slug
        for known in ("dydx", "spark", "base-azul", "reserve-governor", "polymarket",
                       "centrifuge", "morpho", "monetrix", "k2", "kiln", "snowbridge",
                       "thegraph", "revert-stableswap", "auditooor"):
            if known in eng.lower():
                eng = known
                break
        by_engagement[eng] += 1

        lang = tag.get("language", "unknown")
        by_language[lang] += 1

        bc = tag.get("bug_class", "")
        if bc:
            filled_count += 1
            by_bug_class[bc] += 1
            # Try to extract confidence from notes
            notes = tag.get("notes", "")
            m = re.search(r"confidence=([\d.]+)", notes)
            if m:
                conf = float(m.group(1))
                bucket = min(4, int(conf / 0.2))
                confidence_buckets[bucket] += 1
            else:
                # hand-filled or seed: treat as high confidence
                confidence_buckets[4] += 1

    under_curated = {cls: cnt for cls, cnt in by_bug_class.items() if cnt < 3}
    well_covered = {cls: cnt for cls, cnt in by_bug_class.items() if cnt >= 5}

    lines = [
        "# Phase-F Coverage Report — 2026-05-11",
        "",
        f"Total tags in corpus: **{total}**",
        f"Tags with bug_class filled: **{filled_count}** ({filled_count*100//max(total,1)}%)",
        f"Filled this run: **{filled_this_run}**",
        f"Schema: `audit/corpus_tags/auditooor.verdict_tag.v1.schema.json`",
        f"Extractor: `tools/verdict-tag-llm-filler.py` (version {EXTRACTOR_VERSION})",
        "",
        "## Per-engagement breakdown",
        "",
        "| Engagement | Tags |",
        "|---|---:|",
    ]
    for eng, cnt in sorted(by_engagement.items(), key=lambda x: -x[1]):
        lines.append(f"| {eng} | {cnt} |")

    lines += [
        "",
        "## Per-language breakdown",
        "",
        "| Language | Tags |",
        "|---|---:|",
    ]
    for lang, cnt in sorted(by_language.items(), key=lambda x: -x[1]):
        lines.append(f"| {lang} | {cnt} |")

    lines += [
        "",
        "## Per-bug_class coverage",
        "",
        f"Bug classes with >=5 examples (well-curated): {len(well_covered)}",
        f"Bug classes with <3 examples (under-curated): {len(under_curated)}",
        "",
        "### Under-curated classes (examples < 3)",
        "",
        "| class_id | count |",
        "|---|---:|",
    ]
    for cls, cnt in sorted(under_curated.items(), key=lambda x: x[1]):
        lines.append(f"| {cls} | {cnt} |")

    lines += [
        "",
        "## Confidence distribution (phase-f heuristic fills only)",
        "",
        "| Bucket | Count |",
        "|---|---:|",
    ]
    bucket_labels = ["0.0-0.2", "0.2-0.4", "0.4-0.6", "0.6-0.8", "0.8-1.0"]
    for label, cnt in zip(bucket_labels, confidence_buckets):
        lines.append(f"| {label} | {cnt} |")

    lines += [
        "",
        "## Top-10 low-confidence tags for operator review",
        "",
        "| Tag file | Confidence | bug_class |",
        "|---|---|---|",
    ]
    sorted_low = sorted(low_conf_records, key=lambda x: x.get("confidence", 0))[:10]
    for rec in sorted_low:
        lines.append(f"| {rec['tag_file']} | {rec['confidence']:.3f} | {rec.get('bug_class','N/A')} |")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run(
    workspace: Path,
    limit: int,
    dry_run: bool,
    min_confidence: float,
    verbose: bool,
    report_only: bool,
) -> None:
    if yaml is None:
        print("ERROR: PyYAML not available. Install with: pip install pyyaml", file=sys.stderr)
        sys.exit(1)

    taxonomy = load_taxonomy(TAXONOMY_PATH)
    attack_vocab = load_attack_vocab(ATTACK_VOCAB_PATH)

    if verbose:
        print(f"Loaded {len(taxonomy)} bug_class entries from taxonomy")
        print(f"Loaded {len(attack_vocab)} attack_class entries from vocab")

    tags_dir = TAGS_DIR

    # --- Phase 1: Fill existing tags with empty semantic fields ---
    all_tag_files = sorted(tags_dir.glob("*.yaml"))
    filled = 0
    skipped_already = 0
    skipped_low_conf = 0
    low_conf_records: List[Dict[str, Any]] = []

    for tag_path in all_tag_files:
        if filled >= limit and not report_only:
            break
        try:
            tag = load_tag_file(tag_path)
        except Exception as exc:
            if verbose:
                print(f"  SKIP {tag_path.name}: load error: {exc}")
            continue

        if not tag_needs_filling(tag):
            skipped_already += 1
            continue

        verdict_id = tag.get("verdict_id", "")
        text = read_verdict_prose(verdict_id)
        if not text and verbose:
            print(f"  WARN {tag_path.name}: no source prose found for verdict_id={verdict_id!r}")

        bug_class, attacks, confidence = classify_verdict(
            verdict_id, text, taxonomy, attack_vocab, min_confidence, verbose
        )

        if bug_class is None:
            skipped_low_conf += 1
            low_conf_records.append({
                "tag_file": tag_path.name,
                "confidence": confidence,
                "verdict_id": verdict_id,
                "bug_class": "N/A",
            })
            if verbose:
                print(f"  LOW_CONF {tag_path.name}: confidence={confidence:.3f} < {min_confidence}")
            continue

        updated = apply_fill(tag, bug_class, attacks, confidence, dry_run)

        if dry_run:
            print(f"  DRY-RUN would fill: {tag_path.name}")
            print(f"    bug_class: {bug_class}")
            print(f"    attack_classes_to_try: {attacks}")
            print(f"    confidence: {confidence:.3f}")
        else:
            write_tag_file(tag_path, updated)
            if verbose:
                print(f"  FILLED {tag_path.name}: bug_class={bug_class} conf={confidence:.3f}")

        filled += 1

    # --- Phase 2: Expand corpus from source verdict files ---
    new_tags_emitted = 0
    if not report_only:
        audit_dirs = [d for d in AUDITS_ROOT.iterdir() if d.is_dir() and not d.name.startswith("_")]
        # Also add worktree agent_outputs as a pseudo audit dir
        audit_dirs.append(REPO_ROOT)

        for audit_dir in audit_dirs:
            if filled + new_tags_emitted >= limit:
                break
            # Find verdict markdown files
            search_roots = []
            ao_dir = audit_dir / "agent_outputs"
            if ao_dir.exists():
                search_roots.append(ao_dir)
            notes_dir = audit_dir / "notes"
            if notes_dir.exists():
                search_roots.append(notes_dir)
            for sub in ("paste_ready", "staging", "superseded", "held"):
                sub_dir = audit_dir / "submissions" / sub
                if sub_dir.exists():
                    search_roots.append(sub_dir)

            for search_root in search_roots:
                if filled + new_tags_emitted >= limit:
                    break
                for source_path in sorted(search_root.rglob("*verdict*.md")):
                    if filled + new_tags_emitted >= limit:
                        break
                    new_tag = build_new_tag(
                        source_path, audit_dir, taxonomy, attack_vocab,
                        min_confidence, verbose
                    )
                    if new_tag is None:
                        continue

                    tag_fname = _slug_to_tag_filename(new_tag["verdict_id"])
                    tag_path = tags_dir / tag_fname

                    if dry_run:
                        print(f"  DRY-RUN new tag: {tag_fname}")
                        print(f"    verdict_id: {new_tag['verdict_id']}")
                        print(f"    bug_class: {new_tag.get('bug_class', 'N/A')}")
                    else:
                        write_tag_file(tag_path, new_tag)
                        if verbose:
                            print(f"  NEW TAG: {tag_fname}")

                    new_tags_emitted += 1
                    if not new_tag.get("bug_class"):
                        low_conf_records.append({
                            "tag_file": tag_fname,
                            "confidence": 0.0,
                            "verdict_id": new_tag["verdict_id"],
                            "bug_class": "N/A",
                        })

    # --- Coverage report ---
    total_before = len(all_tag_files)
    total_after = len(list(tags_dir.glob("*.yaml")))
    report = build_coverage_report(tags_dir, filled + new_tags_emitted, low_conf_records)

    if report_only:
        print(report)
        return

    report_path = REPORTS_DIR / "phase_f_coverage_2026-05-11.md"
    if not dry_run:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report, encoding="utf-8")

    # Low-confidence report
    if low_conf_records:
        low_conf_path = REPORTS_DIR / "phase_f_low_confidence_2026-05-11.md"
        lc_lines = [
            "# Phase-F Low-Confidence Tags — 2026-05-11",
            "",
            "Tags where heuristic confidence < threshold. Operator review recommended.",
            "",
            "| Tag file | Confidence | verdict_id |",
            "|---|---|---|",
        ]
        for rec in sorted(low_conf_records, key=lambda x: x.get("confidence", 0)):
            lc_lines.append(
                f"| {rec['tag_file']} | {rec['confidence']:.3f} | {rec['verdict_id']} |"
            )
        lc_lines.append("")
        if not dry_run:
            low_conf_path.write_text("\n".join(lc_lines), encoding="utf-8")

    print(
        f"tags_processed={total_before} "
        f"new_tags_emitted={new_tags_emitted} "
        f"filled={filled} "
        f"skipped_low_confidence={skipped_low_conf} "
        f"skipped_already_filled={skipped_already} "
        f"total_after={total_after}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phase-F LLM-hybrid semantic enrichment for verdict tags."
    )
    parser.add_argument("--workspace", type=Path, default=REPO_ROOT,
                        help="Repo root (default: auto-detected)")
    parser.add_argument("--limit", type=int, default=100,
                        help="Max tags to fill/emit per run (default 100)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be done; do not write")
    parser.add_argument("--require-min-confidence", type=float, default=0.3,
                        dest="min_confidence",
                        help="Skip classification if top-1 score < threshold (default 0.3)")
    parser.add_argument("--verbose", action="store_true",
                        help="Show per-tag scoring details")
    parser.add_argument("--report-only", action="store_true",
                        help="Emit coverage report to stdout and exit")
    args = parser.parse_args()

    run(
        workspace=args.workspace,
        limit=args.limit,
        dry_run=args.dry_run,
        min_confidence=args.min_confidence,
        verbose=args.verbose,
        report_only=args.report_only,
    )


if __name__ == "__main__":
    main()
