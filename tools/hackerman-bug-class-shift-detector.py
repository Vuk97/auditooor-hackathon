#!/usr/bin/env python3
"""Wave-2 W2.9 hackerman bug-class-shift detector (PR #726 follow-up).

Flags hackerman corpus records whose claimed ``attack_class`` drifted across
PoC iterations OR whose ``attack_class`` / ``impact_class`` doesn't match the
rubric row the submission selected.

This is a PREVIEW / SURVEILLANCE tool only - it does NOT auto-rewrite, merge,
or delete any record. It emits two artifacts:

1. ``.auditooor/bug_class_shift.jsonl`` (gitignored, machine-readable) - one
   JSON object per drift candidate, with the record path, drift category,
   prior vs current values, and the rubric phrase that triggered the
   rubric-mismatch check (if any).
2. ``docs/HACKERMAN_BUG_CLASS_SHIFT_PREVIEW_2026-05-16.md`` (committed,
   operator-readable) - top-10 candidates plus summary stats and the per
   drift-category breakdown.

Drift categories
----------------
- ``prior_attack_class_drift``: record has either
    * ``record_extensions.prior_attack_class`` field present AND its value
      (a string OR the last entry of a list) differs from the record's
      current ``attack_class``, OR
    * ``function_shape.shape_tags`` contains one or more entries prefixed
      ``prior:`` / ``prior-attack-class:`` whose normalised value differs
      from the current ``attack_class``.
- ``rubric_row_vs_impact_class_mismatch``: record cites a known rubric
  phrase ("Direct loss of funds", "Permanent freezing of funds", "Theft of
  governance", "RPC API crash", etc.) in any of the rubric-source fields
  (``rubric_row``, ``severity_at_finding`` if it has the phrase, the body
  of ``attacker_action_sequence`` / ``required_preconditions``, or a
  ``shape_tags`` entry prefixed ``rubric:``) AND the record's
  ``impact_class`` is NOT in the expected set for that rubric phrase.

Rubric phrase -> expected impact_class set
-----------------------------------------
- ``direct loss of funds`` / ``loss of funds`` / ``theft of funds`` /
  ``direct theft`` / ``fund drain`` / ``unauthorized withdraw`` ->
  ``{theft}``
- ``permanent freezing`` / ``freezing of funds`` / ``frozen`` ->
  ``{freeze}``
- ``governance takeover`` / ``theft of governance`` ->
  ``{governance-takeover}``
- ``rpc api crash`` / ``denial of service`` / ``dos`` (as standalone) ->
  ``{dos}``
- ``griefing`` -> ``{griefing}``
- ``yield redistribution`` / ``yield diversion`` ->
  ``{yield-redistribution}``
- ``privilege escalation`` -> ``{privilege-escalation}``
- ``precision loss`` / ``rounding error`` -> ``{precision-loss}``

Walking strategy is identical to ``hackerman-cross-corpus-dupe-finder.py``:
record.json wins over record.yaml for the same record-slug dir; flat
``tags/<name>.yaml`` files contribute under subtree=``__flat__``.

Determinism
-----------
- Record paths are sorted asc.
- Drift candidate emission order: (drift_category asc, record path asc).
- ``--generated-at`` override (env
  ``AUDITOOOR_BUG_CLASS_SHIFT_GENERATED_AT``) pins the timestamp so the
  docs file stays byte-stable across runs.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

try:  # pragma: no cover - optional pyyaml.
    import yaml  # type: ignore[import-not-found]
except Exception:  # noqa: BLE001
    yaml = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_JSONL_OUT = REPO_ROOT / ".auditooor" / "bug_class_shift.jsonl"
DEFAULT_DOCS_OUT = REPO_ROOT / "docs" / "HACKERMAN_BUG_CLASS_SHIFT_PREVIEW_2026-05-16.md"

SCHEMA = "auditooor.hackerman_bug_class_shift.v1"
FLAT_SUBTREE_SENTINEL = "__flat__"
TOP_N_DOCS = 10

DRIFT_PRIOR_ATTACK_CLASS = "prior_attack_class_drift"
DRIFT_RUBRIC_MISMATCH = "rubric_row_vs_impact_class_mismatch"

# Rubric phrase -> set of allowed impact_class values. Phrase keys are
# lowercased and matched case-insensitively via substring against a
# normalised (whitespace-collapsed, lowercased) blob built from rubric
# source fields.
RUBRIC_PHRASE_TO_IMPACT: dict[str, frozenset[str]] = {
    "direct loss of funds": frozenset({"theft"}),
    "loss of funds": frozenset({"theft"}),
    "theft of funds": frozenset({"theft"}),
    "direct theft": frozenset({"theft"}),
    "fund drain": frozenset({"theft"}),
    "unauthorized withdraw": frozenset({"theft"}),
    "unauthorized transfer": frozenset({"theft"}),
    "permanent freezing": frozenset({"freeze"}),
    "freezing of funds": frozenset({"freeze"}),
    "frozen funds": frozenset({"freeze"}),
    "governance takeover": frozenset({"governance-takeover"}),
    "theft of governance": frozenset({"governance-takeover"}),
    "rpc api crash": frozenset({"dos"}),
    "denial of service": frozenset({"dos"}),
    "griefing": frozenset({"griefing"}),
    "yield redistribution": frozenset({"yield-redistribution"}),
    "yield diversion": frozenset({"yield-redistribution"}),
    "privilege escalation": frozenset({"privilege-escalation"}),
    "precision loss": frozenset({"precision-loss"}),
    "rounding error": frozenset({"precision-loss"}),
}

# Fields scanned for rubric phrases. ``rubric_row`` is the primary anchor;
# the others provide secondary signal so the gate can fire on records that
# embed the rubric phrase in their attacker-sequence or preconditions text
# without a top-level ``rubric_row`` field.
RUBRIC_SCAN_FIELDS = (
    "rubric_row",
    "rubric",
    "severity_rubric_row",
    "attacker_action_sequence",
    "required_preconditions",
    "fix_pattern",
    "fix_anti_pattern_avoided",
)

# shape_tags markers consumed by the prior-attack-class extractor.
PRIOR_SHAPE_TAG_PREFIXES = ("prior:", "prior-attack-class:", "was:", "previously:")

# shape_tags markers consumed by the rubric scan (e.g.
# ``rubric:direct-loss-of-funds``).
RUBRIC_SHAPE_TAG_PREFIXES = ("rubric:", "rubric-row:")

_NORMALISE_RE = re.compile(r"\s+")


# ---------------------------------------------------------------------------
# Loader helpers - shared shape with hackerman-cross-corpus-dupe-finder.py.
# ---------------------------------------------------------------------------


def _yaml_load(text: str) -> dict[str, Any]:
    if yaml is not None:
        try:
            data = yaml.safe_load(text)
            return data if isinstance(data, dict) else {}
        except Exception:  # noqa: BLE001
            return {}
    out: dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("#") or line.startswith(" "):
            continue
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip().strip("\"'")
    return out


def _json_load(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except Exception:  # noqa: BLE001
        return {}
    return data if isinstance(data, dict) else {}


def iter_records(tags_dir: Path) -> Iterable[tuple[str, Path, dict[str, Any]]]:
    """Yield ``(subtree, record_path, record_data)`` tuples.

    JSON wins over YAML when both exist in a record-slug directory. Flat
    ``tags/<name>.yaml`` files are yielded with subtree=``__flat__``.
    """
    if not tags_dir.exists():
        return
    for entry in sorted(tags_dir.iterdir()):
        if entry.is_file() and entry.suffix == ".yaml":
            data = _yaml_load(entry.read_text(encoding="utf-8", errors="replace"))
            if data:
                yield FLAT_SUBTREE_SENTINEL, entry, data
    for subtree_dir in sorted(p for p in tags_dir.iterdir() if p.is_dir()):
        subtree_name = subtree_dir.name
        for record_dir in sorted(p for p in subtree_dir.iterdir() if p.is_dir()):
            json_path = record_dir / "record.json"
            yaml_path = record_dir / "record.yaml"
            if json_path.exists():
                data = _json_load(json_path.read_text(encoding="utf-8", errors="replace"))
                if data:
                    yield subtree_name, json_path, data
                    continue
            if yaml_path.exists():
                data = _yaml_load(yaml_path.read_text(encoding="utf-8", errors="replace"))
                if data:
                    yield subtree_name, yaml_path, data
        for entry in sorted(subtree_dir.iterdir()):
            if entry.is_file() and entry.suffix == ".yaml":
                data = _yaml_load(entry.read_text(encoding="utf-8", errors="replace"))
                if data:
                    yield subtree_name, entry, data


# ---------------------------------------------------------------------------
# Drift detectors.
# ---------------------------------------------------------------------------


def _normalise(value: Any) -> str:
    if value is None:
        return ""
    return _NORMALISE_RE.sub(" ", str(value).strip().lower())


def _norm_class(value: Any) -> str:
    """Normalise an attack_class value for equality comparison.

    Lowercases, strips whitespace, and collapses underscores/colons to
    hyphens so that ``access_control_missing_modifier`` and
    ``access-control-missing-modifier`` are treated as the same class.
    """
    norm = _normalise(value)
    norm = norm.replace("_", "-").replace(":", "-")
    norm = re.sub(r"-{2,}", "-", norm)
    return norm.strip("-")


def extract_prior_attack_classes(record: dict[str, Any]) -> list[str]:
    """Return prior_attack_class values surfaced by the record.

    Sources (in order):
    - ``record_extensions.prior_attack_class`` (string OR list).
    - ``function_shape.shape_tags`` entries with one of
      :data:`PRIOR_SHAPE_TAG_PREFIXES`.
    Values are normalised via :func:`_norm_class` and de-duplicated while
    preserving first-seen order.
    """
    seen: list[str] = []
    seen_set: set[str] = set()

    def _add(value: Any) -> None:
        norm = _norm_class(value)
        if not norm or norm in seen_set:
            return
        seen_set.add(norm)
        seen.append(norm)

    ext = record.get("record_extensions")
    if isinstance(ext, dict):
        prior = ext.get("prior_attack_class")
        if isinstance(prior, list):
            for v in prior:
                _add(v)
        elif prior is not None:
            _add(prior)

    fs = record.get("function_shape")
    if isinstance(fs, dict):
        tags = fs.get("shape_tags")
        if isinstance(tags, list):
            for tag in tags:
                if not isinstance(tag, str):
                    continue
                tag_lower = tag.lower()
                for prefix in PRIOR_SHAPE_TAG_PREFIXES:
                    if tag_lower.startswith(prefix):
                        _add(tag_lower[len(prefix):])
                        break
    return seen


def detect_prior_attack_class_drift(
    record: dict[str, Any],
) -> dict[str, Any] | None:
    """Return a drift descriptor when prior_attack_class != current."""
    priors = extract_prior_attack_classes(record)
    if not priors:
        return None
    current = _norm_class(record.get("attack_class"))
    drifted = [p for p in priors if p and p != current]
    if not drifted:
        return None
    return {
        "drift_category": DRIFT_PRIOR_ATTACK_CLASS,
        "prior_attack_classes": priors,
        "current_attack_class": current,
        "drifted_priors": drifted,
    }


def _rubric_scan_blob(record: dict[str, Any]) -> str:
    """Build a normalised lowercased blob from rubric-source fields."""
    chunks: list[str] = []
    for field in RUBRIC_SCAN_FIELDS:
        v = record.get(field)
        if v is None:
            continue
        if isinstance(v, list):
            chunks.extend(str(item) for item in v if item is not None)
        else:
            chunks.append(str(v))
    fs = record.get("function_shape")
    if isinstance(fs, dict):
        tags = fs.get("shape_tags")
        if isinstance(tags, list):
            for tag in tags:
                if not isinstance(tag, str):
                    continue
                tag_lower = tag.lower()
                for prefix in RUBRIC_SHAPE_TAG_PREFIXES:
                    if tag_lower.startswith(prefix):
                        chunks.append(tag_lower[len(prefix):].replace("-", " "))
                        break
    return _normalise(" ".join(chunks))


def detect_rubric_row_vs_impact_class_mismatch(
    record: dict[str, Any],
) -> dict[str, Any] | None:
    """Return a drift descriptor when the rubric phrase doesn't match."""
    blob = _rubric_scan_blob(record)
    if not blob:
        return None
    impact = _normalise(record.get("impact_class"))
    if not impact:
        return None
    matched_phrases: list[str] = []
    expected_union: set[str] = set()
    for phrase, allowed in RUBRIC_PHRASE_TO_IMPACT.items():
        if phrase in blob:
            matched_phrases.append(phrase)
            expected_union |= set(allowed)
    if not matched_phrases:
        return None
    if impact in expected_union:
        return None
    return {
        "drift_category": DRIFT_RUBRIC_MISMATCH,
        "rubric_phrases_matched": sorted(matched_phrases),
        "current_impact_class": impact,
        "expected_impact_class_any_of": sorted(expected_union),
    }


# ---------------------------------------------------------------------------
# Aggregator.
# ---------------------------------------------------------------------------


def _record_id(record: dict[str, Any], path: Path) -> str:
    rid = record.get("record_id")
    if isinstance(rid, str) and rid.strip():
        return rid.strip()
    return path.name


def build_candidates(
    records: Iterable[tuple[str, Path, dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Walk records and return drift candidates."""
    out: list[dict[str, Any]] = []
    for subtree, path, data in records:
        try:
            rel = path.resolve().relative_to(REPO_ROOT.resolve())
            rel_str = str(rel)
        except ValueError:
            rel_str = str(path)
        record_id = _record_id(data, path)
        base = {
            "subtree": subtree,
            "path": rel_str,
            "record_id": record_id,
        }
        prior = detect_prior_attack_class_drift(data)
        if prior is not None:
            out.append({**base, **prior})
        rubric = detect_rubric_row_vs_impact_class_mismatch(data)
        if rubric is not None:
            out.append({**base, **rubric})
    out.sort(key=lambda c: (c["drift_category"], c["path"]))
    return out


# ---------------------------------------------------------------------------
# Renderers.
# ---------------------------------------------------------------------------


def render_jsonl(candidates: list[dict[str, Any]], generated_at: str) -> str:
    by_cat: dict[str, int] = defaultdict(int)
    for c in candidates:
        by_cat[c["drift_category"]] += 1
    header = {
        "schema_version": SCHEMA,
        "generated_at_iso": generated_at,
        "candidate_count": len(candidates),
        "by_drift_category": dict(sorted(by_cat.items())),
    }
    lines = [json.dumps(header, sort_keys=True)]
    for c in candidates:
        lines.append(json.dumps(c, sort_keys=True))
    return "\n".join(lines) + "\n"


def _summary_stats(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    by_cat: dict[str, int] = defaultdict(int)
    by_subtree: dict[str, int] = defaultdict(int)
    for c in candidates:
        by_cat[c["drift_category"]] += 1
        by_subtree[c["subtree"]] += 1
    return {
        "total_candidates": len(candidates),
        "by_drift_category": dict(sorted(by_cat.items())),
        "by_subtree": dict(sorted(by_subtree.items())),
    }


def _format_candidate_table_row(idx: int, c: dict[str, Any]) -> str:
    if c["drift_category"] == DRIFT_PRIOR_ATTACK_CLASS:
        prior = ", ".join(f"`{p}`" for p in c.get("drifted_priors", []))
        detail = f"prior={prior} -> current=`{c.get('current_attack_class','')}`"
    else:
        phrases = ", ".join(
            f"`{p}`" for p in c.get("rubric_phrases_matched", [])
        )
        expected = ", ".join(
            f"`{p}`" for p in c.get("expected_impact_class_any_of", [])
        )
        detail = (
            f"rubric={phrases} expected impact_class in {{{expected}}} "
            f"got=`{c.get('current_impact_class','')}`"
        )
    return (
        f"| {idx} | `{c['drift_category']}` | `{c['subtree']}` | "
        f"`{c['record_id']}` | {detail} |"
    )


def render_docs(
    candidates: list[dict[str, Any]],
    generated_at: str,
    tags_dir: Path,
    total_records: int,
) -> str:
    stats = _summary_stats(candidates)
    lines: list[str] = []
    lines.append("# Hackerman Bug-Class-Shift - Preview")
    lines.append("")
    lines.append(f"- Schema: `{SCHEMA}`")
    lines.append(f"- Generated at: `{generated_at}`")
    lines.append(f"- Tags dir: `{tags_dir}`")
    lines.append(f"- Records scanned: `{total_records}`")
    lines.append(f"- Drift candidates: `{stats['total_candidates']}`")
    lines.append("")
    lines.append(
        "PREVIEW / SURVEILLANCE artifact. No record is auto-rewritten or"
    )
    lines.append(
        "auto-merged. Machine-readable candidate list at"
        " `.auditooor/bug_class_shift.jsonl` (gitignored)."
    )
    lines.append("")
    lines.append("## Drift categories")
    lines.append("")
    lines.append(
        "- `prior_attack_class_drift`: record has a documented prior"
        " attack_class (via `record_extensions.prior_attack_class` or a"
        " `prior:` / `was:` shape-tag) that differs from the record's"
        " current `attack_class`."
    )
    lines.append(
        "- `rubric_row_vs_impact_class_mismatch`: record cites a known"
        " rubric phrase (`direct loss of funds`, `permanent freezing`,"
        " `governance takeover`, etc.) in one of the rubric-source fields"
        " but the record's `impact_class` is NOT in the expected set."
    )
    lines.append("")
    lines.append("## Summary stats")
    lines.append("")
    lines.append("### Candidates by drift category")
    lines.append("")
    lines.append("| drift_category | candidate_count |")
    lines.append("|----------------|----------------:|")
    if stats["by_drift_category"]:
        for k, v in stats["by_drift_category"].items():
            lines.append(f"| `{k}` | {v} |")
    else:
        lines.append("| _none_ | 0 |")
    lines.append("")
    lines.append("### Candidates by subtree (top 20)")
    lines.append("")
    lines.append("| subtree | candidate_count |")
    lines.append("|---------|----------------:|")
    top_subtrees = sorted(
        stats["by_subtree"].items(), key=lambda kv: (-kv[1], kv[0])
    )[:20]
    if top_subtrees:
        for k, v in top_subtrees:
            lines.append(f"| `{k}` | {v} |")
    else:
        lines.append("| _none_ | 0 |")
    lines.append("")
    lines.append(f"## Top-{TOP_N_DOCS} drift candidates")
    lines.append("")
    if not candidates:
        lines.append("_No drift candidates detected._")
    else:
        lines.append(
            "| # | drift_category | subtree | record_id | detail |"
        )
        lines.append(
            "|--:|----------------|---------|-----------|--------|"
        )
        for i, c in enumerate(candidates[:TOP_N_DOCS], start=1):
            lines.append(_format_candidate_table_row(i, c))
    lines.append("")
    lines.append("## Provenance")
    lines.append("")
    lines.append(
        "Generated by `tools/hackerman-bug-class-shift-detector.py`."
        " Walks `audit/corpus_tags/tags/**/record.{json,yaml}` + flat"
        " `tags/*.yaml`, applies two read-only drift detectors"
        " (prior_attack_class drift; rubric_row vs impact_class mismatch),"
        " and emits this preview alongside the gitignored JSONL artifact."
        " No record is mutated by this tool."
    )
    lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _resolve_generated_at(arg: str | None) -> str:
    if arg:
        return arg
    env = os.environ.get("AUDITOOOR_BUG_CLASS_SHIFT_GENERATED_AT")
    if env:
        return env
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tags-dir",
        default=str(DEFAULT_TAGS_DIR),
        help="Hackerman corpus tags directory (default: %(default)s).",
    )
    parser.add_argument(
        "--jsonl-out",
        default=str(DEFAULT_JSONL_OUT),
        help="JSONL preview artifact path (gitignored).",
    )
    parser.add_argument(
        "--docs-out",
        default=str(DEFAULT_DOCS_OUT),
        help="Operator-readable Markdown preview path.",
    )
    parser.add_argument(
        "--generated-at",
        default=None,
        help="Override the generated_at_iso timestamp.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Also dump the full candidate list to stdout as JSON.",
    )
    args = parser.parse_args(argv)

    tags_dir = Path(args.tags_dir)
    generated_at = _resolve_generated_at(args.generated_at)

    records = list(iter_records(tags_dir))
    total_records = len(records)
    candidates = build_candidates(records)

    jsonl_out = Path(args.jsonl_out)
    docs_out = Path(args.docs_out)
    jsonl_out.parent.mkdir(parents=True, exist_ok=True)
    docs_out.parent.mkdir(parents=True, exist_ok=True)

    jsonl_text = render_jsonl(candidates, generated_at)
    docs_text = render_docs(candidates, generated_at, tags_dir, total_records)
    jsonl_out.write_text(jsonl_text, encoding="utf-8")
    docs_out.write_text(docs_text, encoding="utf-8")

    by_cat: dict[str, int] = defaultdict(int)
    for c in candidates:
        by_cat[c["drift_category"]] += 1
    summary = {
        "schema_version": SCHEMA,
        "generated_at_iso": generated_at,
        "tags_dir": str(tags_dir),
        "records_scanned": total_records,
        "candidate_count": len(candidates),
        "by_drift_category": dict(sorted(by_cat.items())),
        "jsonl_out": str(jsonl_out),
        "docs_out": str(docs_out),
    }
    if args.json:
        print(
            json.dumps(
                {"summary": summary, "candidates": candidates}, sort_keys=True
            )
        )
    else:
        print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
