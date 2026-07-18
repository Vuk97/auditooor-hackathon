#!/usr/bin/env python3
"""Bootstrap reviewed-ish anti-pattern notes from primary lesson sources.

This is intentionally narrower than tools/memory-anti-pattern-emitter.py:
it converts reference/triager_patterns.json plus reference/outcomes.jsonl into
5-20 markdown notes readable by vault_anti_pattern_corpus. Corpus
fix_anti_pattern_avoided phrases are attached only as supporting reminders and
never increase confidence.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LIMIT = 20
MIN_NOTES = 5
MAX_NOTES = 20


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:88] or "anti-pattern"


def _one_line(value: Any, max_chars: int = 240) -> str:
    text = " ".join(str(value or "").replace("\n", " ").split())
    return text[:max_chars]


def _fm_string(value: Any, max_chars: int = 240) -> str:
    text = _one_line(value, max_chars=max_chars).replace('"', "'")
    return f'"{text}"'


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _ids_from_examples(examples: list[str]) -> set[str]:
    ids: set[str] = set()
    for example in examples:
        ids.update(re.findall(r"#(\d+)", example))
    return ids


def _looks_concrete_example(example: str) -> bool:
    lowered = example.lower()
    return bool(example.strip()) and "hypothetical" not in lowered and "(none" not in lowered


def _outcome_numeric_ids(row: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for key in ("finding_id", "submission_id"):
        raw = str(row.get(key) or "")
        ids.update(re.findall(r"(?:^|[-#])(\d+)$", raw))
        if raw.isdigit():
            ids.add(raw)
    return ids


def _outcomes_by_id(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    indexed: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        for item_id in _outcome_numeric_ids(row):
            indexed.setdefault(item_id, []).append(row)
    return indexed


def _load_fix_anti_patterns(tags_dir: Path, max_rows: int = 300) -> list[str]:
    """Line-scan public corpus records for fix_anti_pattern_avoided values."""
    if not tags_dir.exists():
        return []
    values: list[str] = []
    seen: set[str] = set()
    for path in sorted(tags_dir.rglob("*")):
        if len(values) >= max_rows:
            break
        if not path.is_file() or path.suffix.lower() not in {".yaml", ".yml", ".json"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if path.suffix.lower() == ".json":
            try:
                obj = json.loads(text)
            except json.JSONDecodeError:
                obj = {}
            raw = obj.get("fix_anti_pattern_avoided") if isinstance(obj, dict) else None
            candidates = [raw] if raw else []
        else:
            candidates = []
            for line in text.splitlines():
                if line.strip().startswith("fix_anti_pattern_avoided:"):
                    candidates.append(line.split(":", 1)[1])
        for raw in candidates:
            value = _one_line(str(raw).strip().strip('"').strip("'"), max_chars=180)
            key = value.lower()
            if value and key not in seen:
                seen.add(key)
                values.append(value)
                if len(values) >= max_rows:
                    break
    return values


def _keywords(text: str) -> set[str]:
    stop = {
        "finding",
        "pattern",
        "impact",
        "without",
        "proof",
        "state",
        "concrete",
        "severity",
        "claim",
        "claims",
        "source",
        "outcome",
        "triager",
    }
    return {w for w in re.findall(r"[a-z0-9]{5,}", text.lower()) if w not in stop}


def _related_fix_phrases(rejection: dict[str, Any], fix_phrases: list[str]) -> list[str]:
    basis = " ".join(
        [
            str(rejection.get("name") or ""),
            str(rejection.get("description") or ""),
            str(rejection.get("pre_submit_guard") or ""),
            " ".join(rejection.get("triager_language") or []),
        ]
    )
    basis_terms = _keywords(basis)
    scored: list[tuple[int, str]] = []
    for phrase in fix_phrases:
        overlap = len(basis_terms & _keywords(phrase))
        if overlap >= 3:
            scored.append((overlap, phrase))
    scored.sort(key=lambda item: (-item[0], item[1].lower()))
    return [phrase for _, phrase in scored[:3]]


def _is_lesson_outcome(row: dict[str, Any]) -> bool:
    text = " ".join(
        str(row.get(key) or "")
        for key in ("status", "outcome", "outcome_class", "rejection_reason", "fp_reason")
    ).lower()
    lesson_terms = ("rejected", "declined", "duplicate", "dupe", "oos", "not_a_bug")
    return any(term in text for term in lesson_terms)


def _confidence(primary_samples: int, outcome_samples: int) -> str:
    if outcome_samples >= 2 or primary_samples >= 3:
        return "high"
    if outcome_samples >= 1 or primary_samples >= 1:
        return "medium"
    return "low"


def _recommendation_for(rejection: dict[str, Any]) -> str:
    guard = _one_line(rejection.get("pre_submit_guard"), max_chars=220)
    if guard:
        return guard
    name = str(rejection.get("name") or "this anti-pattern").lower()
    return f"Do not advance {name} unless the draft proves a concrete in-scope security impact."


def _render_note(
    rejection: dict[str, Any],
    outcomes: list[dict[str, Any]],
    related_fix_phrases: list[str],
    today: str,
) -> str:
    title = _one_line(rejection.get("name"), max_chars=120)
    examples = [str(x) for x in (rejection.get("examples") or [])]
    concrete_examples = [x for x in examples if _looks_concrete_example(x)]
    concrete_sample_count = len(concrete_examples)
    sample_size = max(1, concrete_sample_count, len(outcomes))
    confidence = _confidence(concrete_sample_count, len(outcomes))
    recommendation = _recommendation_for(rejection)
    if confidence == "low":
        related_fix_phrases = []

    fm = "\n".join(
        [
            "---",
            f"title: {_fm_string(title, max_chars=120)}",
            f"recommendation: {_fm_string(recommendation, max_chars=260)}",
            f"sample_size: {sample_size}",
            f"confidence: {confidence}",
            "counter_examples: 0",
            f"last_validated_at: {today}",
            f"source_kind: {_fm_string('triager_patterns+outcomes')}",
            f"source_id: {_fm_string(rejection.get('id'), max_chars=40)}",
            f"generated_by: {_fm_string('tools/anti-pattern-corpus-bootstrap.py')}",
            "---",
            "",
        ]
    )

    lines = [
        fm,
        f"# {title}",
        "",
        "## Recommendation",
        recommendation,
        "",
        "## Lesson",
        _one_line(rejection.get("description"), max_chars=900),
        "",
        "## Primary Evidence",
        f"- Triager pattern `{rejection.get('id')}` from `reference/triager_patterns.json`.",
    ]
    for outcome in outcomes[:5]:
        outcome_id = outcome.get("finding_id") or outcome.get("submission_id") or "unknown"
        status = outcome.get("status") or outcome.get("outcome") or outcome.get("outcome_class") or "unknown"
        lines.append(f"- Outcome `{outcome_id}`: {_one_line(status, max_chars=180)}.")
    if concrete_examples:
        lines.append("")
        lines.append("## Source Examples")
        for example in concrete_examples[:5]:
            lines.append(f"- {_one_line(example, max_chars=280)}")

    lines.append("")
    lines.append("## Supporting Corpus Reminders")
    lines.append("These fix_anti_pattern_avoided phrases are supporting context only; they do not raise confidence.")
    if related_fix_phrases:
        for phrase in related_fix_phrases:
            lines.append(f"- {_one_line(phrase, max_chars=220)}")
    else:
        lines.append("- None matched.")

    lines.append("")
    lines.append("## Counter-Examples")
    lines.append("No counter-examples are recorded in the source lesson set.")
    lines.append("")
    return "\n".join(lines)


def build_notes(repo_root: Path, limit: int = DEFAULT_LIMIT) -> dict[str, str]:
    triager_path = repo_root / "reference" / "triager_patterns.json"
    outcomes_path = repo_root / "reference" / "outcomes.jsonl"
    tags_dir = repo_root / "audit" / "corpus_tags" / "tags"

    triager = _load_json(triager_path)
    outcomes_index = _outcomes_by_id(_load_jsonl(outcomes_path))
    fix_phrases = _load_fix_anti_patterns(tags_dir)
    today = dt.date.today().isoformat()

    notes: dict[str, str] = {}
    for rejection in (triager.get("rejections") or [])[:limit]:
        if not isinstance(rejection, dict):
            continue
        ids = _ids_from_examples([str(x) for x in (rejection.get("examples") or [])])
        matched_outcomes: list[dict[str, Any]] = []
        seen_outcomes: set[int] = set()
        for item_id in sorted(ids, key=lambda value: int(value) if value.isdigit() else value):
            lesson_rows = [row for row in outcomes_index.get(item_id, []) if _is_lesson_outcome(row)]
            for outcome in lesson_rows:
                marker = id(outcome)
                if marker not in seen_outcomes:
                    seen_outcomes.add(marker)
                    matched_outcomes.append(outcome)
        slug = _slugify(str(rejection.get("name") or rejection.get("id") or "anti-pattern"))
        notes[f"{slug}.md"] = _render_note(
            rejection,
            matched_outcomes,
            _related_fix_phrases(rejection, fix_phrases),
            today,
        )
    return notes


def write_notes(notes: dict[str, str], output_dir: Path, dry_run: bool = False) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for filename, body in sorted(notes.items()):
        path = output_dir / filename
        written.append(path)
        if not dry_run:
            path.write_text(body, encoding="utf-8")
    return written


def bootstrap(repo_root: Path = REPO_ROOT, limit: int = DEFAULT_LIMIT, dry_run: bool = False) -> list[Path]:
    limit = max(1, min(limit, MAX_NOTES))
    notes = build_notes(repo_root, limit=limit)
    if not (MIN_NOTES <= len(notes) <= MAX_NOTES):
        raise SystemExit(f"expected {MIN_NOTES}-{MAX_NOTES} notes, got {len(notes)}")
    return write_notes(notes, repo_root / "obsidian-vault" / "anti-patterns", dry_run=dry_run)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    written = bootstrap(args.repo_root.resolve(), limit=args.limit, dry_run=args.dry_run)
    action = "would write" if args.dry_run else "wrote"
    print(json.dumps({"action": action, "count": len(written), "paths": [str(p) for p in written]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
