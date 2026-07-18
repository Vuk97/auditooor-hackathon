#!/usr/bin/env python3
"""Inventory lesson-enforcement predicates compiled from local prose inputs.

This is a read-only, offline-only wrapper around prose-to-lesson-compiler.py.
It scans explicit files or directories for supported local inputs and returns a
bounded enforcement map for later gate integration.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
COMPILER_PATH = Path(__file__).resolve().with_name("prose-to-lesson-compiler.py")
SCHEMA = "auditooor.lesson_enforcement_inventory.v1"
SCHEMA_VERSION = "1.0"
TOOL_VERSION = "1.0.0"
DEFAULT_MAX_FILES = 200
DEFAULT_MAX_LESSONS = 250
SUPPORTED_SUFFIXES = {".json", ".jsonl", ".md", ".markdown", ".txt", ".text"}
DEFAULT_INPUTS = (
    ROOT / "reference" / "curated_lessons.jsonl",
    ROOT / "reference" / "outcomes.jsonl",
    ROOT / "reference" / "triager_patterns.md",
    ROOT / "reference" / "triager_patterns.json",
)


def _load_compiler():
    spec = importlib.util.spec_from_file_location("prose_to_lesson_compiler", COMPILER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load compiler from {COMPILER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def iter_input_files(paths: Sequence[Path], *, max_files: int = DEFAULT_MAX_FILES) -> tuple[list[Path], list[str], bool]:
    files: list[Path] = []
    warnings: list[str] = []
    truncated = False
    for raw in paths:
        path = raw.expanduser().resolve()
        if path.is_file():
            candidates = [path]
        elif path.is_dir():
            candidates = sorted(
                candidate
                for candidate in path.rglob("*")
                if candidate.is_file()
                and candidate.suffix.lower() in SUPPORTED_SUFFIXES
                and ".git" not in candidate.parts
            )
        else:
            warnings.append(f"input path missing: {path}")
            continue
        for candidate in candidates:
            if candidate.suffix.lower() not in SUPPORTED_SUFFIXES:
                warnings.append(f"unsupported suffix skipped: {candidate}")
                continue
            files.append(candidate)
            if len(files) >= max_files:
                truncated = True
                return files, warnings, truncated
    return files, warnings, truncated


def enforcement_action(enforcement_level: str) -> str:
    if enforcement_level == "hard_pre_poc":
        return "block proof work until predicate-specific proof obligation is answered"
    if enforcement_level == "hard_pre_submit":
        return "block paste-ready or submission until overclaim/scope issue is resolved"
    if enforcement_level == "hard_paste_ready":
        return "block paste-ready packaging until lesson gate passes"
    if enforcement_level == "hard_commit_or_dispatch":
        return "block dispatch/commit until receipt or typed exception exists"
    if enforcement_level == "advisory_worker_context":
        return "surface as worker context and proof-upgrade guidance"
    return "not enforceable; retain only as context"


def build_enforcement_rows(lessons: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for lesson in lessons:
        if not isinstance(lesson, dict):
            continue
        predicate = str(lesson.get("predicate") or "")
        level = str(lesson.get("enforcement_level") or "not_enforceable")
        if not predicate:
            continue
        key = (predicate, level)
        row = grouped.setdefault(
            key,
            {
                "predicate": predicate,
                "enforcement_level": level,
                "gate_phase": lesson.get("gate_phase"),
                "action": enforcement_action(level),
                "lesson_count": 0,
                "examples": [],
            },
        )
        row["lesson_count"] += 1
        if len(row["examples"]) < 5:
            row["examples"].append(
                {
                    "lesson_id": lesson.get("lesson_id"),
                    "source_ref": lesson.get("source_ref"),
                    "confidence": lesson.get("confidence"),
                    "matched_signals": lesson.get("matched_signals") or [],
                    "snippet": lesson.get("snippet"),
                }
            )
    return sorted(
        grouped.values(),
        key=lambda row: (str(row["enforcement_level"]), str(row["predicate"])),
    )


def build_inventory(
    paths: Sequence[Path],
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_lessons: int = DEFAULT_MAX_LESSONS,
    max_chars_per_source: int | None = None,
) -> dict[str, Any]:
    compiler = _load_compiler()
    files, warnings, file_limit_truncated = iter_input_files(paths, max_files=max_files)
    generated = compiler.utc_now_iso()
    compilations: list[dict[str, Any]] = []
    remaining = max_lessons
    for path in files:
        if remaining <= 0:
            break
        kwargs: dict[str, Any] = {"max_lessons": remaining, "generated_at": generated}
        if max_chars_per_source is not None:
            kwargs["max_chars_per_source"] = max_chars_per_source
        payload = compiler.compile_path(path, **kwargs)
        compilations.append(payload)
        remaining -= len(payload.get("lessons") or [])

    merged = compiler.merge_compilations(compilations, generated_at=generated)
    lessons = list(merged.get("lessons") or [])[:max_lessons]
    compile_summary = merged.get("summary", {}) if isinstance(merged.get("summary"), dict) else {}
    lesson_limit_truncated = (
        len(merged.get("lessons") or []) > len(lessons)
        or len(compilations) < len(files)
        or bool(compile_summary.get("truncated"))
    )
    predicate_counts: dict[str, int] = {}
    level_counts: dict[str, int] = {}
    for lesson in lessons:
        predicate = str(lesson.get("predicate") or "")
        level = str(lesson.get("enforcement_level") or "")
        if predicate:
            predicate_counts[predicate] = predicate_counts.get(predicate, 0) + 1
        if level:
            level_counts[level] = level_counts.get(level, 0) + 1

    warnings.extend(str(item) for item in compile_summary.get("warnings") or [])
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "generated_at_utc": generated,
        "offline_only": True,
        "network_access": False,
        "source_files": [str(path) for path in files],
        "summary": {
            "files_scanned": len(files),
            "lessons_compiled": len(lessons),
            "predicate_counts": predicate_counts,
            "enforcement_level_counts": level_counts,
            "positive_reward_claim_lines_suppressed": int(
                compile_summary.get("positive_reward_claim_lines_suppressed") or 0
            ),
            "file_limit_truncated": file_limit_truncated,
            "lesson_limit_truncated": lesson_limit_truncated,
            "warnings": warnings,
        },
        "enforcement_rows": build_enforcement_rows(lessons),
        "lessons": lessons,
        "positive_reward_claim_policy": "positive reward assertions are not surfaced as lesson evidence",
    }


def render_text(inv: dict[str, Any]) -> str:
    summary = inv.get("summary", {})
    lines = [
        "lesson-enforcement inventory",
        f"schema={inv.get('schema')} schema_version={inv.get('schema_version')} offline_only={inv.get('offline_only')}",
        f"files_scanned={summary.get('files_scanned', 0)} lessons_compiled={summary.get('lessons_compiled', 0)}",
    ]
    rows = inv.get("enforcement_rows") or []
    if not rows:
        lines.append("no lesson predicates detected")
        return "\n".join(lines) + "\n"
    lines.append("")
    for row in rows:
        lines.append(
            f"- {row['predicate']} level={row['enforcement_level']} "
            f"count={row['lesson_count']} gate={row.get('gate_phase')}"
        )
        lines.append(f"  action: {row['action']}")
    return "\n".join(lines) + "\n"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="*", type=Path, help="Files or directories to inventory. Defaults to local reference lesson sources.")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-lessons", type=int, default=DEFAULT_MAX_LESSONS)
    parser.add_argument("--max-chars-per-source", type=int, default=None)
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    paths = args.inputs or [path for path in DEFAULT_INPUTS if path.exists()]
    payload = build_inventory(
        paths,
        max_files=args.max_files,
        max_lessons=args.max_lessons,
        max_chars_per_source=args.max_chars_per_source,
    )
    if args.out_json:
        out = args.out_json.expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_text(payload), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
